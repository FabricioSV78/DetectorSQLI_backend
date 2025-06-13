import time
import re
import os
import json
from collections import defaultdict
from antlr4 import *
from JavaLexer import JavaLexer
from JavaParser import JavaParser
from JavaParserListener import JavaParserListener
import networkx as nx
import matplotlib.pyplot as plt
from pyvis.network import Network

# ------------------------- FUNCIONES AUXILIARES -------------------------

def determinar_capa_desde_archivo(ruta_archivo, nombre_paquete, nombre_clase):
    ruta = ruta_archivo.replace("\\", "/").lower() if ruta_archivo else ""
    paquete = nombre_paquete.lower() if nombre_paquete else ""
    clase = nombre_clase.lower() if nombre_clase else ""

    if ('/presentacion/' in ruta or clase.endswith('controller') or
        '.controller.' in paquete):
        return 'presentacion'
    elif ('/logica/' in ruta or clase.endswith('service') or
          '.service.' in paquete):
        return 'logica'
    elif ('/datos/' in ruta or clase.endswith('dao') or
          '.dao.' in paquete):
        return 'datos'
    elif ('/modelo/' in ruta or clase.endswith('entidad') or
          '.entidad.' in paquete):
        return 'modelo'
    else:
        return 'desconocida'

# --------------------------- DETECTOR PRINCIPAL --------------------------

ENTRADAS_USUARIO = ["getParameter", "nextLine", "readLine", "input", "getInputStream"]
MALAS_PRACTICAS = ["createStatement", "addBatch", "prepareCall"]
PALABRAS_SQL = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC", "UNION", "FROM", "WHERE"]
VARIABLES_IGNORADAS = {"event", "e", "evt", "args"}
PRACTICAS_SEGURAS = ["PreparedStatement", "setString", "setInt", "setBoolean", "setDate", "setParameter"]

class SQLiDetector(JavaParserListener):
    def __init__(self, archivo_fuente=""):
        self.variables_riesgosas = {}
        self.variables_descontaminadas = set()
        self.alertas_emitidas = set()
        self.alertas_por_linea = defaultdict(list)
        self.codigo_fuente = {}
        self.archivo_actual = archivo_fuente
        self.grafo_codigo = nx.DiGraph()
        self.nombre_paquete = ""
        self.clase_actual = ""
        self.capa_actual = ""
        self.metodo_actual = ""
        if archivo_fuente and os.path.exists(archivo_fuente):
            with open(archivo_fuente, 'r', encoding='utf-8') as f:
                self.codigo_fuente_lineas = f.readlines()
        else:
            self.codigo_fuente_lineas = []

    def enterCompilationUnit(self, ctx):
        if ctx.packageDeclaration():
            self.nombre_paquete = ctx.packageDeclaration().qualifiedName().getText()

    def enterClassDeclaration(self, ctx):
        self.clase_actual = ctx.identifier().getText()
        self.capa_actual = determinar_capa_desde_archivo(self.archivo_actual, self.nombre_paquete, self.clase_actual)

        if self.capa_actual == "desconocida":
            print(f"[IGNORADO] Clase fuera de estándar: {self.clase_actual} en archivo {self.archivo_actual}")
            self.clase_actual = None
            return

        self.grafo_codigo.add_node(self.clase_actual, tipo="clase")

    def enterExpression(self, ctx):
        if self.clase_actual is None:
            return
        texto = ctx.getText()
        
        set_method_match = re.search(r'(\w+)\.(setString|setInt|setBoolean|setDate|setParameter)\(\s*(\d+)\s*,\s*([^)]+)', texto)
        if set_method_match:
            stmt_var = set_method_match.group(1)
            param_value = set_method_match.group(4).strip()
            
            # Marcar el PreparedStatement como seguro
            self.variables_descontaminadas.add(stmt_var)
            
            # Marcar el parámetro como seguro (si es una variable)
            if re.match(r'^\w+$', param_value):
                self.variables_descontaminadas.add(param_value)
            
            # Si el parámetro viene de un método get de una entidad, marcar el objeto como seguro
            getter_match = re.search(r'(\w+)\.get\w+\(\)', param_value)
            if getter_match:
                self.variables_descontaminadas.add(getter_match.group(1))
                # También marcar la variable de la entidad como segura
                if getter_match.group(1) in self.variables_riesgosas:
                    self.variables_riesgosas.pop(getter_match.group(1))
    
    def enterMethodDeclaration(self, ctx):
        if self.clase_actual is None:
            return
        self.metodo_actual = ctx.identifier().getText()
        metodo_id = f"{self.clase_actual}.{self.metodo_actual}"
        self.grafo_codigo.add_node(metodo_id, tipo="metodo")
        self.grafo_codigo.add_edge(self.clase_actual, metodo_id)
        if ctx.formalParameters():
            params = ctx.formalParameters().formalParameterList()
            if params:
                for param in params.formalParameter():
                    tipo_param = param.typeType().getText()
                    nombre_param = param.variableDeclaratorId().getText()
                    nodo_param = f"{metodo_id}.{nombre_param}"
                    self.grafo_codigo.add_node(nodo_param, tipo="parametro")
                    self.grafo_codigo.add_edge(metodo_id, nodo_param)
                    # Solo marcar como riesgoso si no es una entidad
                    if (nombre_param not in VARIABLES_IGNORADAS and 
                        not tipo_param.endswith("Entidad")):
                        self.variables_riesgosas[nombre_param] = (ctx.start.line, "PARAMETER")

    def enterLocalVariableDeclaration(self, ctx):
        if self.clase_actual is None:
            return
        texto = ctx.getText()
        texto_up = texto.upper()
        linea = ctx.start.line
        self._capturar_fragmento_codigo(linea)
        metodo_id = f"{self.clase_actual}.{self.metodo_actual}"
        matches = re.findall(r'(\w+)\s+(\w+)', texto)

        # Detección mejorada de PreparedStatement
        if "PreparedStatement" in texto and "prepareStatement" in texto:
            # Marcar todas las variables del PreparedStatement como seguras
            for tipo, nombre in matches:
                if tipo == "PreparedStatement":
                    self.variables_descontaminadas.add(nombre)
                    # Marcar también la variable SQL si usa parámetros (?)
                    if "?" in texto:
                        sql_var = re.search(r'(String\s+(\w+)\s*=\s*"[^"]\?[^"]")', texto)
                        if sql_var:
                            self.variables_descontaminadas.add(sql_var.group(2))

        # Procesar todas las variables declaradas
        for tipo, nombre in matches:
            nodo_var = f"{metodo_id}.{nombre}"
            self.grafo_codigo.add_node(nodo_var, tipo="variable")
            self.grafo_codigo.add_edge(metodo_id, nodo_var)

        # Verificación de vulnerabilidad solo si no es consulta preparada
        es_consulta_preparada = (
            "PreparedStatement" in texto and 
            "?" in texto and 
            "prepareStatement" in texto
        )
        
        contiene_sql = any(sql in texto_up for sql in PALABRAS_SQL) and ('"' in texto or "'" in texto)

        if not es_consulta_preparada:
            for var in self.variables_riesgosas:
                if var in texto and contiene_sql:
                    if var in self.variables_descontaminadas:
                        continue
                    self._alert(linea, "CRÍTICO", "SQLi por uso de parámetro no validado",
                            f"Se usa la variable '{var}' directamente en SQL en {self.capa_actual.upper()}")

    def enterStatement(self, ctx):
        if self.clase_actual is None:
            return
        texto = ctx.getText()
        texto_up = texto.upper()
        linea = ctx.start.line
        self._capturar_fragmento_codigo(linea)

        if "preparestatement" in texto_up and "?" in texto and "+" not in texto:
            return

        # Condición mejorada para consultas seguras
        es_consulta_segura = (
            any(practica in texto for practica in PRACTICAS_SEGURAS) or
            any(var in self.variables_descontaminadas for var in re.findall(r'\b\w+\b', texto)) or
            ("PreparedStatement" in texto and "?" in texto) or
            ("try" in texto and "PreparedStatement" in texto) or
            any(texto.strip().startswith(f"{var}.") for var in self.variables_descontaminadas)
        )
        
        contiene_sql = any(sql in texto_up for sql in PALABRAS_SQL) and ('"' in texto or "'" in texto)

        # Lógica de detección de vulnerabilidades
        if not es_consulta_segura:
            # Detección de concatenación SQL insegura
            if '+' in texto and contiene_sql:
                for var in self.variables_riesgosas:
                    if var in texto and var not in self.variables_descontaminadas:
                        self._alert(linea, "CRÍTICO", "SQLi por concatenación",
                                f"Variable '{var}' concatenada en SQL en {self.capa_actual.upper()}")

            # Detección de uso directo de variables en SQL
            for var in self.variables_riesgosas:
                if var in texto and contiene_sql and var not in self.variables_descontaminadas:
                    self._alert(linea, "CRÍTICO", "SQLi por parámetro no validado",
                            f"Variable '{var}' usada directamente en SQL")

        # Detección de Statement inseguros (solo si no es contexto seguro)
        if any(metodo in texto for metodo in MALAS_PRACTICAS) and not es_consulta_segura:
            if self.capa_actual in ["presentacion", "logica"] and contiene_sql:
                self._alert(linea, "CRÍTICO", "Violación de arquitectura",
                        f"SQL ejecutado directamente en capa {self.capa_actual.upper()}")

    def _capturar_fragmento_codigo(self, linea):
        if not self.codigo_fuente_lineas:
            return
        inicio = max(0, linea - 2)
        fin = min(len(self.codigo_fuente_lineas), linea + 1)
        fragmento = "".join(self.codigo_fuente_lineas[inicio:fin]).strip()
        self.codigo_fuente[linea] = fragmento

    def _alert(self, linea, nivel, tipo, detalles):
        mensaje_str = detalles if isinstance(detalles, str) else "|".join(detalles)
        clave = f"{self.archivo_actual}:{linea}-{tipo}-{mensaje_str}"
        if clave in self.alertas_emitidas:
            return
        self.alertas_emitidas.add(clave)

        for var in self.variables_riesgosas:
            if var in self.codigo_fuente.get(linea, ""):
                metodo_id = f"{self.clase_actual}.{self.metodo_actual}"
                nodo_var = f"{metodo_id}.{var}"
                if self.grafo_codigo.has_node(nodo_var):
                    self.grafo_codigo.nodes[nodo_var]["riesgoso"] = True
                # Verificar si la vulnerabilidad llega hasta la capa de datos
                if self.grafo_codigo.has_node(metodo_id):
                    if self.hay_camino_hacia_datos(metodo_id, self.grafo_codigo):
                        self.grafo_codigo.nodes[metodo_id]["riesgoso"] = True
                    elif self.capa_actual in ["logica", "presentacion"]:
                        print(f"[DETECTADO EN {self.capa_actual.upper()}] {metodo_id} ejecuta SQL directamente.")
                        self.grafo_codigo.nodes[metodo_id]["riesgoso"] = True
                    else:
                        print(f"[IGNORADO - No llega a datos y no está en capa lógica/presentación] {metodo_id}")
                        return


        alerta = {
            "nivel": nivel,
            "tipo": tipo,
            "linea": linea,
            "codigo": self.codigo_fuente.get(linea, ""),
            "archivo": self.archivo_actual,
            "detalles": detalles
        }
        self.alertas_por_linea[linea].append(alerta)

    def hay_camino_hacia_datos(self, metodo_inicio, grafo):
        """
        Verifica si desde un método riesgoso se alcanza alguna clase de la capa de datos (DAO).
        """
        # si el método ya pertenece a una clase DAO, no necesitamos buscar ruta
        nombre_clase = metodo_inicio.split(".")[0]
        if self._es_capa_datos(nombre_clase):
            print(f"[BACKTRACKING] {metodo_inicio} ya pertenece a clase DAO → válido")
            return True

        if metodo_inicio not in grafo.nodes:
            print(f"[BACKTRACKING TEST] Desde: {metodo_inicio}")
            print(f"[CLASES DESTINO POSIBLES]: {[n for n in grafo.nodes if '.' not in n and self._es_capa_datos(n)]}")
            return False
        try:
            for nodo in grafo.nodes:
                # Validamos que sea un nodo de clase (no tiene punto)
                if isinstance(nodo, str) and '.' not in nodo:
                    atributos = grafo.nodes[nodo]
                    if atributos.get("tipo") == "clase" and self._es_capa_datos(nodo):
                        if nx.has_path(grafo, metodo_inicio, nodo):
                            return True
            return False
        except Exception as e:
            print(f"[ERROR backtracking]: {e}")
            return False


    def _es_capa_datos(self, nombre_clase):
        """
        Determina si el nombre de clase corresponde a la capa 'datos' según la convención.
        Se considera válido si el nombre termina en DAO o contiene 'datos' en su ruta.
        """
        nombre = nombre_clase.lower()
        return (
            nombre.endswith("dao") or
            ".dao." in nombre or
            "datos" in nombre  
        )



# --------------------------- ANALIZADOR DE PROYECTO ---------------------------
#def guardar_resultados_en_json(resultados, path="resultados.json"):
   # with open(path, "w", encoding="utf-8") as f:
       # json.dump(resultados, f, indent=2, ensure_ascii=False)

def analizar_proyecto(directorio):
    resultados = []
    lineas_unicas = set()
    archivos_analizados = set()
    inicio = time.time()
    grafo = nx.DiGraph()

    for root, _, files in os.walk(directorio):
        for file in files:
            if file.endswith(".java"):
                ruta = os.path.join(root, file)
                archivos_analizados.add(ruta)
                print(f"Analizando: {ruta}")
                try:
                    input_stream = FileStream(ruta, encoding='utf-8')
                    lexer = JavaLexer(input_stream)
                    stream = CommonTokenStream(lexer)
                    parser = JavaParser(stream)
                    tree = parser.compilationUnit()

                    detector = SQLiDetector(ruta)
                    walker = ParseTreeWalker()
                    walker.walk(detector, tree)

                    for alertas in detector.alertas_por_linea.values():
                        resultados.append({
                            "archivo": alertas[0]["archivo"],
                            "linea": alertas[0]["linea"],
                            "codigo": alertas[0]["codigo"],
                            "detalles": [
                                f"[{a['nivel']}] {a['tipo']}: {mensaje}"
                                for a in alertas
                                for mensaje in (a["detalles"] if isinstance(a["detalles"], list) else [a["detalles"]])
                            ]
                        })
                        lineas_unicas.add((alertas[0]["archivo"], alertas[0]["linea"]))
                        grafo.update(detector.grafo_codigo)
                except Exception as e:
                    print(f"Error en {ruta}: {str(e)}")

    fin = time.time()
    estadisticas = {
        "archivos analizados": len(archivos_analizados),
        "lineas afectadas": len(lineas_unicas),
        "tiempo de analisis": round(fin - inicio, 2)
    }
    return resultados, estadisticas, grafo

def mostrar_grafo_codigo(grafo):
    plt.figure(figsize=(16, 10))
    pos = nx.spring_layout(grafo)
    labels = {n: n for n in grafo.nodes()}
    colors = []

    for n in grafo.nodes(data=True):
        tipo = n[1].get("tipo", "")
        riesgoso = n[1].get("riesgoso", False)
        if riesgoso:
            colors.append("red")
        elif tipo == "clase":
            colors.append("lightgreen")
        elif tipo == "metodo":
            colors.append("skyblue")
        elif tipo == "parametro":
            colors.append("orange")
        elif tipo == "variable":
            colors.append("salmon")
        else:
            colors.append("lightgray")

    nx.draw(grafo, pos, with_labels=True, labels=labels,
            node_color=colors, node_size=2000, font_size=9,
            edge_color='gray')
    plt.title("Grafo de flujo estructural del código Java (nodos riesgosos en rojo)")
    plt.show()

def mostrar_resultados(resultados, estadisticas):
    print("\n=== RESULTADOS DEL ANÁLISIS ===")
    if not resultados:
        print("No se detectaron vulnerabilidades.")
        return
    for i, alerta in enumerate(resultados, 1):
        print("-" * 80)
        print(f"{i}. Archivo : {alerta['archivo']}")
        print(f"   Línea   : {alerta['linea']}")
        print(f"   Código  :\n{alerta['codigo']}")
        print("   Detalles:")
        for d in alerta['detalles']:
            print(f"   - {d}")

    print("\n=== RESUMEN ===")
    print(f"Archivos analizados      : {estadisticas['archivos analizados']}")
    print(f"Líneas con vulnerabilidad: {estadisticas['lineas afectadas']}")
    print(f"Tiempo total de análisis : {estadisticas['tiempo de analisis']} segundos")

    if 'clases fuera de estándar' in estadisticas:
        print(f"Clases fuera de estándar : {estadisticas['clases fuera de estándar']}")


import time
import re
import os
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

    if ('/controller/' in ruta or clase.endswith('controller') or
        '.controller.' in paquete or '.presentation.' in paquete or '.view.' in paquete or '/application/' in ruta):
        return 'presentacion'
    elif ('/service/' in ruta or clase.endswith('service') or
          '.service.' in paquete or '.business.' in paquete or '.logic.' in paquete or '/businesslayer/' in ruta):
        return 'logica'
    elif ('/dao/' in ruta or clase.endswith('dao') or clase.endswith('repository') or
          '.dao.' in paquete or '.repository.' in paquete or '.data.' in paquete or '/datalayer/' in ruta):
        return 'datos'
    else:
        return 'desconocida'

# --------------------------- DETECTOR PRINCIPAL --------------------------

ENTRADAS_USUARIO = ["getParameter", "nextLine", "readLine", "input", "getInputStream"]
MALAS_PRACTICAS = ["createStatement", "executeQuery", "executeUpdate", "execute", "addBatch", "prepareCall"]
PALABRAS_SQL = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC", "UNION", "FROM", "WHERE"]
VARIABLES_IGNORADAS = {"event", "e", "evt", "args"}

class SQLiDetector(JavaParserListener):
    def __init__(self, archivo_fuente=""):
        self.variables_riesgosas = {}
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
        self.grafo_codigo.add_node(self.clase_actual, tipo="clase")

    def enterMethodDeclaration(self, ctx):
        self.metodo_actual = ctx.identifier().getText()
        metodo_id = f"{self.clase_actual}.{self.metodo_actual}"
        self.grafo_codigo.add_node(metodo_id, tipo="metodo")
        self.grafo_codigo.add_edge(self.clase_actual, metodo_id)
        if ctx.formalParameters():
            params = ctx.formalParameters().formalParameterList()
            if params:
                for param in params.formalParameter():
                    nombre_param = param.variableDeclaratorId().getText()
                    nodo_param = f"{metodo_id}.{nombre_param}"
                    self.grafo_codigo.add_node(nodo_param, tipo="parametro")
                    self.grafo_codigo.add_edge(metodo_id, nodo_param)
                    if nombre_param not in VARIABLES_IGNORADAS:
                        self.variables_riesgosas[nombre_param] = (ctx.start.line, "PARAMETER")

    def enterLocalVariableDeclaration(self, ctx):
        texto = ctx.getText()
        texto_up = texto.upper()
        linea = ctx.start.line
        self._capturar_fragmento_codigo(linea)
        metodo_id = f"{self.clase_actual}.{self.metodo_actual}"
        matches = re.findall(r'(\w+)\s+(\w+)', texto)

        for tipo, nombre in matches:
            nodo_var = f"{metodo_id}.{nombre}"
            self.grafo_codigo.add_node(nodo_var, tipo="variable")
            self.grafo_codigo.add_edge(metodo_id, nodo_var)

        contiene_sql = any(sql in texto_up for sql in PALABRAS_SQL) and ('"' in texto or "'" in texto)

        for var in self.variables_riesgosas:
            if var in texto and contiene_sql:
                self._alert(linea, "CRÍTICO", "SQLi por uso de parámetro no validado",
                            f"Se usa la variable '{var}' directamente en una sentencia SQL en la capa '{self.capa_actual.upper()}'. Esto puede permitir inyección SQL si no se valida correctamente.")

    def enterStatement(self, ctx):
        texto = ctx.getText()
        texto_up = texto.upper()
        linea = ctx.start.line
        self._capturar_fragmento_codigo(linea)

        contiene_sql = any(sql in texto_up for sql in PALABRAS_SQL) and ('"' in texto or "'" in texto)

        for var in self.variables_riesgosas:
            if var in texto and contiene_sql:
                self._alert(linea, "CRÍTICO", "SQLi por uso de parámetro no validado",
                            f"Se usa la variable '{var}' directamente en una sentencia SQL en la capa '{self.capa_actual.upper()}'. Esto puede permitir inyección SQL si no se valida correctamente.")

        if '+' in texto and contiene_sql:
            for var in self.variables_riesgosas:
                if var in texto:
                    self._alert(linea, "CRÍTICO", "SQLi por concatenación",
                                f"La variable '{var}' contaminada se concatena en una sentencia SQL en la capa '{self.capa_actual.upper()}'. Esto puede permitir inyección SQL.")

        if any(metodo in texto for metodo in MALAS_PRACTICAS):
            if self.capa_actual in ["presentacion", "logica"] and contiene_sql:
                self._alert(linea, "CRÍTICO", "Violación de arquitectura N-capas",
                            f"En la capa '{self.capa_actual.upper()}' no está permitido ejecutar sentencias SQL directamente. Las operaciones SQL deben realizarse solo en la capa de datos.")

    def _capturar_fragmento_codigo(self, linea):
        if not self.codigo_fuente_lineas:
            return
        inicio = max(0, linea - 2)
        fin = min(len(self.codigo_fuente_lineas), linea + 1)
        fragmento = "".join(self.codigo_fuente_lineas[inicio:fin]).strip()
        self.codigo_fuente[linea] = fragmento

    def _alert(self, linea, nivel, tipo, detalle):
        clave = f"{linea}-{tipo}"
        if clave in self.alertas_emitidas:
            return
        self.alertas_emitidas.add(clave)

        for var in self.variables_riesgosas:
            if var in self.codigo_fuente.get(linea, ""):
                metodo_id = f"{self.clase_actual}.{self.metodo_actual}"
                nodo_var = f"{metodo_id}.{var}"
                if self.grafo_codigo.has_node(nodo_var):
                    self.grafo_codigo.nodes[nodo_var]["riesgoso"] = True
                if self.grafo_codigo.has_node(metodo_id):
                    self.grafo_codigo.nodes[metodo_id]["riesgoso"] = True

        alerta = {
            "nivel": nivel,
            "tipo": tipo,
            "linea": linea,
            "codigo": self.codigo_fuente.get(linea, ""),
            "archivo": self.archivo_actual,
            "detalle": detalle
        }
        self.alertas_por_linea[linea].append(alerta)

# --------------------------- ANALIZADOR DE PROYECTO ---------------------------

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
                            "detalles": [f"[{a['nivel']}] {a['tipo']}: {a['detalle']}" for a in alertas]
                        })
                        lineas_unicas.add((alertas[0]["archivo"], alertas[0]["linea"]))
                        grafo.update(detector.grafo_codigo)
                except Exception as e:
                    print(f"Error en {ruta}: {str(e)}")

    fin = time.time()
    estadisticas = {
        "archivos": len(archivos_analizados),
        "lineas_afectadas": len(lineas_unicas),
        "tiempo": round(fin - inicio, 2)
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

def mostrar_grafo_interactivo(grafo):
    net = Network(height="800px", width="100%", notebook=False, directed=True)
    for nodo, data in grafo.nodes(data=True):
        color = "red" if data.get("riesgoso") else {
            "clase": "lightgreen",
            "metodo": "skyblue",
            "parametro": "orange",
            "variable": "mediumseagreen"
        }.get(data.get("tipo"), "lightgray")
        net.add_node(nodo, label=nodo, color=color)
    for origen, destino in grafo.edges():
        net.add_edge(origen, destino)

    net.write_html("grafo_interactivo.html", open_browser=True)

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
    print(f"Archivos analizados      : {estadisticas['archivos']}")
    print(f"Líneas con vulnerabilidad: {estadisticas['lineas_afectadas']}")
    print(f"Tiempo total de análisis : {estadisticas['tiempo']} segundos")

# --------------------------- EJEMPLO DE USO ---------------------------

if __name__ == "__main__":
    carpeta = input("Ingrese la ruta de su proyecto Java: ").strip()
    alertas, stats, grafo = analizar_proyecto(carpeta)
    mostrar_resultados(alertas, stats)
    mostrar_grafo_interactivo(grafo)
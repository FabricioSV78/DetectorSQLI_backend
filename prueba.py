import time
import networkx as nx
import re
from antlr4 import *
from JavaLexer import JavaLexer
from JavaParser import JavaParser
from JavaParserListener import JavaParserListener
import matplotlib.pyplot as plt



ENTRADAS_USUARIO = [
    "getParameter", "nextLine", "readLine", "input", "getInputStream", "getQueryString",
    "getAttribute", "getParameterMap", "getRequest", "getCookies", "getHeader"
]

PALABRAS_SQL = [
    "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC", "UNION", "FROM", "WHERE"
]

MALAS_PRACTICAS = [
    "createStatement", "executeQuery", "executeUpdate", 
    "execute", "addBatch", "prepareCall"
]

class SQLiDetector(JavaParserListener):
    def __init__(self):
        self.variables_riesgosas = {}
        self.alertas_emitidas = set()
        self.flujos_alertados = set()
        self.bucle_activo = False
        self.nivel_bucle = 0
        self.grafo = nx.DiGraph()
        self.fragmentos_incumplidos = []

    def enterStatement(self, ctx):
        texto = ctx.getText().replace(" ", "").upper()
        if texto.startswith("FOR(") or texto.startswith("WHILE(") or texto.startswith("DO{"):
            self.bucle_activo = True
            self.nivel_bucle += 1

    def exitStatement(self, ctx):
        texto = ctx.getText().replace(" ", "").upper()
        if texto.startswith("FOR(") or texto.startswith("WHILE(") or texto.startswith("DO{"):
            self.nivel_bucle -= 1
            if self.nivel_bucle <= 0:
                self.bucle_activo = False

        texto = ctx.getText().upper()

        for metodo in MALAS_PRACTICAS + ["PREPARESTATEMENT"]:
            patron_llamada = r'\.\s*' + metodo + r'\s*\('
            if re.search(patron_llamada, texto, re.IGNORECASE):
                self.grafo.add_node(metodo, tipo="sink")
                for var in self.variables_riesgosas:
                    if re.search(r'\b' + re.escape(var) + r'\b', texto, re.IGNORECASE):
                        self.grafo.add_edge(var, metodo)

        for nodo in self.grafo.nodes:
            if self.grafo.nodes[nodo].get("entrada_usuario", False):
                for sink in [n for n in self.grafo.nodes if self.grafo.nodes[n].get("tipo") == "sink"]:
                    if nx.has_path(self.grafo, nodo, sink):
                        camino = f"{nodo} → {sink}"
                        if camino not in self.flujos_alertados:
                            self.flujos_alertados.add(camino)
                            self._alert("CRÍTICO", "Flujo desde entrada de usuario hacia ejecución SQL",
                                        camino, ctx.start.line,
                                        f"Camino peligroso detectado entre '{nodo}' y '{sink}'")

    def enterVariableDeclarator(self, ctx):
        nombre_var = ctx.variableDeclaratorId().getText()
        if ctx.variableInitializer():
            raw_value = ctx.variableInitializer().getText()
            valor = raw_value.upper()
            linea = ctx.start.line

            if nombre_var not in self.variables_riesgosas:
                self.variables_riesgosas[nombre_var] = (raw_value, linea, [])

            riesgos = self.variables_riesgosas[nombre_var][2]

            if any(inp.lower() in raw_value.lower() for inp in ENTRADAS_USUARIO):
                if "USER_INPUT" not in riesgos:
                    riesgos.append("USER_INPUT")
                self.grafo.add_node(nombre_var, tipo="var", entrada_usuario=True)
            else:
                self.grafo.add_node(nombre_var, tipo="var", entrada_usuario=False)

            for otra_var in self.variables_riesgosas:
                patron = r'\b' + re.escape(otra_var) + r'\b(?!\s*\()'
                if re.search(patron, raw_value):
                    self.grafo.add_edge(otra_var, nombre_var)

            if any(sql in valor for sql in PALABRAS_SQL) and '+' in raw_value:
                if "SQL_CONCAT" not in riesgos:
                    riesgos.append("SQL_CONCAT")
                    detalle = f"La variable '{nombre_var}' se construyó a partir de datos del usuario sin protección"
                    if self.bucle_activo:
                        detalle += " (dentro de un bucle)"
                    self._alert("CRÍTICO", "SQLi por concatenación directa con entrada de usuario",
                                raw_value, linea, detalle)

            self.variables_riesgosas[nombre_var] = (raw_value, linea, riesgos)

    def _alert(self, nivel, tipo, fragmento, linea, detalles=None): 
        self.fragmentos_incumplidos.append({ "nivel": nivel, "tipo": tipo, "linea": linea, "fragmento": fragmento, "detalle": detalles or "" })
        print(f" [{nivel}] {tipo}")
        print(f"   Línea: {linea}")
        print(f"   Fragmento: {fragmento[:200]}" + ("..." if len(fragmento) > 200 else ""))
        if detalles:
            print(f"   {detalles}")
        print("─" * 50)


        

def mostrar_grafo(grafo):
    pos = nx.spring_layout(grafo, seed=42, k=1.7, iterations=50)
    tipos = nx.get_node_attributes(grafo, 'tipo')
    entrada_usuario = nx.get_node_attributes(grafo, 'entrada_usuario')

    colores = []
    for nodo in grafo.nodes():
        if tipos.get(nodo) == 'sink':
            colores.append('red')
        elif entrada_usuario.get(nodo):
            colores.append('orange')
        else:
            colores.append('lightblue')

    plt.figure(figsize=(10, 7))
    nx.draw_networkx_nodes(grafo, pos, node_color=colores, node_size=700)
    nx.draw_networkx_edges(grafo, pos, arrows=True, arrowstyle='->', edge_color='gray', arrowsize=15)
    nx.draw_networkx_labels(grafo, pos, font_size=8)

    plt.title("Grafo de flujo de datos para análisis de SQLi")
    plt.axis('off')
    plt.tight_layout()
    plt.show()

def analizar_archivo(ruta_archivo):
    inicio = time.time()
    input_stream = FileStream(ruta_archivo, encoding='utf-8')
    lexer = JavaLexer(input_stream)
    stream = CommonTokenStream(lexer)
    parser = JavaParser(stream)
    tree = parser.compilationUnit()

    walker = ParseTreeWalker()
    detector = SQLiDetector()
    walker.walk(detector, tree)
    fin = time.time()
    print(f"Tiempo de análisis: {fin - inicio:.2f} segundos")
    print(f"Cantidad de codigos vulnerables: {len(detector.fragmentos_incumplidos)}")
    mostrar_grafo(detector.grafo)

if __name__ == "__main__":
    analizar_archivo("Ejemplo2.java")

import matplotlib.pyplot as plt
from fpdf import FPDF
import os
import networkx as nx
from networkx.drawing.nx_pydot import to_pydot
from unidecode import unidecode
from pyvis.network import Network


def mostrar_grafo_interactivo(grafo, output_path="grafo.html"):
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

    net.write_html(output_path, open_browser=False)



def generar_heatmap_por_archivo(resultados, output_path="heatmap.png"):
    from collections import defaultdict

    conteo = defaultdict(int)
    for alerta in resultados:
        archivo = os.path.basename(alerta['archivo'])
        conteo[archivo] += 1

    archivos = list(conteo.keys())
    valores = list(conteo.values())

    plt.figure(figsize=(10, max(3, len(archivos) * 0.5)))
    plt.barh(archivos, valores, color='salmon')
    plt.xlabel("Número de vulnerabilidades")
    plt.title("Mapa de calor por archivo")
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def generar_pdf_reporte(resultados, stats, output_path="reporte.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=unidecode("REPORTE DE VULNERABILIDADES SQLi"), ln=True, align='C')
    pdf.ln(10)

    if stats:
        pdf.set_font("Arial", 'B', 12)
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(200, 8, txt=unidecode("Resumen del análisis"), ln=True, fill=True)
        pdf.set_font("Arial", '', 11)
        for clave, valor in stats.items():
            pdf.cell(200, 8, txt=unidecode(f"{clave}: {valor}"), ln=True)
        pdf.ln(5)

    agrupado = {}
    for alerta in resultados:
        archivo = os.path.relpath(alerta['archivo'], start='project').replace("\\", "/")
        if archivo not in agrupado:
            agrupado[archivo] = []
        agrupado[archivo].append(alerta)

    for archivo, registros in agrupado.items():
        pdf.set_font("Arial", 'B', 12)
        pdf.set_fill_color(200, 220, 255)
        pdf.cell(200, 8, txt=unidecode(f"Archivo: {archivo}"), ln=True, fill=True)
        for entry in registros:
            pdf.set_font("Arial", 'B', 11)
            pdf.cell(200, 6, txt=unidecode(f"Línea: {entry['linea']}"), ln=True)
            pdf.set_font("Arial", 'I', 10)
            pdf.set_text_color(80)
            for linea in entry['codigo'].splitlines():
                pdf.multi_cell(0, 5, unidecode(f"  {linea}"))
            pdf.set_text_color(0)
            pdf.set_font("Arial", '', 10)
            pdf.cell(200, 6, txt=unidecode("Detalles:"), ln=True)
            for detalle in entry.get("detalles", []):
                limpio = unidecode(detalle.replace("→", "->"))
                pdf.multi_cell(0, 6, f"    - {limpio}")
            pdf.ln(4)
        pdf.ln(5)

    pdf.output(output_path)

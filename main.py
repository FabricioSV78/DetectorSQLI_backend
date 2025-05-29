import os
import zipfile
import shutil
import json
import re
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse
from fpdf import FPDF
from fastapi.middleware.cors import CORSMiddleware
from unidecode import unidecode
from detector import analizar_proyecto, mostrar_grafo_interactivo, determinar_capa_desde_archivo


app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


UPLOAD_DIR = "uploaded"
EXTRACTED_DIR = "project"
PDF_REPORT_PATH = "reporte_final.pdf"
RESULTADOS_JSON = "resultados.json"

file_contents = {}
analysis_results = {}
analysis_stats = {}
grafo = None  

@app.post("/upload")
async def upload_project(file: UploadFile = File(...)):
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Solo se permiten archivos .zip")

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(EXTRACTED_DIR, exist_ok=True)

    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    shutil.rmtree(EXTRACTED_DIR, ignore_errors=True)
    os.makedirs(EXTRACTED_DIR, exist_ok=True)

    # Descomprimir
    with zipfile.ZipFile(file_path, "r") as zip_ref:
        zip_ref.extractall(EXTRACTED_DIR)

    global file_contents, analysis_results, analysis_stats, grafo
    file_contents = {}
    analysis_results = {}
    analysis_stats = {}
    grafo = None

    capa_por_archivo = {}

    for root, _, files in os.walk(EXTRACTED_DIR):
        for name in files:
            if name.endswith(".java"):
                path = os.path.join(root, name)
                with open(path, encoding="utf-8", errors="ignore") as f:
                    code = f.read()
                    rel_path = os.path.relpath(path, EXTRACTED_DIR).replace("\\", "/")
                    file_contents[rel_path] = code

                    # Determinar capa
                    nombre_paquete = extraer_paquete_java(code)
                    nombre_clase = os.path.splitext(os.path.basename(rel_path))[0]
                    capa = determinar_capa_desde_archivo(rel_path, nombre_paquete, nombre_clase)
                    capa_por_archivo[rel_path] = capa

    # Validar si el proyecto contiene todas las capas necesarias
    capas_esperadas = {'presentacion', 'logica', 'datos', 'modelo'}
    capas_detectadas = set(capa_por_archivo.values())

    if not capas_esperadas.issubset(capas_detectadas):
        return {
            "status": f"Estructura no válida: faltan capas {capas_esperadas - capas_detectadas}",
            "archivos": list(file_contents.keys()),
            "capas_detectadas": dict(capa_por_archivo),
            "estadisticas": analysis_stats
        }

    # Ejecutar el detector real
    resultados, stats, grafo = analizar_proyecto(EXTRACTED_DIR)
    analysis_stats = stats

    if grafo is None or grafo.number_of_nodes() == 0:
        return {
            "status": "Estructura no válida: el proyecto no contiene clases que cumplan con el estándar N-capas",
            "archivos": list(file_contents.keys()),
            "estadisticas": analysis_stats
        }

    for alerta in resultados:
        archivo = os.path.relpath(alerta.get("archivo", "desconocido.java"), EXTRACTED_DIR).replace("\\", "/")

        if archivo not in analysis_results:
            analysis_results[archivo] = {
                "codigo": file_contents.get(archivo, ""),  # Código completo
                "vulnerabilidades": []
            }

        analysis_results[archivo]["vulnerabilidades"].append({
            "linea": alerta.get("linea", -1),
            "codigo": alerta.get("codigo", ""),
            "detalles": alerta.get("detalles", [])
        })

    return {
        "status": "Proyecto analizado",
        "archivos": list(file_contents.keys()),
        "capas_detectadas": dict(capa_por_archivo),
        "estadisticas": analysis_stats,
        "resultados": analysis_results
    }


@app.get("/files")
async def list_files():
    return list(file_contents.keys())

@app.get("/grafo")
async def mostrar_grafo():
    from detector import mostrar_grafo_interactivo
    mostrar_grafo_interactivo(grafo)
    return FileResponse("grafo_interactivo.html", media_type="text/html")


@app.get("/file/{nombre_archivo:path}")
async def get_file_details(nombre_archivo: str):
    ruta_normalizada = nombre_archivo.replace("\\", "/")
    if ruta_normalizada not in analysis_results:
        print(f"NO SE ENCONTRÓ: {ruta_normalizada}")
        print("DISPONIBLES:", list(analysis_results.keys()))
        raise HTTPException(status_code=404, detail="Archivo no encontrado")

    return analysis_results[ruta_normalizada]


@app.get("/report/download")
async def download_report():
    if not analysis_results:
        raise HTTPException(status_code=404, detail="No hay resultados de análisis")

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="REPORTE DE VULNERABILIDADES SQLi", ln=True, align='C')
    pdf.ln(10)

    # Mostrar primero resumen del análisis
    if analysis_stats:
        pdf.set_font("Arial", 'B', 12)
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(200, 8, txt="Resumen del análisis", ln=True, fill=True)
        pdf.set_font("Arial", '', 11)
        for clave, valor in analysis_stats.items():
            texto = unidecode(f"{clave}: {valor}")
            pdf.cell(200, 8, txt=texto, ln=True)
        pdf.ln(5)

    # Vulnerabilidades por archivo
    for archivo, contenido in analysis_results.items():
        pdf.set_font("Arial", 'B', 12)
        pdf.set_fill_color(200, 220, 255)
        pdf.cell(200, 8, txt=unidecode(f"Archivo: {archivo}"), ln=True, fill=True)

        registros = contenido.get("vulnerabilidades", [])
        for entry in registros:
            pdf.set_font("Arial", 'B', 11)
            pdf.cell(200, 6, txt=unidecode(f"Línea: {entry['linea']}"), ln=True)
            pdf.set_font("Arial", 'I', 10)
            pdf.set_text_color(80)
            for linea in entry['codigo'].splitlines():
                pdf.multi_cell(0, 5, unidecode(f"  {linea}"))
            pdf.set_text_color(0)
            pdf.set_font("Arial", '', 10)
            pdf.cell(200, 6, txt="Detalles:", ln=True)
            for detalle in entry.get("detalles", []):
                limpio = unidecode(detalle.replace("→", "->"))
                pdf.multi_cell(0, 6, f"    - {limpio}")
            pdf.ln(4)
        pdf.ln(5)

    pdf.output(PDF_REPORT_PATH)
    return FileResponse(PDF_REPORT_PATH, media_type="application/pdf", filename="reporte_vulnerabilidades.pdf")

def extraer_paquete_java(codigo_fuente):
    match = re.search(r'^\s*package\s+([\w.]+);', codigo_fuente, re.MULTILINE)
    return match.group(1) if match else ""

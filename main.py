import os
import zipfile
import shutil
import json
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse
from fpdf import FPDF
from fastapi.middleware.cors import CORSMiddleware
from detector import analizar_proyecto, mostrar_grafo_interactivo


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

    for root, _, files in os.walk(EXTRACTED_DIR):
        for name in files:
            if name.endswith(".java"):
                path = os.path.join(root, name)
                with open(path, encoding="utf-8", errors="ignore") as f:
                    code = f.read()
                    rel_path = os.path.relpath(path, os.path.join(EXTRACTED_DIR, "src")).replace("\\", "/")
                    file_contents[rel_path] = code


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
        archivo = os.path.relpath(alerta.get("archivo", "desconocido.java"), EXTRACTED_DIR)
        if archivo not in analysis_results:
            analysis_results[archivo] = []
        analysis_results[archivo].append({
            "linea": alerta.get("linea", -1),
            "codigo": alerta.get("codigo", ""),
            "detalles": alerta.get("detalles", [])
        })

    return {
        "status": "Proyecto analizado",
        "archivos": list(file_contents.keys()),
        "estadisticas": analysis_stats
    }


@app.get("/files")
async def list_files():
    return list(file_contents.keys())

@app.get("/grafo")
async def mostrar_grafo():
    mostrar_grafo_interactivo(grafo)
    return



@app.get("/file/{nombre_archivo}")
async def get_file_details(nombre_archivo: str):
    if nombre_archivo not in file_contents:
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    return {
        "codigo": file_contents[nombre_archivo],
        "vulnerabilidades": analysis_results.get(nombre_archivo, [])
    }


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
            pdf.cell(200, 8, txt=f"{clave}: {valor}", ln=True)
        pdf.ln(5)

    # Vulnerabilidades por archivo
    for archivo, registros in analysis_results.items():
        pdf.set_font("Arial", 'B', 12)
        pdf.set_fill_color(200, 220, 255)
        pdf.cell(200, 8, txt=f"Archivo: {archivo}", ln=True, fill=True)
        for entry in registros:
            pdf.set_font("Arial", 'B', 11)
            pdf.cell(200, 6, txt=f"Línea: {entry['linea']}", ln=True)
            pdf.set_font("Arial", 'I', 10)
            pdf.set_text_color(80)
            for linea in entry['codigo'].splitlines():
                pdf.multi_cell(0, 5, f"  {linea}")
            pdf.set_text_color(0)
            pdf.set_font("Arial", '', 10)
            pdf.cell(200, 6, txt=f"Detalles:", ln=True)
            for detalle in entry.get("detalles", []):
                detalle = detalle.replace("→", "->")
                pdf.multi_cell(0, 6, f"    - {detalle}")
            pdf.ln(4)
        pdf.ln(5)

    pdf.output(PDF_REPORT_PATH)
    return FileResponse(PDF_REPORT_PATH, media_type="application/pdf", filename="reporte_vulnerabilidades.pdf")

import os
import zipfile
import shutil
import re
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fpdf import FPDF
from fastapi.middleware.cors import CORSMiddleware
from unidecode import unidecode
from detector import analizar_proyecto, determinar_capa_desde_archivo
import matplotlib
import matplotlib.pyplot as plt
matplotlib.use("Agg")
import seaborn as sns
import numpy as np
from autenticacion import obtener_usuario_desde_token
from fastapi import Depends
from sqlalchemy.orm import Session
from db import get_db
from modelos import Proyecto, Archivo, Vulnerabilidad
from generar_resultados_utils import mostrar_grafo_interactivo, generar_heatmap_por_archivo, generar_pdf_reporte 

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
RESULTS_DIR = "resultados"
os.makedirs(RESULTS_DIR, exist_ok=True)

from uuid import uuid4

@app.post("/upload")
async def upload_project(file: UploadFile = File(...), db: Session = Depends(get_db), usuario=Depends(obtener_usuario_desde_token)):
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Solo se permiten archivos .zip")

    # Guardar ZIP temporalmente
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Extraer ZIP a carpeta única por proyecto
    proyecto_uuid = str(uuid4())
    extracted_path = os.path.join(EXTRACTED_DIR, proyecto_uuid)
    os.makedirs(extracted_path, exist_ok=True)
    with zipfile.ZipFile(file_path, "r") as zip_ref:
        zip_ref.extractall(extracted_path)

    # Procesar archivos
    file_contents = {}
    capa_por_archivo = {}

    for root, _, files in os.walk(extracted_path):
        for name in files:
            if name.endswith(".java"):
                path = os.path.join(root, name)
                with open(path, encoding="utf-8", errors="ignore") as f:
                    code = f.read()
                    rel_path = os.path.relpath(path, extracted_path).replace("\\", "/")
                    file_contents[rel_path] = code

                    paquete = extraer_paquete_java(code)
                    clase = os.path.splitext(os.path.basename(rel_path))[0]
                    capa = determinar_capa_desde_archivo(rel_path, paquete, clase)
                    capa_por_archivo[rel_path] = capa

    capas_esperadas = {'presentacion', 'logica', 'datos', 'modelo'}
    capas_detectadas = set(capa_por_archivo.values())

    if not capas_esperadas.issubset(capas_detectadas):
        return {
            "status": f"Estructura no válida: faltan capas {capas_esperadas - capas_detectadas}",
            "archivos": list(file_contents.keys()),
            "capas_detectadas": dict(capa_por_archivo),
        }

    # Analizar el proyecto
    resultados, stats, grafo = analizar_proyecto(extracted_path)
    if grafo is None or grafo.number_of_nodes() == 0:
        return {
            "status": "Estructura no válida: el proyecto no contiene clases válidas",
            "archivos": list(file_contents.keys())
        }

    # Crear proyecto en base de datos
    nuevo_proyecto = Proyecto(
        nombre=file.filename,
        usuario_id=usuario.id,
        path_grafo="",
        path_heatmap="",
        path_pdf=""
    )
    db.add(nuevo_proyecto)
    db.commit()
    db.refresh(nuevo_proyecto)

    proyecto_id = nuevo_proyecto.id
    nombre_grafo = f"grafo_{proyecto_id}.html"
    nombre_heatmap = f"heatmap_{proyecto_id}.png"
    nombre_pdf = f"reporte_{proyecto_id}.pdf"

    path_grafo = os.path.join(RESULTS_DIR, nombre_grafo)
    path_heatmap = os.path.join(RESULTS_DIR, nombre_heatmap)
    path_pdf = os.path.join(RESULTS_DIR, nombre_pdf)

    # Generar archivos visuales
    mostrar_grafo_interactivo(grafo, output_path=path_grafo)
    generar_heatmap_por_archivo(resultados, output_path=path_heatmap)
    generar_pdf_reporte(resultados, stats, output_path=path_pdf)

    # Actualizar rutas en proyecto
    nuevo_proyecto.path_grafo = path_grafo
    nuevo_proyecto.path_heatmap = path_heatmap
    nuevo_proyecto.path_pdf = path_pdf
    db.commit()

    # Guardar archivos y vulnerabilidades
    for alerta in resultados:
        archivo = os.path.relpath(alerta.get("archivo", "desconocido.java"), extracted_path).replace("\\", "/")
        codigo = file_contents.get(archivo, "")

        archivo_bd = Archivo(nombre=archivo, codigo_fuente=codigo, proyecto_id=proyecto_id)
        db.add(archivo_bd)
        db.commit()
        db.refresh(archivo_bd)

        for detalle in alerta.get("detalles", []):
            db.add(Vulnerabilidad(
                linea=alerta.get("linea", -1),
                fragmento=alerta.get("codigo", ""),
                detalles="\n".join(alerta.get("detalles", [])),
                archivo_id=archivo_bd.id
            ))
    db.commit()

    # Limpieza opcional
    os.remove(file_path)
    shutil.rmtree(extracted_path, ignore_errors=True)

    return {
        "status": "Proyecto analizado y guardado",
        "proyecto_id": proyecto_id,
        "archivos": list(file_contents.keys()),
        "capas_detectadas": dict(capa_por_archivo),
        "estadisticas": stats
    }

@app.get("/files/{proyecto_id}")
def list_files(proyecto_id: int, db: Session = Depends(get_db), usuario=Depends(obtener_usuario_desde_token)):
    archivos = db.query(Archivo).filter_by(proyecto_id=proyecto_id).all()
    if not archivos:
        raise HTTPException(status_code=404, detail="No se encontraron archivos para este proyecto")
    
    return [archivo.nombre for archivo in archivos]


@app.get("/grafo/{proyecto_id}")
def grafo_html(
    proyecto_id: int,
    usuario=Depends(obtener_usuario_desde_token),
    db: Session = Depends(get_db)
):
    proyecto = db.query(Proyecto).filter_by(id=proyecto_id, usuario_id=usuario.id).first()
    if not proyecto or not proyecto.path_grafo or not os.path.exists(proyecto.path_grafo):
        raise HTTPException(status_code=404, detail="Archivo de grafo no encontrado")

    with open(proyecto.path_grafo, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())



@app.get("/file/{proyecto_id}/{nombre_archivo:path}")
def get_file_details(proyecto_id: int, nombre_archivo: str, db: Session = Depends(get_db), usuario=Depends(obtener_usuario_desde_token)):
    archivo = db.query(Archivo).filter_by(nombre=nombre_archivo, proyecto_id=proyecto_id).first()
    if not archivo:
        raise HTTPException(status_code=404, detail="Archivo no encontrado")

    vulns = db.query(Vulnerabilidad).filter_by(archivo_id=archivo.id).all()
    return {
        "codigo": archivo.codigo_fuente,
        "vulnerabilidades": [
            {
                "linea": v.linea,
                "codigo": v.fragmento,
                "detalles": v.detalles.split("\n")
            }
            for v in vulns
        ]
    }



@app.get("/report/download/{proyecto_id}")
def descargar_reporte(proyecto_id: int, db: Session = Depends(get_db)):
    proyecto = db.query(Proyecto).filter_by(id=proyecto_id).first()
    if not proyecto:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")

    archivos = db.query(Archivo).filter_by(proyecto_id=proyecto.id).all()
    if not archivos:
        raise HTTPException(status_code=404, detail="No hay archivos analizados")

    resultados = []
    for archivo in archivos:
        vulns = db.query(Vulnerabilidad).filter_by(archivo_id=archivo.id).all()
        for vuln in vulns:
            resultados.append({
                "archivo": archivo.nombre,
                "linea": vuln.linea,
                "codigo": vuln.fragmento,
                "detalles": vuln.detalles.split("\n")
            })

    if not resultados:
        raise HTTPException(status_code=404, detail="No hay vulnerabilidades detectadas")

    stats = {
        "Archivos analizados": len(archivos),
        "Vulnerabilidades encontradas": len(resultados)
    }

    ruta_pdf = f"reporte_{proyecto_id}.pdf"
    generar_pdf_reporte(resultados, stats, output_path=ruta_pdf)
    return FileResponse(ruta_pdf, media_type="application/pdf", filename="reporte_vulnerabilidades.pdf")

def extraer_paquete_java(codigo_fuente):
    match = re.search(r'^\s*package\s+([\w.]+);', codigo_fuente, re.MULTILINE)
    return match.group(1) if match else ""

@app.get("/line-heatmap/{proyecto_id}")
def generar_line_heatmap(
    proyecto_id: int,
    usuario=Depends(obtener_usuario_desde_token),
    db: Session = Depends(get_db)
):
    # Verificar que el proyecto le pertenece al usuario
    proyecto = db.query(Proyecto).filter_by(id=proyecto_id, usuario_id=usuario.id).first()
    if not proyecto:
        raise HTTPException(status_code=403, detail="Proyecto no encontrado o no autorizado")

    archivos = db.query(Archivo).filter_by(proyecto_id=proyecto_id).all()
    if not archivos:
        raise HTTPException(status_code=404, detail="No hay archivos para este proyecto")

    heatmap_data = []
    archivos_nombres = []
    max_bin = 0
    bin_size = 10

    for archivo in archivos:
        vulns = db.query(Vulnerabilidad).filter_by(archivo_id=archivo.id).all()
        lineas = [v.linea for v in vulns if v.linea is not None]

        if not lineas:
            continue

        bins = {}
        for linea in lineas:
            b = linea // bin_size
            bins[b] = bins.get(b, 0) + 1
            max_bin = max(max_bin, b)

        fila = [bins.get(i, 0) for i in range(max_bin + 1)]
        heatmap_data.append(fila)
        archivos_nombres.append(os.path.basename(archivo.nombre))

    if not heatmap_data:
        raise HTTPException(status_code=404, detail="No hay datos para graficar")

    # Normalizar todas las filas al mismo largo
    for fila in heatmap_data:
        fila.extend([0] * (max_bin + 1 - len(fila)))

    heat_data = np.array(heatmap_data)
    xticks = [f"{i*bin_size}-{(i+1)*bin_size - 1}" for i in range(max_bin + 1)]

    plt.figure(figsize=(max(12, len(xticks) * 0.8), len(archivos_nombres) * 1.2))
    sns.set(font_scale=0.9)
    ax = sns.heatmap(
        heat_data,
        cmap="Reds",
        cbar=True,
        xticklabels=xticks,
        yticklabels=archivos_nombres,
        linewidths=0.3,
        linecolor="gray"
    )
    ax.set_xlabel("Bloques de líneas de código")
    ax.set_ylabel("Archivo")
    ax.set_title("Mapa de Calor por Bloques de Líneas (agrupado cada 10 líneas)")
    plt.tight_layout()

    path = f"resultados/heatmap_{proyecto_id}.png"
    plt.savefig(path, dpi=150)
    plt.close()

    return FileResponse(path, media_type="image/png", filename=f"heatmap_{proyecto_id}.png")


@app.get("/proyectos")
def listar_proyectos(usuario=Depends(obtener_usuario_desde_token), db: Session = Depends(get_db)):
    proyectos = db.query(Proyecto).filter(Proyecto.usuario_id == usuario.id).all()
    return [{"id": p.id, "nombre": p.nombre, "fecha": p.fecha_subida} for p in proyectos]



@app.get("/resultados/{proyecto_id}")
def ver_resultado(
    proyecto_id: int,
    usuario=Depends(obtener_usuario_desde_token),
    db: Session = Depends(get_db)
):
    proyecto = db.query(Proyecto).filter_by(id=proyecto_id, usuario_id=usuario.id).first()
    if not proyecto:
        raise HTTPException(status_code=403, detail="Proyecto no autorizado")

    archivos = db.query(Archivo).filter_by(proyecto_id=proyecto_id).all()
    resultado = {}

    for archivo in archivos:
        vulns = db.query(Vulnerabilidad).filter_by(archivo_id=archivo.id).all()
        resultado[archivo.nombre] = {
            "codigo": archivo.codigo_fuente,
            "vulnerabilidades": [
                {"linea": v.linea, "codigo": v.fragmento, "detalles": v.detalles.split("\n")}
                for v in vulns
            ]
        }

    return resultado

from autenticacion import router as auth_router
app.include_router(auth_router, prefix="/auth")


import init_db 
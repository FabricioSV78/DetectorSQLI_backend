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
from collections import Counter
import plotly.graph_objects as go
from collections import defaultdict

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

    # Agrupar vulnerabilidades por archivo y línea
    agrupadas_por_archivo = {}

    for alerta in resultados:
        archivo = os.path.relpath(alerta.get("archivo", "desconocido.java"), extracted_path).replace("\\", "/")
        linea = alerta.get("linea", -1)
        fragmento = alerta.get("codigo", "")
        detalles = alerta.get("detalles", [])

        if archivo not in agrupadas_por_archivo:
            agrupadas_por_archivo[archivo] = {}

        # Buscar si ya hay una línea con el mismo fragmento
        ya_existe = False
        for l, info in agrupadas_por_archivo[archivo].items():
            if info["fragmento"].strip() == fragmento.strip():
                # Fusionar los detalles sin duplicar
                info["detalles"].extend([d for d in detalles if d not in info["detalles"]])
                ya_existe = True
                break

        if not ya_existe:
            agrupadas_por_archivo[archivo][linea] = {
                "fragmento": fragmento,
                "detalles": detalles
            }


    for archivo, lineas in agrupadas_por_archivo.items():
        codigo = file_contents.get(archivo, "")
        archivo_bd = Archivo(nombre=archivo, codigo_fuente=codigo, proyecto_id=proyecto_id)
        db.add(archivo_bd)
        db.commit()
        db.refresh(archivo_bd)

        for linea, info in lineas.items():
            db.add(Vulnerabilidad(
                linea=linea,
                fragmento=info["fragmento"],
                detalles="\n".join(info["detalles"]),
                archivo_id=archivo_bd.id
            ))
    db.commit()

    # Limpieza 
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
    
    tipo_counter = Counter()
    for r in resultados:
        for detalle in r.get("detalles", []):
            linea = detalle.strip().replace(":", ":")
            tipo = linea.split(":")[0].strip()
            tipo_counter[tipo] += 1

    stats = {
        "Archivos analizados": len(archivos),
        "Vulnerabilidades encontradas": len(resultados)
    }

    ruta_pdf = f"reporte_{proyecto_id}.pdf"

    generar_pdf_reporte(resultados, stats, tipo_counter=tipo_counter, output_path=ruta_pdf)

    return FileResponse(ruta_pdf, media_type="application/pdf", filename="reporte_vulnerabilidades.pdf")

def extraer_paquete_java(codigo_fuente):
    match = re.search(r'^\s*package\s+([\w.]+);', codigo_fuente, re.MULTILINE)
    return match.group(1) if match else ""

@app.get("/interactive-heatmap/{proyecto_id}")
def generar_heatmap_agrupado(
    proyecto_id: int,
    usuario=Depends(obtener_usuario_desde_token),
    db: Session = Depends(get_db)
):
    proyecto = db.query(Proyecto).filter_by(id=proyecto_id, usuario_id=usuario.id).first()
    if not proyecto:
        raise HTTPException(status_code=403, detail="Proyecto no autorizado")

    archivos = db.query(Archivo).filter_by(proyecto_id=proyecto_id).all()
    if not archivos:
        raise HTTPException(status_code=404, detail="No hay archivos para este proyecto")

    x_lineas = []
    y_vuln_pct = []

    datos_archivos = []

    for archivo in archivos:
        total = archivo.codigo_fuente.count("\n")
        num_vulns = db.query(Vulnerabilidad).filter_by(archivo_id=archivo.id).count()

        if total > 0:
            porcentaje = (num_vulns / total) * 100
            x_lineas.append(total)
            y_vuln_pct.append(porcentaje)
            datos_archivos.append({
                "archivo": archivo,
                "lineas": total,
                "porcentaje": porcentaje,
                "vulnerabilidades": num_vulns
            })

    if not x_lineas:
        raise HTTPException(status_code=404, detail="No hay datos para graficar")

    # Configuración de bins
    nbinsx = 20
    nbinsy = 20

    x_min, x_max = min(x_lineas), max(x_lineas)
    y_min, y_max = min(y_vuln_pct), max(y_vuln_pct)

    x_bins = np.linspace(x_min, x_max, nbinsx + 1)
    y_bins = np.linspace(y_min, y_max, nbinsy + 1)

    # Agrupación por bin
    bin_info = defaultdict(list)

    for data in datos_archivos:
        x = data["lineas"]
        y = data["porcentaje"]
        archivo = data["archivo"]
        num_vulns = data["vulnerabilidades"]

        x_bin = min(np.digitize(x, x_bins) - 1, nbinsx - 1)
        y_bin = min(np.digitize(y, y_bins) - 1, nbinsy - 1)
        bin_key = (x_bin, y_bin)

        bin_info[bin_key].append(f"""
            <b>Archivo:</b> {archivo.nombre}<br>
            <b>Líneas totales:</b> {x}<br>
            <b>Vulnerabilidades:</b> {num_vulns}<br>
            <b>% Vulnerable:</b> {y:.2f}%<br><br>
        """)

    scatter_x = []
    scatter_y = []
    scatter_customdata = []

    for (x_bin, y_bin), textos in bin_info.items():
        x_center = (x_bins[x_bin] + x_bins[x_bin + 1]) / 2
        y_center = (y_bins[y_bin] + y_bins[y_bin + 1]) / 2

        scatter_x.append(x_center)
        scatter_y.append(y_center)
        scatter_customdata.append("".join(textos))

    # Crear figura
    fig = go.Figure()

    # Heatmap
    fig.add_trace(go.Histogram2d(
        x=x_lineas,
        y=y_vuln_pct,
        colorscale='YlOrRd',
        colorbar=dict(title='Cantidad de archivos'),
        nbinsx=nbinsx,
        nbinsy=nbinsy,
        hoverinfo='none'
    ))

    # Puntos invisibles con datos agrupados
    fig.add_trace(go.Scatter(
        x=scatter_x,
        y=scatter_y,
        mode='markers',
        marker=dict(size=10, opacity=0, color='rgba(0,0,0,0)'),
        customdata=scatter_customdata,
        hovertemplate="%{customdata}<extra></extra>",
        name="Archivos agrupados"
    ))

    # Layout
    fig.update_layout(
        title=f'Mapa de Calor Interactivo (Proyecto {proyecto_id})',
        xaxis_title='Líneas totales por archivo',
        yaxis_title='% de líneas vulnerables',
        width=1000,
        height=800,
        template='plotly_white',
        hovermode='closest',
        showlegend=False,
        annotations=[
            dict(
                x=0.5,
                y=1.05,
                xref='paper',
                yref='paper',
                text='Pasa el mouse sobre los puntos para ver detalles de cada archivo',
                showarrow=False,
                font=dict(size=12)
            )
        ]
    )

    return HTMLResponse(content=fig.to_html(full_html=True, include_plotlyjs='cdn'))

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
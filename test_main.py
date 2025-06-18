import os
import warnings
warnings.filterwarnings("ignore", category=PendingDeprecationWarning)
import zipfile
import tempfile
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def crear_zip_proyecto_temporal():
    temp_dir = tempfile.mkdtemp()

    estructuras = {
        "presentacion/LoginController.java": 'package presentacion;\npublic class LoginController { }',
        "logica/LoginService.java": 'package logica;\npublic class LoginService { }',
        "modelo/UsuarioEntidad.java": 'package modelo;\npublic class UsuarioEntidad { }',
        "datos/TestDAO.java": '''
            package datos;
            public class TestDAO {
                public void buscar(String input) {
                    String sql = "SELECT * FROM tabla WHERE valor=" + input;
                }
            }
        '''
    }

    for ruta, contenido in estructuras.items():
        archivo_path = os.path.join(temp_dir, ruta)
        os.makedirs(os.path.dirname(archivo_path), exist_ok=True)
        with open(archivo_path, "w", encoding="utf-8") as f:
            f.write(contenido)

    zip_path = os.path.join(tempfile.gettempdir(), "test_proyecto.zip")
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        for ruta in estructuras.keys():
            zipf.write(os.path.join(temp_dir, ruta), arcname=ruta)

    return zip_path


def test_login_y_subida_de_proyecto():
    # Registro del usuario (si no existe)
    registro_data = {
        "nombre": "admin",
        "correo": "admin@gmail.com",
        "password": "123456"
    }
    registro_resp = client.post("/auth/register", json=registro_data)
    assert registro_resp.status_code in [200, 400]  # 400 si ya existe

    # Login del usuario
    login_data = {
        "correo": "admin@gmail.com",
        "password": "123456"
    }
    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    # Subir archivo .zip con autenticación
    zip_path = crear_zip_proyecto_temporal()
    with open(zip_path, "rb") as f:
        response = client.post(
            "/upload",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": ("test_proyecto.zip", f, "application/zip")}
        )

    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "proyecto_id" in data or "estructura" in data
    print("Respuesta del servidor:", data)

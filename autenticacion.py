from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from modelos import Usuario
from db import get_db
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer
from fastapi import Request

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

SECRET_KEY = "clave_secreta_segura"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter()

class RegistroSchema(BaseModel):
    nombre: str
    correo: str
    password: str

class LoginSchema(BaseModel):
    correo: str
    password: str

def verificar_password(llano, hashed):
    return pwd_context.verify(llano, hashed)

def hashear_password(password):
    return pwd_context.hash(password)

def crear_token(datos: dict, expiracion: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    copia = datos.copy()
    expira = datetime.utcnow() + timedelta(minutes=expiracion)
    copia.update({"exp": expira})
    return jwt.encode(copia, SECRET_KEY, algorithm=ALGORITHM)

@router.post("/register")
def registrar_usuario(request: RegistroSchema, db: Session = Depends(get_db)):
    if db.query(Usuario).filter_by(correo=request.correo).first():
        raise HTTPException(status_code=400, detail="Correo ya registrado")

    nuevo = Usuario(
        username=request.nombre,
        correo=request.correo,
        contrasena=hashear_password(request.password)
    )
    db.add(nuevo)
    db.commit()
    db.refresh(nuevo)
    return {"mensaje": "Usuario registrado", "id": nuevo.id}

@router.post("/login")
def login(request: LoginSchema, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter_by(correo=request.correo).first()
    if not usuario or not verificar_password(request.password, usuario.contrasena):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    token = crear_token({"sub": str(usuario.id)})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user_id": usuario.id  
    }

def obtener_usuario_desde_token(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=401, detail="Token inválido o no proporcionado")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))
        usuario = db.query(Usuario).filter_by(id=user_id).first()
        if usuario is None:
            raise credentials_exception
        return usuario
    except JWTError:
        raise credentials_exception



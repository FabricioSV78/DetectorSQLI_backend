from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime

Base = declarative_base()

class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=False, nullable=False)
    correo = Column(String(100), unique=True, nullable=False)
    contrasena = Column(String(255), nullable=False)

    proyectos = relationship("Proyecto", back_populates="usuario")

class Proyecto(Base):
    __tablename__ = "proyectos"

    id = Column(Integer, primary_key=True)
    nombre = Column(String(150), nullable=False)
    fecha_subida = Column(DateTime, default=datetime.utcnow)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"))

    usuario = relationship("Usuario", back_populates="proyectos")
    archivos = relationship("Archivo", back_populates="proyecto")

    path_grafo = Column(String(255))
    path_heatmap = Column(String(255))
    path_pdf = Column(String(255))
          

class Archivo(Base):
    __tablename__ = "archivos"

    id = Column(Integer, primary_key=True)
    nombre = Column(String(255), nullable=False)
    codigo_fuente = Column(Text, nullable=False)
    proyecto_id = Column(Integer, ForeignKey("proyectos.id"))

    proyecto = relationship("Proyecto", back_populates="archivos")
    vulnerabilidades = relationship("Vulnerabilidad", back_populates="archivo")

class Vulnerabilidad(Base):
    __tablename__ = "vulnerabilidades"

    id = Column(Integer, primary_key=True)
    linea = Column(Integer)
    fragmento = Column(Text)
    detalles = Column(Text)

    archivo_id = Column(Integer, ForeignKey("archivos.id"))
    archivo = relationship("Archivo", back_populates="vulnerabilidades")

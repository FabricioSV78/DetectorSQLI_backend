from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import os

engine = create_engine("postgresql://postgres:Joseallain27@localhost:5432/taller_db")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Declaración base
Base = declarative_base()

# Dependencia para obtener sesión en rutas
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

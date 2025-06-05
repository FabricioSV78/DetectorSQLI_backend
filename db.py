from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import os

DATABASE_VE = os.getenv("DATABASE_VE")

engine = create_engine(DATABASE_VE)

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

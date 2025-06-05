from modelos import Base
from db import engine

# Crea todas las tablas
Base.metadata.create_all(bind=engine)
print("Tablas creadas en PostgreSQL local")

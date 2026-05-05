import os
from dotenv import load_dotenv
load_dotenv()

from core.database import engine
from core.auth import Base, UserModel, hash_password, get_user, create_user
import uuid
from datetime import datetime

# Crear tablas
Base.metadata.create_all(bind=engine)
print("Tablas creadas")

# Crear admin
try:
    existing = get_user("daniel")
    if existing:
        print(f"Usuario ya existe: daniel")
    else:
        create_user("daniel", "daniel.glez.solucionador@gmail.com", "Centinela24", is_admin=True)
        print("Admin creado exitosamente")
except Exception as e:
    print(f"Error: {e}")
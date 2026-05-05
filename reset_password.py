import os
from dotenv import load_dotenv
load_dotenv()

from core.database import SessionLocal
from core.auth import UserModel, hash_password

db = SessionLocal()
try:
    user = db.query(UserModel).filter(UserModel.username == "daniel").first()
    if user:
        user.hashed_password = hash_password("Centinela24!")
        db.commit()
        print(f"Contraseña actualizada para: {user.username}")
    else:
        print("Usuario no encontrado")
finally:
    db.close()
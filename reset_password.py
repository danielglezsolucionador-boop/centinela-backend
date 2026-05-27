import os
from dotenv import load_dotenv

load_dotenv()

from core.auth import UserModel, hash_password
from core.database import SessionLocal

admin_username = os.environ.get("ADMIN_USERNAME", "daniel")
new_password = os.environ.get("ADMIN_PASSWORD")

if not new_password:
    raise RuntimeError("ADMIN_PASSWORD is required for reset_password.py")

db = SessionLocal()
try:
    user = db.query(UserModel).filter(UserModel.username == admin_username).first()
    if user:
        user.hashed_password = hash_password(new_password)
        db.commit()
        print(f"Password updated for: {user.username}")
    else:
        print("User not found")
finally:
    db.close()

import os
from dotenv import load_dotenv

load_dotenv()

from core.auth import Base, create_user, get_user
from core.database import engine

admin_username = os.environ.get("ADMIN_USERNAME", "daniel")
admin_email = os.environ.get("ADMIN_EMAIL", "admin@centinela.local")
admin_password = os.environ.get("ADMIN_PASSWORD")

if not admin_password:
    raise RuntimeError("ADMIN_PASSWORD is required for fix_admin.py")

Base.metadata.create_all(bind=engine)
existing = get_user(admin_username)

if existing:
    print(f"Admin already exists: {admin_username}")
else:
    create_user(admin_username, admin_email, admin_password, is_admin=True)
    print(f"Admin created: {admin_username}")

import os
import uuid
import bcrypt as _bcrypt
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import Column, String, Boolean, DateTime
from core.database import Base, SessionLocal, engine

# â”€â”€ Config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    if os.environ.get("ENVIRONMENT") == "production":
        raise RuntimeError("SECRET_KEY must be configured in production")
    SECRET_KEY = "centinela-local-dev-secret-change-me"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

bearer_scheme = HTTPBearer(auto_error=False)

def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").lower() in {"1", "true", "yes", "on"}

SERVERLESS_MODE = _env_flag("SERVERLESS_MODE") or _env_flag("VERCEL")

# â”€â”€ User Model â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class UserModel(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

if SERVERLESS_MODE:
    print("auth schema init deferred: serverless mode")
else:
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        print(f"auth schema init deferred: {e}")

# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def hash_password(password: str) -> str:
    return _bcrypt.hashpw(password[:72].encode(), _bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain[:72].encode(), hashed.encode())

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(username: str):
    db = SessionLocal()
    try:
        return db.query(UserModel).filter(UserModel.username == username).first()
    except Exception as e:
        print(f"get_user error: {e}")
        return None
    finally:
        db.close()

def create_user(username: str, email: str, password: str, is_admin: bool = False):
    db = SessionLocal()
    try:
        user = UserModel(
            id=str(uuid.uuid4()),
            username=username,
            email=email,
            hashed_password=hash_password(password),
            is_admin=is_admin,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

# â”€â”€ Auth dependency â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not credentials:
        raise credentials_exception
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None or not user.is_active:
        raise credentials_exception
    return user

async def get_admin_user(current_user=Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

# â”€â”€ Create default admin on startup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def init_default_admin():
    admin_username = os.environ.get("ADMIN_USERNAME", "daniel")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@centinela.local")
    if not admin_password:
        if os.environ.get("ENVIRONMENT") == "production":
            raise RuntimeError("ADMIN_PASSWORD must be configured in production")
        admin_password = "centinela-local-dev-password-change-me"
    try:
        existing = get_user(admin_username)
        if not existing:
            create_user(admin_username, admin_email, admin_password, is_admin=True)
            print(f"OK Admin user created: {admin_username}")
        else:
            print(f"OK Admin user exists: {admin_username}")
    except Exception as e:
        print(f"admin init skipped: {e}")

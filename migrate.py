import os
from sqlalchemy import create_engine, text

DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)

with engine.connect() as conn:
    try:
        conn.execute(text("ALTER TABLE events RENAME COLUMN \"user\" TO user_id"))
        conn.commit()
        print("✅ Columna renombrada: user -> user_id")
    except Exception as e:
        print(f"Info: {e}")
    
    try:
        result = conn.execute(text("SELECT COUNT(*) FROM events"))
        print(f"✅ Eventos en DB: {result.scalar()}")
    except Exception as e:
        print(f"Error: {e}")
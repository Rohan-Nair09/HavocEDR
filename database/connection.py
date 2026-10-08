import os
import sys
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Load environment variables
load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', '.env'))

# Use a writable per-user location for packaged builds; keep the project-local
# database for source runs so developers can inspect and back up its data.
if os.getenv("DATABASE_URL"):
    DATABASE_URL = os.environ["DATABASE_URL"]
elif getattr(sys, "frozen", False) or "__compiled__" in globals():
    app_data = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "HavocGuardEDR" / "database"
    app_data.mkdir(parents=True, exist_ok=True)
    DATABASE_URL = URL.create("sqlite", database=str(app_data / "havocguard.db"))
else:
    DATABASE_URL = "sqlite:///database/havocguard.db"

# Create SQLAlchemy engine
# connect_args={"check_same_thread": False} is needed for SQLite
engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)

# Create a sessionmaker
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for declarative models
Base = declarative_base()

def get_db():
    """Dependency to get the database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

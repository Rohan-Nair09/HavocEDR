import logging
from .connection import engine, Base
from . import models # Ensure all models are loaded before calling create_all

# Configure logging for database initialization
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

def init_db() -> bool:
    """
    Initializes the SQLite database and creates all required tables if they don't exist.
    It is idempotent and safe to run multiple times. It does not overwrite data.
    
    Returns:
        bool: True if successful, False if an error occurred.
    """
    try:
        logger.info("Starting database initialization...")
        # create_all is safe to call multiple times; it will only create tables that do not exist.
        Base.metadata.create_all(bind=engine)
        logger.info("Base tables created/verified.")
        
        # Run schema migrations
        from .migrations import MigrationManager
        migrator = MigrationManager(engine)
        migrator.run_migrations()
        
        logger.info("Database and tables initialized successfully.")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return False

if __name__ == "__main__":
    init_db()

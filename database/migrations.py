import logging
from sqlalchemy import text
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

class MigrationManager:
    """
    Manages SQLite database schema migrations safely and idempotently.
    Tracks applied migrations to avoid re-running them.
    """
    def __init__(self, engine: Engine):
        self.engine = engine
        self._init_migration_table()

    def _init_migration_table(self):
        """Ensure the tracking table for migrations exists."""
        query = """
        CREATE TABLE IF NOT EXISTS _migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR UNIQUE,
            applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
        with self.engine.begin() as conn:
            conn.execute(text(query))

    def has_migration_run(self, name: str) -> bool:
        """Check if a migration has already been applied."""
        query = text("SELECT 1 FROM _migrations WHERE name = :name")
        with self.engine.connect() as conn:
            result = conn.execute(query, {"name": name}).fetchone()
            return result is not None

    def mark_migration_run(self, name: str):
        """Mark a migration as completed in the tracking table."""
        query = text("INSERT INTO _migrations (name) VALUES (:name)")
        with self.engine.begin() as conn:
            conn.execute(query, {"name": name})

    def column_exists(self, table_name: str, column_name: str) -> bool:
        """Inspect the schema using PRAGMA table_info to check if a column exists."""
        query = text(f"PRAGMA table_info({table_name})")
        with self.engine.connect() as conn:
            columns = conn.execute(query).fetchall()
            # PRAGMA table_info returns tuples like: (cid, name, type, notnull, dflt_value, pk)
            for col in columns:
                if col[1] == column_name:
                    return True
        return False

    def add_column_if_not_exists(self, table_name: str, column_name: str, column_type: str):
        """Safely add a column if it does not already exist."""
        if not self.column_exists(table_name, column_name):
            logger.info(f"Adding column '{column_name}' to table '{table_name}'...")
            query = text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
            with self.engine.begin() as conn:
                conn.execute(query)
            logger.info(f"Column '{column_name}' added successfully.")
        else:
            logger.debug(f"Column '{column_name}' already exists in '{table_name}'. Skipping.")

    def run_migrations(self):
        """Run all registered migrations sequentially."""
        logger.info("Checking for pending database migrations...")
        
        # Define all migrations in order here
        migrations = [
            ("001_add_service_monitor_columns", self.migration_001),
            ("002_add_registry_monitor_columns", self.migration_002),
            ("003_add_fim_monitor_columns", self.migration_003),
            ("004_add_usb_monitor_columns", self.migration_004),
            ("005_add_network_monitor_columns", self.migration_005),
        ]
        
        for name, func in migrations:
            if not self.has_migration_run(name):
                logger.info(f"Running migration: {name}")
                try:
                    func()
                    self.mark_migration_run(name)
                    logger.info(f"Migration {name} completed successfully.")
                except Exception as e:
                    logger.error(f"Migration {name} failed: {e}")
                    raise
            else:
                logger.debug(f"Migration {name} already applied.")

    # --- MIGRATIONS ---

    def migration_001(self):
        """Adds binpath, is_signed, and suspicion_reasons to the services table."""
        # Ensure the table actually exists before attempting to alter it
        # (It will exist if Base.metadata.create_all ran, or we can just rely on the framework)
        try:
            self.add_column_if_not_exists("services", "binpath", "VARCHAR")
            self.add_column_if_not_exists("services", "is_signed", "BOOLEAN")
            self.add_column_if_not_exists("services", "suspicion_reasons", "TEXT")
        except Exception as e:
            # If the table 'services' doesn't exist yet, this will fail.
            # But we should run migrations AFTER Base.metadata.create_all() creates base tables.
            raise

    def migration_002(self):
        """Adds RegistryMonitor specific columns to the registry_events table."""
        try:
            self.add_column_if_not_exists("registry_events", "hive", "VARCHAR")
            self.add_column_if_not_exists("registry_events", "key_path", "VARCHAR")
            self.add_column_if_not_exists("registry_events", "value_name", "VARCHAR")
            self.add_column_if_not_exists("registry_events", "old_value", "TEXT")
            self.add_column_if_not_exists("registry_events", "new_value", "TEXT")
            self.add_column_if_not_exists("registry_events", "change_type", "VARCHAR")
            self.add_column_if_not_exists("registry_events", "is_signed", "BOOLEAN")
            self.add_column_if_not_exists("registry_events", "suspicion_reasons", "TEXT")
        except Exception:
            raise

    def migration_003(self):
        """Adds FIM specific columns to the file_events table."""
        try:
            self.add_column_if_not_exists("file_events", "previous_file_path", "VARCHAR")
            self.add_column_if_not_exists("file_events", "old_sha256", "VARCHAR")
            self.add_column_if_not_exists("file_events", "suspicion_reasons", "TEXT")
        except Exception:
            raise

    def migration_004(self):
        """Adds USB Monitor specific columns to the usb_events table."""
        try:
            self.add_column_if_not_exists("usb_events", "vendor_id", "VARCHAR")
            self.add_column_if_not_exists("usb_events", "product_id", "VARCHAR")
            self.add_column_if_not_exists("usb_events", "serial_number", "VARCHAR")
            self.add_column_if_not_exists("usb_events", "drive_letter", "VARCHAR")
            self.add_column_if_not_exists("usb_events", "previously_seen", "BOOLEAN")
            self.add_column_if_not_exists("usb_events", "suspicion_reasons", "TEXT")
        except Exception:
            raise

    def migration_005(self):
        """Adds Network Monitor specific columns to the network_connections table."""
        try:
            self.add_column_if_not_exists("network_connections", "local_ip", "VARCHAR")
            self.add_column_if_not_exists("network_connections", "username", "VARCHAR")
            self.add_column_if_not_exists("network_connections", "suspicion_reasons", "TEXT")
        except Exception:
            raise

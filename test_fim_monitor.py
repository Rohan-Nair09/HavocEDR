import time
import os
import logging
from database.connection import SessionLocal
from database.models import FileEvent
from monitoring.db_writer import DatabaseWriter
from monitoring.fim_monitor import FIMMonitor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

TEST_DIR = os.path.join(os.environ.get("TEMP", "C:\\Temp"), "HavocFIMTest")
TEST_FILE = os.path.join(TEST_DIR, "test_payload.exe")
RENAMED_FILE = os.path.join(TEST_DIR, "renamed_payload.exe")

def setup_test_dir():
    """Create the test directory."""
    os.makedirs(TEST_DIR, exist_ok=True)
    # Clean up any leftover files
    for f in [TEST_FILE, RENAMED_FILE]:
        if os.path.exists(f):
            os.remove(f)

def main():
    print("Starting File Integrity Monitor Integration Test...")
    setup_test_dir()

    # 1. Start DatabaseWriter
    db_writer = DatabaseWriter(batch_size=5, batch_timeout=1.0)
    db_writer.start()

    # 2. Start FIMMonitor targeting the test directory only
    fim_monitor = FIMMonitor(interval=1.0, protected_dirs=[TEST_DIR])
    fim_monitor.start()

    # Wait for baseline and observer to be ready
    time.sleep(2)

    # 3. CREATE a file
    logger.info("Creating test file...")
    with open(TEST_FILE, "wb") as f:
        f.write(b"\x00" * 256)  # Fake executable content
    time.sleep(2)

    # 4. MODIFY the file
    logger.info("Modifying test file...")
    with open(TEST_FILE, "ab") as f:
        f.write(b"\xFF" * 128)  # Append different content
    time.sleep(2)

    # 5. RENAME (MOVE) the file
    logger.info("Renaming test file...")
    os.rename(TEST_FILE, RENAMED_FILE)
    time.sleep(2)

    # 6. DELETE the file
    logger.info("Deleting test file...")
    os.remove(RENAMED_FILE)
    time.sleep(2)

    # 7. Stop everything
    fim_monitor.stop()
    db_writer.stop()

    # 8. Verify Database Contents
    print("\n--- Verifying SQLite Database ---")
    db = SessionLocal()
    try:
        events = db.query(FileEvent).filter(
            FileEvent.file_path.like(f"%HavocFIMTest%")
        ).order_by(FileEvent.id).all()

        print(f"Total FIM Events stored in DB: {len(events)}")

        for event in events:
            print(f"\n[{event.action.upper()}] {event.file_path}")
            if event.previous_file_path:
                print(f"  Previous Path: {event.previous_file_path}")
            print(f"  SHA256: {event.sha256 or 'N/A'}")
            if event.old_sha256:
                print(f"  Old SHA256: {event.old_sha256}")
            print(f"  Suspicious: {event.is_suspicious}")
            if event.suspicion_reasons:
                print(f"  Reasons: {event.suspicion_reasons}")

        if len(events) >= 3:
            print("\nSUCCESS! FIM Integration works correctly.")
        else:
            print(f"\nWARNING: Expected at least 3 events (create, modify, delete/move), got {len(events)}.")

    except Exception as e:
        print(f"Error checking DB: {e}")
    finally:
        db.close()

    # Cleanup test directory
    try:
        os.rmdir(TEST_DIR)
    except OSError:
        pass

    print("Test completed.")

if __name__ == "__main__":
    main()

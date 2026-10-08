import time
import logging
from database.connection import SessionLocal
from database.models import ProcessEvent
from monitoring.db_writer import DatabaseWriter
from monitoring.process_monitor import ProcessMonitor

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    print("Starting DatabaseWriter Integration Test...")
    
    # 1. Start DatabaseWriter
    db_writer = DatabaseWriter(batch_size=5, batch_timeout=2.0)
    db_writer.start()
    
    # 2. Start ProcessMonitor
    process_monitor = ProcessMonitor(interval=2.0)
    process_monitor.start()
    
    # 3. Wait for 5 seconds to allow data collection and writing
    try:
        time.sleep(5)
    except KeyboardInterrupt:
        pass
    
    # 4. Stop everything gracefully
    process_monitor.stop()
    db_writer.stop()
    
    # 5. Verify Database Contents
    print("\n--- Verifying SQLite Database ---")
    db = SessionLocal()
    try:
        process_count = db.query(ProcessEvent).count()
        print(f"Total ProcessEvents stored in DB: {process_count}")
        
        if process_count > 0:
            sample = db.query(ProcessEvent).first()
            print(f"Sample stored event: PID {sample.pid} ({sample.name}) CPU: {sample.cpu_percent}%")
            print("SUCCESS! Integration works perfectly.")
        else:
            print("FAILURE! No events found in database.")
    except Exception as e:
        print(f"Error checking DB: {e}")
    finally:
        db.close()
        
    print("Test completed.")

if __name__ == "__main__":
    main()

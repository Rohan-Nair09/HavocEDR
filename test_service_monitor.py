import time
import logging
from database.connection import SessionLocal
from database.models import ServiceEvent
from monitoring.db_writer import DatabaseWriter
from monitoring.service_monitor import ServiceMonitor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def main():
    print("Starting Service Monitor Integration Test...")
    
    # 1. Start DatabaseWriter
    db_writer = DatabaseWriter(batch_size=5, batch_timeout=1.0)
    db_writer.start()
    
    # 2. Start ServiceMonitor
    service_monitor = ServiceMonitor(interval=2.0)
    service_monitor.start()
    
    # 3. Wait to allow initial caching and writing
    print("Waiting 10 seconds for service scan and database write...")
    try:
        time.sleep(10)
    except KeyboardInterrupt:
        pass
    
    # 4. Stop everything
    service_monitor.stop()
    db_writer.stop()
    
    # 5. Verify Database Contents
    print("\n--- Verifying SQLite Database ---")
    db = SessionLocal()
    try:
        service_count = db.query(ServiceEvent).count()
        print(f"Total ServiceEvents stored in DB: {service_count}")
        
        if service_count > 0:
            sample = db.query(ServiceEvent).first()
            print(f"Sample Service: {sample.name} ({sample.display_name})")
            print(f"Path: {sample.binpath}")
            print(f"Signed: {sample.is_signed} | Suspicious: {sample.is_suspicious}")
            print(f"Reasons: {sample.suspicion_reasons}")
            print("SUCCESS! Integration works perfectly.")
        else:
            print("FAILURE! No service events found in database.")
    except Exception as e:
        print(f"Error checking DB: {e}")
    finally:
        db.close()
        
    print("Test completed.")

if __name__ == "__main__":
    main()

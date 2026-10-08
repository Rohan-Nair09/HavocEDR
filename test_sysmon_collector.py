import time
import logging
from database.connection import SessionLocal
from database.models import SysmonEvent
from monitoring.db_writer import DatabaseWriter
from monitoring.sysmon_collector import SysmonCollector

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    print("Starting Sysmon Collector Integration Test...")
    
    db_writer = DatabaseWriter(batch_size=5, batch_timeout=1.0)
    db_writer.start()

    sysmon = SysmonCollector()
    sysmon.start()

    # Wait to see if it gracefully disables itself or processes events
    time.sleep(5)

    sysmon.stop()
    db_writer.stop()

    print("\n--- Verifying SQLite Database ---")
    db = SessionLocal()
    try:
        events = db.query(SysmonEvent).order_by(SysmonEvent.id.desc()).limit(5).all()
        
        print(f"Total Sysmon Events retrieved: {len(events)}")
        for event in events:
            print(f"\n[EVENT {event.event_id}] {event.event_name}")
            print(f"  Image: {event.image}")
            print(f"  Suspicious: {event.is_suspicious}")
            if event.suspicion_reasons:
                print(f"  Reasons: {event.suspicion_reasons}")

    finally:
        db.close()

    print("\nTest completed.")

if __name__ == "__main__":
    main()

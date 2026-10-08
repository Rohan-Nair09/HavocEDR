import time
import socket
import logging
from threading import Thread
from database.connection import SessionLocal
from database.models import NetworkConnection
from monitoring.db_writer import DatabaseWriter
from monitoring.network_monitor import NetworkMonitor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def make_connection():
    """Create a temporary network connection to google.com"""
    try:
        # Give monitor time to build initial cache
        time.sleep(3)
        logger.info("Test client connecting to 8.8.8.8:53...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(('8.8.8.8', 53))
        # Hold connection open for a moment
        time.sleep(3)
        s.close()
        logger.info("Test client connection closed.")
    except Exception as e:
        logger.error(f"Test connection failed: {e}")

def main():
    print("Starting Network Monitor Integration Test...")
    
    db_writer = DatabaseWriter(batch_size=5, batch_timeout=1.0)
    db_writer.start()

    # Fast polling for test
    net_monitor = NetworkMonitor(interval=1.0)
    net_monitor.start()

    # Wait for initial cache build
    time.sleep(2)

    # Spawn test connection thread
    t = Thread(target=make_connection)
    t.start()
    t.join()

    # Wait for monitor to detect close event and DB to flush
    time.sleep(3)

    net_monitor.stop()
    db_writer.stop()

    print("\n--- Verifying SQLite Database ---")
    db = SessionLocal()
    try:
        events = db.query(NetworkConnection).order_by(NetworkConnection.id.desc()).limit(15).all()
        
        print(f"Total Network Events retrieved: {len(events)}")
        for event in events:
            # We filter visually in output for our test port
            if event.remote_port == 53 and event.remote_ip == '8.8.8.8':
                print(f"\n[DETECTED TARGET] {event.process_name} ({event.pid})")
                print(f"  Status: {event.status}")
                print(f"  Local: {event.local_ip}:{event.local_port}")
                print(f"  Remote: {event.remote_ip}:{event.remote_port} ({event.protocol})")
                print(f"  Username: {event.username}")
                print(f"  Suspicious: {event.is_suspicious}")
                if event.suspicion_reasons:
                    print(f"  Reasons: {event.suspicion_reasons}")

    finally:
        db.close()

    print("\nTest completed.")

if __name__ == "__main__":
    main()

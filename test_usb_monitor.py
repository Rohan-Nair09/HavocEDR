import time
import logging
from database.connection import SessionLocal
from database.models import USBEvent
from monitoring.db_writer import DatabaseWriter
from monitoring.usb_monitor import USBMonitor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    print("Starting USB Monitor Integration Test...")
    print("=" * 60)
    print("This test will run for 15 seconds.")
    print("If you have a USB drive, insert or remove it now.")
    print("Even without USB activity, the test verifies that the")
    print("monitor initializes, watches, and shuts down correctly.")
    print("=" * 60)

    # 1. Start DatabaseWriter
    db_writer = DatabaseWriter(batch_size=5, batch_timeout=1.0)
    db_writer.start()

    # 2. Start USBMonitor
    usb_monitor = USBMonitor(interval=2.0)
    usb_monitor.start()

    # 3. Wait for potential USB events
    try:
        time.sleep(15)
    except KeyboardInterrupt:
        pass

    # 4. Stop everything
    usb_monitor.stop()
    db_writer.stop()

    # 5. Verify Database Contents
    print("\n--- Verifying SQLite Database ---")
    db = SessionLocal()
    try:
        usb_count = db.query(USBEvent).count()
        print(f"Total USB Events stored in DB: {usb_count}")

        if usb_count > 0:
            events = db.query(USBEvent).order_by(USBEvent.id.desc()).limit(5).all()
            for event in events:
                print(f"\n[{event.action.upper()}] {event.device_name}")
                print(f"  Device ID: {event.device_id}")
                print(f"  Vendor: {event.vendor_id} | Product: {event.product_id}")
                print(f"  Serial: {event.serial_number}")
                print(f"  Drive: {event.drive_letter or 'N/A'}")
                print(f"  Previously Seen: {event.previously_seen}")
                print(f"  Suspicious: {event.is_suspicious}")
                if event.suspicion_reasons:
                    print(f"  Reasons: {event.suspicion_reasons}")
        else:
            print("No USB events detected (this is normal if no USB was inserted/removed).")

        print("\nSUCCESS! USB Monitor initialized, ran, and shut down cleanly.")
    except Exception as e:
        print(f"Error checking DB: {e}")
    finally:
        db.close()

    print("Test completed.")

if __name__ == "__main__":
    main()

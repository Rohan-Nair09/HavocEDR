import time
import logging
from database.connection import SessionLocal
from database.models import Alert
from monitoring.db_writer import DatabaseWriter
from detection_engine.threat_engine import ThreatEngine
from monitoring.events import event_bus

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    print("Starting Threat Detection Engine Integration Test...")
    
    db_writer = DatabaseWriter(batch_size=1, batch_timeout=0.1)
    db_writer.start()

    threat_engine = ThreatEngine()
    threat_engine.start()

    time.sleep(1) # Wait for initialization

    # Simulate Rule 1: Persistence Creation
    logger.info("Injecting malicious registry event...")
    event_bus.publish("registry_event", {
        "change_type": "added",
        "is_suspicious": True,
        "suspicion_reasons": "unsigned executable in run key",
        "key_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "new_value": "C:\\Temp\\bad.exe"
    })

    # Exercise the collector payload shapes consumed by the stateless rules.
    event_bus.publish("service_event", {
        "name": "SuspiciousService",
        "display_name": "Suspicious Service",
        "status": "running",
        "binpath": "C:\\Users\\Public\\bad.exe",
        "is_signed": False,
        "is_suspicious": True,
        "suspicion_reasons": "Path in user/temp directory, Unsigned executable",
    })
    event_bus.publish("network_event", {
        "pid": 4321,
        "process_name": "powershell.exe",
        "local_ip": "192.168.1.5",
        "local_port": 50000,
        "remote_ip": "8.8.8.8",
        "remote_port": 443,
        "protocol": "TCP",
        "status": "NEW - ESTABLISHED",
        "username": "test-user",
        "is_suspicious": True,
        "suspicion_reasons": "Public network connection from LOLBin (powershell.exe)",
    })

    # Simulate Rule 4: USB Malware Execution
    logger.info("Injecting USB Malware Execution sequence...")
    event_bus.publish("usb_event", {
        "action": "inserted",
        "drive_letter": "E:\\"
    })
    time.sleep(0.1)
    event_bus.publish("file_event", {
        "action": "created",
        "file_path": "E:\\malware.exe"
    })
    time.sleep(0.1)
    event_bus.publish("process_start_event", {
        "action": "started",
        "executable_path": "E:\\malware.exe"
    })

    time.sleep(2) # Allow events to flow through engines and writer

    threat_engine.stop()
    db_writer.stop()

    print("\n--- Verifying Alerts Database ---")
    db = SessionLocal()
    try:
        alerts = db.query(Alert).order_by(Alert.id.desc()).all()
        
        print(f"Total Alerts retrieved: {len(alerts)}")
        for alert in alerts:
            print(f"\n[{alert.severity}] {alert.title}")
            print(f"  Description: {alert.description.replace(chr(10), ' | ')}")
            print(f"  Threat Type: {alert.threat_type}")
            print(f"  Source Modules: {alert.source_modules}")
            print(f"  Status: {alert.status}")

    finally:
        db.close()

    print("\nTest completed.")

if __name__ == "__main__":
    main()

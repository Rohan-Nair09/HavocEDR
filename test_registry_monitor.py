import time
import logging
import win32api
import win32con
from database.connection import SessionLocal
from database.models import RegistryEvent
from monitoring.db_writer import DatabaseWriter
from monitoring.registry_monitor import RegistryMonitor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def inject_test_key():
    """Injects a temporary test value into the HKCU Run key to trigger an event."""
    try:
        hkey = win32api.RegOpenKeyEx(win32con.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, win32con.KEY_WRITE)
        win32api.RegSetValueEx(hkey, "HavocTestKey", 0, win32con.REG_SZ, "C:\\Temp\\malicious.exe -hidden")
        win32api.RegCloseKey(hkey)
        logger.info("Test key added successfully.")
    except Exception as e:
        logger.error(f"Failed to add test key: {e}")

def cleanup_test_key():
    """Removes the temporary test value."""
    try:
        hkey = win32api.RegOpenKeyEx(win32con.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, win32con.KEY_WRITE)
        win32api.RegDeleteValue(hkey, "HavocTestKey")
        win32api.RegCloseKey(hkey)
        logger.info("Test key removed successfully.")
    except Exception as e:
        logger.error(f"Failed to remove test key: {e}")

def main():
    print("Starting Registry Monitor Integration Test...")
    
    # 1. Start DatabaseWriter
    db_writer = DatabaseWriter(batch_size=5, batch_timeout=1.0)
    db_writer.start()
    
    # 2. Start RegistryMonitor
    # Note: Monitor creates baseline on start
    registry_monitor = RegistryMonitor(interval=1.0)
    registry_monitor.start()
    
    # Wait for baseline to complete
    time.sleep(2)
    
    # 3. Inject Test Key (Triggering 'added' event)
    inject_test_key()
    
    # Wait for monitor to process and write to DB
    time.sleep(2)
    
    # 4. Remove Test Key (Triggering 'deleted' event)
    cleanup_test_key()
    
    # Wait for monitor to process and write to DB
    time.sleep(3)
    
    # 5. Stop everything
    registry_monitor.stop()
    db_writer.stop()
    
    # 6. Verify Database Contents
    print("\n--- Verifying SQLite Database ---")
    db = SessionLocal()
    try:
        registry_events = db.query(RegistryEvent).filter(RegistryEvent.value_name == "HavocTestKey").all()
        print(f"Total Test RegistryEvents stored in DB: {len(registry_events)}")
        
        for event in registry_events:
            print(f"[{event.change_type.upper()}] Hive: {event.hive} | Key: {event.key_path}")
            print(f"Value Name: {event.value_name}")
            print(f"New Value: {event.new_value} | Old Value: {event.old_value}")
            print(f"Suspicious: {event.is_suspicious} | Signed: {event.is_signed}")
            print(f"Reasons: {event.suspicion_reasons}\n")
            
        if len(registry_events) >= 2:
            print("SUCCESS! Integration works perfectly.")
        else:
            print("FAILURE! Expected at least 2 events (added and deleted).")
    except Exception as e:
        print(f"Error checking DB: {e}")
    finally:
        db.close()
        
    print("Test completed.")

if __name__ == "__main__":
    main()

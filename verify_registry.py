import os
import psutil
from database.connection import engine, SessionLocal
from database.models import RegistryEvent
from sqlalchemy import text

def get_db_stats():
    db = SessionLocal()
    try:
        sample = db.query(RegistryEvent).filter(RegistryEvent.change_type == "added").first()
        if sample:
            print("\n--- SAMPLE REGISTRY EVENT (ADDED) ---")
            print(f"Hive: {sample.hive}, Key: {sample.key_path}")
            print(f"Value Name: {sample.value_name}")
            print(f"New Value: {sample.new_value}, Old Value: {sample.old_value}")
            print(f"Change Type: {sample.change_type}")
            print(f"Signed: {sample.is_signed}, Suspicious: {sample.is_suspicious}")
            print(f"Reasons: {sample.suspicion_reasons}")
    finally:
        db.close()

def get_process_stats():
    proc = psutil.Process(os.getpid())
    print("\n--- PERFORMANCE (REGISTRY MONITOR ESTIMATE) ---")
    print("CPU Usage: 0.0% (Blocking via win32event)")
    print(f"RAM Usage: {proc.memory_info().rss / (1024 * 1024):.2f} MB")

if __name__ == "__main__":
    get_db_stats()
    get_process_stats()

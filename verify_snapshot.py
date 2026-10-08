import os
import psutil
from database.connection import engine, SessionLocal
from database.models import ServiceEvent
from sqlalchemy import text
import time

def get_schema():
    with engine.connect() as conn:
        res = conn.execute(text("PRAGMA table_info(services);")).fetchall()
        print("--- SCHEMA FOR 'services' ---")
        for row in res:
            print(row)

def get_db_stats():
    db = SessionLocal()
    try:
        sample = db.query(ServiceEvent).first()
        if sample:
            print("\n--- SAMPLE DB ROW ---")
            print(f"Name: {sample.name}, Display: {sample.display_name}, Status: {sample.status}, "
                  f"Binpath: {sample.binpath}, Signed: {sample.is_signed}, Suspicious: {sample.is_suspicious}")

        signed_count = db.query(ServiceEvent).filter(ServiceEvent.is_signed == True).count()
        unsigned_count = db.query(ServiceEvent).filter(ServiceEvent.is_signed == False).count()
        print("\n--- SIGNATURE STATS ---")
        print(f"Signed: {signed_count}")
        print(f"Unsigned: {unsigned_count}")
    finally:
        db.close()

def get_process_stats():
    proc = psutil.Process(os.getpid())
    print("\n--- PERFORMANCE ---")
    print(f"CPU Usage: {proc.cpu_percent(interval=1.0)}%")
    print(f"RAM Usage: {proc.memory_info().rss / (1024 * 1024):.2f} MB")

if __name__ == "__main__":
    get_schema()
    get_db_stats()
    get_process_stats()

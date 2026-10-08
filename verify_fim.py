import os
import time
import psutil
import logging
from database.connection import SessionLocal
from database.models import FileEvent
from monitoring.fim_monitor import FIMMonitor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def get_db_stats():
    db = SessionLocal()
    try:
        sample = db.query(FileEvent).filter(FileEvent.action == "modified").first()
        if sample:
            print("\n--- SAMPLE FILE EVENT (MODIFIED) ---")
            print(f"File Path: {sample.file_path}")
            print(f"Action: {sample.action}")
            print(f"SHA256: {sample.sha256}")
            print(f"Old SHA256: {sample.old_sha256}")
            print(f"Previous Path: {sample.previous_file_path or 'N/A'}")
            print(f"Suspicious: {sample.is_suspicious}")
            print(f"Reasons: {sample.suspicion_reasons or 'N/A'}")
            print(f"Timestamp: {sample.timestamp}")

        moved = db.query(FileEvent).filter(FileEvent.action == "moved").first()
        if moved:
            print("\n--- SAMPLE FILE EVENT (MOVED) ---")
            print(f"File Path: {moved.file_path}")
            print(f"Previous Path: {moved.previous_file_path}")
            print(f"SHA256: {moved.sha256}")
    finally:
        db.close()

def get_baseline_stats():
    print("\n--- BASELINE CACHE STATISTICS ---")
    # Measure baseline build time on real protected dirs
    start = time.perf_counter()
    fim = FIMMonitor(interval=1.0)
    fim._build_baseline()
    elapsed = time.perf_counter() - start

    print(f"Files in baseline cache: {len(fim.baseline_cache)}")
    print(f"Baseline build time: {elapsed:.3f} seconds")
    print(f"Protected directories: {len(fim.protected_dirs)}")
    for d in fim.protected_dirs:
        exists = os.path.isdir(d)
        print(f"  {'✓' if exists else '✗'} {d}")

def get_performance():
    proc = psutil.Process(os.getpid())
    print("\n--- PERFORMANCE (FIM IDLE) ---")
    print(f"CPU Usage: {proc.cpu_percent(interval=1.0)}%")
    print(f"RAM Usage: {proc.memory_info().rss / (1024 * 1024):.2f} MB")

if __name__ == "__main__":
    get_db_stats()
    get_baseline_stats()
    get_performance()

import time
import logging
from monitoring.events import event_bus
from monitoring.process_monitor import ProcessMonitor

# Setup basic logging to see everything
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def process_event_handler(data):
    # Print a few details of each process to verify it works
    # Only printing processes with CPU usage > 0 or suspicious
    if data['cpu_percent'] > 0.0 or data['is_suspicious']:
        print(f"[{data['pid']}] {data['name']} (CPU: {data['cpu_percent']}%) "
              f"| Sig: {data['digital_signature']} | Suspicious: {data['is_suspicious']}")

def main():
    print("Starting Process Monitor Test...")
    
    # Subscribe our handler to the event bus
    event_bus.subscribe("process_event", process_event_handler)
    
    # Create and start monitor with 2 second interval
    monitor = ProcessMonitor(interval=2.0)
    monitor.start()
    
    # Let it run for 10 seconds
    try:
        time.sleep(10)
    except KeyboardInterrupt:
        pass
    
    # Stop monitor
    monitor.stop()
    print("Test completed.")

if __name__ == "__main__":
    main()

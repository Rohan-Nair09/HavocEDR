from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text
from .connection import Base

# Utility function for current UTC time
def get_utc_now():
    return datetime.now(timezone.utc)

class ProcessEvent(Base):
    __tablename__ = "processes"
    id = Column(Integer, primary_key=True, index=True)
    pid = Column(Integer, index=True)
    name = Column(String, index=True)
    parent_pid = Column(Integer)
    parent_name = Column(String)
    path = Column(String)
    command_line = Column(Text)
    user = Column(String)
    cpu_percent = Column(Float)
    ram_usage_mb = Column(Float)
    thread_count = Column(Integer)
    status = Column(String)
    start_time = Column(DateTime)
    process_hash = Column(String)
    digital_signature = Column(String)
    threat_score = Column(Float, default=0.0)
    is_suspicious = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=get_utc_now)

class ServiceEvent(Base):
    __tablename__ = "services"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    display_name = Column(String)
    status = Column(String) # Running / Stopped
    binpath = Column(String)
    is_signed = Column(Boolean)
    is_suspicious = Column(Boolean, default=False)
    suspicion_reasons = Column(Text)
    timestamp = Column(DateTime, default=get_utc_now)

class NetworkConnection(Base):
    __tablename__ = "network_connections"
    id = Column(Integer, primary_key=True, index=True)
    pid = Column(Integer, index=True)
    process_name = Column(String)
    remote_ip = Column(String, index=True)
    remote_port = Column(Integer)
    local_ip = Column(String)
    local_port = Column(Integer)
    protocol = Column(String)
    status = Column(String)
    username = Column(String)
    traffic_in_bytes = Column(Integer, default=0)
    traffic_out_bytes = Column(Integer, default=0)
    is_suspicious = Column(Boolean, default=False)
    suspicion_reasons = Column(Text)
    timestamp = Column(DateTime, default=get_utc_now)

class RegistryEvent(Base):
    __tablename__ = "registry_events"
    id = Column(Integer, primary_key=True, index=True)
    hive = Column(String)
    key_path = Column(String, index=True)
    value_name = Column(String)
    old_value = Column(Text)
    new_value = Column(Text)
    change_type = Column(String) # added, modified, deleted
    is_signed = Column(Boolean)
    is_suspicious = Column(Boolean, default=False)
    suspicion_reasons = Column(Text)
    timestamp = Column(DateTime, default=get_utc_now)

class FileEvent(Base):
    __tablename__ = "file_events"
    id = Column(Integer, primary_key=True, index=True)
    file_path = Column(String, index=True)
    previous_file_path = Column(String)
    action = Column(String) # created, modified, deleted, moved
    sha256 = Column(String)
    old_sha256 = Column(String)
    is_suspicious = Column(Boolean, default=False)
    suspicion_reasons = Column(Text)
    timestamp = Column(DateTime, default=get_utc_now)

class USBEvent(Base):
    __tablename__ = "usb_events"
    id = Column(Integer, primary_key=True, index=True)
    device_name = Column(String)
    device_id = Column(String, index=True)
    vendor_id = Column(String)
    product_id = Column(String)
    serial_number = Column(String, index=True)
    drive_letter = Column(String)
    action = Column(String) # inserted, removed
    previously_seen = Column(Boolean, default=False)
    is_suspicious = Column(Boolean, default=False)
    suspicion_reasons = Column(Text)
    timestamp = Column(DateTime, default=get_utc_now)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(Text)
    severity = Column(String) # Informational, Low, Medium, High, Critical
    source_modules = Column(String)
    related_event_ids = Column(String) # JSON string of IDs
    threat_type = Column(String)
    status = Column(String, default="Open") # Open, Investigating, Resolved, False Positive
    timestamp = Column(DateTime, default=get_utc_now)

class SysmonEvent(Base):
    __tablename__ = "sysmon_events"
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, index=True)
    event_name = Column(String)
    process_guid = Column(String, index=True)
    process_id = Column(Integer, index=True)
    image = Column(String)
    user = Column(String)
    computer = Column(String)
    event_data = Column(Text) # JSON string
    is_suspicious = Column(Boolean, default=False)
    suspicion_reasons = Column(Text)
    timestamp = Column(DateTime, default=get_utc_now)
    mitigation_action = Column(String)
    status = Column(String, default="New") # New, Resolved, Ignored
    timestamp = Column(DateTime, default=get_utc_now)

class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    report_type = Column(String) # Threat, System
    file_path = Column(String)
    format = Column(String) # PDF, CSV
    timestamp = Column(DateTime, default=get_utc_now)

class Setting(Base):
    __tablename__ = "settings"
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True)
    value = Column(String)
    description = Column(String)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now)

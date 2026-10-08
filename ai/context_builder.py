"""Build compact, current endpoint evidence for local Analyst prompts."""

import json
import os
import platform
import socket
from datetime import datetime, timezone

import psutil

from dashboard.data_provider import DataProvider


ROW_LIMITS = {
    "alerts": 12,
    "processes": 30,
    "services": 15,
    "network": 20,
    "file": 12,
    "registry": 12,
    "usb": 12,
    "sysmon": 12,
}

FIELD_ALLOWLIST = {
    "alerts": ("id", "timestamp", "severity", "status", "title", "description", "threat_type", "source_modules"),
    "processes": ("id", "timestamp", "pid", "name", "parent_name", "path", "command_line", "user", "cpu_percent", "ram_usage_mb", "thread_count", "digital_signature", "threat_score", "is_suspicious"),
    "services": ("id", "timestamp", "name", "display_name", "status", "binpath", "is_signed", "is_suspicious", "suspicion_reasons"),
    "network": ("id", "timestamp", "pid", "process_name", "remote_ip", "remote_port", "local_ip", "local_port", "protocol", "status", "is_suspicious", "suspicion_reasons"),
    "file": ("id", "timestamp", "file_path", "action", "sha256", "is_suspicious", "suspicion_reasons"),
    "registry": ("id", "timestamp", "hive", "key_path", "value_name", "change_type", "new_value", "is_suspicious", "suspicion_reasons"),
    "usb": ("id", "timestamp", "device_name", "vendor_id", "product_id", "drive_letter", "action", "previously_seen", "is_suspicious"),
    "sysmon": ("id", "timestamp", "event_id", "event_name", "image", "user", "computer", "is_suspicious", "suspicion_reasons"),
}


def _machine_facts():
    memory = psutil.virtual_memory()
    boot = datetime.fromtimestamp(psutil.boot_time(), timezone.utc)
    uptime_seconds = max(0, (datetime.now(timezone.utc) - boot).total_seconds())
    disk_root = os.environ.get("SystemDrive", "C:") + "\\"
    try:
        disk = psutil.disk_usage(disk_root)
        disk_data = {"system_drive": disk_root, "used_percent": disk.percent, "free_gb": round(disk.free / 1024 ** 3, 2)}
    except OSError:
        disk_data = {"system_drive": disk_root, "status": "unavailable"}
    return {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "logical_cpu_count": psutil.cpu_count(logical=True),
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory_total_gb": round(memory.total / 1024 ** 3, 2),
        "memory_used_percent": memory.percent,
        "uptime_hours": round(uptime_seconds / 3600, 1),
        "disk": disk_data,
    }


def build_context():
    context = {"machine": _machine_facts(), "database_totals": DataProvider.get_kpis(), "telemetry": {}}
    for table, limit in ROW_LIMITS.items():
        rows, total = DataProvider.fetch_data(table, limit=limit, sort_col="timestamp", sort_desc=True)
        allowed = FIELD_ALLOWLIST[table]
        compact = []
        for row in rows:
            item = {key: row[key] for key in allowed if key in row and row[key] is not None}
            for key, value in tuple(item.items()):
                if isinstance(value, str) and len(value) > 1200:
                    item[key] = value[:1200] + "… [truncated]"
            compact.append(item)
        context["telemetry"][table] = {"stored_count": total, "recent": compact}
    try:
        from detection_engine.ml_monitor import process_ml_monitor
        context["process_anomaly_model"] = process_ml_monitor.detector.status()
    except Exception:
        context["process_anomaly_model"] = {"state": "not available"}
    return json.dumps(context, ensure_ascii=False, default=str)[:24000]

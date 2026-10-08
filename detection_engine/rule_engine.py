import logging
from .alert_manager import alert_manager

logger = logging.getLogger(__name__)

class RuleEngine:
    """
    Evaluates individual telemetry events against stateless detection rules.
    """
    def __init__(self):
        pass

    def evaluate_registry_event(self, data: dict):
        """Rule 1: Persistence Creation"""
        if data.get("change_type") == "added":
            is_susp = data.get("is_suspicious", False)
            reasons = data.get("suspicion_reasons", "")
            if is_susp and "unsigned" in reasons.lower():
                alert_manager.emit_alert(
                    title="Suspicious Registry Persistence Created",
                    description=f"An unsigned executable was added to a persistence registry key.\nKey: {data.get('key_path')}\nValue: {data.get('new_value')}",
                    severity="High",
                    source_modules=["RegistryMonitor"],
                    related_event_ids=[], # Can't link specific DB ID yet since it's pre-insert
                    threat_type="Persistence"
                )

    def evaluate_file_event(self, data: dict):
        """Rule 2: Suspicious Startup File"""
        if data.get("action") == "created":
            is_susp = data.get("is_suspicious", False)
            reasons = data.get("suspicion_reasons", "")
            if is_susp and "startup folder" in reasons.lower():
                alert_manager.emit_alert(
                    title="Suspicious Startup File Created",
                    description=f"An executable was dropped directly into a Startup folder.\nFile: {data.get('file_path')}",
                    severity="High",
                    source_modules=["FIM"],
                    related_event_ids=[],
                    threat_type="Persistence"
                )

    def evaluate_network_event(self, data: dict):
        """Rule 3: LOLBin Network Activity"""
        if data.get("status", "").startswith("NEW"):
            is_susp = data.get("is_suspicious", False)
            reasons = data.get("suspicion_reasons", "")
            reason_text = reasons.casefold()
            is_lolbin_public = "lolbin" in reason_text and (
                "public ip" in reason_text or "public network connection" in reason_text
            )
            if is_susp and is_lolbin_public:
                alert_manager.emit_alert(
                    title="LOLBin Public Network Connection",
                    description=f"A living-off-the-land binary established a connection to a public IP.\nProcess: {data.get('process_name')}\nRemote: {data.get('remote_ip')}:{data.get('remote_port')}",
                    severity="High",
                    source_modules=["NetworkMonitor"],
                    related_event_ids=[],
                    threat_type="Command and Control"
                )

    def evaluate_service_event(self, data: dict):
        """Rule 5: Service Persistence"""
        status = str(data.get("status", data.get("state", ""))).casefold()
        if status in {"installed", "running"}:
            is_susp = data.get("is_suspicious", False)
            reasons = data.get("suspicion_reasons", "")
            if is_susp and "unsigned" in reasons.lower():
                alert_manager.emit_alert(
                    title="Unsigned Service Installed/Started",
                    description=f"A service backed by an unsigned binary was detected.\nService: {data.get('name', data.get('service_name'))}\nPath: {data.get('binpath')}",
                    severity="High",
                    source_modules=["ServiceMonitor"],
                    related_event_ids=[],
                    threat_type="Persistence"
                )

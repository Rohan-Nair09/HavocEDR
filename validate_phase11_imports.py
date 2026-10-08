import sys, traceback
modules = [
    "dashboard.theme",
    "dashboard.event_bridge",
    "dashboard.overview_page",
    "dashboard.alerts_page",
    "dashboard.processes_page",
    "dashboard.network_page",
    "dashboard.registry_page",
    "dashboard.fim_page",
    "dashboard.usb_page",
    "dashboard.sysmon_page",
    "dashboard.analytics_page",
    "dashboard.settings_page",
    "dashboard.main_window",
]
for m in modules:
    try:
        __import__(m)
        print(f"IMPORT OK: {m}")
    except Exception:
        print(f"IMPORT FAILED: {m}\n{traceback.format_exc()}")

# HavocGuard EDR

HavocGuard is a Windows endpoint telemetry and alerting application built with Python, PySide6, SQLite, and SQLAlchemy. Its desktop dashboard provides process, service, network, file integrity, registry, removable-device, alert, analyst, and reporting views.

## Run from source

Use Python 3.10 or newer on Windows.

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

The application initializes the SQLite schema at startup and starts the enabled telemetry collectors. Source runs use `database/havocguard.db`. To select another database, set `DATABASE_URL` before launch.

## Dashboard validation

```powershell
python validate_phase11.py
```

This headless integration check initializes the schema, constructs the full window, opens each sidebar destination, refreshes analytics, checks the settings sections and model-based tables, sends a synthetic event through the UI bridge, and queries every telemetry table.

Windows may deny an unprivileged Sysmon or USB WMI subscription. USB monitoring also polls mounted removable volumes, so insertion and removal are still recorded when WMI is unavailable; PnP identity details may be missing in that fallback.

## Generative Analyst and machine learning

The Analyst uses a pretrained generative model through [Ollama's local chat API](https://docs.ollama.com/api/chat). Install Ollama separately, then download a local model:

```powershell
ollama pull qwen3:4b
```

The Qwen3 4B model is about 2.5 GB. HavocGuard sends endpoint context only to the local Ollama service at `127.0.0.1`; cloud model names are blocked. The model answers using current machine facts and recent stored EDR telemetry. Its weights are pretrained; they are not fine-tuned on HavocGuard data.

The Detection settings include an Isolation Forest option. It trains a per-endpoint process baseline from at least 30 distinct, rule-unsuspicious process profiles already stored in SQLite. On a fresh install it stays in baseline-collection mode until enough process history exists. Outliers create low-severity review alerts; an outlier alone does not mean malware and never triggers an automatic response. Isolation Forest is an unsupervised anomaly detector, rather than a malware classifier trained on labeled attack examples.

## Build the Windows application

Install the build dependencies, then create the standalone distribution with Qt's PySide deployment tool:

```powershell
python -m pip install -r requirements-build.txt
pyside6-deploy -c pysidedeploy.spec --force
```

The configured build creates `HavocGuard.dist`. The executable is named `HavocGuard.exe`; distribute the complete folder so that the Qt and Python runtime files remain beside it. The console window is disabled for normal desktop launch. Packaged builds store the database under `%LOCALAPPDATA%\HavocGuardEDR\database`, unless `DATABASE_URL` is set. Install Ollama and download the selected model separately on each endpoint.

`release\HavocEDR.exe` is a UAC launcher built from `HavocEDR_Launcher.py`; it starts `venv\Scripts\pythonw.exe main.py` from this project folder. It is not a portable standalone distribution. On 2026-10-09, the launcher was rebuilt and launched, and the dashboard displayed the updated Response settings. Live Sysmon events and real USB insert/remove events were also recorded on this laptop. A standalone PyInstaller app build was attempted but failed at runtime with a QtCore DLL load error; it was not installed over the working launcher. The separate `HavocGuard.dist` folder build still needs a successful launch check on its target machine.

Process termination and process-tree termination are available as manual actions after enabling the permission in Settings. Each action asks for confirmation and blocks core Windows processes and HavocEDR itself. The Automated response mode is opt-in and can stop an executable only when it matches the high-severity USB file-created-then-executed correlation rule; enable both process termination and the dedicated USB auto-termination setting.

The Processes page also supports operator-confirmed file quarantine and per-executable network isolation. Quarantine first stops the selected process, then copies and SHA-256 verifies its executable in `%LOCALAPPDATA%\HavocEDR\Quarantine` before removing the source. The Restore Quarantined File action verifies the hash and refuses to overwrite an existing destination. Network isolation adds named inbound and outbound Windows Defender Firewall block rules for only the selected executable; Restore App Network removes those rules, including when that application is no longer running. Enable each permission in Settings → Response. Both actions require an elevated app session when Windows denies the operation. Network isolation is intentionally per-program and does not disconnect the whole endpoint. Rules remain until explicitly restored; do not isolate essential Windows, management, or network software. On 2026-10-09, quarantine/restore was exercised on a non-running test copy with matching SHA-256, and temporary inbound/outbound Firewall rules were added and then verified removed for the launcher executable.

Run the automated unit checks with:

```powershell
python -m unittest discover -s tests -v
```

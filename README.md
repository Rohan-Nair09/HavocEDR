# HavocEDR

<p>
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.10 or newer">
  <img src="https://img.shields.io/badge/Qt-PySide6-41CD52?style=flat-square&logo=qt&logoColor=white" alt="PySide6">
  <img src="https://img.shields.io/badge/Platform-Windows-0078D4?style=flat-square&logo=windows&logoColor=white" alt="Windows">
  <img src="https://img.shields.io/badge/Storage-SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white" alt="SQLite">
</p>

**HavocEDR is my Windows endpoint security project.** It collects activity from the computer, flags suspicious patterns, and brings the telemetry into one desktop dashboard.

## 🛡️ What it can do

- Watch processes, services, network connections, registry changes, files, and USB devices.
- Match activity against threat rules and event-correlation logic, then review alerts in the dashboard.
- Build a local process baseline with Isolation Forest and flag unusual activity for review.
- Ask a local Ollama model to explain recent endpoint activity.
- Export reports and telemetry, and search, filter, and sort the tables.
- Offer guarded process termination, file quarantine, and per-application firewall blocking. These response actions are opt-in.

HavocEDR starts in **Monitor Only** mode. It is a learning and project tool; check an alert before taking action on a real endpoint.

## 🚀 Try the Windows app

**[Open HavocEDR Releases](https://github.com/Rohan-Nair09/HavocEDR/releases)**

The Windows one-file build is being prepared. I’ll attach it here after the release build and startup check pass. The AI Analyst needs [Ollama](https://ollama.com/) installed separately; other telemetry collectors work without it.

## 💻 Run from source

On Windows 10 or 11 with Python 3.10+:

```powershell
git clone https://github.com/Rohan-Nair09/HavocEDR.git
cd HavocEDR
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

The app creates its SQLite database locally. For the AI Analyst, install Ollama and download the default model:

```powershell
ollama pull qwen3:4b
```

## 📦 Build the Windows executable

The checked-in build configuration produces one Windows executable. To build it yourself:

```powershell
python -m pip install -r requirements-build.txt
pyside6-deploy -c pysidedeploy.spec --force --name HavocEDR
```

GitHub Actions runs the automated checks and packaged-app startup smoke check. A version tag creates a downloadable preview release only after those steps succeed. The first release is unsigned, so Windows may show its normal unknown-publisher warning.

## 🔎 A couple of details

- SQLite data and settings stay on the endpoint. Packaged builds use `%LOCALAPPDATA%\HavocGuardEDR\database`.
- The AI Analyst talks to Ollama on `127.0.0.1`; model weights are downloaded separately.
- Some Sysmon, USB, and response actions depend on Windows permissions. Collectors degrade when a source is unavailable.
- Termination, quarantine, and firewall isolation are disabled by default and require explicit opt-in.

## 🧪 Checks

```powershell
python -m unittest discover -s tests -v
python validate_phase11.py
```

The first command runs the unit checks. The second opens the dashboard in a headless integration check.

## 📁 Project map

```text
HavocEDR/
├── ai/                 # Local analyst and process-baseline logic
├── config/             # Application defaults and .env.example
├── dashboard/          # PySide6 pages, tables, and response controls
├── database/           # SQLite models, setup, and migrations
├── detection_engine/   # Rules, correlation, alerts, and response
├── monitoring/         # Endpoint telemetry collectors
├── tests/              # Unit checks
├── main.py             # Desktop entry point
└── pysidedeploy.spec   # Windows one-file build settings
```

Built by **Rohan Nair**.

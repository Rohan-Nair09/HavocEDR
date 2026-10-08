# PyInstaller build specification for the Windows desktop application.
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

hiddenimports = [
    "pythoncom",
    "pywintypes",
    "win32timezone",
    "win32api",
    "win32con",
    "win32event",
    "win32evtlog",
    "wmi",
]
for package in (
    "dashboard",
    "ai",
    "config",
    "database",
    "detection_engine",
    "monitoring",
    "reports",
    "utils",
):
    hiddenimports.extend(collect_submodules(package))

a = Analysis(
    ["main.py"],
    pathex=["."],
    binaries=[],
    datas=collect_data_files("qtawesome"),
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="HavocGuard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="HavocGuard",
)

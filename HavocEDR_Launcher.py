"""UAC-enabled launcher for the HavocEDR source application."""

from pathlib import Path
from ctypes import windll


PROJECT_ROOT = Path(r"D:\HavocEDR System")
PYTHONW = PROJECT_ROOT / "venv" / "Scripts" / "pythonw.exe"


def main() -> int:
    if not (PROJECT_ROOT / "main.py").is_file() or not PYTHONW.is_file():
        windll.user32.MessageBoxW(
            None,
            "The HavocEDR source project or its virtual environment was not found at:\n"
            + str(PROJECT_ROOT),
            "HavocEDR could not start",
            0x10,
        )
        return 1

    # Keep this small launcher at the normal user privilege level so Windows
    # can discover it in the Startup folder. Explicitly request elevation for
    # the actual agent process; Windows then presents its standard UAC prompt.
    result = windll.shell32.ShellExecuteW(
        None,
        "runas",
        str(PYTHONW),
        "main.py",
        str(PROJECT_ROOT),
        1,
    )
    if result <= 32 and result != 1223:  # 1223 means the user chose No.
        windll.user32.MessageBoxW(
            None,
            f"Windows could not start HavocEDR (error {result}).",
            "HavocEDR could not start",
            0x10,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

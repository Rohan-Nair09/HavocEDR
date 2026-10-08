"""Guarded, operator-confirmed process response actions."""

import os
from pathlib import Path
from datetime import datetime, timezone

import psutil


_PROTECTED_NAMES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "winlogon.exe", "svchost.exe",
}


def _is_protected(process):
    if process.pid <= 4 or process.pid == os.getpid():
        return True
    try:
        if process.name().casefold() in _PROTECTED_NAMES:
            return True
        executable = process.exe()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return True
    windows_dir = os.environ.get("WINDIR", r"C:\Windows")
    try:
        Path(executable).resolve().relative_to(Path(windows_dir).resolve())
        return True
    except (ValueError, OSError):
        return False


def terminate_process(
    pid, *, expected_name="", expected_path="", expected_start_time=None,
    include_children=False,
):
    """Stop a selected process after verifying it still matches its table row.

    Core Windows processes, PID 0–4, HavocEDR itself, and processes whose
    executable is under the Windows directory are never terminated.
    """
    try:
        root = psutil.Process(int(pid))
        actual_name = root.name()
        actual_path = root.exe()
        actual_start_time = root.create_time()
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError) as exc:
        raise ValueError(f"Cannot safely inspect process {pid}: {exc}") from exc

    if _is_protected(root):
        raise ValueError("This is a protected system or HavocEDR process and cannot be terminated here.")
    if expected_name and actual_name.casefold() != expected_name.casefold():
        raise ValueError("The process ID now belongs to a different process. Refresh the table and try again.")
    if expected_path:
        if not actual_path or os.path.normcase(os.path.abspath(actual_path)) != os.path.normcase(os.path.abspath(expected_path)):
            raise ValueError("The process executable no longer matches the selected row. Refresh the table and try again.")
    if expected_start_time:
        try:
            if isinstance(expected_start_time, str):
                expected_start_time = datetime.fromisoformat(expected_start_time.replace("Z", "+00:00"))
            if expected_start_time.tzinfo is None:
                expected_start_time = expected_start_time.replace(tzinfo=timezone.utc)
            expected_epoch = expected_start_time.timestamp()
        except (AttributeError, TypeError, ValueError, OverflowError) as exc:
            raise ValueError("The selected row has no valid process start time. Refresh the table and try again.") from exc
        if abs(actual_start_time - expected_epoch) > 2.0:
            raise ValueError("The process ID has been reused since this row was recorded. Refresh the table and try again.")

    targets = []
    if include_children:
        try:
            targets.extend(child for child in root.children(recursive=True) if not _is_protected(child))
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            raise ValueError(f"Cannot safely inspect child processes: {exc}") from exc
    targets.append(root)
    target_ids = [process.pid for process in targets]

    for process in targets:
        if _is_protected(process):
            continue
        try:
            process.terminate()
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied as exc:
            raise PermissionError(f"Windows denied termination of PID {process.pid}.") from exc

    _, alive = psutil.wait_procs(targets, timeout=3.0)
    for process in alive:
        if _is_protected(process):
            continue
        try:
            process.kill()
        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied as exc:
            raise PermissionError(f"Windows denied termination of PID {process.pid}.") from exc
    if alive:
        psutil.wait_procs(alive, timeout=2.0)

    still_running = [p.pid for p in targets if p.is_running()]
    if still_running:
        raise RuntimeError("Windows could not stop process(es): " + ", ".join(map(str, still_running)))
    return target_ids

"""Reversible, explicitly invoked endpoint response actions."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import psutil

from dashboard.process_actions import _PROTECTED_NAMES, _is_protected


def _normalized(path):
    return os.path.normcase(os.path.abspath(os.path.expandvars(str(path))))


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_target(path):
    target = Path(path).resolve(strict=True)
    if not target.is_file():
        raise ValueError("Selected executable is not a file.")
    if target.suffix.casefold() != ".exe":
        raise ValueError("Only Windows .exe files are supported by these response actions.")
    if _normalized(target) == _normalized(sys.executable):
        raise ValueError("HavocEDR's own runtime cannot be quarantined or network-blocked.")
    windows_dir = Path(os.environ.get("WINDIR", r"C:\Windows")).resolve()
    try:
        target.relative_to(windows_dir)
    except ValueError:
        pass
    else:
        raise ValueError("Windows system files cannot be quarantined or network-blocked here.")
    if target.name.casefold() in _PROTECTED_NAMES:
        raise ValueError("A protected Windows executable cannot be quarantined or network-blocked.")
    return target


def quarantine_executable(path, *, quarantine_root=None):
    """Copy, hash-verify, and remove an executable into a user-private quarantine.

    Refuses live process images. The original is removed only after the staged
    quarantine copy has the same SHA-256 digest.
    """
    source = _validate_target(path)
    for process in psutil.process_iter(["exe"]):
        try:
            if process.info.get("exe") and _normalized(process.info["exe"]) == _normalized(source):
                raise RuntimeError("This executable is still running. Terminate it, then retry quarantine.")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if quarantine_root is None:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        quarantine_root = Path(base) / "HavocEDR" / "Quarantine"
    root = Path(quarantine_root)
    root.mkdir(parents=True, exist_ok=True)
    item_id = uuid.uuid4().hex
    quarantined = root / f"{item_id}.quarantined"
    staging = root / f".{item_id}.staging"
    metadata = root / f"{item_id}.json"
    digest = _sha256_file(source)
    try:
        shutil.copy2(source, staging)
        copied_digest = _sha256_file(staging)
        if copied_digest != digest:
            raise IOError("Quarantine copy verification failed; original file was left in place.")
        os.replace(staging, quarantined)
        # Recheck source bytes immediately before deletion to avoid removing a changed file.
        if _sha256_file(source) != digest:
            raise RuntimeError("The source file changed during quarantine; original was left in place.")
        metadata.write_text(json.dumps({
            "id": item_id,
            "original_path": str(source),
            "quarantined_path": str(quarantined),
            "sha256": digest,
        }, indent=2), encoding="utf-8")
        source.unlink()
    except Exception:
        staging.unlink(missing_ok=True)
        if source.exists() and quarantined.exists():
            quarantined.unlink(missing_ok=True)
            metadata.unlink(missing_ok=True)
        raise
    return {"id": item_id, "original_path": str(source), "quarantined_path": str(quarantined), "sha256": digest}


def restore_quarantined(item_id, *, quarantine_root=None):
    """Restore a quarantined file to its original location after hash checks."""
    if not item_id or any(char not in "0123456789abcdef" for char in item_id.casefold()):
        raise ValueError("Invalid quarantine item identifier.")
    if quarantine_root is None:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        quarantine_root = Path(base) / "HavocEDR" / "Quarantine"
    root = Path(quarantine_root).resolve()
    metadata_path = (root / f"{item_id}.json").resolve()
    if metadata_path.parent != root:
        raise ValueError("Invalid quarantine metadata path.")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    source = Path(metadata["quarantined_path"]).resolve(strict=True)
    if source.parent != root or source.name != f"{item_id}.quarantined":
        raise ValueError("Quarantine metadata points outside the quarantine folder.")
    target = Path(metadata["original_path"])
    if target.exists():
        raise FileExistsError(f"Restore target already exists: {target}")
    if _sha256_file(source) != metadata["sha256"]:
        raise ValueError("Quarantined file hash does not match its metadata; restore was refused.")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    if _sha256_file(target) != metadata["sha256"]:
        target.unlink(missing_ok=True)
        raise IOError("Restored copy failed hash verification.")
    source.unlink()
    metadata_path.unlink()
    return str(target)


def list_quarantined_items(*, quarantine_root=None):
    """Return indexed quarantine entries without reading or executing their contents."""
    if quarantine_root is None:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        quarantine_root = Path(base) / "HavocEDR" / "Quarantine"
    root = Path(quarantine_root)
    if not root.exists():
        return []
    items = []
    for metadata_path in root.glob("*.json"):
        try:
            data = json.loads(metadata_path.read_text(encoding="utf-8"))
            if data.get("id") == metadata_path.stem and (root / f"{metadata_path.stem}.quarantined").is_file():
                items.append(data)
        except (OSError, ValueError, TypeError):
            continue
    return sorted(items, key=lambda item: item.get("original_path", "").casefold())


def _firewall_rule_names(path):
    digest = hashlib.sha256(_normalized(path).encode("utf-8")).hexdigest()[:20]
    stem = f"HavocEDR-AppIsolation-{digest}"
    return f"{stem}-Outbound", f"{stem}-Inbound"


def _network_ledger_path():
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / "HavocEDR" / "NetworkIsolation.json"


def _read_network_ledger():
    path = _network_ledger_path()
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or any(not isinstance(item, str) for item in data):
        raise ValueError("Network isolation record is invalid; restore cannot safely update it.")
    return data


def _write_network_ledger(paths):
    ledger = _network_ledger_path()
    ledger.parent.mkdir(parents=True, exist_ok=True)
    temp = ledger.with_suffix(".tmp")
    temp.write_text(json.dumps(sorted(set(paths), key=str.casefold), indent=2), encoding="utf-8")
    os.replace(temp, ledger)


def list_isolated_executables():
    """List executable paths whose HavocEDR firewall rules are recorded locally."""
    return _read_network_ledger()


def isolate_executable_network(path):
    """Block inbound and outbound connections for one executable via Windows Firewall."""
    target = _validate_target(path)
    ledger = _read_network_ledger()
    names = _firewall_rule_names(target)
    created = []
    for name, direction in zip(names, ("out", "in")):
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}",
             f"dir={direction}", "action=block", f"program={target}", "enable=yes", "profile=any"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if result.returncode != 0:
            for previous in created:
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={previous}"],
                               capture_output=True, text=True, timeout=15, check=False)
            message = (result.stderr or result.stdout or "Windows Firewall rejected the rule.").strip()
            raise PermissionError(f"Could not enable process network isolation (administrator rights may be required): {message}")
        created.append(name)
    try:
        normalized = _normalized(target)
        if not any(_normalized(existing) == normalized for existing in ledger):
            ledger.append(str(target))
        _write_network_ledger(ledger)
    except Exception:
        for name in names:
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
                           capture_output=True, text=True, timeout=15, check=False)
        raise
    return names


def restore_executable_network(path):
    """Remove HavocEDR's inbound/outbound rules for one executable."""
    target = Path(os.path.abspath(os.path.expandvars(str(path))))
    errors = []
    for name in _firewall_rule_names(target):
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if result.returncode != 0:
            errors.append((result.stderr or result.stdout or "Windows Firewall rejected the rule.").strip())
    if errors:
        raise PermissionError("Could not remove all isolation rules (administrator rights may be required): " + "; ".join(errors))
    try:
        normalized = _normalized(target)
        _write_network_ledger([item for item in _read_network_ledger() if _normalized(item) != normalized])
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Firewall rules were removed, but the local restore list could not be updated: {exc}") from exc
    return True

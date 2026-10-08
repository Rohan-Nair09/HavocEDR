from PySide6.QtWidgets import QHBoxLayout, QPushButton, QMessageBox, QInputDialog
from .base_table_page import BaseTablePage
from dashboard.models.processes_model import ProcessesModel
from dashboard.process_actions import terminate_process
from dashboard.response_actions import (
    quarantine_executable, isolate_executable_network, restore_executable_network,
    list_quarantined_items, restore_quarantined, list_isolated_executables,
)
from config.settings import SettingsManager
import qtawesome as qta

class ProcessesPage(BaseTablePage):
    def __init__(self, bridge=None, parent=None):
        super().__init__("Processes", "Monitor and manage running processes.", bridge, parent)
        
        # Create and set the model
        self.process_model = ProcessesModel()
        self.set_model(self.process_model)

        # Wire the event bridge for real-time updates
        if self.bridge:
            self.bridge.process_updated.connect(self._on_process_update)

        # Add specific Process actions to the toolbar layout
        action_layout = QHBoxLayout()
        action_layout.setSpacing(8)
        
        btn_terminate = QPushButton(qta.icon('fa5s.ban', color='#FF4D4D'), " Terminate Process")
        btn_terminate.setObjectName("terminate_process_button")
        btn_terminate.setStyleSheet("background-color: transparent; border: 1px solid #FF4D4D; color: #FF4D4D; padding: 6px 12px; border-radius: 4px;")
        btn_terminate.clicked.connect(lambda: self._respond_to_selected_process(tree=False))
        
        btn_kill_tree = QPushButton(qta.icon('fa5s.skull-crossbones', color='#FF4D4D'), " Kill Process Tree")
        btn_kill_tree.setObjectName("kill_process_tree_button")
        btn_kill_tree.setStyleSheet("background-color: transparent; border: 1px solid #FF4D4D; color: #FF4D4D; padding: 6px 12px; border-radius: 4px;")
        btn_kill_tree.clicked.connect(lambda: self._respond_to_selected_process(tree=True))
        
        btn_quarantine = QPushButton(qta.icon('fa5s.shield-virus', color='#FF9800'), " Quarantine")
        btn_quarantine.setObjectName("quarantine_process_button")
        btn_quarantine.clicked.connect(self._quarantine_selected_process)
        btn_quarantine.setStyleSheet("background-color: transparent; border: 1px solid #FF9800; color: #FF9800; padding: 6px 12px; border-radius: 4px;")

        btn_isolate = QPushButton(qta.icon('fa5s.wifi', color='#FF9800'), " Block App Network")
        btn_isolate.setObjectName("isolate_process_network_button")
        btn_isolate.clicked.connect(lambda: self._network_isolation_selected_process(restore=False))
        btn_isolate.setToolTip("Add reversible Windows Firewall block rules for this executable only.")
        btn_isolate.setStyleSheet("background-color: transparent; border: 1px solid #FF9800; color: #FF9800; padding: 6px 12px; border-radius: 4px;")

        btn_restore_network = QPushButton(qta.icon('fa5s.wifi', color='#00B8AA'), " Restore App Network")
        btn_restore_network.setObjectName("restore_process_network_button")
        btn_restore_network.clicked.connect(self._restore_network_isolation)
        btn_restore_network.setToolTip("Remove this executable's HavocEDR firewall block rules.")

        btn_restore_quarantine = QPushButton(qta.icon('fa5s.undo', color='#00B8AA'), " Restore Quarantined File")
        btn_restore_quarantine.setObjectName("restore_quarantined_file_button")
        btn_restore_quarantine.clicked.connect(self._restore_quarantined_file)
        
        action_layout.addStretch()
        action_layout.addWidget(btn_terminate)
        action_layout.addWidget(btn_kill_tree)
        action_layout.addWidget(btn_quarantine)
        action_layout.addWidget(btn_isolate)
        action_layout.addWidget(btn_restore_network)
        action_layout.addWidget(btn_restore_quarantine)
        
        self.layout.insertLayout(2, action_layout)

    def _selected_process(self):
        selection = self.table.selectionModel().selectedRows()
        if not selection:
            QMessageBox.information(self, "Select a process", "Select a process row first.")
            return None
        source_index = self.proxy_model.mapToSource(selection[0])
        if not source_index.isValid():
            return None
        return self.process_model.get_raw_data()[source_index.row()]

    def _respond_to_selected_process(self, tree=False):
        row = self._selected_process()
        if not row:
            return
        if (SettingsManager.get("response_mode") or "Ask Before Responding") == "Monitor Only":
            QMessageBox.information(self, "Monitor-only mode", "Process response actions are disabled while Response Mode is set to Monitor Only.")
            return
        if (SettingsManager.get("response_terminate_process") or "false").casefold() != "true":
            QMessageBox.information(
                self, "Response action disabled",
                "Enable ‘Allow process termination’ in Settings → Response before using this action.",
            )
            return
        try:
            pid = int(row.get("pid"))
        except (TypeError, ValueError):
            QMessageBox.warning(self, "Invalid process", "The selected row does not contain a valid process ID.")
            return
        name = str(row.get("name") or "Unknown")
        action = "terminate this process and its child processes" if tree else "terminate this process"
        answer = QMessageBox.question(
            self, "Confirm process response",
            f"Do you want to {action}?\n\n{name} (PID {pid})\n\nThis may interrupt applications or unsaved work.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        try:
            stopped = terminate_process(
                pid,
                expected_name=name,
                expected_path=str(row.get("path") or row.get("executable_path") or ""),
                expected_start_time=row.get("start_time"),
                include_children=tree,
            )
        except (ValueError, OSError, PermissionError, RuntimeError) as exc:
            QMessageBox.warning(self, "Process not terminated", str(exc))
            return
        QMessageBox.information(
            self, "Process response complete",
            f"Stopped {len(stopped)} process(es) for {name} (PID {pid}).",
        )

    def _on_process_update(self, payload):
        """Called automatically when EventBus emits a process event via bridge."""
        self.process_model.add_row(payload)

    def _response_path(self, row):
        path = str(row.get("path") or row.get("executable_path") or "").strip()
        if not path:
            QMessageBox.warning(self, "Executable path unavailable", "The selected process has no executable path, so this response cannot be applied safely.")
            return None
        return path

    def _response_allowed(self, setting_key, label):
        if (SettingsManager.get("response_mode") or "Monitor Only") == "Monitor Only":
            QMessageBox.information(self, "Monitor-only mode", "Change Response Mode in Settings → Response before using response actions.")
            return False
        if (SettingsManager.get(setting_key) or "false").casefold() != "true":
            QMessageBox.information(self, "Response action disabled", f"Enable ‘{label}’ in Settings → Response first.")
            return False
        return True

    def _quarantine_selected_process(self):
        row = self._selected_process()
        if not row or not self._response_allowed("response_quarantine_file", "Allow file quarantine"):
            return
        path = self._response_path(row)
        if not path:
            return
        try:
            pid = int(row.get("pid"))
        except (TypeError, ValueError):
            QMessageBox.warning(self, "Invalid process", "The selected row does not contain a valid process ID.")
            return
        name = str(row.get("name") or "Unknown")
        answer = QMessageBox.warning(
            self, "Stop and quarantine executable?",
            f"This will stop {name} (PID {pid}) and move its executable into HavocEDR quarantine.\n\n"
            "The executable will no longer be available at its current path. You can restore it later from the quarantine folder.\n\nContinue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        try:
            terminate_process(
                pid,
                expected_name=name,
                expected_path=path,
                expected_start_time=row.get("start_time"),
            )
            item = quarantine_executable(path)
        except (ValueError, OSError, PermissionError, RuntimeError) as exc:
            QMessageBox.warning(self, "Quarantine incomplete", f"{exc}\n\nCheck whether the process stopped. If it did, the executable may still be at its original location.")
            return
        QMessageBox.information(self, "Quarantined", f"Executable quarantined successfully.\n\nID: {item['id']}\nSHA-256: {item['sha256']}\nSaved at: {item['quarantined_path']}")

    def _network_isolation_selected_process(self, *, restore):
        row = self._selected_process()
        if not row or not self._response_allowed("response_block_network", "Allow per-process network isolation"):
            return
        path = self._response_path(row)
        if not path:
            return
        title = "Restore application network?" if restore else "Block application network?"
        action = "remove HavocEDR's inbound and outbound firewall rules for" if restore else "block inbound and outbound network traffic for"
        answer = QMessageBox.question(
            self, title,
            f"Do you want to {action} this executable?\n\n{path}\n\n"
            "This applies only to this program, not the whole computer. Administrator rights may be required.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        try:
            if restore:
                restore_executable_network(path)
                message = "HavocEDR firewall rules removed."
            else:
                isolate_executable_network(path)
                message = "Inbound and outbound firewall block rules were added for this executable."
        except (ValueError, OSError, PermissionError, RuntimeError) as exc:
            QMessageBox.warning(self, "Network response failed", str(exc))
            return
        QMessageBox.information(self, "Network response complete", message)

    def _restore_quarantined_file(self):
        items = list_quarantined_items()
        if not items:
            QMessageBox.information(self, "Quarantine empty", "There are no indexed files to restore.")
            return
        labels = [f"{item['original_path']}  [{item['id'][:8]}]" for item in items]
        label, accepted = QInputDialog.getItem(self, "Restore quarantined file", "Choose a file to restore:", labels, 0, False)
        if not accepted:
            return
        selected = items[labels.index(label)]
        answer = QMessageBox.question(
            self, "Confirm restore",
            f"Restore this quarantined executable to its original location?\n\n{selected['original_path']}\n\n"
            "The restore is refused if the destination already exists or the file hash has changed.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        try:
            restored = restore_quarantined(selected["id"])
        except (ValueError, OSError, PermissionError, RuntimeError) as exc:
            QMessageBox.warning(self, "Restore failed", str(exc))
            return
        QMessageBox.information(self, "File restored", f"Restored and verified:\n{restored}")

    def _restore_network_isolation(self):
        paths = list_isolated_executables()
        if not paths:
            QMessageBox.information(self, "No isolated applications", "HavocEDR has no recorded application firewall blocks to restore.")
            return
        path, accepted = QInputDialog.getItem(self, "Restore application network", "Choose an isolated application:", paths, 0, False)
        if not accepted:
            return
        answer = QMessageBox.question(
            self, "Restore application network?",
            f"Remove HavocEDR's inbound and outbound firewall rules for this executable?\n\n{path}",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        try:
            restore_executable_network(path)
        except (ValueError, OSError, PermissionError, RuntimeError) as exc:
            QMessageBox.warning(self, "Network restore failed", str(exc))
            return
        QMessageBox.information(self, "Network restored", f"HavocEDR firewall rules removed for:\n{path}")

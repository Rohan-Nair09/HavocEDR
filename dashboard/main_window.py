from PySide6.QtWidgets import QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QStackedWidget

# Local UI components
from dashboard.header import HeaderBar
from dashboard.sidebar import Sidebar
from dashboard.event_bridge import ui_event_bridge
from dashboard.theme import Theme
from config.settings import SettingsManager

class MainWindow(QMainWindow):
    """Root window – Sidebar | HeaderBar | Page Content."""
    def __init__(self, ui_event_bridge=None, data_provider=None):
        super().__init__()
        self.bridge = ui_event_bridge or globals()["ui_event_bridge"]
        self.data_provider = data_provider
        self.setWindowTitle("HavocGuard EDR")
        self.resize(1366, 768)
        Theme.apply_stylesheet(self._application(), SettingsManager.get("theme") or "Dark")
        hints = self._application().styleHints()
        scheme_changed = getattr(hints, "colorSchemeChanged", None)
        if scheme_changed is not None:
            scheme_changed.connect(self._on_system_color_scheme_changed)

        # Central container widget
        container = QWidget()
        self.setCentralWidget(container)

        # ---- Layout -------------------------------------------------
        main_h = QHBoxLayout(container)
        main_h.setContentsMargins(0, 0, 0, 0)
        main_h.setSpacing(0)

        # Sidebar (fixed width)
        self.sidebar = Sidebar()
        main_h.addWidget(self.sidebar)

        # Right side – vertical stack: Header + Page area
        right_v = QVBoxLayout()
        right_v.setContentsMargins(0, 0, 0, 0)
        right_v.setSpacing(0)

        # Header bar (fixed height)
        self.header = HeaderBar()
        right_v.addWidget(self.header)

        # Stacked widget for pages
        self.pages = QStackedWidget()
        right_v.addWidget(self.pages)

        main_h.addLayout(right_v)

        # ---- Populate pages -----------------------------------------
        self._register_pages()

        # ---- Wire navigation -----------------------------------------
        for btn_id, btn in self.sidebar.buttons.items():
            btn.clicked.connect(lambda _, n=btn_id: self._switch_page(n))

        self.header.btn_settings.clicked.connect(lambda: self._switch_page("settings"))
        self.header.btn_theme.clicked.connect(self._toggle_theme)
        self.header.btn_notifications.clicked.connect(lambda: self._switch_page("threats_and_alerts"))
        self.header.btn_min.clicked.connect(self.showMinimized)
        self.header.btn_max.clicked.connect(self._toggle_maximized)
        saved_mode = SettingsManager.get("response_mode")
        if saved_mode:
            index = self.header.response_mode.findText(saved_mode)
            if index >= 0:
                self.header.response_mode.setCurrentIndex(index)
        self.header.response_mode.currentTextChanged.connect(
            lambda value: SettingsManager.set("response_mode", value)
        )

        # Start on the live dashboard.
        self._switch_page("dashboard")
        if "dashboard" in self.sidebar.buttons:
            self.sidebar.buttons["dashboard"].setChecked(True)
        Theme.apply_stylesheet(self._application(), SettingsManager.get("theme") or "Dark")

    @staticmethod
    def _application():
        from PySide6.QtWidgets import QApplication
        return QApplication.instance()

    def _register_pages(self):
        """Register page classes without constructing hidden, expensive pages."""
        self.page_factories = {
            "dashboard": ("dashboard.overview_page", "OverviewPage"),
            "processes": ("dashboard.processes_page", "ProcessesPage"),
            "services": ("dashboard.services_page", "ServicesPage"),
            "network": ("dashboard.network_page", "NetworkPage"),
            "file_integrity": ("dashboard.fim_page", "FIMPage"),
            "registry": ("dashboard.registry_page", "RegistryPage"),
            "usb_devices": ("dashboard.usb_page", "USBPage"),
            "threats_and_alerts": ("dashboard.alerts_page", "AlertsPage"),
            "ai_security_analyst": ("dashboard.pages.ai_analyst_page", "AIAnalystPage"),
            "reports_and_analytics": ("dashboard.analytics_page", "AnalyticsPage"),
            "settings": ("dashboard.pages.settings_page", "SettingsPage"),
            "sysmon": ("dashboard.sysmon_page", "SysmonPage"),
        }
        self.page_instances = {}

    def _switch_page(self, btn_id: str):
        """Show the selected page and pause refresh work on hidden pages."""
        page = self.page_instances.get(btn_id)
        if page is None:
            factory = self.page_factories.get(btn_id)
            if factory is None:
                return
            from importlib import import_module
            module_name, class_name = factory
            page_class = getattr(import_module(module_name), class_name)
            page = page_class(self.bridge)
            self.page_instances[btn_id] = page
            self.pages.addWidget(page)
            Theme.apply_stylesheet(self._application(), SettingsManager.get("theme") or "Dark")
        if page:
            for other_page in self.page_instances.values():
                timer = getattr(other_page, "refresh_timer", None)
                if timer is not None and timer.isActive():
                    timer.stop()
            self.pages.setCurrentWidget(page)
            timer = getattr(page, "refresh_timer", None)
            if timer is not None:
                timer.start()

    def _toggle_maximized(self):
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def _toggle_theme(self):
        saved = (SettingsManager.get("theme") or "Dark").casefold()
        next_mode = {"dark": "Light", "light": "System", "system": "Dark"}.get(saved, "Light")
        if SettingsManager.set("theme", next_mode):
            Theme.apply_stylesheet(self._application(), next_mode)
            current = self.pages.currentWidget()
            refresh = getattr(current, "refresh_charts", None)
            if callable(refresh):
                refresh()

    def _on_system_color_scheme_changed(self, *_):
        if (SettingsManager.get("theme") or "Dark").casefold() == "system":
            Theme.apply_stylesheet(self._application(), "System")

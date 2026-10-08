import re

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont


class Theme:
    ACCENT_COLOR = "#00a99d"
    SEV_CRITICAL = "#d93025"
    SEV_HIGH = "#d97706"
    SEV_MEDIUM = "#b77900"
    SEV_LOW = "#1976d2"
    current_mode = "Dark"

    _DARK = {
        "window": "#0b0f19", "panel": "#111827", "raised": "#1f2937",
        "border": "#374151", "text": "#e0e6ed", "muted": "#9ca3af",
        "accent": "#00E5D4", "selection": "#164e63", "input": "#1f2937",
    }
    _LIGHT = {
        "window": "#f4f6f8", "panel": "#ffffff", "raised": "#e8edf2",
        "border": "#c8d0d8", "text": "#17212b", "muted": "#536273",
        "accent": "#007f78", "selection": "#c7eeeb", "input": "#ffffff",
    }

    @classmethod
    def palette(cls):
        return cls._LIGHT if cls.current_mode == "Light" else cls._DARK

    @staticmethod
    def get_font(size=10, bold=False):
        return QFont("Segoe UI", size, QFont.Bold if bold else QFont.Normal)

    @staticmethod
    def get_severity_color(severity):
        colors = {
            "critical": Theme.SEV_CRITICAL,
            "high": Theme.SEV_HIGH,
            "medium": Theme.SEV_MEDIUM,
            "low": Theme.SEV_LOW,
        }
        return QColor(colors.get(str(severity).casefold(), "#9ca3af"))

    @classmethod
    def resolve_mode(cls, app, mode):
        value = str(mode or "Dark").strip().casefold()
        if value != "system":
            return "Light" if value == "light" else "Dark"
        try:
            scheme = app.styleHints().colorScheme()
            if scheme == Qt.ColorScheme.Light:
                return "Light"
            if scheme == Qt.ColorScheme.Dark:
                return "Dark"
        except (AttributeError, RuntimeError):
            pass
        # Older Windows/Qt combinations may not report a system color scheme.
        return "Light" if app.palette().window().color().lightness() >= 128 else "Dark"

    @classmethod
    def apply_stylesheet(cls, app, mode="Dark"):
        resolved = cls.resolve_mode(app, mode)
        cls.current_mode = resolved
        c = cls._LIGHT if resolved == "Light" else cls._DARK
        app.setProperty("havoc_theme_mode", resolved)
        app.setStyleSheet(f"""
            QMainWindow, QWidget {{ background-color: {c['window']}; color: {c['text']};
                font-family: 'Segoe UI', Inter, sans-serif; }}
            QMainWindow {{ background-color: {c['window']}; }}
            #Sidebar {{ background-color: {c['panel']}; border-right: 1px solid {c['border']}; }}
            #Sidebar QPushButton {{ text-align: left; padding: 10px 15px; border: none;
                border-radius: 8px; font-size: 14px; color: {c['muted']}; }}
            #Sidebar QPushButton:hover {{ background-color: {c['raised']}; color: {c['accent']}; }}
            #Sidebar QPushButton:checked {{ background-color: {c['selection']}; color: {c['accent']};
                font-weight: bold; border-left: 3px solid {c['accent']}; border-radius: 4px; }}
            #HeaderBar {{ background-color: {c['window']}; border-bottom: 1px solid {c['border']}; }}
            #HeaderBar QPushButton {{ border: none; border-radius: 4px; padding: 8px; }}
            #HeaderBar QPushButton:hover {{ background-color: {c['raised']}; }}
            QFrame[class="Card"], .Card {{ background-color: {c['panel']}; color: {c['text']};
                border: 1px solid {c['border']}; border-radius: 12px; }}
            QTableView {{ background-color: {c['panel']}; color: {c['text']};
                border: 1px solid {c['border']}; border-radius: 8px; gridline-color: {c['border']};
                selection-background-color: {c['selection']}; selection-color: {c['text']};
                alternate-background-color: {c['window']}; }}
            QHeaderView::section {{ background-color: {c['raised']}; color: {c['muted']};
                padding: 10px; border: none; font-weight: bold; }}
            QTabWidget::pane {{ border: 1px solid {c['border']}; border-radius: 8px; }}
            QTabBar::tab {{ background-color: transparent; color: {c['muted']}; padding: 10px 18px;
                border-bottom: 2px solid transparent; font-weight: bold; }}
            QTabBar::tab:selected {{ color: {c['accent']}; border-bottom: 2px solid {c['accent']}; }}
            QTabBar::tab:hover {{ color: {c['text']}; }}
            QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QTextEdit, QPlainTextEdit {{
                background-color: {c['input']}; color: {c['text']}; border: 1px solid {c['border']};
                border-radius: 6px; padding: 7px 10px; }}
            QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {{
                border: 1px solid {c['accent']}; }}
            QPushButton {{ color: {c['text']}; background-color: {c['raised']};
                border: 1px solid {c['border']}; border-radius: 6px; padding: 7px 12px; }}
            QPushButton:hover {{ border-color: {c['accent']}; }}
            QPushButton.PrimaryAction {{ background-color: {c['accent']}; color: {'#ffffff' if resolved == 'Light' else '#000000'};
                font-weight: bold; border: none; border-radius: 6px; padding: 8px 16px; }}
            QScrollBar:vertical {{ border: none; background: transparent; width: 8px; }}
            QScrollBar::handle:vertical {{ background: {c['border']}; min-height: 20px; border-radius: 4px; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
        """)
        cls._recolor_inline_styles(app, resolved)

    @classmethod
    def _recolor_inline_styles(cls, app, mode):
        """Update page-level styles so inline dark colors follow the theme."""
        light_text = {"#ffffff": "#17212b", "#fff": "#17212b", "#e0e6ed": "#17212b",
                      "#9ca3af": "#536273", "#00e5d4": "#007f78", "#000000": "#ffffff"}
        dark_text = {"#17212b": "#e0e6ed", "#536273": "#9ca3af", "#007f78": "#00e5d4",
                     "#ffffff": "#e0e6ed", "#fff": "#e0e6ed"}
        light_surface = {"#0b0f19": "#f4f6f8", "#111827": "#ffffff", "#1f2937": "#e8edf2",
                         "#374151": "#c8d0d8"}
        dark_surface = {"#f4f6f8": "#0b0f19", "#ffffff": "#111827", "#fff": "#111827",
                        "#e8edf2": "#1f2937", "#c8d0d8": "#374151"}
        pattern = re.compile(
            r"(?P<prefix>(?:^|[;{])\s*(?P<prop>color|selection-color|background-color|background|border-color|gridline-color)\s*:\s*)(?P<value>#[0-9a-fA-F]{3,8})",
            re.IGNORECASE,
        )
        for widget in app.allWidgets():
            inline = widget.styleSheet()
            if not inline:
                continue

            def replace(match):
                value = match.group("value").casefold()
                prop = match.group("prop").casefold()
                if prop in {"color", "selection-color"}:
                    palette = light_text if mode == "Light" else dark_text
                else:
                    palette = light_surface if mode == "Light" else dark_surface
                return match.group("prefix") + palette.get(value, match.group("value"))

            updated = pattern.sub(replace, inline)
            if updated != inline:
                widget.setStyleSheet(updated)

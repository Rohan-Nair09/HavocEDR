import unittest
from unittest.mock import patch

from monitoring.sysmon_collector import SysmonCollector


class SysmonDegradationTests(unittest.TestCase):
    def test_access_denied_disables_subscription_without_raising(self):
        collector = SysmonCollector()
        with patch("monitoring.sysmon_collector.win32evtlog.EvtOpenChannelConfig", return_value=object()), patch(
            "monitoring.sysmon_collector.win32evtlog.EvtSubscribe",
            side_effect=PermissionError("Access is denied"),
        ):
            collector.on_start()

        self.assertFalse(collector._is_enabled)
        self.assertIsNone(collector._subscription)

    def test_missing_channel_disables_collector(self):
        collector = SysmonCollector()
        with patch(
            "monitoring.sysmon_collector.win32evtlog.EvtOpenChannelConfig",
            side_effect=OSError("channel unavailable"),
        ), patch("monitoring.sysmon_collector.win32evtlog.EvtSubscribe") as subscribe:
            collector.on_start()

        self.assertFalse(collector._is_enabled)
        subscribe.assert_not_called()


if __name__ == "__main__":
    unittest.main()

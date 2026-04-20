import unittest
from io import StringIO

from unifi_dns4me.notify import NotificationConfig, Notifier


class NotificationTest(unittest.TestCase):
    def test_empty_urls_disable_notifications(self) -> None:
        notifier = Notifier(NotificationConfig(), stream=StringIO())

        self.assertFalse(notifier.enabled)
        self.assertFalse(notifier.send("title", "body"))

    def test_event_filter_blocks_disabled_event(self) -> None:
        notifier = RecordingNotifier(NotificationConfig(urls=("mock://example",), on_switch=False))

        self.assertFalse(notifier.send("switch", "body", event="switch"))
        self.assertEqual(notifier.messages, [])

    def test_sync_changes_event_can_be_disabled(self) -> None:
        notifier = RecordingNotifier(NotificationConfig(urls=("mock://example",), on_sync_changes=False))

        self.assertFalse(notifier.send("sync", "body", event="sync_changes"))
        self.assertEqual(notifier.messages, [])

    def test_allowed_message_is_sent(self) -> None:
        notifier = RecordingNotifier(NotificationConfig(urls=("mock://example",)))

        self.assertTrue(notifier.send("switch", "body", level="warning", event="switch"))
        self.assertEqual(notifier.messages, [("switch", "body", "warning")])

    def test_failed_delivery_logs_event_context(self) -> None:
        stream = StringIO()
        notifier = FailingNotifier(NotificationConfig(urls=("mock://example",)), stream=stream)

        self.assertFalse(notifier.send("failed title", "body", event="switch_failure"))
        self.assertIn("'switch_failure' (failed title)", stream.getvalue())


class RecordingNotifier(Notifier):
    def __init__(self, config: NotificationConfig) -> None:
        super().__init__(config, stream=StringIO())
        self.messages = []

    def _client(self):
        return self

    def _notify_type(self, level: str):
        return level

    def notify(self, *, title, body, notify_type=None):
        self.messages.append((title, body, notify_type))
        return True


class FailingNotifier(Notifier):
    def __init__(self, config: NotificationConfig, *, stream: StringIO) -> None:
        super().__init__(config, stream=stream)

    def _client(self):
        return self

    def _notify_type(self, level: str):
        return level

    def notify(self, *, title, body, notify_type=None):
        return False


if __name__ == "__main__":
    unittest.main()

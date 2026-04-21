from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TextIO


@dataclass(frozen=True)
class NotificationConfig:
    urls: tuple[str, ...] = ()
    on_sync_error: bool = True
    on_sync_changes: bool = True
    on_switch: bool = True
    on_switch_failure: bool = True
    on_check_fail: bool = True
    on_check_recovery: bool = True


class Notifier:
    def __init__(self, config: NotificationConfig, *, stream: TextIO | None = None) -> None:
        self.config = config
        self.stream = stream
        self._apprise = None
        self._missing_logged = False

    @property
    def enabled(self) -> bool:
        return bool(self.config.urls)

    def send(self, title: str, body: str, *, level: str = "warning", event: str | None = None) -> bool:
        if not self.enabled:
            return False
        if event and not self._event_allowed(event):
            return False

        app = self._client()
        if app is None:
            return False

        notify_type = self._notify_type(level)
        try:
            if notify_type is None:
                ok = app.notify(title=title, body=body)
            else:
                ok = app.notify(title=title, body=body, notify_type=notify_type)
        except Exception as exc:  # pragma: no cover - defensive boundary around third-party transports.
            self._log(f"Notification failed for {self._event_label(event, title)}: {exc}")
            return False

        if not ok:
            self._log(
                f"Notification failed for {self._event_label(event, title)}: "
                "Apprise could not deliver to any configured URL."
            )
        return bool(ok)

    def _client(self):
        if self._apprise is not None:
            return self._apprise

        try:
            import apprise
        except ImportError:
            if not self._missing_logged:
                self._log(
                    "Notifications disabled: apprise is not installed. "
                    "Rebuild/reinstall the package to enable NOTIFY_URLS."
                )
                self._missing_logged = True
            return None

        app = apprise.Apprise()
        for url in self.config.urls:
            app.add(url)
        self._apprise = app
        return app

    def _notify_type(self, level: str):
        try:
            import apprise
        except ImportError:
            return None

        mapping = {
            "info": getattr(apprise.NotifyType, "INFO", None),
            "warning": getattr(apprise.NotifyType, "WARNING", None),
            "error": getattr(apprise.NotifyType, "FAILURE", None),
        }
        return mapping.get(level.lower())

    def _event_allowed(self, event: str) -> bool:
        return {
            "sync_error": self.config.on_sync_error,
            "sync_changes": self.config.on_sync_changes,
            "switch": self.config.on_switch,
            "switch_failure": self.config.on_switch_failure,
            "check_fail": self.config.on_check_fail,
            "check_recovery": self.config.on_check_recovery,
        }.get(event, True)

    def _event_label(self, event: str | None, title: str) -> str:
        if event:
            return f"{event!r} ({title})"
        return title

    def _log(self, message: str) -> None:
        if self.stream is None:
            print(f"{datetime.now().isoformat(timespec='seconds')} ERROR {message}", flush=True)
            return
        print(f"{datetime.now().isoformat(timespec='seconds')} ERROR {message}", file=self.stream, flush=True)

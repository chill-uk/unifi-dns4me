from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .dns4me import ForwardRule


STATE_VERSION = 1


@dataclass(frozen=True)
class ManagedState:
    active_server_index: int
    managed_rules: set[ForwardRule]
    dns4me_servers: tuple[str, ...] = ()


def load_state(path: str) -> ManagedState:
    state_path = Path(path)
    if not state_path.exists():
        return ManagedState(active_server_index=1, managed_rules=set())

    with state_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if not isinstance(data, dict):
        return ManagedState(active_server_index=1, managed_rules=set())

    active_server_index = data.get("active_server_index", 1)
    if not isinstance(active_server_index, int) or active_server_index < 1:
        active_server_index = 1

    servers = data.get("dns4me_servers", [])
    if not isinstance(servers, list):
        servers = []

    return ManagedState(
        active_server_index=active_server_index,
        managed_rules=_parse_managed_rules(data),
        dns4me_servers=tuple(server for server in servers if isinstance(server, str)),
    )


def load_managed_rules(path: str) -> set[ForwardRule]:
    return load_state(path).managed_rules


def _parse_managed_rules(data: dict[str, Any]) -> set[ForwardRule]:
    rules = data.get("managed_rules", [])
    if not isinstance(rules, list):
        return set()

    managed: set[ForwardRule] = set()
    for item in rules:
        if not isinstance(item, dict):
            continue
        domain = item.get("domain")
        server = item.get("server")
        if isinstance(domain, str) and isinstance(server, str):
            managed.add(ForwardRule(domain=domain, server=server))
    return managed


def save_state(path: str, state: ManagedState) -> None:
    state_path = Path(path)
    data: dict[str, Any] = {
        "version": STATE_VERSION,
        "active_server_index": state.active_server_index,
    }
    if state.dns4me_servers:
        data["dns4me_servers"] = list(state.dns4me_servers)
    data["managed_rules"] = [asdict(rule) for rule in sorted(state.managed_rules)]

    temp_path = state_path.with_suffix(f"{state_path.suffix}.tmp")
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        with temp_path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
        temp_path.replace(state_path)
    except OSError as exc:
        raise RuntimeError(f"Could not write state file {state_path}: {exc}") from exc


def save_managed_rules(path: str, rules: set[ForwardRule]) -> None:
    save_state(path, ManagedState(active_server_index=1, managed_rules=rules))

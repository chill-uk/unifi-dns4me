from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .dns4me import ForwardRule


STATE_VERSION = 1


def load_managed_rules(path: str) -> set[ForwardRule]:
    state_path = Path(path)
    if not state_path.exists():
        return set()

    with state_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

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


def save_managed_rules(path: str, rules: set[ForwardRule]) -> None:
    state_path = Path(path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {
        "version": STATE_VERSION,
        "managed_rules": [asdict(rule) for rule in sorted(rules)],
    }

    temp_path = state_path.with_suffix(f"{state_path.suffix}.tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
    temp_path.replace(state_path)


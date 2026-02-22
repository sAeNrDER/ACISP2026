from __future__ import annotations

from dataclasses import dataclass


@dataclass
class NodeConfig:
    index: int
    port: int
    share: int


def default_ports() -> list[int]:
    return [5001, 5002, 5003]

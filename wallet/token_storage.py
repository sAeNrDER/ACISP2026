from __future__ import annotations

import json
from pathlib import Path

TOKEN_FILE = Path('.token_store.json')


def save_token(token: dict, path: Path = TOKEN_FILE):
    path.write_text(json.dumps(token))


def load_token(path: Path = TOKEN_FILE) -> dict:
    return json.loads(path.read_text())


def delete_token(path: Path = TOKEN_FILE):
    if path.exists():
        path.unlink()

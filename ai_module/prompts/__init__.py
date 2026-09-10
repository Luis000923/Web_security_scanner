"""
Prompt registry for the security agent.

Prompts live next to this file as ``*.md`` (or ``*.txt``). ``load_prompt("name")``
returns the file body with any ``---`` YAML-ish front matter stripped. Results are
cached; set ``AI_AGENT_PROMPT_DIR`` to override the directory (e.g. to A/B test
tuned prompts without touching the package).
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

_DEFAULT_DIR = Path(__file__).parent


def _prompt_dir() -> Path:
    override = os.environ.get("AI_AGENT_PROMPT_DIR")
    return Path(override) if override else _DEFAULT_DIR


def _strip_front_matter(text: str) -> str:
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            return text[end + 4 :].lstrip("\n")
    return text


@lru_cache(maxsize=64)
def load_prompt(name: str) -> str:
    for ext in (".md", ".txt", ""):
        path = _prompt_dir() / f"{name}{ext}"
        if path.is_file():
            return _strip_front_matter(path.read_text(encoding="utf-8")).strip()
    raise FileNotFoundError(f"prompt {name!r} not found in {_prompt_dir()}")


def available() -> list[str]:
    return sorted(
        p.stem for p in _prompt_dir().iterdir() if p.suffix in (".md", ".txt")
    )

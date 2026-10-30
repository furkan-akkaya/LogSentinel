"""Identify exact normalized matches to bundled synthetic records, not realness."""

from functools import lru_cache
from pathlib import Path

from .parsers import parse


@lru_cache(maxsize=1)
def demo_ids():
    root = Path(__file__).parent / "demo"
    return frozenset(
        event.id
        for name, fmt in [
            ("linux-auth.log", "linux"),
            ("windows-security.json", "json"),
        ]
        for event in parse((root / name).read_text(), fmt).events
    )


def dataset_kind(identifier):
    return (
        "bundled_synthetic_match" if identifier in demo_ids() else "unverified_import"
    )


def dataset_summary(events):
    matched = sum(e["id"] in demo_ids() for e in events)
    return {
        "bundled_synthetic_match": matched,
        "unverified_import": len(events) - matched,
    }

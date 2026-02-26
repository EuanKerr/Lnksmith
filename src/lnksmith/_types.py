"""Shared type aliases for lnksmith modules."""

from datetime import datetime

TargetPath = str | list[str | tuple[str, str] | tuple[str, str, int]]
Timestamp = int | datetime | str | None

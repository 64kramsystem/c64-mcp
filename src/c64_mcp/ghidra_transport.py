"""GhidraMCP-next local socket search locations."""

import os
from pathlib import Path


def socket_dirs() -> list[Path]:
    user = os.getenv("USER") or "unknown"
    paths: list[Path] = []

    def add(path: Path) -> None:
        if path not in paths:
            paths.append(path)

    if value := os.getenv("XDG_RUNTIME_DIR"):
        add(Path(value) / "ghidra-mcp")
    if hasattr(os, "getuid"):
        add(Path("/run/user") / str(os.getuid()) / "ghidra-mcp")
    if value := os.getenv("TMPDIR"):
        add(Path(value) / f"ghidra-mcp-{user}")
    for root in (Path("/var/folders"), Path("/private/var/folders")):
        try:
            for path in root.glob(f"*/*/T/ghidra-mcp-{user}"):
                add(path)
        except OSError:
            pass
    add(Path("/tmp") / f"ghidra-mcp-{user}")
    return paths

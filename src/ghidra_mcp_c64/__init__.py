"""C64-specific MCP tools for Ghidra."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _installed_version

__all__ = ["__version__"]

try:
    # Derived rather than duplicated: a literal here drifts from pyproject.toml
    # the first time one of the two is bumped alone.
    __version__ = _installed_version("ghidra-mcp-c64")
except PackageNotFoundError:  # pragma: no cover - running from a bare checkout
    __version__ = "0.0.0+unknown"

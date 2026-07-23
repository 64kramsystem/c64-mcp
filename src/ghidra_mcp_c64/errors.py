"""Stable package error categories."""


class C64McpError(RuntimeError):
    """Base error for caller-visible C64 MCP failures."""


class ConfigurationError(C64McpError):
    """Invalid process or tool configuration."""


class GhidraError(C64McpError):
    """Failure returned by the public Ghidra HTTP boundary."""


class ProfileError(C64McpError):
    """Invalid bundled or caller-supplied symbol profile."""


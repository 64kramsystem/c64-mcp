"""Stable package error categories."""


class C64McpError(RuntimeError):
    """Base error for caller-visible C64 MCP failures."""


class ConfigurationError(C64McpError):
    """Invalid process or tool configuration."""


class GhidraError(C64McpError):
    """Failure returned by the public Ghidra HTTP boundary."""


class ProfileError(C64McpError):
    """Invalid bundled or caller-supplied symbol profile."""


class CodecDataError(C64McpError):
    """Invalid bundled C64 codec data."""


class RequestError(C64McpError, ValueError):
    """Invalid C64 tool or codec request."""


class TextLimitError(RequestError):
    """A bounded text operation exceeded a hard safety limit."""


class TokenCycleError(RequestError):
    """Recursive token expansion contains a cycle."""

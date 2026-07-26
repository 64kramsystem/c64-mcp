"""Stable package error categories."""

from __future__ import annotations

from collections.abc import Mapping


class C64McpError(RuntimeError):
    """Base error for caller-visible C64 MCP failures."""


class ConfigurationError(C64McpError):
    """Invalid process or tool configuration."""


class GhidraError(C64McpError):
    """Failure returned by the public Ghidra HTTP boundary."""


class GhidraTransportError(GhidraError):
    """Classified failure before a complete Ghidra HTTP response."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        timeout_layer: str | None,
        outcome_unknown: bool,
        request_committed: bool,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.timeout_layer = timeout_layer
        self.outcome_unknown = outcome_unknown
        self.request_committed = request_committed


class ViceError(C64McpError):
    """Structured expected failure returned by a public VICE tool."""

    def __init__(
        self,
        code: str,
        message: str,
        **details: object,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = dict(details)

    def as_result(self) -> dict[str, object]:
        """Return the stable caller-visible error envelope."""

        error: dict[str, object] = {
            "code": self.code,
            "message": str(self),
        }
        error.update(self.details)
        return {"ok": False, "error": error}

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, object],
        *,
        fallback_code: str,
        fallback_message: str,
    ) -> ViceError:
        """Preserve a structured upstream error without trusting its shape."""

        code = value.get("code", fallback_code)
        message = value.get("message", fallback_message)
        if not isinstance(code, str) or not code:
            code = fallback_code
        if not isinstance(message, str) or not message:
            message = fallback_message
        details = {
            name: item
            for name, item in value.items()
            if name not in {"code", "message"}
        }
        return cls(code, message, **details)


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

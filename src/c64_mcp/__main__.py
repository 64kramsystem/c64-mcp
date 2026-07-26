"""Console entry point."""

from __future__ import annotations

import argparse
import os
from collections.abc import Sequence

from .config import TOOL_PROFILE_NAMES, Settings
from .server import create_server


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Run the C64-specific Ghidra MCP server"
    )
    parser.add_argument(
        "--tool-profile",
        choices=TOOL_PROFILE_NAMES,
        help=(
            "initial tool visibility profile "
            "(overrides GHIDRA_MCP_C64_TOOL_PROFILE)"
        ),
    )
    args = parser.parse_args(argv)
    environ = dict(os.environ)
    if args.tool_profile is not None:
        environ["GHIDRA_MCP_C64_TOOL_PROFILE"] = args.tool_profile
    settings = Settings.from_environ(environ)
    create_server(settings).run(transport=settings.transport)


if __name__ == "__main__":
    main()

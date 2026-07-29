"""Console entry point."""

from __future__ import annotations

import os

from .config import Settings
from .server import create_server


def main() -> None:
    settings = Settings.from_environ(os.environ)
    create_server(settings).run(transport="stdio")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""OSINT INTELLIGENCE — entrypoint.

Usage:
    python run.py [--host 127.0.0.1] [--port 8787]
"""
from __future__ import annotations

import argparse

import app
from app import config
from app.server import serve


def main() -> None:
    parser = argparse.ArgumentParser(description="OSINT INTELLIGENCE server")
    parser.add_argument("--host", default=config.HOST)
    parser.add_argument("--port", type=int, default=config.PORT)
    args = parser.parse_args()

    app.bootstrap()
    serve(args.host, args.port)


if __name__ == "__main__":
    main()

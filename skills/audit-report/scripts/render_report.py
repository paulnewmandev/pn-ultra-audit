#!/usr/bin/env python3
"""Shim: the renderer lives in engine/render_report.py (shared with the CLI). Usage: render_report.py --dir <run-dir> [--lang es|en] [--strict]"""
import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))
from engine.render_report import main  # noqa: E402
if __name__ == "__main__":
    sys.exit(main())

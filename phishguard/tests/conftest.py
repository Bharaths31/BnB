"""Shared pytest configuration.

Ensures the ``phishguard`` package root is importable and disables optional native runtimes
(OCR) so the suite runs on a bare CPU machine.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("PHISHGUARD_DISABLE_OCR", "1")

"""Minimal shim for modern tooling that still discovers ``setup.py``.

Project metadata and the build backend live in ``pyproject.toml``. Modern
builds should use ``python -m build``; direct invocation by legacy tooling is
not supported.
"""

from setuptools import setup


setup()

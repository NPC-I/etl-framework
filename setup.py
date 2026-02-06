#!/usr/bin/env python3
"""
Minimal setup.py shim for backward compatibility.
All configuration is in pyproject.toml.
This file exists only for legacy tools that expect setup.py.
For modern packaging, use pyproject.toml directly.
"""

from setuptools import setup

if __name__ == "__main__":
    setup()

#!/usr/bin/env python3

"""
NoDPI entry point.

Kept as a thin launcher so that ``python3 src/main.py``, ``nodpi.spec``
and the Dockerfile keep working. The code lives in the ``nodpi`` package.
"""

from nodpi.app import main

if __name__ == "__main__":
    main()

"""Bastion: Autonomous Zero-Trust Identity Graph and Threat Detection Kernel in ANSI SQL.

Copyright 2026 Aneesh Krishna Parthasarathy.
Licensed under the Apache License, Version 2.0.
"""

__version__ = "1.0.0"
__author__ = "Aneesh Krishna Parthasarathy"

from bastion.engine import DatabaseEngine, create_engine

__all__ = ["DatabaseEngine", "create_engine", "__version__", "__author__"]

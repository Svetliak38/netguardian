#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NetGuardian entry point.

Kept at the project root so the historical ``python guardian.py`` invocation
and the PyInstaller bootstrap keep working.  All logic lives in the
``netguardian`` package.
"""

from __future__ import annotations

import sys

from netguardian.cli import main

if __name__ == "__main__":
    sys.exit(main())

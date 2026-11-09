#!/usr/bin/env python3
"""Download pinned v2fly geo datasets into the gitignored data directory."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scalvs_metatron.geo_fetch import main

if __name__ == "__main__":
    raise SystemExit(
        main(
            default_lock=ROOT / "data" / "geo.lock.json",
            default_dest=ROOT / "data" / "geo",
        )
    )

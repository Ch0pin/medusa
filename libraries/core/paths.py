"""Repository resources anchored independently of the current working directory."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LIBRARIES = ROOT / 'libraries'
JAVASCRIPT = LIBRARIES / 'js'
MODULES = ROOT / 'modules'

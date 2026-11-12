"""Compatibility alias for libraries.cli.prompts."""
import sys
from libraries.cli import prompts as _implementation

sys.modules[__name__] = _implementation

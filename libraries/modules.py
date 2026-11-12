"""Compatibility alias for libraries.core.modules."""
import sys
from libraries.core import modules as _implementation

sys.modules[__name__] = _implementation

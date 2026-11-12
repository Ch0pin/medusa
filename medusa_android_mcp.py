"""Compatibility alias for libraries.integrations.mcp_android."""
import sys
from libraries.integrations import mcp_android as _implementation

if __name__ == '__main__':
    _implementation.main()
else:
    sys.modules[__name__] = _implementation

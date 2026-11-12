#!/usr/bin/env python3
"""Unified Medusa entry point; legacy imports retain the Android parser API."""
import sys

if __name__ == '__main__':
    from libraries.cli.app import main
    raise SystemExit(main())
else:
    # Preserve integrations that assign module globals such as agent_script.
    from libraries.platforms import android as _backend
    sys.modules[__name__] = _backend

"""Load explicitly built runtime bridges without rewriting frida-tools internals."""
from libraries.core.paths import JAVASCRIPT

GENERATED = JAVASCRIPT / 'generated'


def load_runtime_bridge(runtime):
    if runtime not in {'java', 'objc'}:
        raise ValueError(f'Unsupported runtime bridge: {runtime}')
    path = GENERATED / f'{runtime}.js'
    if not path.is_file():
        raise RuntimeError('Runtime bridges are missing. Run npm ci && npm run build:bridges in the Medusa directory.')
    return path.read_text(encoding='utf-8')

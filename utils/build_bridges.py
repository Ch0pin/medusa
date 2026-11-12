"""Build standalone IIFE runtime bridges with the selected Python environment."""
from pathlib import Path
import json
import sys

import frida

ROOT = Path(__file__).resolve().parents[1]


def main():
    destination = ROOT / 'libraries' / 'js' / 'generated'
    destination.mkdir(parents=True, exist_ok=True)
    compiler = frida.Compiler()
    compiler.on('diagnostics', report_diagnostics)
    for runtime in ('java', 'objc'):
        bundle = compiler.build(
            str(ROOT / 'libraries' / 'bridges' / f'{runtime}.ts'),
            project_root=str(ROOT), source_maps='omitted', compression='terser', bundle_format='iife',
        )
        (destination / f'{runtime}.js').write_text(bundle, encoding='utf-8', newline='\n')


def report_diagnostics(diagnostics):
    if diagnostics:
        print(json.dumps(diagnostics, ensure_ascii=False), file=sys.stderr)


if __name__ == '__main__':
    main()

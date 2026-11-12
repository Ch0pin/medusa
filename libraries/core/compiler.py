"""Agent assembly independent of prompts, device connections and output files."""
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from libraries.core.contracts import ModuleCatalog


@dataclass(frozen=True)
class AgentLayout:
    headers: tuple[str, ...]
    preamble: str
    epilog: str
    jni_prolog: str | None = None


def assemble_agent(
    catalog: ModuleCatalog,
    layout: AgentLayout,
    js_directory: Path,
    options: str,
    runtime_bridge: str | None = None,
    extra_headers: Sequence[str] = (),
) -> str:
    hooks = []
    if runtime_bridge is not None:
        hooks.append(runtime_bridge)
    for filename in (*extra_headers, *layout.headers):
        path = js_directory / filename
        if path.is_file():
            hooks.append(path.read_text())
    delay = ''
    parts = options.split()
    if len(parts) == 2 and '-t' in parts[0]:
        delay = parts[1]
        hooks.append('\n\nsetTimeout(function() {\n')
    hooks.append(layout.preamble)
    if layout.jni_prolog is not None and any('JNICalls' in mod.path for mod in catalog.staged):
        hooks.append(layout.jni_prolog)
    hooks.append(catalog.compile())
    if delay:
        hooks.append(layout.epilog[:-1])
        hooks.append('}}, {});'.format(delay))
    else:
        hooks.append(layout.epilog)
    return ''.join('%s\n' % part for part in hooks)

"""Small lifecycle operations shared by the CLI and MCP adapters.

Platform-specific process resolution, spawn fallback, timeout workers and recording
remain with their adapters. This module does not own those policies.
"""
from pathlib import Path
from typing import Any, Callable

from libraries.core.contracts import ScriptHandle, SessionHandle
from libraries.core.state import SessionState


def create_and_load_script(
    session: SessionHandle,
    source: str,
    on_message: Callable[..., Any],
    on_detached: Callable[..., Any],
    *,
    session_first: bool = False,
    on_created: Callable[[ScriptHandle], None] | None = None,
) -> ScriptHandle:
    script = session.create_script(source)
    if on_created is not None:
        on_created(script)
    return load_created_script(session, script, on_message, on_detached, session_first=session_first)


def load_created_script(
    session: SessionHandle,
    script: ScriptHandle,
    on_message: Callable[..., Any],
    on_detached: Callable[..., Any],
    *,
    session_first: bool = False,
) -> ScriptHandle:
    if session_first:
        session.on('detached', on_detached)
        script.on('message', on_message)
    else:
        script.on('message', on_message)
        session.on('detached', on_detached)
    script.load()
    return script


def reload_script(
    session: SessionHandle,
    state: SessionState,
    agent_path: Path,
    on_message: Callable[..., Any],
    on_detached: Callable[..., Any],
) -> None:
    # Retain the established ordering, including the state visible on failures:
    # unload -> read -> create/assign -> detached callback -> message callback -> load.
    if state.script is None:
        raise AttributeError("'NoneType' object has no attribute 'unload'")
    state.script.unload()
    with agent_path.open() as source:
        create_and_load_script(
            session, source.read(), on_message, on_detached, session_first=True,
            on_created=lambda script: setattr(state, 'script', script),
        )

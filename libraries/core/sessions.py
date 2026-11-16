"""Small lifecycle operations shared by the CLI and MCP adapters.

Platform-specific process resolution, spawn fallback, timeout workers and recording
remain with their adapters. This module does not own those policies.
"""
from pathlib import Path
from typing import Any, Callable
from contextlib import contextmanager
from uuid import uuid4

from libraries.core.contracts import ScriptHandle, SessionHandle
from libraries.core.state import SessionState

MANAGED_MARKER = '// medusa-managed-lifecycle:v1'
CONTROL_MESSAGE = 'medusa:lifecycle'


class ScriptLifecycleError(RuntimeError):
    """An operation stopped at a known stage; the original error is its cause."""

    def __init__(self, stage: str, message: str):
        self.stage = stage
        super().__init__(f'Script {stage} failed: {message}')


@contextmanager
def _operation(state: SessionState):
    if not state.operation_lock.acquire(blocking=False):
        raise ScriptLifecycleError('busy', 'another script operation is still running')
    try:
        yield
    finally:
        state.operation_lock.release()


def _bind_session(session: SessionHandle, state: SessionState, on_detached: Callable[..., Any]) -> None:
    if state.session is session:
        return
    with state.event_lock:
        state.session = session
        state.session_generation += 1
        generation = state.session_generation
        state.detached = False

    def detached(reason, *details):
        with state.event_lock:
            if state.session is not session or state.session_generation != generation:
                return
            state.detached = True
            state.script_loaded = False
            state.lifecycle_status = 'detached'
            state.cleanup_event.set()
            on_detached(reason)

    try:
        session.on('detached', detached)
    except Exception as exc:
        state.session = None
        raise ScriptLifecycleError('subscribe', str(exc)) from exc


def _load(session, state, script, source, on_message):
    with state.event_lock:
        state.script_generation += 1
        generation = state.script_generation
        session_generation = state.session_generation
        state.script = script
        state.script_loaded = False
        state.managed_cleanup = MANAGED_MARKER in source
        state.cleanup_request = None
        state.cleanup_result = None
        state.cleanup_event.clear()
        state.lifecycle_status = 'loading'

    def message_received(message, data):
        with state.event_lock:
            if (state.script is not script or state.script_generation != generation or state.detached
                    or state.session is not session or state.session_generation != session_generation):
                return
            payload = message.get('payload')
            if message.get('type') == 'send' and isinstance(payload, dict) and payload.get('type') == CONTROL_MESSAGE:
                if payload.get('request') == state.cleanup_request:
                    state.cleanup_result = payload
                    state.cleanup_event.set()
                return
            on_message(message, data)

    try:
        script.on('message', message_received)
        script.load()
        with state.event_lock:
            if state.detached:
                raise RuntimeError('session detached during load')
            state.script_loaded = True
            state.lifecycle_status = 'loaded'
    except Exception as exc:
        # Keep the handle: load may have executed code before failing. The next
        # cleanup/exit must account for that script rather than losing ownership.
        state.script_loaded = None
        state.lifecycle_status = 'load_failed'
        raise ScriptLifecycleError('load', str(exc)) from exc


def start_script(session, state, source, on_message, on_detached):
    """Load a CLI script and bind events to this session and script generation."""
    with _operation(state):
        if state.compile_error:
            raise ScriptLifecycleError('compile', state.compile_error)
        if state.script is not None and not state.script.is_destroyed:
            raise ScriptLifecycleError('start', 'previous script still exists; finish its cleanup first')
        _bind_session(session, state, on_detached)
        try:
            script = session.create_script(source)
        except Exception as exc:
            raise ScriptLifecycleError('create', str(exc)) from exc
        _load(session, state, script, source, on_message)


def _cleanup(state: SessionState, timeout: float) -> None:
    script = state.script
    if script is None:
        return
    if not state.managed_cleanup:
        state.cleanup_result = {'ok': True, 'status': 'unmanaged', 'remaining': None}
        return
    # A timed-out request is retained. Retrying waits for its original response;
    # it never starts a competing cleanup against the same script.
    if state.cleanup_request is None:
        state.cleanup_request = uuid4().hex
        state.cleanup_result = None
        state.cleanup_event.clear()
        state.lifecycle_status = 'cleaning'
        try:
            script.post({'type': CONTROL_MESSAGE, 'request': state.cleanup_request})
        except Exception as exc:
            state.lifecycle_status = 'cleanup_unknown'
            raise ScriptLifecycleError('cleanup', str(exc)) from exc
    if not state.cleanup_event.wait(timeout):
        state.lifecycle_status = 'cleanup_pending'
        raise ScriptLifecycleError('cleanup', 'confirmation timed out; script retained, retry after it completes')
    result = state.cleanup_result
    if state.detached or result is None:
        raise ScriptLifecycleError('cleanup', 'session detached before cleanup was confirmed')
    if result.get('ok') is not True:
        state.cleanup_request = None  # Completed failure: explicitly retry failed actions.
        state.lifecycle_status = 'cleanup_failed'
        raise ScriptLifecycleError('cleanup', str(result.get('errors', 'invalid cleanup response')))


def _stop(state: SessionState, timeout: float) -> None:
    script = state.script
    if script is None:
        return
    _cleanup(state, timeout)
    try:
        script.unload()
    except Exception as exc:
        state.script_loaded = None
        state.lifecycle_status = 'unload_failed'
        raise ScriptLifecycleError('unload', str(exc)) from exc
    with state.event_lock:
        state.script = None
        state.script_loaded = False
        state.lifecycle_status = 'unloaded'


def stop_script(state: SessionState, *, cleanup_timeout: float = 5.0) -> None:
    """Clean up managed resources while their JS runtime is still available."""
    with _operation(state):
        _stop(state, cleanup_timeout)


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
    *,
    cleanup_timeout: float = 5.0,
) -> None:
    with _operation(state):
        if state.compile_error:
            raise ScriptLifecycleError('compile', state.compile_error)
        if state.session is not session or state.detached:
            raise ScriptLifecycleError('reload', 'the selected session is detached or has changed')
        # Read and syntax-check without executing the replacement. Preparation
        # failures leave the working script and its resources untouched.
        try:
            source = agent_path.read_text()
            replacement = session.create_script(source)
        except Exception as exc:
            raise ScriptLifecycleError('prepare', str(exc)) from exc
        try:
            _stop(state, cleanup_timeout)
        except Exception as exc:
            # This script has never been loaded, so it owns no app resources.
            try:
                replacement.unload()
            except Exception as discard_error:
                exc.add_note(f'Unused replacement disposal also failed: {discard_error}')
            raise
        _load(session, state, replacement, source, on_message)

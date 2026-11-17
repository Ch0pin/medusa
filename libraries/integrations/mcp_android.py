#!/usr/bin/env python3
"""
Thin MCP adapter for Medusa Android.

This keeps Medusa's interactive CLI untouched and reuses its existing
device/module/session logic through a small stateful wrapper.

Recommended dependency:
    pip install "mcp[cli]"

Recommended transport:
    streamable-http

Medusa prints heavily during normal operation, so HTTP transport is a safer
default than stdio for MCP clients.
"""

from __future__ import annotations

import atexit
import os
import re
import signal
import subprocess
import sys
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Any

try:
    from mcp.server.mcpserver import MCPServer
except ImportError as exc:
    raise SystemExit(
        'MCP SDK 2 is required. Install it with: pip install "mcp[cli]>=2,<3"'
    ) from exc

import frida
from libraries.core.sessions import (
    CONTROL_MESSAGE, ScriptLifecycleError, start_script, reload_script, stop_script,
)
from libraries.core.state import SessionState

from libraries.platforms import android as medusa_app


from libraries.core.paths import ROOT
PACKAGE_SCOPES = {"", "-a", "-s", "-3"}
LOG_FILE_SUFFIX = ".log"
TOOL_CALL_HISTORY_LIMIT = 200
EVENT_BUFFER_LIMIT = 500
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S%z"


class _DeviceExceptionProbe:
    """Observe Frida errors that the legacy parser logs instead of raising.

    Calls, arguments and the parser's existing fallback behavior are preserved.
    Only the MCP caller consumes the captured exception after a failed attach.
    """

    def __init__(self, device: Any):
        self.device = device
        self.last_error: Exception | None = None
        self.stage: str | None = None

    def __getattr__(self, name: str) -> Any:
        value = getattr(self.device, name)
        if name not in {"attach", "spawn", "kill", "resume"}:
            return value
        def invoke(*args, **kwargs):
            try:
                return value(*args, **kwargs)
            except Exception as exc:
                self.last_error = exc
                self.stage = name
                raise
        return invoke

# Instance A — port 8001
# MEDUSA_MCP_TRANSPORT=streamable-http MEDUSA_MCP_PORT=8001 python medusa_android_mcp.py

mcp = MCPServer(
    name="Medusa Android",
    instructions=(
        "Attach Medusa to Android apps through Frida. "
        "Use list_devices first when multiple devices are connected."
    ),
)

class MedusaAndroidBridge:
    class StdoutMirror:
        def __init__(self, base_stream, event_callback):
            self.base_stream = base_stream
            self.event_callback = event_callback
            self.file_stream = None

        def set_file_stream(self, file_stream):
            self.file_stream = file_stream

        def write(self, data):
            if not data:
                return 0

            self.base_stream.write(data)
            self.base_stream.flush()

            if self.file_stream is not None:
                self.file_stream.write(data)
                self.file_stream.flush()

            self.event_callback(data)
            return len(data)

        def flush(self):
            self.base_stream.flush()
            if self.file_stream is not None:
                self.file_stream.flush()

        def isatty(self):
            return hasattr(self.base_stream, "isatty") and self.base_stream.isatty()

    def __init__(self) -> None:
        self.lock = threading.RLock()
        # Frida can emit console output synchronously while a caller owns self.lock.
        self._console_lock = threading.RLock()
        self.parser = medusa_app.Parser()
        self.parser.interactive = False

        self.agent_script_path = ROOT / f"{uuid.uuid4().hex}_agent_script"
        self.agent_script_path.touch(exist_ok=True)
        medusa_app.agent_script = str(self.agent_script_path)

        self.session = None
        self.script = None
        self._lifecycle = SessionState()
        self.reload_in_progress: dict[str, Any] | None = None
        self.last_reload: dict[str, Any] | None = None
        self.cleanup_blocked = False
        self.last_cleanup: dict[str, Any] | None = None
        self._cleanup_watched_script = None
        self._shutting_down = False
        self.events: list[dict[str, Any]] = []
        self.last_detach_reason: str | None = None
        self.current_target: dict[str, Any] = {}
        self.output_path: str | None = None
        self.recording_file = None
        self.original_stdout = None
        self.stdout_proxy = None
        self.console_buffer = ""
        self.selected_device_id: str | None = None
        self.selected_output_path: str | None = None
        self.selected_modules: list[str] = []
        self.agent_overlay_script = ""
        self.attach_in_progress: dict[str, Any] | None = None
        self.detach_in_progress: dict[str, Any] | None = None
        self.current_tool_call: dict[str, Any] | None = None
        self.tool_call_history: list[dict[str, Any]] = []
        self.tool_call_sequence = 0
        self.last_failure: dict[str, Any] | None = None
        self.failure_context: dict[str, Any] | None = None
        self._failure_exception: Exception | None = None
        self.attach_timeout_seconds = float(os.getenv("MEDUSA_MCP_ATTACH_TIMEOUT", "60"))
        self.detach_timeout_seconds = float(os.getenv("MEDUSA_MCP_DETACH_TIMEOUT", "10"))
        self.status_timeout_seconds = float(os.getenv("MEDUSA_MCP_STATUS_TIMEOUT", "2"))

        self.parser.do_reload("dummy")

    def _record_event(self, message: dict[str, Any], payload: Any = None) -> None:
        event: dict[str, Any] = {
            "timestamp": time.time(),
            "type": message.get("type", "unknown"),
        }

        for key, value in message.items():
            if key != "type":
                event[key] = value

        if payload is not None:
            event["has_binary_payload"] = True

        self.events.append(event)
        if len(self.events) > EVENT_BUFFER_LIMIT:
            self.events = self.events[-EVENT_BUFFER_LIMIT:]

    def _operator_timestamp(self, timestamp: float | None = None) -> str:
        return time.strftime(TIMESTAMP_FORMAT, time.localtime(timestamp or time.time()))

    def _write_operator_log(self, message: str) -> None:
        line = f"[{self._operator_timestamp()}] [medusa-mcp] {message}\n"
        stream = getattr(sys, "__stdout__", None) or self.original_stdout or sys.stdout
        try:
            stream.write(line)
            stream.flush()
        except Exception:
            pass

    def _summarize_tool_value(self, value: Any) -> Any:
        if isinstance(value, str):
            if len(value) > 80:
                return f"<str len={len(value)}>"
            return value
        if isinstance(value, (int, float, bool)) or value is None:
            return value
        if isinstance(value, list):
            return f"<list len={len(value)}>"
        if isinstance(value, dict):
            return f"<dict keys={list(value)[:8]}>"
        return f"<{type(value).__name__}>"

    def _summarize_tool_args(self, args: dict[str, Any]) -> dict[str, Any]:
        summary: dict[str, Any] = {}
        for key, value in args.items():
            if key in {"script", "code"}:
                summary[key] = f"<redacted len={len(value) if isinstance(value, str) else 'unknown'}>"
            else:
                summary[key] = self._summarize_tool_value(value)
        return summary

    def _begin_tool_call(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            self.tool_call_sequence += 1
            started_at = time.time()
            call = {
                "id": self.tool_call_sequence,
                "tool": tool_name,
                "status": "running",
                "started_at": started_at,
                "started_at_iso": self._operator_timestamp(started_at),
                "args": self._summarize_tool_args(args),
            }
            self.current_tool_call = dict(call)
            self.tool_call_history.append(dict(call))
            if len(self.tool_call_history) > TOOL_CALL_HISTORY_LIMIT:
                self.tool_call_history = self.tool_call_history[-TOOL_CALL_HISTORY_LIMIT:]
            self._record_event(
                {
                    "type": "mcp-tool-start",
                    "tool": tool_name,
                    "tool_call_id": call["id"],
                    "description": tool_name,
                    "args": call["args"],
                }
            )
            self._write_operator_log(f"tool start #{call['id']} {tool_name} args={call['args']}")
            return call

    def _finish_tool_call(
        self,
        call: dict[str, Any],
        status: str,
        error: str | None = None,
    ) -> None:
        with self.lock:
            finished_at = time.time()
            duration_seconds = round(finished_at - call["started_at"], 3)
            update = {
                "status": status,
                "finished_at": finished_at,
                "finished_at_iso": self._operator_timestamp(finished_at),
                "duration_seconds": duration_seconds,
            }
            if error:
                update["error"] = error
            if self.current_tool_call and self.current_tool_call.get("id") == call["id"]:
                self.current_tool_call = None
            for entry in reversed(self.tool_call_history):
                if entry.get("id") == call["id"]:
                    entry.update(update)
                    break
            self._record_event(
                {
                    "type": f"mcp-tool-{status}",
                    "tool": call["tool"],
                    "tool_call_id": call["id"],
                    "description": call["tool"],
                    **update,
                }
            )
            self._write_operator_log(
                f"tool {status} #{call['id']} {call['tool']} duration={duration_seconds}s"
                + (f" error={error}" if error else "")
            )

    def run_tool(self, tool_name: str, func: Any, **kwargs: Any) -> Any:
        call = self._begin_tool_call(tool_name, kwargs)
        try:
            result = func(**kwargs)
        except Exception as exc:
            self._set_failure_from_exception(tool_name, exc)
            self._finish_tool_call(call, "failed", error=str(exc))
            raise

        self._finish_tool_call(call, "finished")
        return result

    def _set_failure(
        self,
        category: str,
        message: str,
        action: str | None = None,
    ) -> dict[str, Any]:
        failure = {
            "category": category,
            "message": message,
            "action": action,
            "timestamp": time.time(),
            "timestamp_iso": self._operator_timestamp(),
            "operation_id": self.failure_context.get("id") if self.failure_context else None,
            "operation": self.failure_context.get("operation") if self.failure_context else None,
            "target": {key: self.current_target.get(key) for key in ("device_id", "package_name", "pid")},
            "session_generation": self._lifecycle.session_generation,
            "script_generation": self._lifecycle.script_generation,
        }
        self.last_failure = failure
        self._failure_exception = None
        self._record_event(
            {
                "type": "mcp-failure",
                "category": category,
                "description": message,
                "action": action,
            }
        )
        return failure

    def _begin_failure_context(self, operation: str, operation_id: str | None = None) -> None:
        self.failure_context = {"id": operation_id or uuid.uuid4().hex, "operation": operation, "started_at": time.time()}
        self._failure_exception = None

    @staticmethod
    def _exception_chain(exc: Exception) -> list[BaseException]:
        chain: list[BaseException] = []
        current: BaseException | None = exc
        while current is not None and all(current is not item for item in chain):
            chain.append(current)
            current = current.__cause__ or (current.__context__ if not current.__suppress_context__ else None)
        return chain

    def _failure_is_current(self, target: dict[str, Any]) -> bool:
        failure = self.last_failure
        if not failure:
            return False
        if failure.get("operation_id") != (self.failure_context.get("id") if self.failure_context else None):
            return False
        previous = failure.get("target") or {}
        for key in ("device_id", "package_name", "pid"):
            if previous.get(key) is not None and target.get(key) is not None and str(previous[key]) != str(target[key]):
                return False
        return (failure.get("session_generation") == self._lifecycle.session_generation
                and failure.get("script_generation") == self._lifecycle.script_generation)

    def _exception_classification(self, exc: Exception, stage: str) -> tuple[str, str]:
        root = self._exception_chain(exc)[-1]
        text = str(root).casefold()
        kind = type(root).__name__
        if stage == "output_log":
            return "log_path_failed", "Inspect the reported filesystem/path error before retrying logging."
        if stage == "compile" or isinstance(root, SyntaxError) or (
                "syntaxerror" in text and (stage in {"prepare", "create", "load"} or kind == "InvalidArgumentError")):
            return "script_compile_failed", "Correct the reported script syntax or assembly error and retry compilation."
        if "timed out while waiting for stop from process" in text and (
                stage in {"attach", "spawn", "resolve_process"} or kind in {"TimedOutError", "ProcessNotRespondingError"}):
            return "process_stop_timeout", (
                "Check the target PID and freezer state. If frozen, bring the existing app to the foreground and retry. "
                "Relaunch the app only with explicit caller approval, preserving account and data state."
            )
        if re.search(r"device.*(?:offline|not found|unauthorized)|no devices/emulators found", text):
            return "device_offline", "Reconnect or authorize the selected device and recheck its reachability."
        if kind == "ServerNotRunningError":
            return "frida_offline", "Verify the Frida server is reachable on the selected device."
        if kind in {"TransportError", "ProtocolError"} or any(
                phrase in text for phrase in ("connection is closed", "connection terminated", "connection refused")):
            return "frida_transport_error", "Check the Frida connection and retained cleanup state before reattaching."
        if kind in {"ProcessNotFoundError", "ProcessLookupError"}:
            return "target_process_not_found", "Recheck the original PID and the application's current PIDs before attaching."
        if kind == "PermissionDeniedError":
            return "frida_permission_denied", "Check the Frida attach permissions reported by the device."
        if stage.endswith("_timeout"):
            return "operation_timeout", "Inspect the tracked operation; wait for its completion and cleanup before retrying."
        if kind in {"TimedOutError", "ProcessNotRespondingError"}:
            return "frida_timeout", "Check the target PID, freezer state and Frida transport before retrying."
        if stage == "cleanup" and "timed out" in text:
            return "cleanup_timeout", "Check whether the app is frozen; bring it to the foreground if needed, then retry the retained cleanup."
        if stage in {"attach", "spawn", "resolve_process"}:
            return "attach_failed", "Inspect the underlying exception and current process state before retrying."
        return "script_lifecycle_failed", "Inspect the failed stage; complete cleanup before reattaching."

    def _set_failure_from_exception(self, tool_name: str, exc: Exception) -> dict[str, Any] | None:
        if (self._failure_exception is not None
                and any(item is self._failure_exception for item in self._exception_chain(exc))
                and self._failure_is_current(self.current_target)):
            return self.last_failure
        if isinstance(exc, ScriptLifecycleError):
            return self._lifecycle_failure(exc)
        lowered = str(exc).casefold()
        if "invalid package scope" in lowered or (
                lowered.startswith(("cannot ", "refusing ")) and any(part in lowered for part in (
                    "force_restart=true", "still in progress", "cleanup is still pending"))):
            return None
        stage = "output_log" if tool_name in {
            "set_output_path", "check_output_log", "clear_output_log", "rotate_output_log",
        } else "attach" if tool_name in {"attach_app", "ensure_session", "restart_app"} else "unknown"
        if stage == "unknown" and self._exception_classification(exc, stage)[0] == "script_lifecycle_failed":
            return None
        return self._lifecycle_failure(exc, stage)

    def _capture_console_output(self, data: str) -> None:
        with self._console_lock:
            self.console_buffer += data
            while "\n" in self.console_buffer:
                line, self.console_buffer = self.console_buffer.split("\n", 1)
                line = line.rstrip("\r")
                if line:
                    self._record_event({"type": "console", "payload": line})

    def _install_stdout_proxy(self) -> None:
        if self.stdout_proxy is not None:
            return

        self.original_stdout = sys.stdout
        self.stdout_proxy = self.StdoutMirror(self.original_stdout, self._capture_console_output)
        sys.stdout = self.stdout_proxy

    def _uninstall_stdout_proxy(self) -> None:
        with self._console_lock:
            if self.stdout_proxy is None:
                return

            try:
                if self.console_buffer.strip():
                    self._record_event({"type": "console", "payload": self.console_buffer.rstrip("\r")})
            finally:
                self.console_buffer = ""
                sys.stdout = self.original_stdout
                self.stdout_proxy = None
                self.original_stdout = None

    def _on_message(self, message: dict[str, Any], payload: Any) -> None:
        message = dict(message, session_generation=self._lifecycle.session_generation,
                       script_generation=self._lifecycle.script_generation)
        self.parser.script = self._lifecycle.script
        self._record_event(message, payload)
        try:
            self.parser.my_message_handler(message, payload)
        except Exception as exc:
            self.events.append(
                {
                    "timestamp": time.time(),
                    "type": "bridge-error",
                    "description": str(exc),
                }
            )

    def _on_detached(self, reason: Any) -> None:
        # Called through the shared generation guard on Frida's thread. Never
        # wait for self.lock: a tool may own it while joining the Frida worker.
        generation = self._lifecycle.session_generation
        self.last_detach_reason = str(reason)
        self.cleanup_blocked = self._lifecycle.script is not None
        if self.current_target:
            self.current_target["attached"] = False
            self.current_target["detach_reason"] = self.last_detach_reason
        self._record_event({
            "type": "detached", "description": self.last_detach_reason,
            "session_generation": generation,
            "script_generation": self._lifecycle.script_generation,
        })
        if self.lock.acquire(blocking=False):
            try:
                self._deferred_detach_cleanup(reason, generation)
            finally:
                self.lock.release()
        else:
            threading.Thread(target=self._deferred_detach_cleanup,
                             args=(reason, generation), daemon=True).start()

    def _deferred_detach_cleanup(self, reason: Any, generation: int) -> None:
        with self.lock:
            if (self._lifecycle.session_generation != generation
                    or not self._lifecycle.detached):
                return
            self._stop_recording()
            self._uninstall_stdout_proxy()
            self.parser.on_detached(reason)

    def _runtime_status(self) -> dict[str, Any]:
        state = self._lifecycle
        return {
            "session_generation": state.session_generation,
            "script_generation": state.script_generation,
            "frida_transport_alive": bool(state.session is not None and not state.detached),
            "script_loaded": state.script_loaded,
            "lifecycle_status": state.lifecycle_status,
            "cleanup_blocked": self.cleanup_blocked,
            "cleanup_result": dict(state.cleanup_result) if state.cleanup_result else None,
            "last_cleanup": dict(self.last_cleanup) if self.last_cleanup else None,
        }

    def _watch_cleanup(self) -> None:
        # Keep the old generation's cleanup report after the shared loader resets
        # the new script's state. This listener is diagnostic; the shared handler
        # independently validates request IDs before allowing an unload.
        script = self._lifecycle.script
        if script is None or script is self._cleanup_watched_script:
            return
        generation = (self._lifecycle.session_generation, self._lifecycle.script_generation)
        def observe(message, data):
            payload = message.get("payload")
            if message.get("type") != "send" or not isinstance(payload, dict) or payload.get("type") != CONTROL_MESSAGE:
                return
            previous = self.last_cleanup or {}
            if generation < (previous.get("session_generation", 0), previous.get("script_generation", 0)):
                return
            self.last_cleanup = dict(payload, session_generation=generation[0], script_generation=generation[1])
            self._record_event(dict(self.last_cleanup, type="script-cleanup"))
        try:
            script.on("message", observe)
            self._cleanup_watched_script = script
        except Exception as exc:
            self._record_event({"type": "cleanup-observer-error", "description": str(exc)})

    def _sync_lifecycle(self) -> None:
        self.session = self._lifecycle.session
        self._sync_runtime_script(self._lifecycle.script)
        if self.current_target:
            self.current_target["attached"] = bool(
                self._has_live_session() and self._lifecycle.script_loaded is True
                and not self.cleanup_blocked
            )

    def _lifecycle_failure(self, exc: Exception, stage: str | None = None) -> dict[str, Any]:
        failure_stage = getattr(exc, "stage", stage or "unknown")
        cause = self._exception_chain(exc)[-1]
        category, action = self._exception_classification(exc, failure_stage)
        failure = self._set_failure(category, str(exc), action)
        failure.update(stage=failure_stage, exception_type=type(cause).__name__,
                       exception_message=str(cause),
                       traceback="".join(traceback.format_exception(exc)),
                       **self._runtime_status())
        self._failure_exception = exc
        return failure

    def _release_exited_target(self) -> None:
        # A disconnected script cannot unregister Java listeners. Do not infer
        # process death from a detach reason or a package-name lookup.
        if not self.cleanup_blocked:
            return
        state = self._lifecycle
        target = self.current_target
        pid = target.get("pid")
        try:
            old_pid = int(pid)
        except (TypeError, ValueError):
            old_pid = None
        if state.detached and old_pid and self._target_pid_alive(target) is False:
            state.script = None
            state.session = None
            state.script_loaded = False
            state.lifecycle_status = "previous_process_exited"
            self.cleanup_blocked = False
            self._sync_lifecycle()
            self._record_event({"type": "previous-process-exited", "pid": old_pid})
            return
        raise ScriptLifecycleError(
            "cleanup", "previous script cleanup is unconfirmed; use detach_app to retry cleanup. "
            "Same-process reattachment is blocked while cleanup is uncertain.",
        )

    def _target_pid_alive(self, target: dict[str, Any], timeout: float | None = None) -> bool | None:
        """Confirm PID absence independently of the package's process name."""
        try:
            pid = int(target["pid"])
            if pid <= 0 or not target.get("device_id"):
                return None
            result = subprocess.run(
                ["adb", "-s", str(target["device_id"]), "shell", "ps", "-A", "-o", "PID"],
                capture_output=True, text=True, check=False,
                timeout=self.status_timeout_seconds if timeout is None else timeout,
            )
            rows = result.stdout.split()
            if result.returncode != 0 or result.stderr.strip() or len(rows) < 2 or rows[0] != "PID":
                return None
            if not all(row.isdecimal() for row in rows[1:]):
                return None
            return pid in {int(row) for row in rows[1:]}
        except (KeyError, TypeError, ValueError, OSError, subprocess.TimeoutExpired):
            return None

    def _ensure_no_attach_in_progress(self, action: str) -> None:
        if self._shutting_down:
            raise RuntimeError("Medusa is shutting down")
        if self.reload_in_progress:
            raise RuntimeError(f"Cannot {action}; script reload/cleanup is still in progress.")
        if not self.attach_in_progress:
            if not self.detach_in_progress:
                return

            target = self.detach_in_progress.get("package_name", "unknown target")
            raise RuntimeError(f"Cannot {action}; detach from {target} is still in progress.")

        target = self.attach_in_progress.get("package_name", "unknown target")
        phase = self.attach_in_progress.get("phase", "running")
        if phase in {"timed_out", "cleanup_pending"}:
            raise RuntimeError(
                f"Cannot {action}; attach to {target} timed out and cleanup is still pending."
            )

        raise RuntimeError(f"Cannot {action}; attach to {target} is still in progress.")

    def _dispose_runtime(self) -> None:
        # A cleanup/unload failure must stop here; detaching anyway would lose
        # the only remaining way to unregister in-process callbacks.
        if self._lifecycle.detached:
            if self._lifecycle.script is not None:
                raise ScriptLifecycleError("cleanup", "Frida detached before script cleanup was confirmed")
            self._lifecycle.session = None
            return
        stop_script(self._lifecycle)
        session = self._lifecycle.session
        if session is not None:
            try:
                session.detach()
            except Exception as exc:
                raise ScriptLifecycleError("detach", str(exc)) from exc
        self._lifecycle.session = None
        self._lifecycle.detached = True

    def _cleanup_untracked_attach(
        self, attach_result: dict[str, Any], operation_id: str, package_name: str,
    ) -> None:
        if self._shutting_down:
            return
        error = None
        try:
            self._dispose_runtime()
        except Exception as exc:
            error = exc
        with self.lock:
            if not self.attach_in_progress or self.attach_in_progress.get("id") != operation_id:
                return
            self.cleanup_blocked = error is not None
            self._sync_lifecycle()
            self.attach_in_progress = None
            self._stop_recording()
            self._uninstall_stdout_proxy()
            if error is not None:
                self._lifecycle_failure(error)
            self._record_event({
                "type": "attach-timeout-cleanup", "description": package_name,
                "cleaned": error is None, "error": str(error) if error else None,
                **self._runtime_status(),
            })

    def _select_device_id(self, device_id: str | None) -> str:
        if device_id:
            return device_id
        if self.selected_device_id:
            return self.selected_device_id

        devices = [d for d in frida.enumerate_devices() if getattr(d, "type", None) != "local"]
        if len(devices) == 1:
            return devices[0].id
        if not devices:
            raise RuntimeError("No Android/remote Frida devices found.")
        raise RuntimeError("Multiple devices found. Pass device_id explicitly.")

    def select_device(self, device_id: str) -> dict[str, str]:
        with self.lock:
            self._ensure_no_attach_in_progress("select a device")
            selected = device_id.strip()
            if not selected:
                raise RuntimeError("device_id must be a non-empty string.")

            devices = {device.id: device for device in frida.enumerate_devices()}
            if selected not in devices:
                raise RuntimeError(f"Unknown device_id: {selected}")

            self.selected_device_id = selected
            self._ensure_device(selected)
            return {
                "device_id": selected,
                "name": str(devices[selected].name),
                "type": str(getattr(devices[selected], "type", "unknown")),
            }

    def stage_module(self, module_name: str) -> dict[str, Any]:
        with self.lock:
            self._ensure_no_attach_in_progress("stage modules")
            selected = module_name.strip()
            if not selected:
                raise RuntimeError("module_name must be a non-empty string.")

            before = set(self.selected_modules)
            matches = self.search_modules(selected)
            if not matches:
                raise RuntimeError(f"No Medusa modules matched: {selected}")

            for name in matches:
                if name not in self.selected_modules:
                    self.selected_modules.append(name)

            return {
                "requested": selected,
                "added": [name for name in self.selected_modules if name not in before],
                "selected_modules": self.selected_modules,
            }

    def unstage_module(self, module_name: str) -> dict[str, Any]:
        with self.lock:
            self._ensure_no_attach_in_progress("unstage modules")
            selected = module_name.strip()
            if not selected:
                raise RuntimeError("module_name must be a non-empty string.")

            removed: list[str] = []
            remaining = []
            for name in self.selected_modules:
                if name == selected or name.endswith("/" + selected):
                    removed.append(name)
                else:
                    remaining.append(name)

            if not removed:
                raise RuntimeError(f"Module not found in staged set: {selected}")

            self.selected_modules = remaining
            self.parser.modManager.staged = [
                mod for mod in self.parser.modManager.staged
                if mod.Name not in removed
            ]

            return {
                "removed": removed,
                "selected_modules": self.selected_modules,
            }

    def clear_modules(self) -> dict[str, Any]:
        with self.lock:
            self._ensure_no_attach_in_progress("clear modules")
            self.selected_modules = []
            self._reset_staging()
            return {"selected_modules": self.selected_modules}

    def list_modules(
        self,
        prefix: str | None = None,
        category: str | None = None,
        pattern: str | None = None,
    ) -> dict[str, Any]:
        with self.lock:
            modules = self.parser.modManager.available
            if prefix:
                modules = [mod for mod in modules if mod.Name.startswith(prefix)]
            if category:
                modules = [mod for mod in modules if mod.getCategory() == category]
            if pattern:
                lowered = pattern.casefold()
                modules = [mod for mod in modules if lowered in mod.Name.casefold()]

            return {
                "count": len(modules),
                "categories": sorted(self.parser.modManager.categories),
                "modules": [mod.Name for mod in modules],
            }

    def _resolve_module(self, module_name: str):
        exact = [mod for mod in self.parser.modManager.available if mod.Name == module_name]
        if exact:
            return exact[0]

        prefix_matches = [mod for mod in self.parser.modManager.available if mod.Name.startswith(module_name)]
        if len(prefix_matches) == 1:
            return prefix_matches[0]
        if not prefix_matches:
            raise RuntimeError(f"No Medusa module matched: {module_name}")

        raise RuntimeError(
            f"Module name is ambiguous: {module_name}. "
            f"Matches: {[mod.Name for mod in prefix_matches[:10]]}"
        )

    def get_module_source(self, module_name: str) -> dict[str, Any]:
        with self.lock:
            mod = self._resolve_module(module_name)
            return {
                "name": mod.Name,
                "description": mod.Description,
                "help": mod.Help,
                "path": mod.path,
                "options": mod.Options,
                "code": mod.Code,
            }

    def list_staged_modules(self) -> dict[str, Any]:
        with self.lock:
            active = [mod.Name for mod in self.parser.modManager.staged]
            return {
                "selected_modules": list(self.selected_modules),
                "active_staged_modules": active,
                "hook_script_present": bool(self.agent_overlay_script),
                "hook_script_length": len(self.agent_overlay_script),
            }

    def set_output_path(self, output_path: str) -> dict[str, Any]:
        with self.lock:
            self._ensure_no_attach_in_progress("set the output path")
            selected = output_path.strip()
            if not selected:
                raise RuntimeError("output_path must be a non-empty string.")

            output_target = Path(selected).expanduser()
            if output_target.suffix:
                _validate_log_file_path(output_target)
                output_target.parent.mkdir(parents=True, exist_ok=True)
                normalized = output_target.resolve()
            else:
                normalized = output_target.resolve()
                normalized.mkdir(parents=True, exist_ok=True)

            self.selected_output_path = str(normalized)
            if self.last_failure and self.last_failure.get("category") == "log_path_failed":
                self.last_failure = None
            switched_live_output = False
            live_session_writing_to_resolved_path = False
            current_package = self.current_target.get("package_name")
            if self.recording_file is not None and current_package:
                self._stop_recording()
                self._start_recording(current_package, self.selected_output_path)
                if self.current_target:
                    self.current_target["output_path"] = self.output_path
                switched_live_output = True
                live_path = Path(self.output_path) if self.output_path else None
                if live_path is not None:
                    live_session_writing_to_resolved_path = (
                        live_path == normalized
                        if normalized.suffix
                        else live_path.parent == normalized
                    )
                self._record_event(
                    {
                        "type": "output-path-updated",
                        "description": self.output_path,
                    }
                )

            return {
                "selected_output_path": self.selected_output_path,
                "resolved_output_path": str(normalized),
                "output_path": self.output_path,
                "switched_live_output": switched_live_output,
                "live_session_writing_to_resolved_path": live_session_writing_to_resolved_path,
                "output_log": self._inspect_output_log(),
            }

    def clear_output_path(self) -> dict[str, Any]:
        with self.lock:
            self._ensure_no_attach_in_progress("clear the output path")
            self.selected_output_path = None
            return {"selected_output_path": self.selected_output_path}

    def check_output_log(self, output_path: str | None = None) -> dict[str, Any]:
        with self.lock:
            health = self._inspect_output_log(output_path)
            failure = self._classify_failure(output_health=health)
            return {
                **health,
                "failure_classification": failure,
            }

    def clear_output_log(self, output_path: str | None = None) -> dict[str, Any]:
        with self.lock:
            self._ensure_no_attach_in_progress("clear output log")
            target, source = self._resolve_log_target(output_path)
            if target is None:
                raise RuntimeError("No output log is configured.")
            if target.suffix:
                _validate_log_file_path(target)
            if target.exists() and target.is_dir():
                raise RuntimeError(f"Refusing to clear directory output path: {target}")
            if target.suffix.casefold() != LOG_FILE_SUFFIX:
                raise RuntimeError(f"Refusing to clear non-log output path: {target}")

            before = self._inspect_output_log(str(target))
            target.parent.mkdir(parents=True, exist_ok=True)
            active_log = bool(self.output_path and Path(self.output_path).resolve() == target)
            try:
                if active_log and self.recording_file is not None:
                    self.recording_file.seek(0)
                    self.recording_file.truncate()
                    self.recording_file.flush()
                else:
                    with target.open("w", encoding="utf-8"):
                        pass
            except Exception as exc:
                self._set_failure(
                    "log_path_failed",
                    f"Unable to clear output log {target}: {exc}",
                    "Set a writable .log output path.",
                )
                raise

            after = self._inspect_output_log(str(target))
            if self.last_failure and self.last_failure.get("category") == "log_path_failed":
                self.last_failure = None
            self._record_event(
                {
                    "type": "output-log-cleared",
                    "description": str(target),
                    "output_path": str(target),
                }
            )
            return {
                "cleared": True,
                "output_path": str(target),
                "source": source,
                "active_log": active_log,
                "before": before,
                "after": after,
            }

    def rotate_output_log(self, output_path: str | None = None) -> dict[str, Any]:
        with self.lock:
            self._ensure_no_attach_in_progress("rotate output log")
            target, source = self._resolve_log_target(output_path)
            if target is None:
                raise RuntimeError("No output log is configured.")
            if target.suffix:
                _validate_log_file_path(target)
            if target.exists() and target.is_dir():
                raise RuntimeError(f"Refusing to rotate directory output path: {target}")
            if target.suffix.casefold() != LOG_FILE_SUFFIX:
                raise RuntimeError(f"Refusing to rotate non-log output path: {target}")

            before = self._inspect_output_log(str(target))
            active_log = bool(self.output_path and Path(self.output_path).resolve() == target)
            rotated_path = None
            if active_log:
                self._stop_recording()

            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    rotated_path = self._rotated_log_path(target)
                    target.rename(rotated_path)
                with target.open("a", encoding="utf-8") as handle:
                    handle.flush()
                if active_log:
                    self.recording_file = target.open("a", encoding="utf-8")
                    if self.stdout_proxy is not None:
                        self.stdout_proxy.set_file_stream(self.recording_file)
                    self.output_path = str(target)
            except Exception as exc:
                self._set_failure(
                    "log_path_failed",
                    f"Unable to rotate output log {target}: {exc}",
                    "Set a writable .log output path.",
                )
                if active_log and self.recording_file is None and target.exists():
                    try:
                        self.recording_file = target.open("a", encoding="utf-8")
                        if self.stdout_proxy is not None:
                            self.stdout_proxy.set_file_stream(self.recording_file)
                    except Exception:
                        pass
                raise

            after = self._inspect_output_log(str(target))
            if self.last_failure and self.last_failure.get("category") == "log_path_failed":
                self.last_failure = None
            self._record_event(
                {
                    "type": "output-log-rotated",
                    "description": str(target),
                    "output_path": str(target),
                    "rotated_path": str(rotated_path) if rotated_path else None,
                }
            )
            return {
                "rotated": rotated_path is not None,
                "rotated_path": str(rotated_path) if rotated_path else None,
                "output_path": str(target),
                "source": source,
                "active_log": active_log,
                "before": before,
                "after": after,
            }

    def _ensure_device(self, device_id: str | None) -> dict[str, Any]:
        selected_id = self._select_device_id(device_id)
        if getattr(self.parser.device, "id", None) != selected_id:
            self.parser.device_id = selected_id
            self.parser.do_loaddevice("dummy")

        return {
            "id": self.parser.device.id,
            "name": str(self.parser.device.name),
            "type": str(getattr(self.parser.device, "type", "unknown")),
        }

    def _reset_staging(self) -> None:
        scratchpad = self.parser.modManager.getModule("scratchpad")
        existing_scratchpad = scratchpad.Code
        self.parser.modManager.reset()
        scratchpad.Code = existing_scratchpad
        if existing_scratchpad:
            self.parser.modManager.stage("scratchpad")
        self.parser.modified = False

    def _stage_modules(self, modules: list[str]) -> dict[str, list[str]]:
        added: list[str] = []
        missing: list[str] = []

        for module_name in modules:
            before = {mod.Name for mod in self.parser.modManager.staged}
            self.parser.modManager.stage(module_name)
            after = {mod.Name for mod in self.parser.modManager.staged}
            delta = sorted(after - before)
            if delta:
                added.extend(delta)
            else:
                missing.append(module_name)

        if added:
            self.parser.modified = True

        return {"added": added, "missing": missing}

    def _attach_failure_details(self, package_name: str, device: dict[str, Any], spawn: bool) -> str:
        details = [
            f"device_id={device['id']}",
            f"spawn={spawn}",
            f"package_name={package_name}",
        ]

        try:
            self.parser.refreshPackages("-a")
            details.append(f"installed={package_name in self.parser.packages}")
        except Exception:
            details.append("installed=unknown")

        try:
            pid = self.parser.device_controller.get_int_pid(package_name, True)
            details.append(f"pid={pid if pid is not None else 'none'}")
        except Exception:
            details.append("pid=unknown")

        return ", ".join(details)

    def _start_recording(self, package_name: str, output_path: str | None) -> None:
        self._install_stdout_proxy()
        if not output_path:
            self.output_path = None
            if self.stdout_proxy is not None:
                self.stdout_proxy.set_file_stream(None)
            return

        timestamp = time.strftime("%Y%m%d-%H%M%S")
        safe_package = package_name.replace(os.sep, "_")
        output_target = Path(output_path).expanduser()

        try:
            # All validation, directory creation and file opening belong to the
            # output stage; no inference from an exception mentioning "log".
            if output_target.suffix:
                _validate_log_file_path(output_target)
                output_target.parent.mkdir(parents=True, exist_ok=True)
                output_path = output_target.resolve()
            else:
                output_root = output_target.resolve()
                output_root.mkdir(parents=True, exist_ok=True)
                output_path = output_root / f"{safe_package}-{timestamp}.log"
            self.recording_file = output_path.open("a", encoding="utf-8")
        except Exception as exc:
            error = ScriptLifecycleError("output_log", f"Unable to prepare output path {output_target}: {exc}")
            error.__cause__ = exc
            failure = self._lifecycle_failure(error)
            failure["output_path"] = str(Path(output_path).expanduser().resolve())
            if self.stdout_proxy is not None:
                self.stdout_proxy.set_file_stream(None)
            raise error from exc
        if self.stdout_proxy is not None:
            self.stdout_proxy.set_file_stream(self.recording_file)
        self.output_path = str(output_path)

    def _stop_recording(self) -> None:
        if self.stdout_proxy is not None:
            self.stdout_proxy.set_file_stream(None)

        if self.recording_file is None:
            return

        try:
            self.recording_file.close()
        finally:
            self.recording_file = None

    def _sync_runtime_script(self, script: Any) -> None:
        self.script = script
        self.parser.script = script

    def _has_live_session(self) -> bool:
        return bool(self._lifecycle.session is not None and not self._lifecycle.detached)

    def _is_attached(self) -> bool:
        return bool(self._has_live_session() and self._lifecycle.script_loaded is True
                    and not self.cleanup_blocked and not self.reload_in_progress
                    and not self.attach_in_progress and not self.detach_in_progress)

    def _resolve_tail_target(self) -> tuple[Path | None, str]:
        if self.output_path:
            return Path(self.output_path), "active-session-log"

        if not self.selected_output_path:
            return None, "no-output-configured"

        selected = Path(self.selected_output_path)
        if selected.suffix:
            return selected, "selected-output-path"

        package_name = self.current_target.get("package_name")
        if package_name:
            safe_package = package_name.replace(os.sep, "_")
            matches = sorted(selected.glob(f"{safe_package}-*.log"))
            if matches:
                return matches[-1], "selected-output-dir-latest-session"

        matches = sorted(selected.glob("*.log"))
        if matches:
            return matches[-1], "selected-output-dir-latest-log"

        return selected, "selected-output-dir"

    def _resolve_log_target(self, output_path: str | None = None) -> tuple[Path | None, str]:
        if output_path:
            target = Path(output_path).expanduser()
            if target.suffix:
                _validate_log_file_path(target)
            return target.resolve(), "explicit-output-path"
        return self._resolve_tail_target()

    def _is_path_writable(self, path: Path) -> tuple[bool, str | None]:
        try:
            if path.exists():
                if path.is_dir():
                    return os.access(path, os.W_OK), None
                return path.is_file() and os.access(path, os.W_OK), None

            parent = path.parent if path.suffix else path
            while not parent.exists() and parent != parent.parent:
                parent = parent.parent
            return parent.exists() and os.access(parent, os.W_OK), None
        except Exception as exc:
            return False, str(exc)

    def _extract_line_timestamp(self, line: str) -> tuple[str | None, str | None]:
        stripped = line.strip()
        if not stripped:
            return None, None

        patterns = (
            r"^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{4}|Z)?)\]",
            r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})",
        )
        for pattern in patterns:
            match = re.search(pattern, stripped)
            if match:
                return match.group(1), "line"
        return None, None

    def _inspect_output_log(self, output_path: str | None = None) -> dict[str, Any]:
        target, source = self._resolve_log_target(output_path)
        if target is None:
            return {
                "output_path": None,
                "source": source,
                "exists": False,
                "writable": False,
                "writable_error": None,
                "is_file": False,
                "is_directory": False,
                "size": None,
                "mtime": None,
                "mtime_iso": None,
                "line_count": 0,
                "last_line": None,
                "last_line_timestamp": None,
                "last_line_timestamp_source": None,
                "module_banners": {
                    "appeared": False,
                    "matched_modules": [],
                    "generic_banner_count": 0,
                },
                "frida_events_mirrored": None,
                "frida_event_mirror_status": "no-output-configured",
                "error": None,
            }

        if target.suffix:
            _validate_log_file_path(target)

        writable, writable_error = self._is_path_writable(target)
        health: dict[str, Any] = {
            "output_path": str(target),
            "source": source,
            "exists": target.exists(),
            "writable": writable,
            "writable_error": writable_error,
            "is_file": False,
            "is_directory": False,
            "size": None,
            "mtime": None,
            "mtime_iso": None,
            "line_count": 0,
            "last_line": None,
            "last_line_timestamp": None,
            "last_line_timestamp_source": None,
            "module_banners": {
                "appeared": False,
                "matched_modules": [],
                "generic_banner_count": 0,
            },
            "frida_events_mirrored": None,
            "frida_event_mirror_status": "no-frida-events-seen",
            "error": None,
        }

        if not target.exists():
            return health

        try:
            stat_result = target.stat()
            health.update(
                {
                    "is_file": target.is_file(),
                    "is_directory": target.is_dir(),
                    "size": stat_result.st_size if target.is_file() else None,
                    "mtime": stat_result.st_mtime,
                    "mtime_iso": self._operator_timestamp(stat_result.st_mtime),
                }
            )

            if target.is_dir():
                health["error"] = "output target is a directory, not a concrete log file"
                return health
            if not target.is_file():
                health["error"] = "output target is not a regular file"
                return health

            loaded_modules = list(self.current_target.get("staged_modules") or [])
            module_hits: set[str] = set()
            generic_banner_count = 0
            module_terms = {
                module_name: {
                    module_name.casefold(),
                    module_name.rsplit("/", 1)[-1].casefold(),
                }
                for module_name in loaded_modules
            }
            banner_terms = ("script loaded", "loaded,", "loaded ,", "monitor", "hook added")
            last_line = ""
            line_count = 0
            with target.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    line_count += 1
                    last_line = line.rstrip("\n\r")
                    lowered = line.casefold()
                    if any(term in lowered for term in banner_terms):
                        generic_banner_count += 1
                    for module_name, terms in module_terms.items():
                        if any(term and term in lowered for term in terms):
                            module_hits.add(module_name)

            line_timestamp, timestamp_source = self._extract_line_timestamp(last_line)
            health.update(
                {
                    "line_count": line_count,
                    "last_line": last_line or None,
                    "last_line_timestamp": line_timestamp,
                    "last_line_timestamp_source": timestamp_source,
                    "module_banners": {
                        "appeared": bool(module_hits or generic_banner_count),
                        "matched_modules": sorted(module_hits),
                        "generic_banner_count": generic_banner_count,
                    },
                }
            )

            frida_events = [
                event for event in self.events
                if event.get("type") in {"send", "error", "console"}
            ]
            if not self.recording_file or self.stdout_proxy is None:
                health["frida_events_mirrored"] = False
                health["frida_event_mirror_status"] = "not-recording"
            elif not frida_events:
                health["frida_events_mirrored"] = None
                health["frida_event_mirror_status"] = "no-frida-events-seen"
            else:
                latest_event = max(float(event.get("timestamp", 0)) for event in frida_events)
                mirrored = bool(health["mtime"] and health["mtime"] >= latest_event - 2)
                health["frida_events_mirrored"] = mirrored
                health["frida_event_mirror_status"] = "mirrored" if mirrored else "no-recent-log-write"
                health["latest_frida_event_age_seconds"] = round(time.time() - latest_event, 3)
        except Exception as exc:
            health["error"] = str(exc)

        return health

    @staticmethod
    def _output_condition(health: dict[str, Any]) -> dict[str, Any]:
        if (health.get("output_path") and health.get("is_directory") is True
                and Path(health["output_path"]).suffix):
            return {"category": "log_path_failed", "message": "The configured log-file path is a directory.",
                    "action": "Choose a .log file, or a directory path without a file suffix."}
        if health.get("output_path") and health.get("writable") is False:
            return {"category": "log_path_failed", "message": health.get("writable_error") or
                    f"Output path is not writable: {health['output_path']}",
                    "action": "Fix the reported path permissions or select a writable output path."}
        if health.get("output_path") and health.get("error"):
            return {"category": "log_inspection_failed", "message": health["error"],
                    "action": "Inspect the reported log read/metadata error."}
        return {"category": "none", "message": None, "action": None}

    @staticmethod
    def _process_condition(status: dict[str, Any]) -> dict[str, Any]:
        if status.get("device_reachable") is False:
            return {"category": "device_offline", "message": status.get("process_alive_error"),
                    "action": "Reconnect or authorize the selected device, then retry the read-only status check."}
        if status.get("pid_changed") is True:
            return {"category": "target_pid_changed",
                    "message": f"Target PID {status.get('target_pid')} is absent; current application PIDs: {status.get('process_pids')}.",
                    "action": "Finish previous-session cleanup, then explicitly attach to a current PID with spawn=False."}
        if status.get("process_frozen") is True:
            return {"category": "process_frozen",
                    "message": f"Android reports PID {status.get('process_state_pid')} as frozen.",
                    "action": "Bring the existing app to the foreground and retry the retained operation; preserve its process and account state."}
        if status.get("target_pid_alive") is False and status.get("app_alive") is not False:
            return {"category": "target_process_exited", "message": "The original target PID is no longer present.",
                    "action": "Recheck application PIDs and complete old-session cleanup before an explicit attach."}
        if status.get("app_alive") is False:
            return {"category": "app_not_running", "message": "No application process is currently confirmed running.",
                    "action": "Ask the caller to open the app; attach to its existing process. Relaunch/spawn requires explicit caller approval."}
        return {"category": "none", "message": None, "action": None}

    def _current_failure(self, target: dict[str, Any], output_health: dict[str, Any]) -> dict[str, Any] | None:
        if not self._failure_is_current(target):
            return None
        failure = dict(self.last_failure)
        if failure["category"] == "log_path_failed" and failure.get("stage") != "output_log":
            failed_path = failure.get("output_path")
            inspected_path = output_health.get("output_path")
            if inspected_path and (failed_path is None or str(failed_path) == str(inspected_path)):
                if output_health.get("writable") is True and self._output_condition(output_health)["category"] == "none":
                    return None
        failure["age_seconds"] = round(time.time() - failure["timestamp"], 3)
        return failure

    def _classify_failure(
        self,
        process_status: dict[str, Any] | None = None,
        output_health: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        target = dict(self.current_target)
        if process_status is None:
            process_status = self._process_status(target)
        if output_health is None:
            output_health = self._inspect_output_log()
        process_condition = self._process_condition(process_status)
        output_condition = self._output_condition(output_health)
        failure = self._current_failure(target, output_health)
        # A concrete exception keeps precedence over independent health issues.
        # In particular, mentioning a log filename cannot turn an attach timeout
        # into a log-path diagnosis.
        if failure is not None:
            result = failure
        elif process_condition["category"] != "none" and (
                process_condition["category"] != "process_frozen" or self._has_live_session() or self.cleanup_blocked):
            result = dict(process_condition)
        elif output_condition["category"] != "none":
            result = dict(output_condition)
        elif (self._is_attached() and target.get("staged_modules")
                and not any(event.get("type") in {"send", "error", "console"} for event in self.events)
                and not (output_health.get("module_banners") or {}).get("appeared")):
            result = {"category": "no_module_output_yet",
                      "message": "The session is attached, but no Frida/module output has appeared yet.",
                      "action": "Trigger app behavior covered by the staged modules or verify module selection."}
        else:
            result = {"category": "none", "message": None, "action": None}
        result.update(process_condition=process_condition, output_condition=output_condition)
        return result

    def _rotated_log_path(self, path: Path) -> Path:
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        candidate = path.with_name(f"{path.stem}-{timestamp}{path.suffix}")
        counter = 1
        while candidate.exists():
            candidate = path.with_name(f"{path.stem}-{timestamp}-{counter}{path.suffix}")
            counter += 1
        return candidate

    def _slice_recent_events(self, start_index: int, limit: int = 20) -> list[dict[str, Any]]:
        if start_index < 0:
            start_index = 0
        limit = max(1, min(limit, 100))
        return self.events[start_index:start_index + limit]

    def _reload_active_script(self, timeout: float = 10.0) -> bool:
        self._ensure_no_attach_in_progress("reload the script")
        if not self._has_live_session():
            return False
        operation_id = uuid.uuid4().hex
        self._begin_failure_context("reload", operation_id)
        state = self._lifecycle
        original_script = state.script
        result: dict[str, Any] = {}
        self.reload_in_progress = {
            "id": operation_id, "phase": "reloading", "started_at": time.time(),
            "package_name": self.current_target.get("package_name"),
        }
        self.last_reload = {"id": operation_id, "reloaded": False, "timed_out": False}

        def work():
            try:
                reload_script(state.session, state, self.agent_script_path,
                              self._on_message, self._on_detached)
            except Exception as exc:
                result["exception"] = exc
            finally:
                self._watch_cleanup()

        def finish(late: bool):
            if self._shutting_down:
                return False
            # Late loads are never silently promoted to a successful tool result.
            # Dispose a new script (including partially loaded scripts). A
            # preparation/cleanup failure keeps the previous handle for retry.
            if late and state.script is not None and state.script is not original_script:
                try:
                    stop_script(state)
                except Exception as exc:
                    result["cleanup_exception"] = exc
            with self.lock:
                if not self.reload_in_progress or self.reload_in_progress.get("id") != operation_id:
                    return False
                error = result.get("exception")
                cleanup_error = result.get("cleanup_exception")
                self.cleanup_blocked = bool(cleanup_error or state.lifecycle_status in {
                    "cleanup_pending", "cleanup_unknown", "cleanup_failed", "unload_failed", "load_failed",
                } or (state.detached and state.script is not None))
                self._sync_lifecycle()
                self.reload_in_progress = None
                success = not late and error is None and self._has_live_session() and state.script_loaded is True
                self.last_reload.update(reloaded=success, timed_out=late, **self._runtime_status())
                if error is not None:
                    self.last_reload["error"] = self._lifecycle_failure(error)
                if cleanup_error is not None:
                    self.last_reload["cleanup_error"] = self._lifecycle_failure(cleanup_error)
                if success:
                    self.last_failure = None
                self._record_event({"type": "reload-completed", **self.last_reload})
                return success

        worker = threading.Thread(target=work, daemon=True)
        worker.start()
        worker.join(timeout=timeout)
        if worker.is_alive():
            self.reload_in_progress.update(phase="cleanup_pending", timed_out_at=time.time())
            self.last_reload.update(timed_out=True, error=self._lifecycle_failure(
                TimeoutError(f"Reload timed out after {timeout}s; operation is still tracked"), "reload_timeout"))
            def complete_late():
                worker.join()
                finish(True)
            threading.Thread(target=complete_late, daemon=True).start()
            return False
        return finish(False)

    def _compile_with_agent_overlay(self) -> dict[str, Any]:
        scratchpad = self.parser.modManager.getModule("scratchpad")
        original_code = scratchpad.Code
        original_staged = list(self.parser.modManager.staged)

        try:
            scratchpad.Code = self.agent_overlay_script
            if self.agent_overlay_script:
                if scratchpad not in self.parser.modManager.staged:
                    self.parser.modManager.staged.append(scratchpad)
            else:
                self.parser.modManager.staged = [
                    mod for mod in self.parser.modManager.staged if mod.Name != "scratchpad"
                ]

            try:
                self.parser.do_compile("")
                if self.parser.state.session.compile_error:
                    raise ScriptLifecycleError("compile", self.parser.state.session.compile_error)
            except Exception as exc:
                self._set_failure(
                    "script_compile_failed",
                    str(exc),
                    "Fix or clear the staged hook script/modules.",
                )
                raise
        finally:
            scratchpad.Code = original_code
            self.parser.modManager.staged = original_staged

        return {
            "hook_script_present": bool(self.agent_overlay_script),
            "hook_script_length": len(self.agent_overlay_script),
        }

    def _apply_agent_script(
        self,
        reload_if_attached: bool = True,
        event_start_index: int | None = None,
    ) -> dict[str, Any]:
        self._begin_failure_context("compile_and_reload")
        try:
            compile_result = self._compile_with_agent_overlay()
        except Exception as exc:
            failure = self._lifecycle_failure(exc, "compile")
            return {"compiled": False, "reloaded": False, "attached": self._is_attached(),
                    "reload_skipped_reason": "compile_failed", "compile_error": failure,
                    "new_events": [], "new_event_count": 0, **self._runtime_status()}
        reloaded = False
        reload_skipped_reason = None
        reload_result = None
        if reload_if_attached and self._has_live_session():
            reloaded = self._reload_active_script()
            reload_result = dict(self.last_reload) if self.last_reload else None
            if not reloaded:
                reload_skipped_reason = "reload_pending" if self.reload_in_progress else "reload_failed"
        elif reload_if_attached:
            reload_skipped_reason = "no_live_session"
        return {
            "compiled": True,
            "reloaded": reloaded,
            "attached": self._is_attached(),
            "reload_skipped_reason": reload_skipped_reason,
            "reload_result": reload_result,
            **self._runtime_status(),
            "new_event_count": len(self.events) - event_start_index if event_start_index is not None else None,
            "new_events": self._slice_recent_events(event_start_index) if event_start_index is not None else [],
            **compile_result,
        }

    def get_hook_script(self) -> dict[str, Any]:
        with self.lock:
            return {
                "content": self.agent_overlay_script,
                "length": len(self.agent_overlay_script),
                "has_content": bool(self.agent_overlay_script),
            }

    def set_hook_script(self, script: str, reload_if_attached: bool = True) -> dict[str, Any]:
        with self.lock:
            self._ensure_no_attach_in_progress("set the hook script")
            event_start_index = len(self.events)
            self.agent_overlay_script = script
            result = self._apply_agent_script(
                reload_if_attached=reload_if_attached,
                event_start_index=event_start_index,
            )
            result.update(self.get_hook_script())
            return result

    def append_hook_script(self, script: str, reload_if_attached: bool = True) -> dict[str, Any]:
        with self.lock:
            self._ensure_no_attach_in_progress("append to the hook script")
            event_start_index = len(self.events)
            self.agent_overlay_script += script
            result = self._apply_agent_script(
                reload_if_attached=reload_if_attached,
                event_start_index=event_start_index,
            )
            result.update(self.get_hook_script())
            return result

    def clear_hook_script(self, reload_if_attached: bool = True) -> dict[str, Any]:
        with self.lock:
            self._ensure_no_attach_in_progress("clear the hook script")
            event_start_index = len(self.events)
            self.agent_overlay_script = ""
            result = self._apply_agent_script(
                reload_if_attached=reload_if_attached,
                event_start_index=event_start_index,
            )
            result.update(self.get_hook_script())
            return result

    def list_devices(self) -> list[dict[str, str]]:
        with self.lock:
            return [
                {
                    "id": device.id,
                    "name": str(device.name),
                    "type": str(getattr(device, "type", "unknown")),
                }
                for device in frida.enumerate_devices()
            ]

    def list_packages(self, device_id: str | None = None, scope: str = "-3") -> dict[str, Any]:
        with self.lock:
            self._ensure_no_attach_in_progress("list packages")
            scope = _normalize_package_scope(scope)
            device = self._ensure_device(device_id)
            self.parser.refreshPackages(scope)
            return {
                "device": device,
                "scope": scope,
                "count": len(self.parser.packages),
                "packages": sorted(self.parser.packages),
            }

    def search_modules(self, pattern: str) -> list[str]:
        with self.lock:
            return sorted(self.parser.modManager.findModule(pattern))

    def attach_app(
        self,
        package_name: str,
        device_id: str | None = None,
        spawn: bool = True,
        pid: int | None = None,
        modules: list[str] | None = None,
        reset_staging: bool = True,
        compile_script: bool = True,
        output_path: str | None = None,
        reuse_if_attached: bool = True,
        force_restart: bool = False,
    ) -> dict[str, Any]:
        with self.lock:
            self._ensure_no_attach_in_progress("attach an app")
            self._release_exited_target()
            target = dict(self.current_target)
            attached = self._is_attached()
            effective_device_id = device_id or target.get("device_id") or self.selected_device_id

        if reuse_if_attached and attached:
            status = self.session_status()
            same_package = target.get("package_name") == package_name
            same_device = (
                not effective_device_id
                or target.get("device_id") == effective_device_id
            )
            same_spawn = bool(target.get("spawn")) == bool(spawn)
            if same_package and same_device and same_spawn and status.get("target_pid_alive") is True:
                return {
                    "reused": True,
                    "changed": False,
                    "device": {
                        "id": target.get("device_id"),
                        "name": str(getattr(self.parser.device, "name", "")) or None,
                        "type": str(getattr(self.parser.device, "type", "")) or None,
                    },
                    "target": target,
                    "stage_result": {"added": [], "missing": []},
                    "output_path": status.get("output_path"),
                    "status": status,
                }

            should_detach = bool(self.session or self.script)
        else:
            should_detach = bool(self.session or self.script)

        if should_detach and not force_restart:
            current_package = target.get("package_name", "unknown target")
            raise RuntimeError(
                f"Refusing to replace active session for {current_package}. "
                "Pass force_restart=True to detach it and attach a new session."
            )

        if should_detach:
            detached = self.detach_app()
            if not detached["detached"]:
                raise ScriptLifecycleError("cleanup", "previous session has not finished detaching")

        operation_id = uuid.uuid4().hex
        with self.lock:
            self._ensure_no_attach_in_progress("attach an app")
            self._begin_failure_context("attach", operation_id)
            self.current_target = {
                "package_name": package_name, "device_id": effective_device_id,
                "spawn": spawn, "pid": pid, "attached": False,
            }

            device = self._ensure_device(effective_device_id)
            self.current_target["device_id"] = device["id"]

            stage_result = {"added": [], "missing": []}
            if reset_staging:
                self._reset_staging()
            effective_modules = modules if modules is not None else list(self.selected_modules)
            if effective_modules:
                stage_result = self._stage_modules(effective_modules)

            effective_output_path = output_path if output_path is not None else self.selected_output_path
            # Invalidate deferred cleanup from the previous session before a new
            # recording is opened. start_script will bind the next generation.
            self._lifecycle.session_generation += 1
            self._start_recording(package_name, effective_output_path)
            try:
                if compile_script:
                    self._compile_with_agent_overlay()
                source = self.agent_script_path.read_text(encoding="utf-8")
            except Exception:
                self._stop_recording()
                self._uninstall_stdout_proxy()
                raise

            staged_modules = [mod.Name for mod in self.parser.modManager.staged]
            output_path_snapshot = self.output_path
            parser_device = self.parser.device
            requested_pid = -1 if pid is None else pid
            self.attach_in_progress = {
                "id": operation_id,
                "phase": "attaching",
                "started_at": time.time(),
                "package_name": package_name,
                "device_id": device["id"],
                "spawn": spawn,
                "pid": pid,
                "output_path": self.output_path,
                "staged_modules": staged_modules,
            }
            self.current_target = {
                "package_name": package_name, "device_id": device["id"], "spawn": spawn,
                "pid": pid, "attached": False, "staged_modules": staged_modules,
                "output_path": self.output_path,
            }

        # Run blocking Frida spawn/attach + script load outside self.lock so
        # status/log reads and stdout capture can continue during slow attaches.
        attach_timeout = self.attach_timeout_seconds
        attach_result: dict[str, Any] = {}

        def _do_attach():
            try:
                observed_device = _DeviceExceptionProbe(parser_device)
                fs = self.parser.frida_session_handler(observed_device, spawn, package_name, requested_pid)
                try:
                    self.current_target["pid"] = int(self.parser.pid)
                except (TypeError, ValueError):
                    pass
                if fs is None:
                    if observed_device.last_error is not None:
                        raise ScriptLifecycleError(observed_device.stage or "attach", str(observed_device.last_error)) from observed_device.last_error
                    attach_result["error_none"] = True
                    return
                attach_result["session"] = fs
                self.current_target["pid"] = self.parser.pid
                start_script(fs, self._lifecycle, source, self._on_message, self._on_detached)
                self._watch_cleanup()
                attach_result["script"] = self._lifecycle.script
                if spawn:
                    try:
                        parser_device.resume(self.parser.pid)
                    except Exception:
                        pass
            except Exception as exc:
                attach_result["exception"] = exc
                try:
                    if self._lifecycle.session is None and attach_result.get("session") is not None:
                        self._lifecycle.session = attach_result["session"]
                    self._watch_cleanup()
                    self._dispose_runtime()
                except Exception as cleanup_error:
                    attach_result["cleanup_exception"] = cleanup_error

        worker = threading.Thread(target=_do_attach, daemon=True)
        worker.start()
        worker.join(timeout=attach_timeout)

        if worker.is_alive():
            def _cleanup_late_attach():
                worker.join()
                self._cleanup_untracked_attach(attach_result, operation_id, package_name)

            threading.Thread(target=_cleanup_late_attach, daemon=True).start()
            with self.lock:
                if self.attach_in_progress and self.attach_in_progress.get("id") == operation_id:
                    self.attach_in_progress["phase"] = "cleanup_pending"
                    self.attach_in_progress["timed_out_at"] = time.time()
                    self._stop_recording()
                    self._uninstall_stdout_proxy()
                    self._set_failure(
                        "attach_failed",
                        f"Timed out ({attach_timeout}s) attaching to {package_name}.",
                        "Check Frida/device health and retry after cleanup completes.",
                    )
            raise RuntimeError(
                f"Timed out ({attach_timeout}s) attaching to {package_name}. "
                "The Frida spawn/attach call did not complete in time. "
                "A background cleanup watcher will detach any late Frida session before "
                "mutating Medusa operations are allowed again."
            )

        if attach_result.get("error_none"):
            with self.lock:
                details = self._attach_failure_details(package_name, device, spawn)
                output_path_snapshot = self.output_path
                self._stop_recording()
                self._uninstall_stdout_proxy()
                if self.attach_in_progress and self.attach_in_progress.get("id") == operation_id:
                    self.attach_in_progress = None
                self._set_failure(
                    "attach_failed",
                    f"Unable to attach Medusa to {package_name}. {details}.",
                    "Check whether the app is installed/running and whether Frida is reachable.",
                )
            raise RuntimeError(
                f"Unable to attach Medusa to {package_name}. {details}. "
                f"output_path={output_path_snapshot}. "
                "Check the Medusa server terminal for the underlying Frida error."
            )

        if "exception" in attach_result:
            with self.lock:
                self.cleanup_blocked = "cleanup_exception" in attach_result
                self._sync_lifecycle()
                self.attach_in_progress = None
                self._stop_recording()
                self._uninstall_stdout_proxy()
                failure = self._lifecycle_failure(attach_result["exception"], "attach")
                if self.cleanup_blocked:
                    failure["cleanup_error"] = str(attach_result["cleanup_exception"])
            error = attach_result["exception"]
            if isinstance(error, ScriptLifecycleError):
                raise error
            raise ScriptLifecycleError("attach", str(error)) from error

        with self.lock:
            if self._shutting_down or self._lifecycle.detached:
                self.cleanup_blocked = self._lifecycle.script is not None
                self.attach_in_progress = None
                self._sync_lifecycle()
                error = ScriptLifecycleError("attach", "session ended before attach could be committed")
                self._lifecycle_failure(error)
                raise error
            self.cleanup_blocked = False
            self._sync_lifecycle()

            self.current_target = {
                "package_name": package_name,
                "device_id": device["id"],
                "spawn": spawn,
                "pid": self.parser.pid,
                "attached": True,
                "detach_reason": None,
                "staged_modules": staged_modules,
                "output_path": self.output_path,
            }
            self.last_detach_reason = None
            self.last_failure = None
            if self.attach_in_progress and self.attach_in_progress.get("id") == operation_id:
                self.attach_in_progress = None
            self._record_event(
                {
                    "type": "attached",
                    **self._runtime_status(),
                    "description": package_name,
                    "device_id": device["id"],
                    "output_path": self.output_path,
                }
            )

            return {
                "device": device,
                "target": self.current_target,
                "stage_result": stage_result,
                "output_path": output_path_snapshot,
            }

    def ensure_session(
        self,
        package_name: str,
        device_id: str | None = None,
        modules: list[str] | None = None,
        output_path: str | None = None,
        spawn: bool = True,
        force_restart: bool = False,
    ) -> dict[str, Any]:
        with self.lock:
            self._ensure_no_attach_in_progress("ensure a session")
            target = dict(self.current_target)
            attached = self._is_attached()
            effective_device_id = device_id or target.get("device_id") or self.selected_device_id
            required_modules = list(modules or [])
            if output_path:
                output_target = Path(output_path).expanduser()
                if output_target.suffix:
                    _validate_log_file_path(output_target)
                normalized_output_path = str(output_target.resolve())
            else:
                normalized_output_path = None

        status = self.session_status()
        loaded_modules = set(status.get("loaded_modules") or [])
        missing_modules = [
            module_name for module_name in required_modules
            if module_name not in loaded_modules
        ]

        reasons: list[str] = []
        if not attached:
            reasons.append("not_attached")
        if target.get("package_name") != package_name:
            reasons.append("package_mismatch")
        if effective_device_id and target.get("device_id") != effective_device_id:
            reasons.append("device_mismatch")
        if bool(target.get("spawn")) != bool(spawn):
            reasons.append("spawn_mismatch")
        if status.get("target_pid_alive") is not True:
            reasons.append("target_pid_not_confirmed_alive")
        if missing_modules:
            reasons.append("missing_modules")
        if normalized_output_path and status.get("output_path") != normalized_output_path:
            reasons.append("output_path_mismatch")

        if not reasons:
            return {
                "changed": False,
                "action": "reused",
                "status": status,
                "missing_modules": [],
            }

        attach = self.attach_app(
            package_name=package_name,
            device_id=effective_device_id,
            spawn=spawn,
            modules=required_modules,
            reset_staging=True,
            compile_script=True,
            output_path=normalized_output_path,
            reuse_if_attached=False,
            force_restart=force_restart,
        )
        return {
            "changed": True,
            "action": "attached",
            "reasons": reasons,
            "missing_modules": missing_modules,
            "attach": attach,
            "status": self.session_status(),
        }

    def restart_app(self, spawn: bool | None = None, force_restart: bool = False) -> dict[str, Any]:
        with self.lock:
            self._ensure_no_attach_in_progress("restart the app")
            package_name = self.current_target.get("package_name")
            if not package_name:
                raise RuntimeError("No previous target available to restart.")
            if not force_restart:
                raise RuntimeError(
                    "restart_app will detach and restart the current session. "
                    "Pass force_restart=True to continue."
                )

            next_spawn = self.current_target.get("spawn") if spawn is None else spawn
            device_id = self.current_target.get("device_id") or self.selected_device_id
            output_path = self.current_target.get("output_path") or self.selected_output_path
            selected_modules = list(self.selected_modules)

        self.detach_app()
        return self.attach_app(
            package_name=package_name,
            device_id=device_id,
            spawn=bool(next_spawn),
            pid=None,
            modules=selected_modules,
            reset_staging=True,
            compile_script=True,
            output_path=output_path,
            reuse_if_attached=False,
            force_restart=True,
        )

    def detach_app(self) -> dict[str, Any]:
        with self.lock:
            self._ensure_no_attach_in_progress("detach the app")
            operation_id = uuid.uuid4().hex
            self._begin_failure_context("detach", operation_id)
            last_target = dict(self.current_target)
            output_path = self.output_path
            self.detach_in_progress = {
                "id": operation_id, "phase": "detaching", "started_at": time.time(),
                "package_name": last_target.get("package_name", "unknown target"),
            }
        result: dict[str, Any] = {"detached": False}

        def work():
            try:
                self._dispose_runtime()
                result["detached"] = True
            except Exception as exc:
                result["exception"] = exc

        def finish(late: bool):
            with self.lock:
                if self._shutting_down or not self.detach_in_progress or self.detach_in_progress.get("id") != operation_id:
                    return
                error = result.get("exception")
                self.cleanup_blocked = error is not None
                self._sync_lifecycle()
                self.detach_in_progress = None
                if error is None:
                    self._stop_recording()
                    self._uninstall_stdout_proxy()
                else:
                    result["error"] = self._lifecycle_failure(error)
                self._record_event({"type": "detach-completed", "detached": result["detached"],
                                    "timed_out": late, **self._runtime_status()})

        worker = threading.Thread(target=work, daemon=True)
        worker.start()
        worker.join(timeout=self.detach_timeout_seconds)
        timed_out = worker.is_alive()
        if timed_out:
            with self.lock:
                self.detach_in_progress.update(phase="cleanup_pending", timed_out_at=time.time())
                result["error"] = self._lifecycle_failure(
                    TimeoutError("Detach timed out; cleanup is still tracked"), "detach_timeout")
            def complete_late():
                worker.join()
                finish(True)
            threading.Thread(target=complete_late, daemon=True).start()
        else:
            finish(False)
        with self.lock:
            return {
                "detached": result["detached"] if not timed_out else False,
                "detach_timed_out": timed_out,
                "detach_timeout_seconds": self.detach_timeout_seconds,
                "error": result.get("error"), "last_target": last_target,
                "last_detach_reason": self.last_detach_reason, "output_path": output_path,
                **self._runtime_status(),
            }

    def fast_cleanup(self) -> None:
        # Use non-blocking acquire so SIGINT isn't blocked when attach_app
        # holds the lock on a slow Frida spawn.
        acquired = self.lock.acquire(blocking=False)
        try:
            self._shutting_down = True
            self._lifecycle.session_generation += 1
            self._lifecycle.script_generation += 1
            self._lifecycle.detached = True
            self._lifecycle.script_loaded = False
            self._lifecycle.lifecycle_status = "shutdown"
            self.reload_in_progress = None
            self.script = None
            self.session = None
            self.parser.script = None
            self.attach_in_progress = None
            self.detach_in_progress = None
            if self.current_target:
                self.current_target["attached"] = False
        finally:
            if acquired:
                self.lock.release()

        # Intentionally avoid any Frida API calls during process shutdown.
        # Even "best effort" unload/detach can wedge SIGINT exit on some
        # sessions, and the OS will clean up the connection when the process
        # terminates.
        self._stop_recording()
        self._uninstall_stdout_proxy()

    @staticmethod
    def _parse_android_process_state(dump: str, pid: int) -> dict[str, Any]:
        result = {"process_state_pid": pid, "process_frozen": None, "process_cached": None,
                  "process_background": None, "process_state_code": None, "process_state_error": None}
        lines = dump.splitlines()
        pattern = re.compile(r"^\s*\*APP\*.*?ProcessRecord\{[^}]*?\s" + str(pid) + r":")
        starts = [index for index, line in enumerate(lines) if pattern.search(line)]
        if len(starts) != 1:
            result["process_state_error"] = "Exact target PID block is unavailable or ambiguous in ActivityManager output"
            return result
        start = starts[0]
        indent = len(lines[start]) - len(lines[start].lstrip())
        end = next((i for i in range(start + 1, len(lines)) if lines[i].strip()
                    and len(lines[i]) - len(lines[i].lstrip()) <= indent), len(lines))
        block = "\n".join(lines[start:end])
        for field, token in (("process_frozen", "isFrozen"), ("process_cached", "cached")):
            matches = set(re.findall(r"\b" + token + r"=(true|false)\b", block))
            if len(matches) == 1:
                result[field] = matches.pop() == "true"
        state = re.search(r"\bcurProcState=(-?\d+)\b", block)
        if state:
            result["process_state_code"] = int(state.group(1))
        # Cached/frozen is positive evidence of background state. Uncached is
        # not proof of foreground, so preserve unknown instead of guessing.
        if result["process_cached"] is True or result["process_frozen"] is True:
            result["process_background"] = True
        if result["process_frozen"] is None:
            result["process_state_error"] = "Freezer state is not exposed unambiguously for this PID"
        return result

    def _android_process_state(self, target: dict[str, Any], pid: int, timeout: float) -> dict[str, Any]:
        result = {"process_state_pid": pid, "process_frozen": None, "process_cached": None,
                  "process_background": None, "process_state_code": None, "process_state_error": None}
        if timeout <= 0:
            result["process_state_error"] = "Process status time budget exhausted before freezer inspection"
            return result
        try:
            observed = subprocess.run(
                ["adb", "-s", str(target["device_id"]), "shell", "dumpsys", "activity", "processes"],
                capture_output=True, text=True, check=False, timeout=timeout,
            )
            if observed.returncode != 0 or observed.stderr.strip():
                result["process_state_error"] = observed.stderr.strip() or "ActivityManager inspection failed"
            else:
                result = self._parse_android_process_state(observed.stdout, pid)
        except (OSError, subprocess.TimeoutExpired) as exc:
            result["process_state_error"] = str(exc)
        result["process_state_observed_at"] = time.time()
        return result

    def _process_status(self, target: dict[str, Any]) -> dict[str, Any]:
        package_name, device_id = target.get("package_name"), target.get("device_id")
        try:
            expected_pid = int(target["pid"]) if target.get("pid") is not None else None
            if expected_pid is not None and expected_pid <= 0:
                expected_pid = None
        except (TypeError, ValueError):
            expected_pid = None
        status: dict[str, Any] = {
            "process_alive": None, "app_alive": None, "package_process_alive": None,
            "process_alive_error": None, "process_pids": [], "process_pid_matches_target": None,
            "target_pid": expected_pid, "target_pid_alive": None, "pid_changed": None,
            "device_reachable": None, "process_frozen": None, "process_cached": None,
            "process_background": None, "process_state_pid": None, "process_state_code": None,
            "process_state_error": None, "process_status_observed_at": time.time(),
        }
        if not package_name or not device_id:
            status["process_alive_error"] = "no target package/device"
            return status
        deadline = time.monotonic() + self.status_timeout_seconds
        try:
            result = subprocess.run(
                ["adb", "-s", str(device_id), "shell", "pidof", str(package_name)],
                capture_output=True, text=True, timeout=max(0.001, self.status_timeout_seconds), check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            status["process_alive_error"] = str(exc)
            return status
        stdout, stderr = result.stdout.strip(), result.stderr.strip()
        if re.search(r"device.*(?:offline|not found|unauthorized)|no devices/emulators found", stderr.casefold()):
            status.update(device_reachable=False, process_alive_error=stderr)
            return status
        tokens = stdout.split()
        if result.returncode not in (0, 1) or stderr or any(not token.isdecimal() or int(token) <= 0 for token in tokens):
            status["process_alive_error"] = stderr or "pidof returned invalid PID data or an unsuccessful status"
        else:
            pids = list(dict.fromkeys(int(token) for token in tokens))
            status.update(process_pids=pids, package_process_alive=bool(pids), device_reachable=True)
            if expected_pid is not None:
                status["process_pid_matches_target"] = expected_pid in pids
        if expected_pid is not None:
            if expected_pid in status["process_pids"]:
                status["target_pid_alive"] = True
            else:
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    status["target_pid_alive"] = self._target_pid_alive(target, timeout=remaining)
                if status["target_pid_alive"] is not None:
                    status["device_reachable"] = True
            status["pid_changed"] = (
                bool(status["process_pids"]) if status["target_pid_alive"] is False
                else False if status["target_pid_alive"] is True else None
            )
        if status["target_pid_alive"] is True or status["package_process_alive"] is True:
            status["app_alive"] = True
        elif status["package_process_alive"] is False and (expected_pid is None or status["target_pid_alive"] is False):
            status["app_alive"] = False
        # Compatibility alias now describes app presence; callers must use the
        # separate exact-PID field to decide whether a session can be reused.
        status["process_alive"] = status["app_alive"]
        state_pid = expected_pid if status["target_pid_alive"] is True else (
            status["process_pids"][0] if expected_pid is None and status["process_pids"] else None)
        if state_pid is not None:
            status.update(self._android_process_state(target, state_pid, deadline - time.monotonic()))
        return status

    def _output_log_status(self) -> dict[str, Any]:
        if not self.output_path:
            return {
                "exists": False,
                "is_file": False,
                "is_directory": False,
                "size": None,
                "mtime": None,
                "mtime_iso": None,
                "error": None,
            }

        path = Path(self.output_path)
        try:
            if not path.exists():
                return {
                    "exists": False,
                    "is_file": False,
                    "is_directory": False,
                    "size": None,
                    "mtime": None,
                    "mtime_iso": None,
                    "error": None,
                }

            stat_result = path.stat()
            mtime = stat_result.st_mtime
            return {
                "exists": True,
                "is_file": path.is_file(),
                "is_directory": path.is_dir(),
                "size": stat_result.st_size if path.is_file() else None,
                "mtime": mtime,
                "mtime_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(mtime)),
                "error": None,
            }
        except Exception as exc:
            return {
                "exists": None,
                "is_file": None,
                "is_directory": None,
                "size": None,
                "mtime": None,
                "mtime_iso": None,
                "error": str(exc),
            }

    def session_status(self) -> dict[str, Any]:
        with self.lock:
            target = dict(self.current_target)
            staged_modules = [mod.Name for mod in self.parser.modManager.staged]
            loaded_modules = list(target.get("staged_modules") or [])
            process_status = self._process_status(target)
            output_log = self._inspect_output_log()
            failure_classification = self._classify_failure(process_status, output_log)
            return {
                "device_id": getattr(self.parser.device, "id", None),
                "selected_device_id": self.selected_device_id,
                "selected_output_path": self.selected_output_path,
                "selected_modules": self.selected_modules,
                "hook_script_length": len(self.agent_overlay_script),
                "current_tool_call": dict(self.current_tool_call) if self.current_tool_call else None,
                "recent_tool_calls": [dict(call) for call in self.tool_call_history[-10:]],
                "last_failure": dict(self.last_failure) if self.last_failure else None,
                "failure_context": dict(self.failure_context) if self.failure_context else None,
                "last_failure_is_current": self._current_failure(target, output_log) is not None,
                "output_path_ready": (False if failure_classification["output_condition"]["category"] == "log_path_failed"
                                      else output_log.get("writable")) if output_log.get("output_path") else None,
                "process_condition": failure_classification["process_condition"],
                "output_condition": failure_classification["output_condition"],
                "failure_classification": failure_classification,
                "attach_in_progress": bool(self.attach_in_progress),
                "attach_operation": dict(self.attach_in_progress) if self.attach_in_progress else None,
                "reload_in_progress": bool(self.reload_in_progress),
                "reload_operation": dict(self.reload_in_progress) if self.reload_in_progress else None,
                "last_reload": dict(self.last_reload) if self.last_reload else None,
                **self._runtime_status(),
                "detach_in_progress": bool(self.detach_in_progress),
                "detach_operation": dict(self.detach_in_progress) if self.detach_in_progress else None,
                "attached": self._is_attached(),
                "target": target,
                "last_detach_reason": self.last_detach_reason,
                "staged_modules": staged_modules,
                "loaded_modules": loaded_modules,
                "event_count": len(self.events),
                "recording": self.recording_file is not None,
                "output_path": self.output_path,
                "output_log": output_log,
                **process_status,
            }

    def session_summary(self) -> dict[str, Any]:
        status = self.session_status()
        with self.lock:
            target = dict(status.get("target") or {})
            package_name = target.get("package_name") or "no package"
            pid = target.get("pid")
            device_id = target.get("device_id") or status.get("device_id") or status.get("selected_device_id")
            modules = list(status.get("loaded_modules") or status.get("staged_modules") or [])
            output_path = status.get("output_path")
            last_event = self.events[-1] if self.events else None
            if last_event:
                last_event_age_seconds = round(time.time() - float(last_event.get("timestamp", time.time())), 3)
            else:
                last_event_age_seconds = None

            attached_text = (
                f"attached to {package_name} PID {pid}" if status.get("attached")
                else f"not attached; last target {package_name}"
            )
            modules_text = "/".join(modules) if modules else "none"
            output_text = output_path or "not recording"
            event_text = (
                f"{last_event_age_seconds}s ago" if last_event_age_seconds is not None
                else "never"
            )
            summary = (
                f"{attached_text} on device {device_id}; modules {modules_text}; "
                f"writing to {output_text}; last event {event_text}."
            )

            return {
                "summary": summary,
                "attached": status.get("attached"),
                "package": package_name,
                "pid": pid,
                "device_id": device_id,
                "modules": modules,
                "output_path": output_path,
                "last_event_age_seconds": last_event_age_seconds,
                "current_tool_call": status.get("current_tool_call"),
                "failure_classification": status.get("failure_classification"),
                "output_log": status.get("output_log"),
                "process_alive": status.get("process_alive"),
                "process_pids": status.get("process_pids"),
                **{key: status.get(key) for key in (
                    "app_alive", "package_process_alive", "target_pid", "target_pid_alive", "pid_changed",
                    "device_reachable", "process_frozen", "process_cached", "process_background",
                    "process_state_pid", "process_state_code", "process_state_error", "process_alive_error",
                    "process_condition", "output_condition", "output_path_ready", "last_failure_is_current",
                    "failure_context",
                )},
                "recording": status.get("recording"),
                "reload_in_progress": status.get("reload_in_progress"),
                "last_reload": status.get("last_reload"),
                **self._runtime_status(),
            }

    def recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.lock:
            limit = max(1, min(limit, 200))
            return self.events[-limit:]

    def tail_output(
        self,
        lines: int = 200,
        since_line: int | None = None,
        line_offset: int | None = None,
        cursor: Any = None,
    ) -> dict[str, Any]:
        with self.lock:
            target, source = self._resolve_tail_target()
            if target is None:
                return {
                    "output_path": None,
                    "content": "",
                    "line_count": 0,
                    "source": source,
                    "total_lines": 0,
                    "start_line": 0,
                    "next_line": 0,
                    "cursor": None,
                    "next_cursor": None,
                }

            if target.suffix:
                _validate_log_file_path(target)
            if not target.exists():
                return {
                    "output_path": str(target),
                    "content": "",
                    "line_count": 0,
                    "exists": False,
                    "source": source,
                    "total_lines": 0,
                    "start_line": 0,
                    "next_line": 0,
                    "cursor": cursor,
                    "next_cursor": {
                        "path": str(target),
                        "line_offset": 0,
                        "total_lines": 0,
                        "size": 0,
                        "mtime": None,
                    },
                }
            if target.is_dir():
                return {
                    "output_path": str(target),
                    "content": "",
                    "line_count": 0,
                    "exists": True,
                    "is_directory": True,
                    "source": source,
                    "total_lines": 0,
                    "start_line": 0,
                    "next_line": 0,
                    "cursor": cursor,
                    "next_cursor": None,
                }
            if target.suffix.casefold() != LOG_FILE_SUFFIX:
                raise RuntimeError(f"Refusing to read non-log output path: {target}")

            cursor_path = None
            cursor_total_lines = None
            cursor_line_offset = None
            if isinstance(cursor, dict):
                cursor_path = cursor.get("path")
                cursor_line_offset = cursor.get("line_offset", cursor.get("next_line"))
                cursor_total_lines = cursor.get("total_lines")
            elif cursor is not None:
                try:
                    cursor_line_offset = int(cursor)
                except (TypeError, ValueError):
                    cursor_line_offset = None

            lines = max(1, min(lines, 2000))
            with target.open("r", encoding="utf-8", errors="replace") as handle:
                content_lines = handle.readlines()

            total_lines = len(content_lines)
            cursor_reset = False
            start_line = since_line if since_line is not None else line_offset
            if start_line is None:
                start_line = cursor_line_offset
            if cursor_path and cursor_path != str(target):
                start_line = 0
                cursor_reset = True
            if cursor_total_lines is not None:
                try:
                    if int(cursor_total_lines) > total_lines:
                        start_line = 0
                        cursor_reset = True
                except (TypeError, ValueError):
                    pass
            if start_line is None:
                start_line = max(0, total_lines - lines)
            start_line = max(0, min(start_line, total_lines))
            end_line = min(total_lines, start_line + lines)
            tail = "".join(content_lines[start_line:end_line])
            stat_result = target.stat()
            next_cursor = {
                "path": str(target),
                "line_offset": end_line,
                "total_lines": total_lines,
                "size": stat_result.st_size,
                "mtime": stat_result.st_mtime,
                "mtime_iso": self._operator_timestamp(stat_result.st_mtime),
            }
            return {
                "output_path": str(target),
                "content": tail,
                "line_count": end_line - start_line,
                "exists": True,
                "source": source,
                "total_lines": total_lines,
                "start_line": start_line,
                "next_line": end_line,
                "cursor": cursor,
                "next_cursor": next_cursor,
                "cursor_reset": cursor_reset,
            }

    def cleanup(self) -> None:
        try:
            self.fast_cleanup()
        finally:
            try:
                self.agent_script_path.unlink(missing_ok=True)
            except Exception:
                pass


bridge = MedusaAndroidBridge()
atexit.register(bridge.cleanup)


def _handle_termination(signum, _frame) -> None:
    try:
        bridge.cleanup()
    finally:
        os._exit(128 + int(signum))


def _normalize_device_id(device_id: Any) -> str | None:
    if device_id is None:
        return None

    text = str(device_id).strip()
    if not text or text.lower() == "null":
        return None

    return text


def _normalize_output_path(output_path: Any) -> str | None:
    if output_path is None:
        return None

    text = str(output_path).strip()
    if not text or text.lower() == "null":
        return None

    return text


def _validate_log_file_path(path: Path) -> None:
    if path.suffix.casefold() != LOG_FILE_SUFFIX:
        raise RuntimeError(
            f"Output files must end in {LOG_FILE_SUFFIX}. "
            "Pass a directory path to let Medusa create a per-session .log file."
        )


def _normalize_package_scope(scope: Any) -> str:
    if scope is None:
        return "-3"

    text = str(scope).strip()
    if text.lower() == "null":
        return "-3"
    if text not in PACKAGE_SCOPES:
        allowed = '", "'.join(sorted(PACKAGE_SCOPES))
        raise RuntimeError(f'Invalid package scope: {text!r}. Allowed values: "{allowed}".')

    return text


def _call_tool(tool_name: str, func: Any, **kwargs: Any) -> Any:
    return bridge.run_tool(tool_name, func, **kwargs)


@mcp.tool()
def list_devices() -> list[dict[str, str]]:
    """List Frida-visible devices."""
    return _call_tool("list_devices", bridge.list_devices)


@mcp.tool()
def select_device(device_id: str) -> dict[str, str]:
    """Select the active Frida device for subsequent tool calls."""
    return _call_tool("select_device", bridge.select_device, device_id=device_id)


@mcp.tool()
def stage_module(module_name: str) -> dict[str, Any]:
    """Add one Medusa module or prefix match to the staged MCP module set."""
    return _call_tool("stage_module", bridge.stage_module, module_name=module_name)


@mcp.tool()
def unstage_module(module_name: str) -> dict[str, Any]:
    """Remove a single module from the staged set by exact name or suffix match."""
    return _call_tool("unstage_module", bridge.unstage_module, module_name=module_name)


@mcp.tool()
def clear_modules() -> dict[str, Any]:
    """Clear the staged MCP module set."""
    return _call_tool("clear_modules", bridge.clear_modules)


@mcp.tool()
def list_modules(
    prefix: str | None = None,
    category: str | None = None,
    pattern: str | None = None,
) -> dict[str, Any]:
    """Browse Medusa modules by optional prefix, category, or substring filter."""
    return _call_tool("list_modules", bridge.list_modules, prefix=prefix, category=category, pattern=pattern)


@mcp.tool()
def get_module_source(module_name: str) -> dict[str, Any]:
    """Return a Medusa module's metadata and JavaScript source."""
    return _call_tool("get_module_source", bridge.get_module_source, module_name=module_name)


@mcp.tool()
def list_staged_modules() -> dict[str, Any]:
    """Show selected modules, currently active staged modules, and hook-script state."""
    return _call_tool("list_staged_modules", bridge.list_staged_modules)


@mcp.tool()
def set_output_path(output_path: str) -> dict[str, Any]:
    """Set the default file or directory used for session output logs, updating a live session if one exists."""
    return _call_tool("set_output_path", bridge.set_output_path, output_path=output_path)


@mcp.tool()
def clear_output_path() -> dict[str, Any]:
    """Clear the default output path used for session output logs."""
    return _call_tool("clear_output_path", bridge.clear_output_path)


@mcp.tool()
def check_output_log(output_path: Any = None) -> dict[str, Any]:
    """Return health details for the active or selected Medusa output log."""
    return _call_tool(
        "check_output_log",
        bridge.check_output_log,
        output_path=_normalize_output_path(output_path),
    )


@mcp.tool()
def clear_output_log(output_path: Any = None) -> dict[str, Any]:
    """Truncate the active or selected Medusa output log without changing paths."""
    return _call_tool(
        "clear_output_log",
        bridge.clear_output_log,
        output_path=_normalize_output_path(output_path),
    )


@mcp.tool()
def rotate_output_log(output_path: Any = None) -> dict[str, Any]:
    """Move the active or selected Medusa output log aside and reopen a fresh log file."""
    return _call_tool(
        "rotate_output_log",
        bridge.rotate_output_log,
        output_path=_normalize_output_path(output_path),
    )


@mcp.tool()
def get_hook_script() -> dict[str, Any]:
    """Return the current MCP agent hook overlay script."""
    return _call_tool("get_hook_script", bridge.get_hook_script)


@mcp.tool()
def set_hook_script(script: str, reload_if_attached: bool = True) -> dict[str, Any]:
    """Replace the current MCP agent hook overlay, compile it, and return any immediate post-reload events."""
    return _call_tool(
        "set_hook_script",
        bridge.set_hook_script,
        script=script,
        reload_if_attached=reload_if_attached,
    )


@mcp.tool()
def append_hook_script(script: str, reload_if_attached: bool = True) -> dict[str, Any]:
    """Append JavaScript to the current MCP agent hook overlay, compile it, and return any immediate post-reload events."""
    return _call_tool(
        "append_hook_script",
        bridge.append_hook_script,
        script=script,
        reload_if_attached=reload_if_attached,
    )


@mcp.tool()
def clear_hook_script(reload_if_attached: bool = True) -> dict[str, Any]:
    """Clear the MCP agent hook overlay, compile the empty result, and return any immediate post-reload events."""
    return _call_tool(
        "clear_hook_script",
        bridge.clear_hook_script,
        reload_if_attached=reload_if_attached,
    )


@mcp.tool()
def list_packages(device_id: Any = None, scope: str = "-3") -> dict[str, Any]:
    """List installed Android packages for a device."""
    return _call_tool(
        "list_packages",
        bridge.list_packages,
        device_id=_normalize_device_id(device_id),
        scope=_normalize_package_scope(scope),
    )


@mcp.tool()
def search_modules(pattern: str) -> list[str]:
    """Search Medusa modules by substring."""
    return _call_tool("search_modules", bridge.search_modules, pattern=pattern)


@mcp.tool()
def attach_app(
    package_name: str,
    device_id: Any = None,
    spawn: bool = True,
    pid: int | None = None,
    modules: list[str] | None = None,
    reset_staging: bool = True,
    compile_script: bool = True,
    output_path: Any = None,
    reuse_if_attached: bool = True,
    force_restart: bool = False,
) -> dict[str, Any]:
    """Attach Medusa to an app and load the compiled agent script."""
    return _call_tool(
        "attach_app",
        bridge.attach_app,
        package_name=package_name,
        device_id=_normalize_device_id(device_id),
        spawn=spawn,
        pid=pid,
        modules=modules,
        reset_staging=reset_staging,
        compile_script=compile_script,
        output_path=_normalize_output_path(output_path),
        reuse_if_attached=reuse_if_attached,
        force_restart=force_restart,
    )


@mcp.tool()
def ensure_session(
    package_name: str,
    device_id: Any = None,
    modules: list[str] | None = None,
    output_path: Any = None,
    spawn: bool = True,
    force_restart: bool = False,
) -> dict[str, Any]:
    """Reuse a matching live Medusa session, or attach if package/device/modules/output do not match."""
    return _call_tool(
        "ensure_session",
        bridge.ensure_session,
        package_name=package_name,
        device_id=_normalize_device_id(device_id),
        modules=modules,
        output_path=_normalize_output_path(output_path),
        spawn=spawn,
        force_restart=force_restart,
    )


@mcp.tool()
def restart_app(spawn: bool | None = None, force_restart: bool = False) -> dict[str, Any]:
    """Restart the last target app using the remembered modules, scratchpad, and output path."""
    return _call_tool("restart_app", bridge.restart_app, spawn=spawn, force_restart=force_restart)


@mcp.tool()
def detach_app() -> dict[str, Any]:
    """Detach the current Medusa/Frida session."""
    return _call_tool("detach_app", bridge.detach_app)


@mcp.tool()
def session_status() -> dict[str, Any]:
    """Return the current Medusa MCP session state."""
    return _call_tool("session_status", bridge.session_status)


@mcp.tool()
def session_summary() -> dict[str, Any]:
    """Return a compact one-shot operator summary of the current Medusa MCP session."""
    return _call_tool("session_summary", bridge.session_summary)


@mcp.tool()
def recent_events(limit: int = 50) -> list[dict[str, Any]]:
    """Return the in-memory event buffer for Frida send/error/attach/detach notifications plus mirrored console output."""
    return _call_tool("recent_events", bridge.recent_events, limit=limit)


@mcp.tool()
def tail_output(
    lines: int = 200,
    since_line: int | None = None,
    line_offset: int | None = None,
    cursor: Any = None,
) -> dict[str, Any]:
    """Read the on-disk Medusa output log by tail or from a specific line offset, with fallback to the selected output path."""
    return _call_tool(
        "tail_output",
        bridge.tail_output,
        lines=lines,
        since_line=since_line,
        line_offset=line_offset,
        cursor=cursor,
    )


def main() -> None:
    transport = os.getenv("MEDUSA_MCP_TRANSPORT", "streamable-http")
    signal.signal(signal.SIGINT, _handle_termination)
    signal.signal(signal.SIGTERM, _handle_termination)
    options = {} if transport == "stdio" else {
        "host": "127.0.0.1",
        "port": int(os.getenv("MEDUSA_MCP_PORT", "8000")),
    }
    mcp.run(transport=transport, **options)


if __name__ == "__main__":
    main()

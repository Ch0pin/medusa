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
import signal
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:
    raise SystemExit(
        'Missing MCP SDK. Install it with: pip install "mcp[cli]"'
    ) from exc

import frida

import medusa as medusa_app


ROOT = Path(__file__).resolve().parent

mcp = FastMCP(
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
        self.parser = medusa_app.Parser()
        self.parser.interactive = False

        self.agent_script_path = ROOT / f"{uuid.uuid4().hex}_agent_script"
        self.agent_script_path.touch(exist_ok=True)
        medusa_app.agent_script = str(self.agent_script_path)

        self.session = None
        self.script = None
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

        self.parser.do_reload("dummy")

    def _record_event(self, message: dict[str, Any], payload: Any = None) -> None:
        event: dict[str, Any] = {
            "timestamp": time.time(),
            "type": message.get("type", "unknown"),
        }

        for key in ("payload", "description", "stack", "fileName", "lineNumber", "columnNumber"):
            if key in message:
                event[key] = message[key]

        if payload is not None:
            event["has_binary_payload"] = True

        self.events.append(event)
        if len(self.events) > 500:
            self.events = self.events[-500:]

    def _capture_console_output(self, data: str) -> None:
        with self.lock:
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
        # This callback fires on Frida's thread.  Acquiring self.lock here
        # can deadlock when the main thread holds the lock while waiting on
        # a blocking Frida call (e.g. script.load / session.create_script).
        # Use trylock: if we can't get the lock, update the minimal atomic
        # state and schedule the full cleanup on a background thread.
        acquired = self.lock.acquire(blocking=False)
        try:
            self.last_detach_reason = str(reason)
            if self.current_target:
                self.current_target["attached"] = False
                self.current_target["detach_reason"] = self.last_detach_reason
            self.session = None
            self.script = None
            self.parser.script = None
            if acquired:
                output_path = self.output_path
                self._stop_recording()
                self._uninstall_stdout_proxy()
                try:
                    self.parser.on_detached(reason)
                finally:
                    self._record_event(
                        {
                            "type": "detached",
                            "description": self.last_detach_reason,
                            "output_path": output_path,
                        }
                    )
            else:
                # Couldn't get the lock — defer cleanup to avoid deadlock.
                self._record_event(
                    {
                        "type": "detached",
                        "description": self.last_detach_reason,
                    }
                )
                threading.Thread(
                    target=self._deferred_detach_cleanup,
                    args=(reason,),
                    daemon=True,
                ).start()
        finally:
            if acquired:
                self.lock.release()

    def _deferred_detach_cleanup(self, reason: Any) -> None:
        """Run the heavy detach cleanup once the lock becomes available."""
        with self.lock:
            self._stop_recording()
            self._uninstall_stdout_proxy()
            try:
                self.parser.on_detached(reason)
            except Exception:
                pass

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

    def clear_modules(self) -> dict[str, Any]:
        with self.lock:
            self.selected_modules = []
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
            selected = output_path.strip()
            if not selected:
                raise RuntimeError("output_path must be a non-empty string.")

            output_target = Path(selected).expanduser()
            if output_target.suffix:
                output_target.parent.mkdir(parents=True, exist_ok=True)
                normalized = output_target.resolve()
            else:
                normalized = output_target.resolve()
                normalized.mkdir(parents=True, exist_ok=True)

            self.selected_output_path = str(normalized)
            switched_live_output = False
            current_package = self.current_target.get("package_name")
            if self.recording_file is not None and current_package:
                self._stop_recording()
                self._start_recording(current_package, self.selected_output_path)
                if self.current_target:
                    self.current_target["output_path"] = self.output_path
                switched_live_output = True
                self._record_event(
                    {
                        "type": "output-path-updated",
                        "description": self.output_path,
                    }
                )

            return {
                "selected_output_path": self.selected_output_path,
                "output_path": self.output_path,
                "switched_live_output": switched_live_output,
            }

    def clear_output_path(self) -> dict[str, Any]:
        with self.lock:
            self.selected_output_path = None
            return {"selected_output_path": self.selected_output_path}

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
        scratchpad.save()
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

        # If a filename is provided, use it exactly. Otherwise treat the value
        # as a directory and create a per-session log file inside it.
        if output_target.suffix:
            output_target.parent.mkdir(parents=True, exist_ok=True)
            output_path = output_target.resolve()
        else:
            output_root = output_target.resolve()
            output_root.mkdir(parents=True, exist_ok=True)
            output_path = output_root / f"{safe_package}-{timestamp}.log"

        self.recording_file = output_path.open("a", encoding="utf-8")
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
        return bool(self.session is not None and self.current_target.get("attached"))

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

    def _slice_recent_events(self, start_index: int, limit: int = 20) -> list[dict[str, Any]]:
        if start_index < 0:
            start_index = 0
        limit = max(1, min(limit, 100))
        return self.events[start_index:start_index + limit]

    def _reload_active_script(self, timeout: float = 10.0) -> bool:
        if not self._has_live_session():
            return False

        if self.script is not None:
            try:
                self.script.unload()
            except Exception:
                pass

        # Run the blocking Frida calls in a worker thread so we can
        # enforce a timeout.  Without this, create_script/load can hang
        # forever when the target process has died but the detach callback
        # hasn't fired yet (or is blocked on self.lock).
        session = self.session
        result: dict[str, Any] = {}

        def _do_reload():
            try:
                with self.agent_script_path.open("r", encoding="utf-8") as handle:
                    script = session.create_script(handle.read())
                script.on("message", self._on_message)
                session.on("detached", self._on_detached)
                script.load()
                result["script"] = script
            except Exception as exc:
                result["error"] = exc

        worker = threading.Thread(target=_do_reload, daemon=True)
        worker.start()
        worker.join(timeout=timeout)

        if worker.is_alive():
            # Timed out — the session is likely dead.
            self.session = None
            self.script = None
            self.parser.script = None
            if self.current_target:
                self.current_target["attached"] = False
                self.current_target["detach_reason"] = "reload_timeout"
            return False

        if "script" in result:
            self._sync_runtime_script(result["script"])
            return True

        # Exception during reload — session is dead.
        self.session = None
        self.script = None
        self.parser.script = None
        if self.current_target:
            self.current_target["attached"] = False
        return False

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

            self.parser.do_compile("")
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
        compile_result = self._compile_with_agent_overlay()
        reloaded = False
        reload_skipped_reason = None
        if reload_if_attached and self._has_live_session():
            reloaded = self._reload_active_script()
            if not reloaded:
                reload_skipped_reason = "session_detached"
        elif reload_if_attached:
            reload_skipped_reason = "no_live_session"
        return {
            "compiled": True,
            "reloaded": reloaded,
            "attached": self._has_live_session(),
            "reload_skipped_reason": reload_skipped_reason,
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
    ) -> dict[str, Any]:
        with self.lock:
            if self.session or self.script:
                self.detach_app()

            device = self._ensure_device(device_id)

            stage_result = {"added": [], "missing": []}
            if reset_staging:
                self._reset_staging()
            effective_modules = modules if modules is not None else list(self.selected_modules)
            if effective_modules:
                stage_result = self._stage_modules(effective_modules)

            effective_output_path = output_path if output_path is not None else self.selected_output_path
            self._start_recording(package_name, effective_output_path)
            if compile_script:
                self._compile_with_agent_overlay()

            # Run blocking Frida spawn/attach + script load in a worker
            # thread with a timeout so we never hold self.lock forever.
            attach_timeout = 60.0
            attach_result: dict[str, Any] = {}

            def _do_attach():
                try:
                    fs = self.parser.frida_session_handler(
                        self.parser.device,
                        spawn,
                        package_name,
                        -1 if pid is None else pid,
                    )
                    if fs is None:
                        attach_result["error_none"] = True
                        return

                    with self.agent_script_path.open("r", encoding="utf-8") as handle:
                        sc = fs.create_script(handle.read())

                    sc.on("message", self._on_message)
                    fs.on("detached", self._on_detached)
                    sc.load()

                    if spawn:
                        try:
                            self.parser.device.resume(self.parser.pid)
                        except Exception:
                            pass

                    attach_result["session"] = fs
                    attach_result["script"] = sc
                except Exception as exc:
                    attach_result["exception"] = exc

            worker = threading.Thread(target=_do_attach, daemon=True)
            worker.start()
            worker.join(timeout=attach_timeout)

            if worker.is_alive():
                self._stop_recording()
                self._uninstall_stdout_proxy()
                raise RuntimeError(
                    f"Timed out ({attach_timeout}s) attaching to {package_name}. "
                    "The Frida spawn/attach call did not complete in time. "
                    "The background thread is still running but the lock has "
                    "been released — restart the MCP server if it remains stuck."
                )

            if attach_result.get("error_none"):
                details = self._attach_failure_details(package_name, device, spawn)
                output_path = self.output_path
                self._stop_recording()
                raise RuntimeError(
                    f"Unable to attach Medusa to {package_name}. {details}. "
                    f"output_path={output_path}. "
                    "Check the Medusa server terminal for the underlying Frida error."
                )

            if "exception" in attach_result:
                output_path = self.output_path
                self.detach_app()
                raise RuntimeError(
                    f"Attached to {package_name} but failed to load the script. "
                    f"output_path={output_path}. error={attach_result['exception']}"
                ) from attach_result["exception"]

            self.session = attach_result["session"]
            self._sync_runtime_script(attach_result["script"])

            self.current_target = {
                "package_name": package_name,
                "device_id": device["id"],
                "spawn": spawn,
                "pid": self.parser.pid,
                "attached": True,
                "detach_reason": None,
                "staged_modules": [mod.Name for mod in self.parser.modManager.staged],
                "output_path": self.output_path,
            }
            self.last_detach_reason = None
            self._record_event(
                {
                    "type": "attached",
                    "description": package_name,
                    "device_id": device["id"],
                    "output_path": self.output_path,
                }
            )

            return {
                "device": device,
                "target": self.current_target,
                "stage_result": stage_result,
                "output_path": self.output_path,
            }

    def restart_app(self, spawn: bool | None = None) -> dict[str, Any]:
        with self.lock:
            package_name = self.current_target.get("package_name")
            if not package_name:
                raise RuntimeError("No previous target available to restart.")

            next_spawn = self.current_target.get("spawn") if spawn is None else spawn
            device_id = self.current_target.get("device_id") or self.selected_device_id
            output_path = self.current_target.get("output_path") or self.selected_output_path

            self.detach_app()
            return self.attach_app(
                package_name=package_name,
                device_id=device_id,
                spawn=bool(next_spawn),
                pid=None,
                modules=list(self.selected_modules),
                reset_staging=True,
                compile_script=True,
                output_path=output_path,
            )

    def detach_app(self) -> dict[str, Any]:
        with self.lock:
            script = self.script
            session = self.session
            self.script = None
            self.session = None
            self.parser.script = None
            if self.current_target:
                self.current_target["attached"] = False
            output_path = self.output_path
            last_target = dict(self.current_target) if self.current_target else {}

        detached = False

        if script is not None:
            try:
                script.unload()
                detached = True
            except Exception:
                pass

        if session is not None:
            try:
                detach = getattr(session, "detach", None)
                if callable(detach):
                    detach()
                    detached = True
            except Exception:
                pass

        self._stop_recording()
        self._uninstall_stdout_proxy()

        with self.lock:
            return {
                "detached": detached,
                "last_target": last_target,
                "last_detach_reason": self.last_detach_reason,
                "output_path": output_path,
            }

    def fast_cleanup(self) -> None:
        # Use non-blocking acquire so SIGINT isn't blocked when attach_app
        # holds the lock on a slow Frida spawn.
        acquired = self.lock.acquire(blocking=False)
        try:
            self.script = None
            self.session = None
            self.parser.script = None
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

    def session_status(self) -> dict[str, Any]:
        with self.lock:
            return {
                "device_id": getattr(self.parser.device, "id", None),
                "selected_device_id": self.selected_device_id,
                "selected_output_path": self.selected_output_path,
                "selected_modules": self.selected_modules,
                "hook_script_length": len(self.agent_overlay_script),
                "attached": bool(self.session and self.script and self.current_target.get("attached")),
                "target": self.current_target,
                "last_detach_reason": self.last_detach_reason,
                "staged_modules": [mod.Name for mod in self.parser.modManager.staged],
                "event_count": len(self.events),
                "recording": self.recording_file is not None,
                "output_path": self.output_path,
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
                }

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
                }

            lines = max(1, min(lines, 2000))
            with target.open("r", encoding="utf-8", errors="replace") as handle:
                content_lines = handle.readlines()

            total_lines = len(content_lines)
            start_line = since_line if since_line is not None else line_offset
            if start_line is None:
                start_line = max(0, total_lines - lines)
            start_line = max(0, min(start_line, total_lines))
            end_line = min(total_lines, start_line + lines)
            tail = "".join(content_lines[start_line:end_line])
            return {
                "output_path": str(target),
                "content": tail,
                "line_count": end_line - start_line,
                "exists": True,
                "source": source,
                "total_lines": total_lines,
                "start_line": start_line,
                "next_line": end_line,
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
        bridge.fast_cleanup()
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


@mcp.tool()
def list_devices() -> list[dict[str, str]]:
    """List Frida-visible devices."""
    return bridge.list_devices()


@mcp.tool()
def select_device(device_id: str) -> dict[str, str]:
    """Select the active Frida device for subsequent tool calls."""
    return bridge.select_device(device_id=device_id)


@mcp.tool()
def stage_module(module_name: str) -> dict[str, Any]:
    """Add one Medusa module or prefix match to the staged MCP module set."""
    return bridge.stage_module(module_name=module_name)


@mcp.tool()
def clear_modules() -> dict[str, Any]:
    """Clear the staged MCP module set."""
    return bridge.clear_modules()


@mcp.tool()
def list_modules(
    prefix: str | None = None,
    category: str | None = None,
    pattern: str | None = None,
) -> dict[str, Any]:
    """Browse Medusa modules by optional prefix, category, or substring filter."""
    return bridge.list_modules(prefix=prefix, category=category, pattern=pattern)


@mcp.tool()
def get_module_source(module_name: str) -> dict[str, Any]:
    """Return a Medusa module's metadata and JavaScript source."""
    return bridge.get_module_source(module_name=module_name)


@mcp.tool()
def list_staged_modules() -> dict[str, Any]:
    """Show selected modules, currently active staged modules, and hook-script state."""
    return bridge.list_staged_modules()


@mcp.tool()
def set_output_path(output_path: str) -> dict[str, Any]:
    """Set the default file or directory used for session output logs, updating a live session if one exists."""
    return bridge.set_output_path(output_path=output_path)


@mcp.tool()
def clear_output_path() -> dict[str, Any]:
    """Clear the default output path used for session output logs."""
    return bridge.clear_output_path()


@mcp.tool()
def get_hook_script() -> dict[str, Any]:
    """Return the current MCP agent hook overlay script."""
    return bridge.get_hook_script()


@mcp.tool()
def set_hook_script(script: str, reload_if_attached: bool = True) -> dict[str, Any]:
    """Replace the current MCP agent hook overlay, compile it, and return any immediate post-reload events."""
    return bridge.set_hook_script(script=script, reload_if_attached=reload_if_attached)


@mcp.tool()
def append_hook_script(script: str, reload_if_attached: bool = True) -> dict[str, Any]:
    """Append JavaScript to the current MCP agent hook overlay, compile it, and return any immediate post-reload events."""
    return bridge.append_hook_script(script=script, reload_if_attached=reload_if_attached)


@mcp.tool()
def clear_hook_script(reload_if_attached: bool = True) -> dict[str, Any]:
    """Clear the MCP agent hook overlay, compile the empty result, and return any immediate post-reload events."""
    return bridge.clear_hook_script(reload_if_attached=reload_if_attached)


@mcp.tool()
def list_packages(device_id: Any = None, scope: str = "-3") -> dict[str, Any]:
    """List installed Android packages for a device."""
    return bridge.list_packages(device_id=_normalize_device_id(device_id), scope=scope)


@mcp.tool()
def search_modules(pattern: str) -> list[str]:
    """Search Medusa modules by substring."""
    return bridge.search_modules(pattern)


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
) -> dict[str, Any]:
    """Attach Medusa to an app and load the compiled agent script."""
    return bridge.attach_app(
        package_name=package_name,
        device_id=_normalize_device_id(device_id),
        spawn=spawn,
        pid=pid,
        modules=modules,
        reset_staging=reset_staging,
        compile_script=compile_script,
        output_path=_normalize_output_path(output_path),
    )


@mcp.tool()
def restart_app(spawn: bool | None = None) -> dict[str, Any]:
    """Restart the last target app using the remembered modules, scratchpad, and output path."""
    return bridge.restart_app(spawn=spawn)


@mcp.tool()
def detach_app() -> dict[str, Any]:
    """Detach the current Medusa/Frida session."""
    return bridge.detach_app()


@mcp.tool()
def session_status() -> dict[str, Any]:
    """Return the current Medusa MCP session state."""
    return bridge.session_status()


@mcp.tool()
def recent_events(limit: int = 50) -> list[dict[str, Any]]:
    """Return the in-memory event buffer for Frida send/error/attach/detach notifications plus mirrored console output."""
    return bridge.recent_events(limit=limit)


@mcp.tool()
def tail_output(
    lines: int = 200,
    since_line: int | None = None,
    line_offset: int | None = None,
) -> dict[str, Any]:
    """Read the on-disk Medusa output log by tail or from a specific line offset, with fallback to the selected output path."""
    return bridge.tail_output(lines=lines, since_line=since_line, line_offset=line_offset)


def main() -> None:
    transport = os.getenv("MEDUSA_MCP_TRANSPORT", "streamable-http")
    signal.signal(signal.SIGINT, _handle_termination)
    signal.signal(signal.SIGTERM, _handle_termination)
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()

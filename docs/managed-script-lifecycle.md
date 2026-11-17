# Managed script cleanup

Interactive Android and iOS sessions prepare the replacement script before
unloading the current one. Reload and the in-session `e` command ask the current
script to clean up its registered resources before unloading. Existing command
names, prompts and ordinary hook output are preserved.

Generated agents include `MedusaLifecycle`. Existing modules continue to work;
cleanup covers resources explicitly registered with this helper. It cannot
enumerate arbitrary Java listeners or prove that every unmanaged hook was undone.
The interactive CLI and MCP adapter use this shared cleanup mechanism. The
standalone `frida` CLI retains its existing host lifecycle policy.

## Android activity callbacks

Within your existing `Java.perform` block, replace:

```javascript
application.registerActivityLifecycleCallbacks(observer);
```

with:

```javascript
MedusaLifecycle.registerActivityLifecycleCallbacks(application, observer);
```

The helper retains the application and observer wrappers, registers the observer,
and unregisters that exact object while the old script is still usable. This
removes the listener registration; it does not unload a class created using
`Java.registerClass`. Use distinct class names when creating classes repeatedly.

## Other resources

Register a cleanup function immediately after acquiring a resource. It can return
a Promise when cleanup is asynchronous. Cleanup runs in reverse registration order.

```javascript
const listener = Interceptor.attach(address, { onEnter() { console.log('called'); } });
MedusaLifecycle.addCleanup('native observer', () => listener.detach());

const timer = MedusaLifecycle.setInterval(() => console.log('tick'), 1000);
```

For Java resources, use `Java.performNow` inside the cleanup function when all
needed wrappers are already available. Use `Java.retain` for wrappers that must
survive beyond the callback in which they were obtained. These APIs follow
[Frida's JavaScript API](https://frida.re/docs/javascript-api/).

The helper uses a reserved `medusa:lifecycle` message type; it leaves `rpc.exports`
available to modules. A cleanup response reports completed actions, errors, and
the remaining registered-resource count. Registration of new managed resources
is rejected once cleanup starts.

## Failure handling

Preparation failures leave the old script untouched. A cleanup failure or timeout
stops replacement and retains the current script handle. Cleanup can partially
succeed, so the retained script is not necessarily fully functional afterward.
Retry `r` to retry failed actions; successful actions are not repeated. After the
five-second cleanup acknowledgement timeout, a retry waits for the original
request instead of starting another concurrent cleanup.

An unload failure prevents replacement. If loading the replacement fails after
partial execution, its handle is retained for cleanup. A failed `e` keeps the
interactive session open so cleanup can be retried. The implementation does not
restart the app, clear data, or claim that a failed load rolled back app effects.

Only cleanup acknowledgement has a five-second deadline. Frida's create, load
and unload calls retain their existing synchronous behavior in the interactive
CLI. MCP runs them in tracked workers with the deadlines described below.

Session and script generations filter stale events without changing ordinary log
lines. A session gets one detach subscription, including across repeated reloads.

## MCP lifecycle results

`set_hook_script`, `append_hook_script`, and `clear_hook_script` preserve the
existing fields and add `reload_result`, session/script generation IDs,
`frida_transport_alive`, `script_loaded`, `lifecycle_status`, `cleanup_blocked`,
`cleanup_result`, and `last_cleanup`. Script load state can be `null` after an
ambiguous load/unload failure. A successful cleanup report is retained with the
generation it belongs to, even after a replacement script starts.

Compilation/assembly failure returns `compiled=false`. A Frida JavaScript syntax
error can occur after assembly succeeded: `compiled=true`, `reloaded=false`,
with the exact exception, stage and traceback in `reload_result.error`.

Reload, attach and detach timeouts keep their operations and handles tracked.
Mutating calls are blocked until the worker completes and cleanup finishes. A
late reload is never silently accepted as a successful tool call: its new script
is cleaned up. A failure while preparing the replacement leaves the old script
available. Cleanup errors retain the relevant handle and allow explicit cleanup
retry rather than permitting an overlapping attachment.

If the Frida transport disappears while a script still exists, MCP blocks
same-process reattachment with uncertain cleanup. It checks the previous target
PID against the device's process PID list, independently of package names, before
allowing a fresh attach after process exit. An unavailable PID probe
keeps the block in place. These checks never relaunch the app or clear data.

`session_status` and `session_summary` expose process, transport, script and
recording state separately, plus the last reload and cleanup results. Script
message events have generation IDs; events and deferred cleanup from an older session
cannot clear a newer session's state or close its recording.

## MCP failure and process diagnostics (P1)

The primary `failure_classification` preserves the underlying exception and failed
operation. A Frida stop timeout is reported as `process_stop_timeout`, even when
its message also mentions an output log. Output failures are identified by the
actual output-file operation or a failed writability check. Log read/metadata
errors use `log_inspection_failed` rather than claiming that the path is unwritable.

The MCP adapter observes exceptions from the device calls used by the legacy
attach handler, including errors that handler logs and suppresses. The interactive
handler and its existing caller-requested spawn/fallback behavior are preserved.

`process_condition` and `output_condition` expose independent observations, so a
Frida failure, frozen process and log-permission problem can be represented at the
same time. `output_path_ready` is the configured path's writability result, or
`null` when recording has no configured path. A concrete current exception takes
precedence over those secondary conditions.

| Field | Meaning |
|---|---|
| `app_alive`, `process_alive` | At least one application PID, or the original target PID, is confirmed present. `process_alive` is the compatibility alias for application presence. |
| `package_process_alive`, `process_pids` | Result of the package-name PID lookup. |
| `target_pid_alive`, `target_pid` | Presence of the original PID, checked independently when the package lookup does not contain it. Session reuse requires this exact PID to be confirmed alive. |
| `pid_changed` | The old PID is confirmed absent while the application has other PIDs. This is distinct from `app_not_running`. |
| `process_frozen`, `process_cached`, `process_state_code` | Values from the exact PID's ActivityManager block. Missing, ambiguous, restricted or timed-out observations remain `null`. |
| `process_background` | `true` when Android explicitly reports cached/frozen state; otherwise `null`, since uncached does not by itself prove foreground state. |
| `device_reachable` | ADB reachability observed during the read-only process probes. Frida transport/script flags separately describe the lifecycle state. |

PID and freezer inspection share the configured status timeout budget. A failed
freezer probe does not erase independently confirmed PID liveness. The probe never
changes Android's freezer configuration or brings an app to the foreground.

Failures carry an operation ID, target snapshot and session/script generations.
`last_failure` may retain history; `last_failure_is_current` says whether it still
applies to the current attempt and target. A new operation or target prevents an
old failure from becoming the current diagnosis. Successful log-path operations
clear the previous path error. An unsubstantiated historical log diagnosis is
ignored when the path checks healthy; an actual file-operation exception remains
visible even when the path is writable, since disk exhaustion and other I/O
failures are independent of permission checks.

Recovery guidance favors foregrounding an existing frozen app, waiting for tracked
cleanup, or attaching to a confirmed replacement PID with `spawn=False`. App
relaunch or spawn requires explicit caller approval and preservation of account
and data state. Classification and status inspection themselves never restart an
app or clear its data.

## Validation

The host tests inject preparation, compilation, cleanup, unload, and load
failures; delayed cleanup responses; overlapping operations; and stale events.
JavaScript tests exercise the actual helper with mocked Android registrations,
timers and asynchronous cleanup. Device-specific behavior still needs a controlled
Android/iOS smoke test before merging this branch into `dev`.

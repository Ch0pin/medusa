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

## Validation

The host tests inject preparation, compilation, cleanup, unload, and load
failures; delayed cleanup responses; overlapping operations; and stale events.
JavaScript tests exercise the actual helper with mocked Android registrations,
timers and asynchronous cleanup. Device-specific behavior still needs a controlled
Android/iOS smoke test before merging this branch into `dev`.

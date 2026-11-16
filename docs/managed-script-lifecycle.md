# Managed script cleanup

Interactive Android and iOS sessions prepare the replacement script before
unloading the current one. Reload and the in-session `e` command ask the current
script to clean up its registered resources before unloading. Existing command
names, prompts and ordinary hook output are preserved.

Generated agents include `MedusaLifecycle`. Existing modules continue to work;
cleanup covers resources explicitly registered with this helper. It cannot
enumerate arbitrary Java listeners or prove that every unmanaged hook was undone.
These changes concern the interactive CLI. The MCP adapter and standalone
`frida` CLI retain their existing host lifecycle policies.

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
and unload calls retain their existing synchronous behavior.

Session and script generations filter stale events without changing ordinary log
lines. A session gets one detach subscription, including across repeated reloads.

## Validation

The host tests inject preparation, compilation, cleanup, unload, and load
failures; delayed cleanup responses; overlapping operations; and stale events.
JavaScript tests exercise the actual helper with mocked Android registrations,
timers and asynchronous cleanup. Device-specific behavior still needs a controlled
Android/iOS smoke test before merging this branch into `dev`.

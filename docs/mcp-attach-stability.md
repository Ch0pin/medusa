# MCP post-attach observation

MCP observes a newly loaded session before reporting a successful attachment. The default observation window is one second. It repeatedly checks the exact target PID through ADB, Frida's session state, and the loaded script's identity/state. Interactive Medusa's CLI is unchanged.

Set `MEDUSA_MCP_ATTACH_STABILITY_WINDOW` when starting the MCP server. Values from 0 to 10 seconds are accepted; 0 explicitly disables the additional delay. For example:

```sh
MEDUSA_MCP_ATTACH_STABILITY_WINDOW=2 MEDUSA_MCP_TRANSPORT=streamable-http /Users/ch0pin/Desktop/medusa/.venv/bin/python /Users/ch0pin/Desktop/medusa/medusa_android_mcp.py
```

The observation stage uses bounded PID probes and allows a final probe of up to 0.5 seconds after the requested window. It is separate from the existing attach and status timeouts. It reads SDK session/script state without invoking RPC exports, Java methods, or application actions. During observation, `attach_operation.phase` is `stabilizing`, and other session mutations remain blocked.

## Responses

`attach_app`, `ensure_session`, `session_status`, and `session_summary` expose `attach_stability`. Its status is `observing`, `passed`, `failed`, `inconclusive`, or `disabled`. Completed reports include the requested and observed durations, check counts, exact PID, session/script generations, module names, the last health sample, the available Frida detach reason, and up to ten recent console/error records (each limited to 1,000 characters).

An observed PID exit, session loss, or script loss produces `action: attach_unstable` and the corresponding failure category. An unknown PID or script-state check produces `attach_unverified`, preserving the distinction between detected failure and missing evidence. A final status snapshot that already reports a dead/detached target cannot be returned with `action: attached`.

`attached` describes the tracked attachment state; an inconclusive observation can retain a live attachment. Callers should inspect `action`, `attach_stability`, and `failure_classification` before proceeding. A disabled window is explicitly labelled and is never reported as passed.

Reusing a session that has passed its observation does not repeat the delay. An inconclusive observation can be checked again through `ensure_session` or a reusable `attach_app` call without replacing the session or script. Old generation verdicts do not apply after a script/session replacement.

## Failure handling and limits

The observer does not restart, respawn, or automatically reattach the application. Session/script handles remain available to the existing cleanup workflow; uncertain cleanup remains guarded. Frida may report detachment after ADB has already confirmed PID exit, so `detach_reason` may be null. Medusa reports the observed PID/session failure without guessing a native crash cause from older application logs.

A passed window establishes only the recorded observations. Later crashes, application responsiveness, and successful installation or triggering of every individual hook require separate evidence. These SDK-state checks are not an agent RPC heartbeat.

## Validation

Twenty-two focused tests cover healthy windows, early exits, SDK detach flags, script destruction, unknown probes, time limits, final-response races, generation changes, reuse, disabled checks, and lock behavior. The existing lifecycle/recovery suites continue to run with their focused fixtures.

Live validation on 2026-11-25 used an isolated MCP adapter and a disposable background-service APK on a Pixel 5a running Android 14. The healthy attachment passed five checks over approximately 1.06 seconds and answered an RPC request. A second attach deliberately terminated only the fixture process after script load; the tool returned `attach_unstable` after approximately 0.58 seconds, with PID-exit evidence, recent fixture output, and `attached: false`. The Frida detach reason was unavailable at that instant and remained null. The disposable APK was removed after validation.

```sh
/Users/ch0pin/Desktop/medusa/.venv/bin/python -B -m unittest discover -s /Users/ch0pin/Desktop/medusa/tests -p test_mcp_attach_stability.py -v
```

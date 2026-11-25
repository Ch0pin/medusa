# MCP device recovery

The MCP adapter refreshes the selected Frida device object when `select_device` is called, including when the identifier is unchanged. This corrects the former ID-only shortcut that could report a newly enumerated phone while retaining its obsolete handle.

For an attach-only operation (`spawn=false`), a typed Frida `InvalidOperationError` containing `device is gone` or `device is lost` permits at most one recovery attempt. The adapter re-enumerates devices, binds the exact requested ID, and retries `attach` against the same failed PID. It does not re-enter package resolution, staging, compilation, or log setup for the retry.

## Retry conditions

The first attach records the PID's process name and kernel start time together with the device boot ID using a read-only, bounded ADB call. Before a retry those values must be obtainable and identical. An unavailable identity probe does not prevent a normal first attach; it prevents automatic retry after device loss.

A retry also requires an active, unexpired attach operation and no retained script, session, pending reload, or uncertain cleanup. Spawn requests and errors during script creation/loading are outside automatic recovery. Recovery never calls spawn, kill, resume, or app-data clearing. A late successful attach is detached without loading its script.

The existing attach timeout bounds the overall operation, including recovery. As with other slow Frida calls, a timed-out worker remains tracked until cleanup completes. Other session mutations stay blocked during that cleanup. Device enumeration refreshes the handle through the existing Frida manager; the adapter does not close or replace the process-wide manager. If its backend remains unhealthy, recovery reports the failure instead of repeatedly retrying or restarting the application.

## Diagnostics

`attach_app`, `session_status`, and `session_summary` include `device_recovery` when recovery was considered. Failures retain that record in `last_failure`, and `recent_events` includes a `device-recovery` event. Fields include the operation ID, device ID, failed PID, enumeration visibility, before/after identity observations, retry attempt, skip reason and outcome. Enumeration visibility is `true` or `false` after a successful enumeration, and `null` when enumeration itself fails.

The failure category `device_lost` is distinct from ADB being offline. A failed second attach retains its own underlying exception category, while the recovery record retains the original device-loss error. Error messages include the enumeration and retry outcomes for callers that have not requested a separate status snapshot.

The selected modules, scratchpad/overlay, compiled source, and output path are preserved across recovery. The active log is opened only once and retains its existing append behavior. Interactive Medusa's CLI/device code is unchanged by this MCP-specific implementation.

## Verification

The recovery tests use fake Frida devices, sessions, and ADB responses. They cover same-ID reselection, exact-PID retry, changed/recycled PIDs, reboot detection, absent devices, unknown identities, uncertain cleanup, spawn requests, second failures, late completion, and preservation of script/module/log configuration.

```sh
/Users/ch0pin/Desktop/medusa/.venv/bin/python -B -m unittest discover -s /Users/ch0pin/Desktop/medusa/tests -p test_mcp_device_recovery.py -v
```

Live validation on 2026-11-25 also passed on a Pixel 5a running Android 14, with Frida client 17.27.4 and Java bridge 7.0.13. A disposable background-service APK was attached through an isolated adapter instance. Closing only a temporary, test-owned Frida device manager produced a genuinely lost device handle and the native `InvalidOperationError: device is gone`; the adapter refreshed it and recovered the same process, with matching PID, boot ID, kernel start time, and process name.

The recovered script executed Java code and answered RPC requests. Module/overlay output appeared once, existing log content was preserved, and reselecting the same device kept the live script usable. Detaching left the test PID alive, and the disposable APK was then removed. Existing operator scratchpad and generated-agent files retained their hashes. The complete suite passed 222 tests, including the five Android SDK integration tests.

This exercises real stale-handle recovery without unplugging USB or restarting a shared Frida server. Physical USB interruption and unhealthy manager/backend scenarios remain distinct failure modes; they retain the bounded-retry and cleanup safeguards described above.

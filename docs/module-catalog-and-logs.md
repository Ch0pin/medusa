# Module catalogs and compact diagnostic views

These changes cover additional module roots, validated imports, and optional aggregation of repeated diagnostic output. Catalog operations do not execute JavaScript or reload an attached application. Raw recording files remain complete.

## Module roots

Set `MEDUSA_MODULE_ROOTS` before starting Medusa or its Android MCP server. The built-in modules directory is always scanned first. Separate additional roots with the operating system's path separator (`:` on macOS/Linux, `;` on Windows). Relative roots are anchored to the checkout, independently of the launch directory.

```sh
MEDUSA_MODULE_ROOTS=/Users/ch0pin/Desktop/Git-Projects/medusa_private MEDUSA_MCP_TRANSPORT=streamable-http /Users/ch0pin/Desktop/medusa/.venv/bin/python /Users/ch0pin/Desktop/medusa/medusa_android_mcp.py
```

Android loads `.med`; iOS loads `.imed`. The original built-in traversal order is preserved. Explicit symlink roots are supported; nested directory symlinks are reported as skipped and can be configured as explicit roots. Repeated paths resolving to the same file are deduplicated. Importing a JNI module from another directory retains initialization based on its declared `JNICalls` category.

Interactive `reload` uses these roots and retains its existing staging-reset/recipe behavior. Its startup messages remain the same. MCP provides a separate `refresh_modules` operation that preserves staged work.

## MCP refresh and import

`refresh_modules` rescans the catalog. Its optional `additional_roots` argument changes the extra roots for that server session. Omitting it reuses the current configuration; `[]` selects only the built-in root. Persistent startup defaults come from `MEDUSA_MODULE_ROOTS`.

```json
{"additional_roots": ["/Users/ch0pin/Desktop/Git-Projects/medusa_private"]}
```

The new index is built before it replaces the current one. Staged module objects, their order, selected modules, scratchpad contents and the MCP overlay are preserved. If a staged source changes, disappears or becomes invalid, its in-memory version remains available and is listed in `retained_staged`. To adopt an edited staged file, explicitly unstage it and refresh/import it again, then compile or reload when appropriate.

`import_module` loads a specific `.med` under its declared `Name`, even when the filename differs. It returns source metadata and code length, without copying the code into scratchpad. `stage` defaults to `true` and selects/stages it for a later compile or attach; it does not change the active script. A repeated import of identical content is idempotent. Imports are remembered across catalog refreshes within that server session.

```json
{"module_path": "/Users/ch0pin/Desktop/Git-Projects/medusa_private/root_detection/frida_root_bypass.med", "stage": true}
```

Files must contain string `Name`, `Description`, `Help` and `Code` fields. `Options` can be a list, object or null. Legacy multiline JSON code strings remain supported. Invalid files are reported with paths and JSON line/column information where available; failed parses never enter the catalog as `None`. Validation checks the module format; JavaScript compilation remains a separate step.

Different files declaring the same name are rejected rather than shadowing one another. This matters when both a repository copy and an external private copy exist. Resolve the source conflict or use distinct declared names. Existing staged replacements and scratchpad edits are protected.

`list_modules` retains its existing names/count/categories and adds roots, source paths and scan errors. `get_module_source` includes source-file hashes and preservation metadata. File hashes identify file snapshots; returned code can reflect retained in-memory edits. Catalog responses report at most 100 errors and include the total error count and truncation flag.

## Optional log aggregation

Existing output remains unchanged by default. Enable `set_console_aggregation` with:

```json
{"enabled": true}
```

The first occurrence of a console line remains visible. Consecutive identical repetitions are summarized with a total and additional count. Long-running repetitions receive periodic summaries as messages arrive; pending counts and partial text are flushed when output changes, recording changes, an explicit flush occurs, or the proxy is removed. Groups reset at observed session/script/PID or output-file boundaries. Context fields describe host observation state, not independently proven attribution of a delayed message to a particular Java hook.

In-memory console records retain `repeat_count`, first/last receive timestamps and event sequence positions. Structured error and lifecycle events keep separate entries. `raw_event_count` counts records before aggregation. Hook-update responses use event sequence positions, so growth of an existing repeat group remains visible; `new_repeat_count` distinguishes new occurrences from the group's cumulative total.

Raw log files retain every original write, including repetitions. These options reduce display/context volume and in-memory noise; they do not reduce raw log file size.

`recent_events` also supports `compact: true` for a read-only compact view of the retained event buffer. This works independently of live console aggregation. Already-aggregated records remain explicit records with counts when reading without that option.

`tail_output` supports `compact: true`:

```json
{"lines": 2000, "line_offset": 0, "compact": true}
```

Each summary identifies one-based physical source line ranges. `line_count`, `next_line` and cursor offsets continue to count raw source lines; `display_line_count` describes the compact presentation. `repeat_groups` applies only to the returned slice (`summary_scope: returned_raw_lines`), so a group spanning pages is counted separately on each page. Neither reading mode rewrites the file. Blank lines and nonidentical values retain their original content.

Restart/reconnect the MCP server/client once to expose the new tools and parameters. Subsequent `refresh_modules` calls refresh the module catalog without restarting the server or disturbing the active script.

## Validation

Thirty-seven focused tests cover malformed modules, name collisions, ordering, external roots, staged/scratchpad preservation, imports during active sessions, complete raw logs, fragmented writes, counters, generation boundaries, cursor pagination, and concurrent console delivery.

Live validation on 2026-11-25 used a disposable background-service APK on a Pixel 5a running Android 14. An externally imported module executed normally. Catalog refresh discovered an additional module while the existing script remained usable through RPC. A 334-line diagnostic burst produced a repeat count of 334, and all 334 occurrences remained in the raw log. Compact tail reported the exact source range (lines 5–338), and reading it left the raw log hash unchanged. The disposable APK was removed after validation.

```sh
/Users/ch0pin/Desktop/medusa/.venv/bin/python -B -m unittest discover -s /Users/ch0pin/Desktop/medusa/tests -p test_module_catalog.py -v
/Users/ch0pin/Desktop/medusa/.venv/bin/python -B -m unittest discover -s /Users/ch0pin/Desktop/medusa/tests -p test_log_aggregation.py -v
```

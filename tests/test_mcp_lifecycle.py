"""MCP lifecycle regressions using fake Frida sessions and temporary agents."""
import contextlib
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from libraries.core.modules import Module
from libraries.core.sessions import MANAGED_MARKER, ScriptLifecycleError, reload_script
from test_script_lifecycle import Session


class FridaSession(Session):
    def __init__(self):
        super().__init__()
        self.detach_calls = 0

    def detach(self):
        self.detach_calls += 1
        for script in self.scripts:
            script.is_destroyed = True
        super().detach()


class MCPLifecycleTests(unittest.TestCase):
    def setUp(self):
        from libraries.integrations import mcp_android
        self.module = mcp_android
        self.context = contextlib.ExitStack()
        self.addCleanup(self.context.close)
        directory = self.context.enter_context(tempfile.TemporaryDirectory())
        self.context.enter_context(patch.object(mcp_android, 'ROOT', Path(directory)))
        self.context.enter_context(patch.object(mcp_android.medusa_app, 'agent_script', 'fixture-agent'))
        self.context.enter_context(patch.object(mcp_android.medusa_app.Parser, 'do_reload', lambda *args: None))
        self.bridge = mcp_android.MedusaAndroidBridge()
        self.addCleanup(self.bridge.cleanup)
        bridge = self.bridge
        bridge.parser.pid = 123
        bridge.parser.device = SimpleNamespace(id='fixture-device', name='Fixture', type='usb', resume=Mock())
        bridge.parser.my_message_handler = Mock()
        bridge.parser.on_detached = Mock()
        bridge._ensure_device = Mock(return_value={'id': 'fixture-device', 'name': 'Fixture', 'type': 'usb'})
        bridge._start_recording = Mock()
        bridge._stop_recording = Mock()
        bridge._uninstall_stdout_proxy = Mock()
        bridge._process_status = Mock(return_value={
            'process_alive': True, 'process_pids': [123], 'process_alive_error': None,
            'app_alive': True, 'target_pid_alive': True, 'target_pid': 123,
            'pid_changed': False, 'device_reachable': True,
        })
        bridge._target_pid_alive = Mock(return_value=True)
        bridge._inspect_output_log = Mock(return_value={'writable': True, 'module_banners': {}})
        scratch = Module(str(Path(directory) / 'scratchpad.med'), 'scratchpad', '', '', '// human work')
        bridge.parser.modManager.available.append(scratch)
        self.scratchpad = scratch
        def compile_agent(*args):
            bridge.parser.state.session.compile_error = None
            bridge.agent_script_path.write_text(MANAGED_MARKER + '\n' + bridge.agent_overlay_script)
        bridge.parser.do_compile = Mock(side_effect=compile_agent)
        self.finished = queue.Queue()
        record = bridge._record_event
        def record_and_notify(message, payload=None):
            record(message, payload)
            if message['type'] in {'reload-completed', 'attach-timeout-cleanup', 'detach-completed'}:
                self.finished.put(message)
        bridge._record_event = record_and_notify
        self.session = FridaSession()
        bridge.parser.frida_session_handler = Mock(return_value=self.session)
        bridge.agent_script_path.write_text(MANAGED_MARKER)
        bridge.attach_app('fixture.package', spawn=False, compile_script=False)
        self.old_script = bridge.script

    def wait_for(self, event_type):
        while True:
            event = self.finished.get(timeout=2)
            if event['type'] == event_type:
                return event

    def test_reload_uses_cleanup_and_one_detach_callback(self):
        for _ in range(3):
            result = self.bridge.set_hook_script('// new')
            self.assertTrue(result['reloaded'])
            self.assertTrue(result['script_loaded'])
            self.assertTrue(result['frida_transport_alive'])
            self.assertEqual(result['last_cleanup']['remaining'], 0)
        self.assertTrue(self.old_script.is_destroyed)
        self.assertEqual(len(self.session.callbacks), 1)
        self.assertEqual(self.bridge.session_summary()['script_generation'], 4)
        self.assertEqual(self.scratchpad.Code, '// human work')

    def test_compile_failure_is_reported_without_reloading_stale_file(self):
        def failed_compile(*args):
            self.bridge.parser.state.session.compile_error = 'fixture assembly error'
        self.bridge.parser.do_compile.side_effect = failed_compile
        result = self.bridge.set_hook_script('// broken')
        self.assertFalse(result['compiled'])
        self.assertFalse(result['reloaded'])
        self.assertEqual(result['compile_error']['stage'], 'compile')
        self.assertIs(self.bridge.script, self.old_script)
        self.assertFalse(self.old_script.is_destroyed)
        self.assertEqual(self.scratchpad.Code, '// human work')

    def test_reload_exception_preserves_original_type_and_message(self):
        self.session.create_error = 'SyntaxError: fixture.js:17 unexpected token'
        result = self.bridge.set_hook_script('// invalid')
        self.assertTrue(result['compiled'])  # Assembly succeeded; Frida rejected JS.
        self.assertFalse(result['reloaded'])
        error = result['reload_result']['error']
        self.assertEqual(error['stage'], 'prepare')
        self.assertEqual(error['exception_type'], 'RuntimeError')
        self.assertIn('fixture.js:17', error['exception_message'])
        self.assertIn('RuntimeError', error['traceback'])
        self.assertIs(self.bridge.script, self.old_script)
        self.assertTrue(result['attached'])

    def test_cleanup_failure_stops_reload_and_automatic_same_pid_reattach(self):
        self.old_script.cleanup_reply = {'ok': False, 'errors': ['unregister observer failed'], 'remaining': 1}
        result = self.bridge.set_hook_script('// replacement')
        self.assertFalse(result['reloaded'])
        self.assertTrue(result['cleanup_blocked'])
        self.assertEqual(result['cleanup_result']['remaining'], 1)
        calls = self.bridge.parser.frida_session_handler.call_count
        with self.assertRaisesRegex(ScriptLifecycleError, 'cleanup is unconfirmed'):
            self.bridge.ensure_session('fixture.package', spawn=False, force_restart=True)
        self.assertEqual(self.bridge.parser.frida_session_handler.call_count, calls)
        self.assertEqual(self.session.detach_calls, 0)
        self.old_script.cleanup_reply = {'ok': True, 'remaining': 0}
        self.assertTrue(self.bridge.set_hook_script('// corrected')['reloaded'])

    def test_unload_failure_does_not_lose_original_handle(self):
        self.old_script.unload_error = 'Frida unload failed'
        result = self.bridge.set_hook_script('// replacement')
        self.assertEqual(result['reload_result']['error']['stage'], 'unload')
        self.assertIs(self.bridge.script, self.old_script)
        self.assertIsNone(result['script_loaded'])
        self.assertTrue(result['frida_transport_alive'])

    def test_partial_load_failure_retains_candidate_for_explicit_cleanup(self):
        self.session.next_load_error = 'failed after partial execution'
        result = self.bridge.set_hook_script('// replacement')
        self.assertEqual(result['reload_result']['error']['stage'], 'load')
        candidate = self.session.scripts[-1]
        self.assertIs(self.bridge.script, candidate)
        self.assertIsNone(result['script_loaded'])
        self.assertTrue(self.bridge.detach_app()['detached'])
        self.assertTrue(candidate.is_destroyed)

    def block_next_load(self):
        entered, release = threading.Event(), threading.Event()
        original = self.session.create_script
        def create(source):
            script = original(source)
            load = script.load
            def blocked_load():
                entered.set()
                if not release.wait(2):
                    raise RuntimeError('test load gate was not released')
                load()
            script.load = blocked_load
            return script
        self.session.create_script = create
        self.addCleanup(release.set)
        return entered, release

    def test_reload_timeout_blocks_mutations_and_disposes_late_candidate(self):
        entered, release = self.block_next_load()
        with self.bridge.lock:
            self.assertFalse(self.bridge._reload_active_script(timeout=0.02))
        self.assertTrue(entered.is_set())
        self.assertIsNotNone(self.bridge.reload_in_progress)
        candidate = self.session.scripts[-1]
        self.assertIs(self.bridge._lifecycle.script, candidate)
        for action in (lambda: self.bridge.set_hook_script('// overlap'), self.bridge.detach_app,
                       lambda: self.bridge.ensure_session('fixture.package', spawn=False)):
            with self.assertRaisesRegex(RuntimeError, 'still in progress'):
                action()
        release.set()
        event = self.wait_for('reload-completed')
        self.assertTrue(event['timed_out'])
        self.assertFalse(event['reloaded'])
        self.assertTrue(candidate.is_destroyed)
        self.assertIsNone(self.bridge.script)
        self.assertIsNone(self.bridge.reload_in_progress)
        self.assertTrue(self.bridge._has_live_session())

    def test_late_cleanup_failure_retains_candidate_and_blocks_reattach(self):
        entered, release = self.block_next_load()
        self.assertFalse(self.bridge._reload_active_script(timeout=0.02))
        candidate = self.session.scripts[-1]
        candidate.cleanup_reply = {'ok': False, 'errors': ['callback busy'], 'remaining': 1}
        release.set()
        event = self.wait_for('reload-completed')
        self.assertIn('callback busy', event['cleanup_error']['message'])
        self.assertIs(self.bridge.script, candidate)
        self.assertTrue(self.bridge.cleanup_blocked)
        self.assertIsNone(self.bridge.reload_in_progress)
        candidate.cleanup_reply = {'ok': True, 'remaining': 0}
        self.assertTrue(self.bridge.detach_app()['detached'])

    def test_cleanup_ack_timeout_reuses_request_and_recovers(self):
        self.old_script.cleanup_reply = None
        def quick_reload(*args, **kwargs):
            return reload_script(*args, **kwargs, cleanup_timeout=0)
        with patch.object(self.module, 'reload_script', side_effect=quick_reload):
            result = self.bridge.set_hook_script('// pending')
        self.assertFalse(result['reloaded'])
        self.assertEqual(result['lifecycle_status'], 'cleanup_pending')
        self.old_script.reply(self.old_script.posts[0], {'ok': True, 'remaining': 0})
        self.assertTrue(self.bridge.set_hook_script('// retry')['reloaded'])
        self.assertEqual(len(self.old_script.posts), 1)

    def test_stale_events_and_deferred_detach_cannot_clear_new_session(self):
        generation = self.bridge._lifecycle.session_generation
        self.assertTrue(self.bridge.detach_app()['detached'])
        newer = FridaSession()
        self.bridge.parser.frida_session_handler.return_value = newer
        self.bridge.attach_app('fixture.package', spawn=False, compile_script=False)
        active = self.bridge.script
        stopped_before = self.bridge._stop_recording.call_count
        self.old_script.emit({'type': 'send', 'payload': 'stale'})
        self.session.detach()
        self.bridge._deferred_detach_cleanup('connection-terminated', generation)
        self.assertIs(self.bridge.script, active)
        self.assertTrue(self.bridge.session_status()['attached'])
        self.assertEqual(self.bridge._stop_recording.call_count, stopped_before)
        self.assertFalse(any(event.get('payload') == 'stale' for event in self.bridge.events))

    def test_live_pid_after_unexpected_detach_is_not_reattached(self):
        self.session.detach()
        self.assertTrue(self.bridge.session_summary()['process_alive'])
        self.assertFalse(self.bridge.session_summary()['frida_transport_alive'])
        with self.assertRaisesRegex(ScriptLifecycleError, 'Same-process reattachment is blocked'):
            self.bridge.ensure_session('fixture.package', spawn=False)
        self.assertEqual(self.bridge.parser.frida_session_handler.call_count, 1)

    def test_confirmed_old_pid_exit_allows_explicit_attach_to_fresh_pid(self):
        self.session.detach()
        self.bridge._target_pid_alive.return_value = False
        self.bridge._process_status.return_value = {
            'process_alive': False, 'process_pids': [456], 'process_alive_error': None,
        }
        newer = FridaSession()
        self.bridge.parser.pid = 456
        self.bridge.parser.frida_session_handler.return_value = newer
        result = self.bridge.attach_app('fixture.package', spawn=False, compile_script=False)
        self.assertEqual(result['target']['pid'], 456)
        self.assertIs(self.bridge.session, newer)
        self.bridge.parser.device.resume.assert_not_called()

    def test_detach_failure_is_retryable_and_never_claimed_successful(self):
        self.old_script.cleanup_reply = {'ok': False, 'errors': ['observer busy'], 'remaining': 1}
        result = self.bridge.detach_app()
        self.assertFalse(result['detached'])
        self.assertEqual(result['error']['stage'], 'cleanup')
        self.assertIs(self.bridge.script, self.old_script)
        self.assertEqual(self.session.detach_calls, 0)
        self.old_script.cleanup_reply = {'ok': True, 'remaining': 0}
        self.assertTrue(self.bridge.detach_app()['detached'])

    def test_generation_is_in_runtime_events_and_summary(self):
        self.old_script.emit({'type': 'send', 'payload': 'fixture event'})
        event = self.bridge.events[-1]
        summary = self.bridge.session_summary()
        self.assertEqual(event['script_generation'], summary['script_generation'])
        self.assertEqual(event['session_generation'], summary['session_generation'])
        self.assertTrue(summary['script_loaded'])

    def test_detach_timeout_keeps_operation_until_late_completion(self):
        release = threading.Event()
        self.addCleanup(release.set)
        unload = self.old_script.unload
        def blocked_unload():
            if not release.wait(2):
                raise RuntimeError('test unload gate was not released')
            unload()
        self.old_script.unload = blocked_unload
        self.bridge.detach_timeout_seconds = 0.02
        result = self.bridge.detach_app()
        self.assertTrue(result['detach_timed_out'])
        self.assertFalse(result['detached'])
        self.assertIsNotNone(self.bridge.detach_in_progress)
        self.assertIs(self.bridge.script, self.old_script)
        with self.assertRaisesRegex(RuntimeError, 'still in progress'):
            self.bridge.attach_app('fixture.package', spawn=False, force_restart=True)
        release.set()
        self.assertTrue(self.wait_for('detach-completed')['detached'])
        self.assertIsNone(self.bridge.script)
        self.assertIsNone(self.bridge.detach_in_progress)

    def test_late_attach_is_cleaned_before_allowing_another_attach(self):
        self.assertTrue(self.bridge.detach_app()['detached'])
        self.session = FridaSession()
        self.bridge.parser.frida_session_handler.return_value = self.session
        entered, release = self.block_next_load()
        self.bridge.attach_timeout_seconds = 0.02
        with self.assertRaisesRegex(RuntimeError, 'Timed out'):
            self.bridge.attach_app('fixture.package', spawn=False, compile_script=False)
        self.assertTrue(entered.is_set())
        candidate = self.session.scripts[-1]
        with self.assertRaisesRegex(RuntimeError, 'cleanup is still pending'):
            self.bridge.attach_app('fixture.package', spawn=False, compile_script=False)
        release.set()
        cleanup = self.wait_for('attach-timeout-cleanup')
        self.assertTrue(cleanup['cleaned'])
        self.assertTrue(candidate.is_destroyed)
        self.assertEqual(self.session.detach_calls, 1)
        self.assertIsNone(self.bridge.attach_in_progress)

    def test_failed_attach_does_not_forget_failed_cleanup(self):
        self.assertTrue(self.bridge.detach_app()['detached'])
        newer = FridaSession()
        newer.next_load_error = 'load failed'
        create = newer.create_script
        def create_failing_script(source):
            script = create(source)
            script.cleanup_reply = {'ok': False, 'errors': ['observer busy'], 'remaining': 1}
            return script
        newer.create_script = create_failing_script
        self.bridge.parser.frida_session_handler.return_value = newer
        with self.assertRaisesRegex(ScriptLifecycleError, 'load failed'):
            self.bridge.attach_app('fixture.package', spawn=False, compile_script=False)
        self.assertTrue(self.bridge.cleanup_blocked)
        self.assertIs(self.bridge.script, newer.scripts[-1])
        self.assertEqual(newer.detach_calls, 0)
        self.assertIn('observer busy', self.bridge.last_failure['cleanup_error'])

    def test_detach_during_load_never_reports_attach_success(self):
        self.assertTrue(self.bridge.detach_app()['detached'])
        newer = FridaSession()
        create = newer.create_script
        def create_detaching_script(source):
            script = create(source)
            script.load = newer.detach
            return script
        newer.create_script = create_detaching_script
        self.bridge.parser.frida_session_handler.return_value = newer
        with self.assertRaisesRegex(ScriptLifecycleError, 'detached during load'):
            self.bridge.attach_app('fixture.package', spawn=False, compile_script=False)
        self.assertFalse(self.bridge.session_status()['attached'])

    def test_failed_pid_probe_does_not_clear_uncertain_cleanup(self):
        self.session.detach()
        self.bridge._target_pid_alive.return_value = None
        self.bridge._process_status.return_value = {
            'process_alive': None, 'process_pids': [], 'process_alive_error': 'device offline',
        }
        with self.assertRaises(ScriptLifecycleError):
            self.bridge.attach_app('fixture.package', spawn=False, compile_script=False)
        self.assertIs(self.bridge.script, self.old_script)

    def test_package_pid_mismatch_does_not_prove_target_pid_exited(self):
        self.session.detach()
        self.bridge._process_status.return_value = {'process_alive': False, 'process_pids': [456]}
        with self.assertRaises(ScriptLifecycleError):
            self.bridge.attach_app('fixture.package', spawn=False, compile_script=False)
        self.assertIs(self.bridge.script, self.old_script)

    def test_exact_pid_probe_distinguishes_absent_from_unknown(self):
        probe = type(self.bridge)._target_pid_alive
        target = {'device_id': 'fixture-device', 'pid': 123}
        for stdout, stderr, code, expected in (
            ('PID\n1\n123\n', '', 0, True), ('PID\n1\n456\n', '', 0, False),
            ('PID\n', '', 0, None), ('', 'device offline', 1, None),
            ('PID\n1\nunexpected\n', '', 0, None),
        ):
            with self.subTest(stdout=stdout), patch.object(self.module.subprocess, 'run',
                    return_value=SimpleNamespace(stdout=stdout, stderr=stderr, returncode=code)) as run:
                self.assertIs(probe(self.bridge, target), expected)
                self.assertEqual(run.call_args.args[0],
                                 ['adb', '-s', 'fixture-device', 'shell', 'ps', '-A', '-o', 'PID'])
        with patch.object(self.module.subprocess, 'run', side_effect=subprocess.TimeoutExpired('adb', 2)):
            self.assertIsNone(probe(self.bridge, target))

    def test_deferred_detach_during_locked_tool_does_not_close_new_recording(self):
        cleaned = threading.Event()
        original = self.bridge._deferred_detach_cleanup
        def deferred(reason, generation):
            try:
                original(reason, generation)
            finally:
                cleaned.set()
        self.bridge._deferred_detach_cleanup = deferred
        with self.bridge.lock:
            worker = threading.Thread(target=self.session.detach, daemon=True)
            worker.start()
            worker.join(timeout=0.5)
            self.assertFalse(worker.is_alive(), 'Frida callback waited on the tool lock')
            self.assertFalse(cleaned.is_set())
            newer = FridaSession()
            self.bridge.parser.frida_session_handler.return_value = newer
            self.bridge._target_pid_alive.return_value = False
            self.bridge.attach_app('fixture.package', spawn=False, compile_script=False)
            stopped_before = self.bridge._stop_recording.call_count
        self.assertTrue(cleaned.wait(1))
        self.assertEqual(self.bridge._stop_recording.call_count, stopped_before)
        self.assertTrue(self.bridge.session_status()['attached'])

    def test_shutdown_status_cannot_claim_an_active_session(self):
        self.bridge.fast_cleanup()
        self.assertFalse(self.bridge.session_status()['attached'])
        self.assertFalse(self.bridge.session_status()['frida_transport_alive'])
        self.assertEqual(self.bridge.session_status()['lifecycle_status'], 'shutdown')


if __name__ == '__main__':
    unittest.main()

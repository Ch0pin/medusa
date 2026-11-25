"""MCP-only device recovery with fake Frida objects and read-only ADB fixtures."""
import subprocess
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from libraries.core.modules import Module
from libraries.core.sessions import ScriptLifecycleError
import test_mcp_lifecycle as fixtures


class DeviceRecoveryTests(unittest.TestCase):
    def setUp(self):
        fixtures.MCPLifecycleTests.setUp(self)
        self.assertTrue(self.bridge.detach_app()['detached'])
        self.session = fixtures.FridaSession()
        self.session._impl = SimpleNamespace(pid=123)
        self.gone = self.module.frida.InvalidOperationError('device is gone')
        self.old = self.device('cached', side_effect=self.gone)
        self.fresh = self.device('fresh', session=self.session)
        self.bridge.parser.device = self.old
        self.controller = SimpleNamespace(id='fixture-device', get_int_pid=Mock(return_value=123))
        self.bridge.parser.device_controller = self.controller
        self.bridge.parser.native_handler = SimpleNamespace(device=self.old)
        self.bridge.parser.frida_session_handler = Mock(wraps=self.module.medusa_app.Parser.frida_session_handler.__get__(self.bridge.parser))
        self.enumerate = self.context.enter_context(patch.object(self.module.frida, 'enumerate_devices', return_value=[self.fresh]))
        self.context.enter_context(patch.object(self.module.medusa_app.time, 'sleep'))
        self.context.enter_context(patch.object(self.module.medusa_app, 'logger'))
        self.controller_factory = self.context.enter_context(patch.object(self.module.medusa_app, 'AndroidDevice'))
        self.bridge._start_recording.reset_mock()
        self.bridge._ensure_device.reset_mock()
        self.bridge.parser.do_compile.reset_mock()
        self.before = dict(self.bridge._read_attach_identity.return_value)
        self.bridge._read_attach_identity.reset_mock()

    def device(self, name, *, side_effect=None, session=None, identity='fixture-device'):
        return SimpleNamespace(id=identity, name=name, type='usb', is_lost=False,
                               attach=Mock(return_value=session, side_effect=side_effect),
                               spawn=Mock(return_value=123), kill=Mock(), resume=Mock())

    def attach(self, **kwargs):
        return self.bridge.attach_app('fixture.package', spawn=False, compile_script=False, **kwargs)

    def assert_no_relaunch(self):
        for device in (self.old, self.fresh):
            device.spawn.assert_not_called()
            device.kill.assert_not_called()
            device.resume.assert_not_called()

    def test_same_id_selection_binds_the_enumerated_object(self):
        result = self.bridge.select_device('fixture-device')
        self.assertEqual(result['name'], 'fresh')
        self.assertIs(self.bridge.parser.device, self.fresh)
        self.assertIs(self.bridge.parser.native_handler.device, self.fresh)
        self.assertIs(self.bridge.parser.device_controller, self.controller)
        self.bridge._ensure_device.assert_not_called()
        self.controller_factory.assert_not_called()

    def test_recovery_retries_once_and_preserves_configuration(self):
        bridge = self.bridge
        module = Module('fixture.med', 'fixture-observer', '', '', '// module')
        bridge.parser.modManager.available.append(module)
        bridge.selected_modules = ['fixture-observer']
        bridge.agent_overlay_script = '// operator overlay'
        bridge.selected_output_path = str(bridge.agent_script_path.with_suffix('.log'))
        scratch_before = self.scratchpad.Code
        result = bridge.attach_app('fixture.package', spawn=False)
        self.old.attach.assert_called_once_with(123)
        self.fresh.attach.assert_called_once_with(123)
        bridge.parser.frida_session_handler.assert_called_once()
        self.controller.get_int_pid.assert_called_once_with('fixture.package')
        self.assertEqual(bridge._read_attach_identity.call_count, 2)
        self.assertEqual(bridge.parser.do_compile.call_count, 1)
        bridge._start_recording.assert_called_once_with('fixture.package', bridge.selected_output_path)
        self.assertEqual(bridge.selected_modules, ['fixture-observer'])
        self.assertEqual(bridge.agent_overlay_script, '// operator overlay')
        self.assertEqual(self.scratchpad.Code, scratch_before)
        self.assertIn('// operator overlay', self.session.scripts[0].source)
        self.assertTrue(result['target']['attached'])
        self.assertEqual(result['device']['name'], 'fresh')
        self.assertEqual(result['device_recovery']['outcome'], 'recovered')
        self.assertTrue(result['device_recovery']['retry_attempted'])
        self.assertTrue(result['device_recovery']['device_enumerated'])
        self.assertIsNone(bridge.last_failure)
        self.assertIsNone(bridge._invalid_device)
        self.controller_factory.assert_not_called()
        self.assert_no_relaunch()

    def test_explicit_pid_is_preserved_without_package_reresolution(self):
        self.attach(pid=123)
        self.controller.get_int_pid.assert_not_called()
        self.fresh.attach.assert_called_once_with(123)
        self.assert_no_relaunch()

    def test_retry_does_not_initialize_an_unneeded_adb_controller(self):
        self.bridge.parser.device_controller = None
        result = self.attach(pid=123)
        self.assertTrue(result['target']['attached'])
        self.controller_factory.assert_not_called()

    def test_unknown_identity_does_not_block_a_successful_first_attach(self):
        self.old.attach.side_effect = None
        self.old.attach.return_value = self.session
        self.bridge._read_attach_identity.return_value = {'verified': False, 'error': 'permission denied'}
        result = self.attach(pid=123)
        self.assertTrue(result['target']['attached'])
        self.assertIsNone(result['device_recovery'])
        self.enumerate.assert_not_called()

    def test_reselecting_same_device_keeps_the_live_session_and_script(self):
        self.old.attach.side_effect = None
        self.old.attach.return_value = self.session
        self.attach()
        script = self.bridge.script
        self.bridge.select_device('fixture-device')
        self.assertIs(self.bridge.script, script)
        self.assertIs(self.bridge.session, self.session)
        self.assertEqual(self.session.detach_calls, 0)
        self.assertIs(self.bridge.parser.device, self.fresh)

    def test_recovery_keeps_existing_log_and_opens_it_only_once(self):
        path = self.bridge.agent_script_path.with_suffix('.log')
        path.write_text('existing log evidence\n')
        self.bridge.selected_output_path = str(path)
        self.bridge._install_stdout_proxy = Mock()
        cls = type(self.bridge)
        self.bridge._start_recording = Mock(wraps=cls._start_recording.__get__(self.bridge))
        self.bridge._stop_recording = Mock(wraps=cls._stop_recording.__get__(self.bridge))
        result = self.attach()
        self.bridge.recording_file.flush()
        self.assertEqual(path.read_text(), 'existing log evidence\n')
        self.bridge._start_recording.assert_called_once_with('fixture.package', str(path))
        self.assertEqual(result['output_path'], str(path.resolve()))

    def test_healthy_attach_does_not_refresh_or_retry(self):
        self.old.attach.side_effect = None
        self.old.attach.return_value = self.session
        result = self.attach()
        self.assertIsNone(result['device_recovery'])
        self.enumerate.assert_not_called()
        self.fresh.attach.assert_not_called()
        self.assertEqual(len(self.session.scripts), 1)

    def test_other_attach_errors_are_not_retried(self):
        self.old.attach.side_effect = self.module.frida.TimedOutError('unexpectedly timed out while waiting for stop from process')
        with self.assertRaises(ScriptLifecycleError):
            self.attach()
        self.assertEqual(self.bridge.last_failure['category'], 'process_stop_timeout')
        self.enumerate.assert_not_called()
        self.fresh.attach.assert_not_called()
        self.assert_no_relaunch()

    def test_repeated_device_loss_is_classified_and_stops_after_one_retry(self):
        self.fresh.attach.side_effect = self.module.frida.InvalidOperationError('device is gone')
        with self.assertRaisesRegex(ScriptLifecycleError, 'device_enumerated=True; retry_attempted=True'):
            self.attach()
        self.assertEqual(self.bridge.last_failure['category'], 'device_lost')
        self.assertEqual(self.bridge.last_failure['device_recovery']['outcome'], 'failed')
        self.old.attach.assert_called_once_with(123)
        self.fresh.attach.assert_called_once_with(123)
        self.enumerate.assert_called_once()
        self.assertIs(self.bridge._invalid_device, self.fresh)
        self.assert_no_relaunch()

    def test_second_failure_keeps_its_own_underlying_cause(self):
        self.fresh.attach.side_effect = self.module.frida.PermissionDeniedError('fixture denied')
        with self.assertRaises(ScriptLifecycleError):
            self.attach()
        self.assertEqual(self.bridge.last_failure['category'], 'frida_permission_denied')
        self.assertEqual(self.bridge.last_failure['exception_message'], 'fixture denied')
        self.assertEqual(self.bridge.last_failure['device_recovery']['original_error'], 'device is gone')

    def test_missing_exact_device_never_falls_back_to_another_phone(self):
        other = self.device('other phone', session=self.session, identity='other-id')
        self.enumerate.return_value = [other]
        with self.assertRaisesRegex(ScriptLifecycleError, 'device_enumerated=False'):
            self.attach()
        self.assertEqual(self.bridge.last_device_recovery['skip_reason'], 'device_absent_or_enumeration_failed')
        self.fresh.attach.assert_not_called()
        other.attach.assert_not_called()
        self.assert_no_relaunch()

    def test_failed_enumeration_reports_unknown_visibility(self):
        self.enumerate.side_effect = self.module.frida.TransportError('enumeration unavailable')
        with self.assertRaisesRegex(ScriptLifecycleError, 'device_enumerated=None'):
            self.attach()
        self.assertIsNone(self.bridge.last_device_recovery['device_enumerated'])
        self.assertEqual(self.bridge.last_device_recovery['enumeration_error'], 'enumeration unavailable')
        self.fresh.attach.assert_not_called()

    def test_lost_candidate_is_rejected(self):
        self.fresh.is_lost = True
        with self.assertRaisesRegex(ScriptLifecycleError, 'device_refresh_failed'):
            self.attach()
        self.fresh.attach.assert_not_called()
        self.assertIs(self.bridge.parser.device, self.old)

    def test_unknown_original_process_identity_disables_retry(self):
        self.bridge._read_attach_identity.return_value = {'pid': 123, 'verified': False, 'error': 'permission denied'}
        with self.assertRaisesRegex(ScriptLifecycleError, 'original_process_identity_unverified'):
            self.attach()
        self.fresh.attach.assert_not_called()
        self.assertEqual(self.bridge._read_attach_identity.call_count, 1)

    def test_changed_pid_boot_start_time_or_process_name_disables_retry(self):
        for field, value in (('pid', 456), ('boot_id', 'another boot'), ('start_time_ticks', '99999'), ('process_name', 'another.package')):
            with self.subTest(field=field):
                self.bridge._read_attach_identity.side_effect = [self.before, dict(self.before, **{field: value})]
                with self.assertRaisesRegex(ScriptLifecycleError, 'process_identity_changed'):
                    self.attach(pid=123)
                self.fresh.attach.assert_not_called()
                self.assert_no_relaunch()

    def test_disappeared_process_disables_retry(self):
        self.bridge._read_attach_identity.side_effect = [self.before, {'verified': False, 'pid': 123, 'error': 'no process'}]
        with self.assertRaisesRegex(ScriptLifecycleError, 'current_process_identity_unverified'):
            self.attach()
        self.fresh.attach.assert_not_called()

    def test_uncertain_cleanup_blocks_retry_and_remains_visible(self):
        def fail(_pid):
            self.bridge.cleanup_blocked = True
            raise self.gone
        self.old.attach.side_effect = fail
        with patch.object(self.bridge, '_dispose_runtime', side_effect=ScriptLifecycleError('cleanup', 'still uncertain')):
            with self.assertRaisesRegex(ScriptLifecycleError, 'cleanup_not_confirmed'):
                self.attach()
        self.assertTrue(self.bridge.cleanup_blocked)
        self.assertIn('still uncertain', self.bridge.last_failure['cleanup_error'])
        self.fresh.attach.assert_not_called()
        self.bridge.cleanup_blocked = False  # release the synthetic guard for fixture teardown

    def test_spawn_request_does_not_gain_an_automatic_retry(self):
        with self.assertRaisesRegex(ScriptLifecycleError, 'spawn_requested'):
            self.bridge.attach_app('fixture.package', spawn=True, compile_script=False)
        self.old.spawn.assert_called_once_with(['fixture.package'])
        self.old.attach.assert_called_once_with(123)
        self.fresh.attach.assert_not_called()
        self.old.kill.assert_not_called()
        self.old.resume.assert_not_called()
        self.bridge._read_attach_identity.assert_not_called()

    def test_script_stage_device_loss_is_not_retried(self):
        self.old.attach.side_effect = None
        self.old.attach.return_value = self.session
        with patch.object(self.module, 'start_script', side_effect=self.gone):
            with self.assertRaises(ScriptLifecycleError):
                self.attach()
        self.assertEqual(self.bridge.last_failure['category'], 'device_lost')
        self.assertEqual(self.bridge.last_device_recovery['skip_reason'], 'failure_after_attach')
        self.fresh.attach.assert_not_called()
        self.assertEqual(self.session.detach_calls, 1)

    def test_recovery_works_when_caller_owns_tool_lock(self):
        self.bridge.attach_timeout_seconds = 0.3
        with self.bridge.lock:
            result = self.attach()
        self.assertTrue(result['target']['attached'])

    def test_timeout_during_identity_check_prevents_retry(self):
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        def delayed_identity(*args):
            if self.bridge._read_attach_identity.call_count == 2:
                entered.set()
                release.wait(2)
            return self.before
        self.bridge._read_attach_identity.side_effect = delayed_identity
        self.bridge.attach_timeout_seconds = 0.02
        with self.assertRaisesRegex(RuntimeError, 'Timed out'):
            self.attach()
        self.assertTrue(entered.is_set())
        release.set()
        fixtures.MCPLifecycleTests.wait_for(self, 'attach-timeout-cleanup')
        self.fresh.attach.assert_not_called()
        self.assertEqual(self.bridge.last_device_recovery['skip_reason'], 'shutdown_or_attach_deadline')

    def test_late_retry_session_is_detached_without_loading_script(self):
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        def delayed_attach(_pid):
            entered.set()
            release.wait(2)
            return self.session
        self.fresh.attach.side_effect = delayed_attach
        self.bridge.attach_timeout_seconds = 0.02
        with self.assertRaisesRegex(RuntimeError, 'Timed out'):
            self.attach()
        self.assertTrue(entered.is_set())
        release.set()
        cleaned = fixtures.MCPLifecycleTests.wait_for(self, 'attach-timeout-cleanup')
        self.assertTrue(cleaned['cleaned'])
        self.assertEqual(self.session.scripts, [])
        self.assertEqual(self.session.detach_calls, 1)
        self.assert_no_relaunch()

    def test_invalid_cached_handle_is_reacquired_on_next_explicit_attempt(self):
        self.bridge._invalid_device = self.old
        result = type(self.bridge)._ensure_device(self.bridge, 'fixture-device')
        self.assertEqual(result['name'], 'fresh')
        self.assertIs(self.bridge.parser.device, self.fresh)
        self.assertIsNone(self.bridge._invalid_device)
        self.controller_factory.assert_not_called()

    def test_invalid_cached_handle_reports_visibility_before_a_new_attach(self):
        self.bridge._invalid_device = self.old
        self.enumerate.return_value = []
        with self.assertRaisesRegex(ScriptLifecycleError, 'device_enumerated=False; retry_attempted=False'):
            type(self.bridge)._ensure_device(self.bridge, 'fixture-device')
        self.assertFalse(self.bridge.last_device_recovery['device_enumerated'])
        self.assertIs(self.bridge._invalid_device, self.old)
        self.old.attach.assert_not_called()
        self.fresh.attach.assert_not_called()

    def test_status_and_summary_include_recovery_details(self):
        self.attach()
        for value in (self.bridge.session_status(), self.bridge.session_summary()):
            self.assertEqual(value['device_recovery']['outcome'], 'recovered')
            self.assertTrue(value['device_recovery']['retry_attempted'])

    def test_generic_message_is_not_enough_to_authorize_recovery(self):
        self.assertFalse(self.bridge._is_device_gone(RuntimeError('device is gone')))
        self.assertTrue(self.bridge._is_device_gone(self.gone))

    def test_process_identity_parser_uses_start_time_and_boot_id(self):
        reader = type(self.bridge)._read_attach_identity
        stat = '123 (fixture process) S ' + ' '.join(['0'] * 18 + ['12345'])
        stdout = self.before['boot_id'] + '\n' + stat + '\nfixture.package\x00private argument\x00'
        response = SimpleNamespace(returncode=0, stderr='', stdout=stdout)
        with patch.object(self.module.subprocess, 'run', return_value=response) as run:
            result = reader(self.bridge, 'fixture-device', 123, timeout=0.5)
        self.assertTrue(result['verified'])
        self.assertEqual(result['start_time_ticks'], '12345')
        self.assertEqual(result['process_name'], 'fixture.package')
        self.assertNotIn('private argument', str(result))
        self.assertEqual(run.call_args.args[0], ['adb', '-s', 'fixture-device', 'shell', 'cat',
                         '/proc/sys/kernel/random/boot_id', '/proc/123/stat', '/proc/123/cmdline'])
        self.assertEqual(run.call_args.kwargs['timeout'], 0.5)

    def test_process_identity_errors_and_malformed_data_are_unknown(self):
        reader = type(self.bridge)._read_attach_identity
        for response in (SimpleNamespace(returncode=1, stderr='permission denied', stdout=''),
                         SimpleNamespace(returncode=0, stderr='', stdout='invalid output')):
            with patch.object(self.module.subprocess, 'run', return_value=response):
                self.assertFalse(reader(self.bridge, 'fixture-device', 123)['verified'])
        with patch.object(self.module.subprocess, 'run', side_effect=subprocess.TimeoutExpired('adb', 0.1)):
            self.assertFalse(reader(self.bridge, 'fixture-device', 123)['verified'])
        with patch.object(self.module.subprocess, 'run') as run:
            self.assertFalse(reader(self.bridge, 'fixture-device', 123, timeout=0)['verified'])
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()

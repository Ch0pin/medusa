"""MCP-only exception and process diagnostics; device calls are mocked."""
import subprocess
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from libraries.core.sessions import ScriptLifecycleError
import test_mcp_lifecycle as lifecycle_fixtures


FROZEN = '''  *APP* UID 10001 ProcessRecord{aaa 999:other.app/u0a1}
    cached=false empty=false
    isPendingFreeze=false isFrozen=false
  *APP* UID 10213 ProcessRecord{d932df 123:fixture.package/u0a213}
    pid=123
    curProcState=15 mRepProcState=15 setProcState=15
    cached=true empty=false
    isPendingFreeze=false isFrozen=true
  *APP* UID 10002 ProcessRecord{bbb 777:another.app/u0a2}
    cached=false empty=false
    isPendingFreeze=false isFrozen=false
'''


class FailureClassificationTests(unittest.TestCase):
    def setUp(self):
        lifecycle_fixtures.MCPLifecycleTests.setUp(self)
        self.healthy_log = {'output_path': '/fixture/agent.log', 'writable': True,
                            'is_file': True, 'error': None, 'module_banners': {'appeared': True}}
        self.live = {'app_alive': True, 'target_pid': 123, 'target_pid_alive': True,
                     'process_alive': True, 'process_pids': [123], 'device_reachable': True,
                     'pid_changed': False, 'process_frozen': False}

    def classify(self, process=None, log=None):
        return self.bridge._classify_failure(process or self.live, log or self.healthy_log)

    def test_stop_timeout_is_never_reclassified_from_log_context(self):
        for suffix in ('', '; output log path=/fixture/agent.log'):
            with self.subTest(suffix=suffix):
                error = self.module.frida.TimedOutError('unexpectedly timed out while waiting for stop from process' + suffix)
                failure = self.bridge._set_failure_from_exception('attach_app', error)
                self.assertEqual(failure['category'], 'process_stop_timeout')
                result = self.classify()
                self.assertEqual(result['category'], 'process_stop_timeout')
                self.assertEqual(result['output_condition']['category'], 'none')
                self.assertIn('explicit caller approval', result['action'])

    def test_wrapper_preserves_root_exception_and_operation(self):
        cause = self.module.frida.TimedOutError('unexpectedly timed out while waiting for stop from process')
        wrapper = ScriptLifecycleError('attach', 'Attach failed; output log path=/fixture/agent.log')
        wrapper.__cause__ = cause
        failure = self.bridge._lifecycle_failure(wrapper)
        failure['cleanup_error'] = 'retained cleanup detail'
        outer = RuntimeError('Outer caller error with output_path=/fixture/agent.log')
        outer.__cause__ = wrapper
        self.assertIs(self.bridge._set_failure_from_exception('ensure_session', outer), failure)
        self.assertEqual(failure['exception_type'], 'TimedOutError')
        self.assertEqual(failure['exception_message'], str(cause))
        self.assertEqual(failure['cleanup_error'], 'retained cleanup detail')
        self.assertEqual(failure['operation_id'], self.bridge.failure_context['id'])

    def test_word_output_in_generic_attach_error_is_not_a_log_error(self):
        failure = self.bridge._set_failure_from_exception('attach_app', RuntimeError('Attach failed; output_path=/fixture/agent.log'))
        self.assertEqual(failure['category'], 'attach_failed')

    def test_log_health_is_independent_even_when_both_subsystems_fail(self):
        self.bridge._set_failure_from_exception('attach_app', self.module.frida.TimedOutError(
            'unexpectedly timed out while waiting for stop from process'))
        result = self.classify(log=dict(self.healthy_log, writable=False, writable_error='permission denied'))
        self.assertEqual(result['category'], 'process_stop_timeout')
        self.assertEqual(result['output_condition']['category'], 'log_path_failed')

    def test_log_read_error_does_not_claim_unwritable_path(self):
        result = self.classify(log=dict(self.healthy_log, error='invalid UTF-8 in log'))
        self.assertEqual(result['category'], 'log_inspection_failed')

    def test_typed_frida_errors_have_distinct_categories(self):
        for kind, category in (
            ('ServerNotRunningError', 'frida_offline'), ('TransportError', 'frida_transport_error'),
            ('ProcessNotFoundError', 'target_process_not_found'), ('PermissionDeniedError', 'frida_permission_denied'),
            ('TimedOutError', 'frida_timeout'), ('ProcessNotRespondingError', 'frida_timeout'),
        ):
            with self.subTest(kind=kind):
                error = getattr(self.module.frida, kind)('fixture error')
                self.assertEqual(self.bridge._set_failure_from_exception('attach_app', error)['category'], category)

    def test_syntax_error_is_reported_while_previous_script_is_still_attached(self):
        error = ScriptLifecycleError('prepare', 'SyntaxError: expecting comma at script.js:42')
        self.bridge._lifecycle_failure(error)
        self.assertTrue(self.bridge._is_attached())
        self.assertEqual(self.classify()['category'], 'script_compile_failed')

    def test_failure_does_not_follow_a_new_attempt_or_target(self):
        self.bridge._set_failure_from_exception('attach_app', RuntimeError('original attach error'))
        old_id = self.bridge.last_failure['operation_id']
        self.bridge._begin_failure_context('attach')
        self.assertNotEqual(self.bridge.failure_context['id'], old_id)
        self.assertEqual(self.classify()['category'], 'none')
        self.bridge._set_failure_from_exception('attach_app', RuntimeError('second attach error'))
        self.bridge.current_target['package_name'] = 'another.package'
        self.assertEqual(self.classify()['category'], 'none')

    def test_old_generation_failure_does_not_apply_to_new_script(self):
        self.bridge._lifecycle_failure(ScriptLifecycleError('load', 'previous failure'))
        self.bridge._lifecycle.script_generation += 1
        self.assertEqual(self.classify()['category'], 'none')

    def test_unsubstantiated_log_failure_is_not_reused_when_path_is_ready(self):
        failure = self.bridge._set_failure('log_path_failed', 'old wrapper claimed a path failure')
        failure['output_path'] = self.healthy_log['output_path']
        self.assertEqual(self.classify()['category'], 'none')

    def test_real_filesystem_error_is_not_erased_by_writability_alone(self):
        error = ScriptLifecycleError('output_log', 'No space left on device')
        error.__cause__ = OSError(28, 'No space left on device')
        self.bridge._lifecycle_failure(error)
        result = self.classify()
        self.assertEqual(result['category'], 'log_path_failed')
        self.assertEqual(result['output_condition']['category'], 'none')
        self.assertIn('No space left', result['exception_message'])

    def test_directory_named_like_log_file_is_not_ready(self):
        self.bridge._inspect_output_log.return_value = dict(self.healthy_log, is_directory=True, is_file=False)
        status = self.bridge.session_status()
        self.assertFalse(status['output_path_ready'])
        self.assertEqual(status['output_condition']['category'], 'log_path_failed')

    def test_cleanup_error_text_is_not_misread_as_attach_or_compile_failure(self):
        for text in ('SyntaxError raised by a custom cleanup callback',
                     'callback message: unexpectedly timed out while waiting for stop from process'):
            failure = self.bridge._lifecycle_failure(ScriptLifecycleError('cleanup', text))
            self.assertNotIn(failure['category'], {'process_stop_timeout', 'script_compile_failed'})
            self.assertEqual(failure['stage'], 'cleanup')

    def test_unrelated_read_error_does_not_replace_attach_failure(self):
        original = self.bridge._set_failure_from_exception('attach_app', RuntimeError('attach error'))
        self.assertIsNone(self.bridge._set_failure_from_exception('get_module_source', RuntimeError('module not found')))
        self.assertIs(self.bridge.last_failure, original)

    def test_replacement_pid_is_distinct_from_app_not_running(self):
        result = self.classify(process=dict(self.live, target_pid_alive=False, process_pids=[456], pid_changed=True))
        self.assertEqual(result['category'], 'target_pid_changed')
        self.assertIn('spawn=False', result['action'])

    def test_frozen_condition_preserves_the_underlying_timeout(self):
        self.bridge._lifecycle_failure(ScriptLifecycleError('cleanup', 'confirmation timed out'))
        result = self.classify(process=dict(self.live, process_frozen=True, process_state_pid=123))
        self.assertEqual(result['category'], 'cleanup_timeout')
        self.assertEqual(result['process_condition']['category'], 'process_frozen')
        self.assertIn('foreground', result['process_condition']['action'])

    def test_new_app_pid_cannot_reuse_the_old_session(self):
        self.bridge._process_status.return_value = dict(self.live, target_pid_alive=False, pid_changed=True, process_pids=[456])
        with self.assertRaisesRegex(RuntimeError, 'Refusing to replace active session'):
            self.bridge.ensure_session('fixture.package', spawn=False)

    def test_matching_original_pid_reuses_session(self):
        self.bridge._process_status.return_value = self.live
        result = self.bridge.ensure_session('fixture.package', spawn=False)
        self.assertEqual(result['action'], 'reused')
        self.assertEqual(self.bridge.parser.frida_session_handler.call_count, 1)

    def test_legacy_parser_swallowed_exception_is_captured_without_restart(self):
        self.assertTrue(self.bridge.detach_app()['detached'])
        error = self.module.frida.TimedOutError('unexpectedly timed out while waiting for stop from process')
        device = SimpleNamespace(id='fixture-device', attach=Mock(side_effect=error), spawn=Mock(), kill=Mock(), resume=Mock())
        self.bridge.parser.device = device
        self.bridge.parser.device_controller = SimpleNamespace(get_int_pid=Mock(return_value=123))
        handler = self.module.medusa_app.Parser.frida_session_handler.__get__(self.bridge.parser)
        self.bridge.parser.frida_session_handler = handler
        with patch.object(self.module.medusa_app.time, 'sleep'), patch.object(self.module.medusa_app, 'logger'):
            with self.assertRaises(ScriptLifecycleError):
                self.bridge.attach_app('fixture.package', spawn=False, compile_script=False)
        failure = self.bridge.last_failure
        self.assertEqual(failure['category'], 'process_stop_timeout')
        self.assertEqual(failure['target']['pid'], 123)
        self.assertEqual(failure['exception_type'], 'TimedOutError')
        device.attach.assert_called_once_with(123)
        device.spawn.assert_not_called()
        device.kill.assert_not_called()
        device.resume.assert_not_called()

    def test_summary_exposes_independent_health_fields(self):
        self.bridge._process_status.return_value = dict(self.live, process_cached=True, process_frozen=True, process_background=True)
        self.bridge._inspect_output_log.return_value = self.healthy_log
        result = self.bridge.session_summary()
        self.assertTrue(result['app_alive'])
        self.assertTrue(result['target_pid_alive'])
        self.assertTrue(result['process_frozen'])
        self.assertTrue(result['output_path_ready'])
        self.assertTrue(result['frida_transport_alive'])

    def test_output_open_error_has_explicit_stage_and_original_cause(self):
        self.bridge._install_stdout_proxy = Mock()
        path = str(self.bridge.agent_script_path.with_suffix('.log'))
        with patch('pathlib.Path.open', side_effect=PermissionError('fixture permission failure')):
            with self.assertRaises(ScriptLifecycleError) as error:
                type(self.bridge)._start_recording(self.bridge, 'fixture.package', path)
        self.assertEqual(error.exception.stage, 'output_log')
        self.assertEqual(self.bridge.last_failure['category'], 'log_path_failed')
        self.assertEqual(self.bridge.last_failure['exception_type'], 'PermissionError')

    def test_device_probe_preserves_successful_calls_and_attributes(self):
        session = object()
        device = SimpleNamespace(id='fixture', attach=Mock(return_value=session))
        probe = self.module._DeviceExceptionProbe(device)
        self.assertEqual(probe.id, 'fixture')
        self.assertIs(probe.attach(123, realm='native'), session)
        device.attach.assert_called_once_with(123, realm='native')
        self.assertIsNone(probe.last_error)

    def test_existing_spawn_fallback_can_still_succeed(self):
        self.assertTrue(self.bridge.detach_app()['detached'])
        session = lifecycle_fixtures.FridaSession()
        session._impl = SimpleNamespace(pid=456)
        device = SimpleNamespace(id='fixture-device', attach=Mock(return_value=session),
                                 spawn=Mock(side_effect=self.module.frida.NotSupportedError('fixture spawn error')),
                                 kill=Mock(), resume=Mock())
        self.bridge.parser.device = device
        self.bridge.parser.device_controller = SimpleNamespace(get_int_pid=Mock(side_effect=[None, 456]))
        self.bridge.parser.frida_session_handler = self.module.medusa_app.Parser.frida_session_handler.__get__(self.bridge.parser)
        with patch.object(self.module.medusa_app.time, 'sleep'), patch.object(self.module.medusa_app, 'logger'), \
                patch.object(self.module.subprocess, 'run') as run:
            result = self.bridge.attach_app('fixture.package', spawn=True, compile_script=False)
        self.assertTrue(result['target']['attached'])
        self.assertIsNone(self.bridge.last_failure)
        device.attach.assert_called_once_with(456)
        device.resume.assert_called_once_with(456)
        self.assertIn('monkey', run.call_args.args[0])

    def process_status(self, pidof_stdout, *, stderr='', code=0, pid_alive=True, state=None):
        self.bridge._target_pid_alive.return_value = pid_alive
        with patch.object(self.module.subprocess, 'run', return_value=SimpleNamespace(
                stdout=pidof_stdout, stderr=stderr, returncode=code)), \
                patch.object(self.bridge, '_android_process_state', return_value=state or {}) as probe:
            result = type(self.bridge)._process_status(self.bridge, self.bridge.current_target)
        return result, probe

    def test_process_status_replacement_pid_keeps_app_alive(self):
        status, probe = self.process_status('456\n', pid_alive=False)
        self.assertTrue(status['process_alive'])
        self.assertTrue(status['app_alive'])
        self.assertFalse(status['target_pid_alive'])
        self.assertTrue(status['pid_changed'])
        probe.assert_not_called()  # Do not attribute a new PID's freezer state to the old target.

    def test_name_lookup_miss_does_not_hide_still_alive_original_pid(self):
        status, _ = self.process_status('', code=1, pid_alive=True)
        self.assertTrue(status['app_alive'])
        self.assertTrue(status['target_pid_alive'])
        self.assertFalse(status['package_process_alive'])
        self.assertFalse(status['pid_changed'])

    def test_failed_exact_pid_probe_preserves_unknown(self):
        status, _ = self.process_status('', code=1, pid_alive=None)
        self.assertIsNone(status['app_alive'])
        self.assertIsNone(status['target_pid_alive'])
        self.assertIsNone(status['pid_changed'])

    def test_confirmed_absence_reports_app_not_running(self):
        status, _ = self.process_status('', code=1, pid_alive=False)
        self.assertFalse(status['app_alive'])
        self.assertEqual(self.classify(process=status)['category'], 'app_not_running')

    def test_device_offline_is_distinct_from_absent_app(self):
        status, probe = self.process_status('', code=1, stderr="adb: device 'fixture-device' not found")
        self.assertFalse(status['device_reachable'])
        self.assertIsNone(status['app_alive'])
        probe.assert_not_called()
        self.assertEqual(self.classify(process=status)['category'], 'device_offline')

    def test_malformed_pid_response_is_unknown(self):
        status, _ = self.process_status('123 invalid', pid_alive=None)
        self.assertIsNone(status['app_alive'])
        self.assertIn('invalid PID', status['process_alive_error'])

    def test_frozen_parser_selects_only_exact_pid_block(self):
        parse = self.bridge._parse_android_process_state
        self.assertTrue(parse(FROZEN, 123)['process_frozen'])
        self.assertTrue(parse(FROZEN, 123)['process_cached'])
        self.assertTrue(parse(FROZEN, 123)['process_background'])
        self.assertFalse(parse(FROZEN, 999)['process_frozen'])
        self.assertIsNone(parse(FROZEN, 999)['process_background'])
        self.assertIsNone(parse(FROZEN, 456)['process_frozen'])

    def test_unavailable_or_conflicting_freezer_state_is_unknown(self):
        parse = self.bridge._parse_android_process_state
        missing = FROZEN.replace('isFrozen=true', 'unavailable=true')
        conflicting = FROZEN.replace('isFrozen=true', 'isFrozen=true isFrozen=false')
        for dump in (missing, conflicting):
            self.assertIsNone(parse(dump, 123)['process_frozen'])
            self.assertIsNotNone(parse(dump, 123)['process_state_error'])

    def test_freezer_state_from_later_dump_section_is_not_used(self):
        dump = '  *APP* UID 10213 ProcessRecord{aaa 123:fixture.package/u0a213}\n    cached=true\n  OTHER SECTION:\n    isFrozen=true\n'
        self.assertIsNone(self.bridge._parse_android_process_state(dump, 123)['process_frozen'])

    def test_freezer_probe_timeout_keeps_confirmed_pid_alive(self):
        results = [SimpleNamespace(stdout='123', stderr='', returncode=0), subprocess.TimeoutExpired('dumpsys', 2)]
        with patch.object(self.module.subprocess, 'run', side_effect=results):
            status = type(self.bridge)._process_status(self.bridge, self.bridge.current_target)
        self.assertTrue(status['app_alive'])
        self.assertTrue(status['target_pid_alive'])
        self.assertIsNone(status['process_frozen'])
        self.assertIsNotNone(status['process_state_error'])

    def test_process_inspection_uses_one_shared_time_budget(self):
        calls = []
        def run(command, **kwargs):
            calls.append(kwargs['timeout'])
            if 'pidof' in command:
                time.sleep(0.01)
                return SimpleNamespace(stdout='123', stderr='', returncode=0)
            return SimpleNamespace(stdout=FROZEN, stderr='', returncode=0)
        with patch.object(self.module.subprocess, 'run', side_effect=run):
            status = type(self.bridge)._process_status(self.bridge, self.bridge.current_target)
        self.assertTrue(status['process_frozen'])
        self.assertLess(calls[1], calls[0])


if __name__ == '__main__':
    unittest.main()

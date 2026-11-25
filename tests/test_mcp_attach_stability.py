"""Post-attach observation through fake Frida sessions and bounded PID probes."""
import os
import unittest
from unittest.mock import Mock, patch

import test_mcp_lifecycle as fixtures


class AttachStabilityTests(unittest.TestCase):
    def setUp(self):
        fixtures.MCPLifecycleTests.setUp(self)
        self.assertTrue(self.bridge.detach_app()['detached'])
        self.session = fixtures.FridaSession()
        self.bridge.parser.frida_session_handler.return_value = self.session
        self.bridge.parser.frida_session_handler.reset_mock()
        self.bridge.attach_stability_window_seconds = 0.02
        self.bridge._target_pid_alive.reset_mock()
        self.device = self.bridge.parser.device

    def attach(self):
        return self.bridge.attach_app('fixture.package', spawn=False, compile_script=False)

    def test_pass_requires_initial_and_final_checks(self):
        result = self.attach()
        report = result['attach_stability']
        self.assertEqual(result['action'], 'attached')
        self.assertTrue(result['target']['attached'])
        self.assertEqual(report['status'], 'passed')
        self.assertGreaterEqual(report['checks'], 2)
        self.assertGreaterEqual(report['observed_seconds'], 0.02)
        self.assertEqual(report['pid'], 123)
        self.assertEqual(report['requested_window_seconds'], 0.02)
        self.assertEqual(report['last_check']['pid_alive'], True)
        self.assertIsNone(report['detach_reason'])
        self.assertIsNone(self.bridge.last_failure)
        self.assertEqual(self.bridge.session_summary()['attach_stability']['status'], 'passed')

    def test_pid_exit_is_reported_without_restarting_or_discarding_handles(self):
        self.bridge._target_pid_alive.side_effect = [True, False]
        result = self.attach()
        self.assertEqual(result['action'], 'attach_unstable')
        self.assertFalse(result['target']['attached'])
        self.assertEqual(result['attach_stability']['reason'], 'target_pid_exited')
        self.assertEqual(self.bridge.last_failure['category'], 'attach_unstable')
        self.assertIs(self.bridge.session, self.session)
        self.assertIsNotNone(self.bridge.script)
        self.assertEqual(self.session.detach_calls, 0)
        self.device.resume.assert_not_called()
        self.bridge.parser.frida_session_handler.assert_called_once()

    def test_detach_with_live_pid_is_distinguished_from_process_exit(self):
        def pid_check(*args, **kwargs):
            if self.bridge._target_pid_alive.call_count == 2:
                for callback in list(self.session.callbacks):
                    callback('connection-terminated', None)
            return True
        self.bridge._target_pid_alive.side_effect = pid_check
        result = self.attach()
        report = result['attach_stability']
        self.assertEqual(result['action'], 'attach_unstable')
        self.assertEqual(report['last_check']['pid_alive'], True)
        self.assertEqual(report['reason'], 'frida_session_detached')
        self.assertEqual(report['detach_reason'], 'connection-terminated')
        self.assertTrue(self.bridge.cleanup_blocked)

    def test_sdk_detached_flag_is_checked_even_before_callback_delivery(self):
        def pid_check(*args, **kwargs):
            self.session.is_detached = True
            return True
        self.bridge._target_pid_alive.side_effect = pid_check
        result = self.attach()
        self.assertEqual(result['action'], 'attach_unstable')
        self.assertFalse(self.bridge.session_status()['frida_transport_alive'])
        self.assertIsNone(result['attach_stability']['detach_reason'])

    def test_script_destruction_during_pid_probe_is_detected(self):
        def pid_check(*args, **kwargs):
            self.bridge._lifecycle.script.is_destroyed = True
            return True
        self.bridge._target_pid_alive.side_effect = pid_check
        result = self.attach()
        self.assertEqual(result['action'], 'attach_unstable')
        self.assertEqual(result['attach_stability']['reason'], 'script_unloaded')
        self.assertFalse(self.bridge.session_status()['script_loaded'])

    def test_unknown_pid_health_is_inconclusive_without_forcing_detach(self):
        self.bridge._target_pid_alive.return_value = None
        result = self.attach()
        self.assertEqual(result['action'], 'attach_unverified')
        self.assertEqual(result['attach_stability']['status'], 'inconclusive')
        self.assertEqual(self.bridge.last_failure['category'], 'attach_unverified')
        self.assertTrue(self.bridge._is_attached())
        self.assertEqual(self.session.detach_calls, 0)
        self.assertGreaterEqual(result['attach_stability']['unknown_checks'], 2)

    def test_probe_exception_is_an_unknown_health_result(self):
        self.bridge._target_pid_alive.side_effect = RuntimeError('fixture probe failure')
        result = self.attach()
        self.assertEqual(result['action'], 'attach_unverified')
        self.assertEqual(result['attach_stability']['last_check']['pid_error'], 'fixture probe failure')

    def test_zero_window_explicitly_disables_extra_checks(self):
        self.bridge.attach_stability_window_seconds = 0
        result = self.attach()
        self.assertEqual(result['action'], 'attached')
        self.assertEqual(result['attach_stability']['status'], 'disabled')
        self.assertEqual(result['attach_stability']['checks'], 0)
        self.bridge._target_pid_alive.assert_not_called()

    def test_inconclusive_window_can_be_rechecked_without_reattaching(self):
        self.bridge._target_pid_alive.return_value = None
        self.assertEqual(self.attach()['action'], 'attach_unverified')
        script = self.bridge.script
        self.bridge._target_pid_alive.return_value = True
        result = self.bridge.ensure_session('fixture.package', spawn=False)
        self.assertEqual(result['action'], 'reused')
        self.assertEqual(result['attach_stability']['status'], 'passed')
        self.assertFalse(result['changed'])
        self.assertIs(self.bridge.script, script)
        self.bridge.parser.frida_session_handler.assert_called_once()
        self.assertEqual(self.session.detach_calls, 0)
        self.assertIsNone(self.bridge.last_failure)

    def test_successful_reuse_does_not_repeat_the_window(self):
        self.attach()
        self.bridge._target_pid_alive.reset_mock()
        result = self.bridge.ensure_session('fixture.package', spawn=False)
        self.assertEqual(result['action'], 'reused')
        self.bridge._target_pid_alive.assert_not_called()

    def test_ensure_session_propagates_unstable_attach(self):
        self.bridge._target_pid_alive.side_effect = [True, False]
        result = self.bridge.ensure_session('fixture.package', spawn=False)
        self.assertEqual(result['action'], 'attach_unstable')
        self.assertEqual(result['attach']['action'], 'attach_unstable')
        self.assertFalse(result['status']['attached'])
        self.assertEqual(result['status']['failure_classification']['category'], 'attach_unstable')

    def test_exit_between_window_and_final_status_cannot_return_attached(self):
        live = dict(self.bridge._process_status.return_value)
        dead = dict(live, target_pid_alive=False, process_alive=False, app_alive=False, process_pids=[])
        self.bridge._process_status.side_effect = [live, dead]
        result = self.bridge.ensure_session('fixture.package', spawn=False)
        self.assertEqual(result['action'], 'attach_unstable')
        self.assertEqual(result['attach']['action'], 'attach_unstable')
        self.assertFalse(result['attach']['target']['attached'])
        self.assertFalse(result['status']['attached'])
        self.assertEqual(result['status']['failure_classification']['category'], 'attach_unstable')
        self.assertEqual(result['attach_stability']['failure_phase'], 'response_validation')

    def test_unknown_final_pid_status_is_not_a_stable_success(self):
        live = dict(self.bridge._process_status.return_value)
        unknown = dict(live, target_pid_alive=None, process_alive=None, app_alive=None)
        self.bridge._process_status.side_effect = [live, unknown]
        result = self.bridge.ensure_session('fixture.package', spawn=False)
        self.assertEqual(result['action'], 'attach_unverified')
        self.assertEqual(result['status']['failure_classification']['category'], 'attach_unverified')
        self.assertEqual(self.session.detach_calls, 0)

    def test_detach_after_script_load_and_before_observation_is_unstable(self):
        original = self.module.start_script
        def load_then_detach(*args, **kwargs):
            original(*args, **kwargs)
            self.session.detach()
        with patch.object(self.module, 'start_script', side_effect=load_then_detach):
            result = self.attach()
        self.assertEqual(result['action'], 'attach_unstable')
        self.assertEqual(result['attach_stability']['detach_reason'], 'process-terminated')

    def test_observation_deadline_does_not_turn_a_slow_probe_into_success(self):
        self.bridge.attach_stability_window_seconds = 0
        self.attach()
        self.bridge.attach_stability_window_seconds = 0.02
        self.bridge.attach_in_progress = {'id': 'fixture-op', 'phase': 'stabilizing'}
        try:
            with patch.object(self.module.time, 'monotonic', side_effect=[0, 0, 0, 1, 1]), \
                    patch.object(self.bridge, '_stability_sample', return_value={'pid_alive': True, 'transport_alive': True, 'script_loaded': True}):
                report = self.bridge._observe_attach_stability('fixture-op', self.bridge.current_target)
        finally:
            self.bridge.attach_in_progress = None
        self.assertEqual(report['status'], 'inconclusive')
        self.assertEqual(report['reason'], 'observation_deadline')
        self.assertEqual(report['checks'], 1)

    def test_recent_output_is_scoped_and_bounded(self):
        def attach_handler(*args):
            for index in range(15):
                self.bridge._record_event({'type': 'console', 'payload': f'fixture {index} ' + 'x' * 2000})
            return self.session
        self.bridge.parser.frida_session_handler.side_effect = attach_handler
        self.bridge._target_pid_alive.return_value = False
        result = self.attach()
        output = result['attach_stability']['recent_output']
        self.assertEqual(len(output), 10)
        self.assertTrue(output[-1]['text'].startswith('fixture 14'))
        self.assertLessEqual(len(output[-1]['text']), 1000)
        self.assertIn('modules', result['attach_stability'])

    def test_no_mutations_are_allowed_during_observation(self):
        def check(*args, **kwargs):
            self.assertEqual(self.bridge.attach_in_progress['phase'], 'stabilizing')
            with self.assertRaisesRegex(RuntimeError, 'still in progress'):
                self.bridge.set_hook_script('// unrelated change')
            return True
        self.bridge._target_pid_alive.side_effect = check
        self.assertEqual(self.attach()['action'], 'attached')

    def test_observation_does_not_deadlock_when_caller_owns_tool_lock(self):
        with self.bridge.lock:
            result = self.attach()
        self.assertEqual(result['action'], 'attached')

    def test_new_generation_does_not_inherit_previous_verdict(self):
        self.attach()
        self.assertIsNotNone(self.bridge._current_attach_stability())
        self.bridge._lifecycle.script_generation += 1
        self.assertIsNone(self.bridge._current_attach_stability())

    def test_generation_change_during_probe_does_not_poison_new_generation(self):
        def check(*args, **kwargs):
            self.bridge._lifecycle.script_generation += 1
            return True
        self.bridge._target_pid_alive.side_effect = check
        self.attach()
        self.assertIsNone(self.bridge._current_attach_stability())
        self.assertIsNone(self.bridge.last_failure)

    def test_pid_probe_budget_is_bounded(self):
        self.attach()
        for call in self.bridge._target_pid_alive.call_args_list:
            self.assertGreater(call.kwargs['timeout'], 0)
            self.assertLessEqual(call.kwargs['timeout'], 0.5)

    def test_configuration_rejects_invalid_or_unbounded_windows(self):
        for value in ('-1', '11', 'nan', 'inf', 'invalid'):
            with self.subTest(value=value), patch.dict(os.environ, MEDUSA_MCP_ATTACH_STABILITY_WINDOW=value):
                with self.assertRaisesRegex(ValueError, 'MEDUSA_MCP_ATTACH_STABILITY_WINDOW'):
                    self.module.MedusaAndroidBridge()


if __name__ == '__main__':
    unittest.main()

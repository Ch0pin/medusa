"""Lossless raw logging and explicitly compact console/MCP presentations."""
import contextlib
import hashlib
import io
import threading
import unittest
from unittest.mock import Mock, patch

from libraries.integrations.log_aggregation import ConsoleAggregator, compact_events, compact_lines
import test_mcp_lifecycle as fixtures


class LogAggregationTests(unittest.TestCase):
    def setUp(self):
        fixtures.MCPLifecycleTests.setUp(self)
        self.base, self.raw = io.StringIO(), io.StringIO()

    def mirror(self, compact=False, callback=None, context=None):
        mirror = self.module.MedusaAndroidBridge.StdoutMirror(
            self.base, callback or Mock(), compact=compact, context=context)
        mirror.set_file_stream(self.raw)
        return mirror

    def test_default_mirroring_remains_byte_for_byte(self):
        callback = Mock()
        mirror = self.mirror(callback=callback)
        chunks = ['hello ', 'café\n', 'again\n', 'again\n', 'partial']
        for chunk in chunks:
            mirror.write(chunk)
        mirror.finish()
        self.assertEqual(self.base.getvalue(), ''.join(chunks))
        self.assertEqual(self.raw.getvalue(), ''.join(chunks))
        self.assertEqual([call.args[0] for call in callback.call_args_list], chunks)

    def test_split_writes_aggregate_complete_messages_and_preserve_raw_log(self):
        mirror = self.mirror(compact=True)
        for _ in range(334):
            mirror.write('[BYPASS-SELF] Property hidden: http.agent')
            mirror.write('\n')
        mirror.finish()
        self.assertEqual(self.raw.getvalue(), '[BYPASS-SELF] Property hidden: http.agent\n' * 334)
        self.assertEqual(self.base.getvalue().count('Property hidden'), 1)
        self.assertIn('repeated 334 times total (333 additional)', self.base.getvalue())

    def test_nonidentical_lines_and_context_boundaries_remain_distinct(self):
        context = [1, 1, 123]
        mirror = self.mirror(compact=True, context=lambda: tuple(context), callback=Mock())
        mirror.write('same\nsame\n')
        context[1] = 2
        mirror.write('same\nvalue=1\nvalue=2\n')
        mirror.finish()
        self.assertEqual(self.base.getvalue().count('same\n'), 2)
        self.assertIn('value=1\nvalue=2\n', self.base.getvalue())
        self.assertEqual(self.raw.getvalue(), 'same\nsame\nsame\nvalue=1\nvalue=2\n')

    def test_periodic_summary_and_final_summary_do_not_double_count(self):
        output = io.StringIO()
        with patch('libraries.integrations.log_aggregation.time.monotonic', return_value=0):
            aggregator = ConsoleAggregator(output.write)
            aggregator.feed('x\n', (1,))
        with patch('libraries.integrations.log_aggregation.time.monotonic', return_value=2):
            aggregator.feed('x\n', (1,))
            aggregator.feed('x\n', (1,))
            aggregator.finish()
            aggregator.finish()
        text = output.getvalue()
        self.assertIn('repeated 2 times total (1 additional)', text)
        self.assertIn('repeated 3 times total (1 additional)', text)
        self.assertEqual(text.count('repeated'), 2)

    def test_partial_output_flushes_without_truncation(self):
        mirror = self.mirror(compact=True)
        mirror.write('same\nsame\npartial')
        mirror.flush()
        mirror.write(' suffix')
        mirror.finish()
        self.assertEqual(self.raw.getvalue(), 'same\nsame\npartial suffix')
        self.assertTrue(self.base.getvalue().endswith('partial suffix'))
        self.assertIn('repeated 2 times', self.base.getvalue())

    def test_recording_change_flushes_old_group_to_console_only(self):
        mirror = self.mirror(compact=True)
        mirror.write('x\nx\n')
        second = io.StringIO()
        mirror.set_file_stream(second)
        mirror.write('x\nx\n')
        mirror.finish()
        self.assertEqual(self.raw.getvalue(), 'x\nx\n')
        self.assertEqual(second.getvalue(), 'x\nx\n')
        self.assertEqual(self.base.getvalue().count('repeated 2'), 2)

    def test_closed_console_does_not_lose_raw_evidence(self):
        self.base = Mock()
        self.base.write.side_effect = BrokenPipeError('closed console')
        self.base.flush.side_effect = BrokenPipeError('closed console')
        callback = Mock()
        mirror = self.mirror(compact=True, callback=callback)
        mirror.write('x\nx\n')
        mirror.finish()
        self.assertEqual(self.raw.getvalue(), 'x\nx\n')
        callback.assert_called_once_with('x\nx\n')
        self.assertEqual(mirror.console_error, 'closed console')

    def test_event_compaction_is_opt_in_and_keeps_counts_and_timestamps(self):
        self.bridge.events = []
        for _ in range(4):
            self.bridge._capture_console_output('repeat\n')
        self.assertEqual(len(self.bridge.recent_events()), 4)
        compact = self.bridge.recent_events(compact=True)
        self.assertEqual(len(compact), 1)
        self.assertEqual(compact[0]['repeat_count'], 4)
        self.assertLessEqual(compact[0]['first_timestamp'], compact[0]['last_timestamp'])
        self.assertEqual(len(self.bridge.recent_events()), 4)

    def test_enabled_event_buffer_retains_large_repeat_count_and_signal(self):
        self.bridge.events = []
        self.bridge.set_console_aggregation(True)
        start = self.bridge._event_sequence
        self.bridge._capture_console_output('repeat\n' * 1000)
        self.bridge._record_event({'type': 'error', 'description': 'real hook error'})
        self.bridge._record_event({'type': 'error', 'description': 'real hook error'})
        self.assertEqual(len(self.bridge.events), 3)
        self.assertEqual(self.bridge.events[0]['repeat_count'], 1000)
        self.assertEqual(self.bridge._event_sequence - start, 1002)
        self.assertEqual(self.bridge.events[1]['type'], 'error')
        self.assertEqual(self.bridge.events[2]['type'], 'error')

    def test_event_groups_do_not_cross_pid_or_generation_changes(self):
        self.bridge.events = []
        self.bridge.set_console_aggregation(True)
        self.bridge._capture_console_output('same\nsame\n')
        self.bridge._lifecycle.script_generation += 1
        self.bridge._capture_console_output('same\nsame\n')
        self.bridge.current_target['pid'] = 456
        self.bridge._capture_console_output('same\nsame\n')
        self.assertEqual([event['repeat_count'] for event in self.bridge.events], [2, 2, 2])

    def test_partial_console_messages_are_not_combined_across_generations(self):
        self.bridge.events = []
        self.bridge._capture_console_output('old partial')
        self.bridge._lifecycle.script_generation += 1
        self.bridge._capture_console_output('new line\n')
        self.assertEqual([event['payload'] for event in self.bridge.events], ['old partial', 'new line'])
        self.assertNotEqual(self.bridge.events[0]['observed_script_generation'], self.bridge.events[1]['observed_script_generation'])

    def test_updated_repeat_group_is_visible_to_event_sequence_cursor(self):
        self.bridge.events = []
        self.bridge.set_console_aggregation(True)
        self.bridge._capture_console_output('same\n')
        cursor = self.bridge._event_sequence
        self.bridge._capture_console_output('same\n')
        events = self.bridge._slice_recent_events(cursor)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['repeat_count'], 2)
        self.assertEqual(events[0]['new_repeat_count'], 1)

    def test_compact_tail_keeps_raw_cursor_and_source_line_ranges(self):
        path = self.bridge.agent_script_path.with_suffix('.log')
        raw = 'repeat\n' * 334 + 'important signal\n'
        path.write_text(raw)
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        self.bridge.selected_output_path = str(path)
        result = self.bridge.tail_output(lines=1000, line_offset=0, compact=True)
        self.assertEqual(result['line_count'], 335)
        self.assertEqual(result['display_line_count'], 3)
        self.assertEqual(result['next_line'], 335)
        self.assertEqual(result['repeat_groups'], [{'count': 334, 'first_line': 1, 'last_line': 334}])
        self.assertIn('source lines 1-334', result['content'])
        self.assertIn('important signal', result['content'])
        self.assertEqual(self.bridge.tail_output(lines=1000, line_offset=0)['content'], raw)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)

    def test_compact_tail_pagination_counts_only_returned_raw_lines(self):
        path = self.bridge.agent_script_path.with_suffix('.log')
        path.write_text('repeat\n' * 334)
        self.bridge.selected_output_path = str(path)
        first = self.bridge.tail_output(lines=200, line_offset=0, compact=True)
        second = self.bridge.tail_output(lines=200, cursor=first['next_cursor'], compact=True)
        self.assertEqual(first['repeat_groups'][0]['count'], 200)
        self.assertEqual(second['repeat_groups'][0], {'count': 134, 'first_line': 201, 'last_line': 334})
        self.assertEqual(second['next_line'], 334)
        self.assertEqual(second['summary_scope'], 'returned_raw_lines')

    def test_blank_lines_and_distinct_payloads_are_preserved(self):
        text, groups = compact_lines(['\n', '\n', 'a\n', 'b\n'])
        self.assertEqual(text, '\n\na\nb\n')
        self.assertEqual(groups, [])
        events = compact_events([{'type': 'console', 'payload': 'same', 'module': name} for name in ('one', 'two')])
        self.assertEqual(len(events), 2)

    def test_concurrent_mirroring_does_not_require_the_command_lock(self):
        self.bridge.events = []
        self.bridge.set_console_aggregation(True)
        mirror = self.mirror(compact=True, callback=self.bridge._capture_console_output, context=self.bridge._console_context)
        def emit():
            for _ in range(25):
                mirror.write('same\n')
        with self.bridge.lock:
            threads = [threading.Thread(target=emit, daemon=True) for _ in range(4)]
            for thread in threads: thread.start()
            for thread in threads:
                thread.join(2)
                self.assertFalse(thread.is_alive())
        mirror.finish()
        self.assertEqual(self.raw.getvalue(), 'same\n' * 100)
        self.assertEqual(self.bridge.events[0]['repeat_count'], 100)

    def test_proxy_uninstall_flushes_summary_and_restores_stdout(self):
        # Use the actual proxy lifecycle, not the no-op fixtures.
        with contextlib.redirect_stdout(self.base):
            self.bridge.set_console_aggregation(True)
            self.bridge._install_stdout_proxy()
            proxy = self.bridge.stdout_proxy
            proxy.set_file_stream(self.raw)
            proxy.write('same\nsame\npartial')
            type(self.bridge)._uninstall_stdout_proxy(self.bridge)
            import sys
            self.assertIs(sys.stdout, self.base)
        self.assertIn('repeated 2 times', self.base.getvalue())
        self.assertTrue(self.base.getvalue().endswith('partial'))
        self.assertEqual(self.raw.getvalue(), 'same\nsame\npartial')
        self.assertEqual(self.bridge.events[-1]['payload'], 'partial')


if __name__ == '__main__':
    unittest.main()

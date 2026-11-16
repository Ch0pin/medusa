"""Lifecycle failure injection, with no attached devices or application changes."""
import contextlib
import importlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from libraries.core.sessions import (
    CONTROL_MESSAGE, MANAGED_MARKER, ScriptLifecycleError,
    reload_script, start_script, stop_script,
)
from libraries.core.state import SessionState


class Script:
    def __init__(self, owner, source):
        self.owner = owner
        self.source = source
        self.callbacks = {}
        self.is_destroyed = False
        self.load_error = None
        self.unload_error = None
        self.cleanup_reply = {'ok': True, 'remaining': 0, 'cleaned': ['observer'], 'errors': []}
        self.posts = []

    def on(self, signal, callback):
        self.callbacks[signal] = callback

    def load(self):
        self.owner.events.append(('load', self))
        if self.load_error:
            raise RuntimeError(self.load_error)

    def unload(self):
        self.owner.events.append(('unload', self))
        if self.unload_error:
            raise RuntimeError(self.unload_error)
        self.is_destroyed = True

    def post(self, message):
        self.posts.append(message)
        self.owner.events.append(('cleanup', self))
        if self.cleanup_reply is not None:
            self.reply(message, self.cleanup_reply)

    def reply(self, request, result):
        self.emit({'type': 'send', 'payload': dict(result, type=CONTROL_MESSAGE, request=request['request'])})

    def emit(self, message):
        self.callbacks['message'](message, None)


class Session:
    def __init__(self):
        self.events = []
        self.scripts = []
        self.callbacks = []
        self.create_error = None
        self.next_load_error = None

    def create_script(self, source):
        self.events.append(('create', source))
        if self.create_error:
            raise RuntimeError(self.create_error)
        script = Script(self, source)
        script.load_error = self.next_load_error
        self.scripts.append(script)
        return script

    def on(self, signal, callback):
        self.callbacks.append(callback)

    def detach(self):
        for callback in self.callbacks:
            callback('process-terminated', None)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'agent.js'
        self.path.write_text(MANAGED_MARKER + '\n// replacement')
        self.state = SessionState()
        self.session = Session()
        self.messages = []
        self.detaches = []
        start_script(self.session, self.state, MANAGED_MARKER,
                     lambda message, data: self.messages.append(message), self.detaches.append)
        self.original = self.state.script
        self.session.events.clear()

    def reload(self, **kwargs):
        reload_script(self.session, self.state, self.path,
                      lambda message, data: self.messages.append(message), self.detaches.append, **kwargs)

    def test_read_and_create_failures_leave_original_running(self):
        for failure in ('missing source', 'syntax error'):
            with self.subTest(failure=failure):
                if failure == 'missing source':
                    self.path.unlink()
                else:
                    self.path.write_text(MANAGED_MARKER)
                    self.session.create_error = failure
                with self.assertRaises(ScriptLifecycleError) as error:
                    self.reload()
                self.assertEqual(error.exception.stage, 'prepare')
                self.assertIsNotNone(error.exception.__cause__)
                self.assertIs(self.state.script, self.original)
                self.assertTrue(self.state.script_loaded)
                self.assertEqual(self.original.posts, [])
                self.assertNotIn(('unload', self.original), self.session.events)

    def test_success_cleans_before_unloading_and_has_one_detach_subscription(self):
        for generation in (2, 3, 4):
            self.reload()
            self.assertEqual(self.state.script_generation, generation)
            self.assertTrue(self.state.script_loaded)
        self.assertEqual(len(self.session.callbacks), 1)
        self.assertEqual([event[0] for event in self.session.events],
                         ['create', 'cleanup', 'unload', 'load'] * 3)

    def test_failed_cleanup_keeps_handle_and_retries_only_after_completed_failure(self):
        self.original.cleanup_reply = {'ok': False, 'errors': ['unregister failed'], 'remaining': 1}
        with self.assertRaisesRegex(ScriptLifecycleError, 'unregister failed'):
            self.reload()
        self.assertIs(self.state.script, self.original)
        self.assertFalse(self.original.is_destroyed)
        self.assertTrue(self.session.scripts[-1].is_destroyed)  # unused replacement
        self.original.cleanup_reply = {'ok': True, 'errors': [], 'remaining': 0}
        self.reload()
        self.assertEqual(len(self.original.posts), 2)
        self.assertTrue(self.original.is_destroyed)

    def test_timeout_retains_request_and_late_confirmation_allows_retry(self):
        self.original.cleanup_reply = None
        for attempt in range(2):
            with self.assertRaisesRegex(ScriptLifecycleError, 'timed out'):
                self.reload(cleanup_timeout=0)
        self.assertEqual(len(self.original.posts), 1)
        self.assertIs(self.state.script, self.original)
        self.original.reply(self.original.posts[0], {'ok': True, 'remaining': 0})
        self.reload(cleanup_timeout=0)
        self.assertEqual(len(self.original.posts), 1)
        self.assertTrue(self.state.script_loaded)

    def test_unload_failure_retains_ownership_and_does_not_load_replacement(self):
        self.original.unload_error = 'Frida unload failed'
        with self.assertRaisesRegex(ScriptLifecycleError, 'Frida unload failed') as error:
            self.reload()
        self.assertEqual(error.exception.stage, 'unload')
        self.assertIs(self.state.script, self.original)
        self.assertIsNone(self.state.script_loaded)
        self.assertNotIn(('load', self.session.scripts[-1]), self.session.events)

    def test_load_failure_retains_failed_script_for_cleanup(self):
        self.session.next_load_error = 'script load failed after partial execution'
        with self.assertRaisesRegex(ScriptLifecycleError, 'partial execution'):
            self.reload()
        failed = self.state.script
        self.assertIs(failed, self.session.scripts[-1])
        self.assertIsNone(self.state.script_loaded)
        self.assertEqual(self.state.lifecycle_status, 'load_failed')
        stop_script(self.state)
        self.assertTrue(failed.is_destroyed)
        self.assertIsNone(self.state.script)

    def test_stale_script_messages_are_ignored_without_changing_normal_logs(self):
        self.reload()
        self.original.emit({'type': 'send', 'payload': 'stale'})
        self.state.script.emit({'type': 'send', 'payload': 'current'})
        self.assertEqual(self.messages, [{'type': 'send', 'payload': 'current'}])

    def test_stale_detach_cannot_invalidate_new_session(self):
        stop_script(self.state)
        newer = Session()
        start_script(newer, self.state, MANAGED_MARKER, lambda *args: None, self.detaches.append)
        self.session.detach()
        self.assertFalse(self.state.detached)
        self.assertTrue(self.state.script_loaded)
        self.assertEqual(self.detaches, [])
        newer.detach()
        self.assertTrue(self.state.detached)
        self.assertFalse(self.state.script_loaded)
        self.assertEqual(self.detaches, ['process-terminated'])

    def test_overlapping_operation_is_rejected(self):
        with self.state.operation_lock:
            with self.assertRaisesRegex(ScriptLifecycleError, 'still running'):
                self.reload()
        self.assertEqual(self.session.events, [])

    def test_failed_compilation_prevents_old_agent_reload(self):
        self.state.compile_error = 'agent assembly failed'
        with self.assertRaisesRegex(ScriptLifecycleError, 'agent assembly failed'):
            self.reload()
        self.assertEqual(self.session.events, [])

    def test_unmanaged_scripts_keep_existing_behavior_without_claiming_cleanup(self):
        self.state.managed_cleanup = False
        stop_script(self.state)
        self.assertEqual(self.original.posts, [])
        self.assertEqual(self.state.cleanup_result['status'], 'unmanaged')

    def test_both_platforms_keep_compile_failures_visible(self):
        for platform in ('android', 'ios'):
            backend = importlib.import_module('libraries.platforms.' + platform)
            parser = backend.Parser()
            with patch.object(backend, 'assemble_agent', side_effect=RuntimeError('fixture compile failure')), \
                    contextlib.redirect_stdout(io.StringIO()):
                parser.do_compile('')
            self.assertTrue(parser.modified)
            self.assertEqual(parser.state.session.compile_error, 'fixture compile failure')

    def test_interactive_reload_failure_can_be_retried_and_exit_cleans_up(self):
        for platform in ('android', 'ios'):
            with self.subTest(platform=platform):
                backend = importlib.import_module('libraries.platforms.' + platform)
                parser = backend.Parser()
                session = Session()
                actions = iter(['r', 'r', 'e', 'e'])
                reads = []

                def human_input(prompt):
                    action = next(actions)
                    reads.append(action)
                    # First reload fails; next one succeeds. First exit fails;
                    # second exit succeeds without losing the interactive loop.
                    if len(reads) in (1, 3):
                        parser.script.cleanup_reply = {'ok': False, 'errors': ['observer busy']}
                    else:
                        parser.script.cleanup_reply = {'ok': True, 'remaining': 0}
                    return action

                with patch.object(backend, 'agent_script', str(self.path)), \
                        patch.object(parser, 'frida_session_handler', return_value=session), \
                        patch.object(parser, 'modification_time', side_effect=[1, 2, 2]), \
                        patch('builtins.input', side_effect=human_input), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    parser.run_frida(False, False, 'fixture.package', None)
                self.assertEqual(reads, ['r', 'r', 'e', 'e'])
                self.assertIsNone(parser.script)
                self.assertEqual(parser.state.session.script_generation, 2)
                self.assertEqual(output.getvalue().count('observer busy'), 2)
                self.assertEqual(len(session.callbacks), 1)

    def test_detach_during_cleanup_prevents_replacement(self):
        def post_and_detach(message):
            self.session.detach()
        self.original.post = post_and_detach
        with self.assertRaisesRegex(ScriptLifecycleError, 'detached'):
            self.reload()
        self.assertIs(self.state.script, self.original)
        self.assertNotIn(('load', self.session.scripts[-1]), self.session.events)

    def test_replacement_disposal_failure_preserves_original_cleanup_error(self):
        original_create = self.session.create_script
        def create(source):
            script = original_create(source)
            script.unload_error = 'discard failed'
            return script
        self.session.create_script = create
        self.original.cleanup_reply = {'ok': False, 'errors': ['unregister failed']}
        with self.assertRaisesRegex(ScriptLifecycleError, 'unregister failed') as error:
            self.reload()
        self.assertIn('discard failed', error.exception.__notes__[0])

    def test_javascript_cleanup_contract(self):
        script = Path(__file__).with_name('managed_lifecycle.cjs')
        subprocess.run(['node', str(script)], check=True, capture_output=True, text=True, timeout=15)


if __name__ == '__main__':
    unittest.main()

"""Agent-file ownership and exit choices, using temporary files only."""
import contextlib
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from libraries.cli.app import argument_parser, create_application, run_application_loop
from libraries.core.agent_files import cleanup_agent_files
from libraries.platforms import android, ios


class AgentCleanupTests(unittest.TestCase):
    def test_failed_deletion_is_reported_and_not_claimed_as_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'owned_agent_script'
            path.touch()
            owned = {str(path): False}
            with patch.object(Path, 'unlink', side_effect=PermissionError('denied')):
                result = cleanup_agent_files(owned)
            self.assertEqual(result.removed, [])
            self.assertEqual(result.errors[path], 'denied')
            self.assertTrue(path.exists())

    def test_empty_cleanup_is_owned_only_and_respects_explicit_keep(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            empty, keep, other = [root / name for name in ('empty_agent_script', 'keep_agent_script', 'other_agent_script')]
            for path in (empty, keep, other):
                path.touch()
            owned = {str(empty): None, str(keep): True}
            result = cleanup_agent_files(owned)
            self.assertEqual(result.removed, [empty])
            self.assertTrue(keep.exists())
            self.assertTrue(other.exists())
            self.assertEqual(cleanup_agent_files(owned).removed, [])

    def test_failure_cleanup_preserves_nonempty_work_without_prompt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'owned_agent_script'
            path.write_text('// keep on unexpected failure')
            owned = {str(path): None}
            self.assertEqual(cleanup_agent_files(owned).removed, [])
            self.assertTrue(path.exists())
            choose = Mock(return_value=False)
            cleanup_agent_files(owned, choose)
            choose.assert_called_once_with(path)
            self.assertFalse(path.exists())

    def test_android_exit_uses_instance_path_and_honors_keep_choice(self):
        for keep in (False, True):
            with self.subTest(keep=keep), tempfile.TemporaryDirectory() as directory:
                own, decoy = Path(directory) / 'own_agent_script', Path(directory) / 'other_agent_script'
                own.write_text('// own')
                decoy.write_text('// another session')
                parser = android.Parser()
                parser.agent_script_path = str(own)
                parser.state.session.agent_files[str(own)] = None
                parser.modManager.available.append(SimpleNamespace(Name='scratchpad', Code=''))
                with patch.object(android, 'agent_script', str(decoy)), patch.object(android, 'Polar') as polar, \
                        patch.object(android, 'logger'), contextlib.redirect_stdout(io.StringIO()):
                    polar.return_value.ask.side_effect = [False, keep]
                    with self.assertRaises(SystemExit):
                        parser.do_exit('')
                cleanup_agent_files(parser.state.session.agent_files)
                self.assertEqual(own.exists(), keep)
                self.assertTrue(decoy.exists())

    def test_ios_reset_removes_owned_file_and_keep_preserves_it(self):
        for reset in (False, True):
            with self.subTest(reset=reset), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'modules').mkdir()
                (root / 'modules' / 'scratchpad.imed').write_text(' ' * 119)
                own = root / 'owned_agent_script'
                own.write_text('// owned')
                parser = ios.Parser()
                parser.base_directory = str(root)
                parser.agent_script_path = str(own)
                parser.state.session.agent_files[str(own)] = None
                with patch.object(ios, 'Polar') as polar, contextlib.redirect_stdout(io.StringIO()):
                    polar.return_value.ask.return_value = reset
                    with self.assertRaises(SystemExit):
                        parser.do_exit('')
                cleanup_agent_files(parser.state.session.agent_files)
                self.assertEqual(own.exists(), not reset)

    def test_legacy_ios_static_agent_still_resets_in_place(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'modules').mkdir()
            (root / 'modules' / 'scratchpad.imed').write_text(' ' * 119)
            path = root / 'agent_ios.js'
            path.write_text('// static legacy agent')
            parser = ios.Parser()
            parser.base_directory = str(root)
            with patch.object(ios, 'agent_script', str(path)), patch.object(ios, 'Polar') as polar, \
                    contextlib.redirect_stdout(io.StringIO()):
                polar.return_value.ask.return_value = True
                with self.assertRaises(SystemExit):
                    parser.do_exit('')
            self.assertEqual(path.read_bytes(), b'')

    def test_exit_after_platform_switch_handles_both_owned_agents(self):
        for keep_previous in (False, True):
            with self.subTest(keep_previous=keep_previous), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                first_path, second_path, other_path = [root / name for name in (
                    'ios_agent_script', 'android_agent_script', 'unrelated_agent_script')]
                for path in (first_path, second_path, other_path):
                    path.write_text('// work')
                args = argument_parser().parse_args([])
                first = create_application('ios', SimpleNamespace(id='ios'), args, Mock())
                second = create_application('android', SimpleNamespace(id='android'), args, Mock())
                for app, path in ((first, first_path), (second, second_path)):
                    app.initialized = True
                    app.agent_script_path = str(path)
                    app.state.session.agent_files[str(path)] = None
                second.modManager.available.append(SimpleNamespace(Name='scratchpad', Code=''))
                def switch():
                    first.pending_switch = ('android', SimpleNamespace(id='android'))
                    return 0
                with patch.object(first, 'cmdloop', side_effect=switch), \
                        patch.object(second, 'cmdloop', side_effect=lambda: second.do_exit('')), \
                        patch.object(second, 'preloop'), \
                        patch('libraries.cli.app.create_application', return_value=second), \
                        patch('libraries.cli.app.Polar') as previous_choice, patch.object(android, 'Polar') as active_choice, \
                        patch.object(android, 'logger'), contextlib.redirect_stdout(io.StringIO()):
                    active_choice.return_value.ask.side_effect = [False, False]
                    previous_choice.return_value.ask.return_value = keep_previous
                    with self.assertRaises(SystemExit):
                        run_application_loop(first, 'ios', args, Mock())
                    previous_choice.return_value.ask.assert_called_once()
                self.assertEqual(first_path.exists(), keep_previous)
                self.assertFalse(second_path.exists())
                self.assertTrue(other_path.exists())


if __name__ == '__main__':
    unittest.main()

"""Exercise Mango redirection through cmd2 using synthetic data and temporary files."""
import contextlib
import io
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from libraries import lib_mango, firebase_tests
from libraries.android_flags import describe_flags
from libraries.lib_adb import AndroidDevice


class TerminalBuffer(io.StringIO):
    def isatty(self):
        return True


class MangoOutputTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='mango-output-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.console, self.errors = io.StringIO(), io.StringIO()
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(contextlib.redirect_stdout(self.console))
        stack.enter_context(contextlib.redirect_stderr(self.errors))
        self.app = lib_mango.parser()
        self.app.current_app_sha256 = 'fixture-sha'
        self.app.package = 'test.fixture'
        self.app.activities = [
            ('sha', 'test.fixture.ExportedActivity', 'true', 'true', '', '', '', 'test.permission.LAUNCH'),
            ('sha', 'test.fixture.PrivateActivity', 'true', 'false', '', '', '', ''),
        ]
        self.app.activityallias = [('sha', 'test.fixture.LaunchAlias', 'true', 'true', '', 'test.fixture.ExportedActivity')]
        self.app.services = [('sha', 'test.fixture.ExportedService', 'true', 'true', '', 'test.permission.SERVICE')]
        self.app.receivers = [('sha', 'test.fixture.ExportedReceiver', 'true', 'true', 'test.permission.RECEIVE')]
        self.app.providers = [('sha', 'test.fixture.ExportedProvider', 'true', 'true', 'true', '', '', '', '', 'test.fixture.provider')]
        self.app.permissions = [('sha', 'test.fixture.CUSTOM', 'signature', '', 'Unknown permission: fixture')]
        self.app.intent_filters = [('test.fixture.ExportedActivity', 'android.intent.action.VIEW', 'android.intent.category.BROWSABLE')]
        self.app.deeplinks = [('test.fixture.ExportedActivity', 'scheme:fixture|host:example.test|path:/café')]
        self.app.schemes, self.app.hosts, self.app.pathPrefixes = set(), set(), set()
        self.app.strings = '<string name="sample">fixture café [literal]</string>\nsecond line'
        self.app.libraries = ['libfixture.so']
        self.app.manifest = [(b'<manifest package="test.fixture"><application/></manifest>',)]
        self.app.info = [('fixture-sha', 'Fixture App', 'test.fixture', '7', '1.0', '23', '35', '', '', '',
                         'false', 'true', '', '', 'fixture.apk', '', 'Android')]
        self.app.database = Mock()
        self.app.database.get_all_notes.return_value = [(1, 'fixture-sha', 'note café')]
        def query(sql):
            if 'sqlite_master' in sql:
                return [('Application',)]
            if 'PRAGMA' in sql:
                return [(0, 'packageName', 'TEXT', 0, None, 0)]
            return [('row café',)]
        self.app.database.query_db.side_effect = query

    def redirect(self, command, name='report.txt', operator='>'):
        destination = self.root / name
        stop = self.app.onecmd_plus_hooks(f'{command} {operator} "{destination}"')
        return destination, stop

    def test_exposure_overwrite_contains_every_section_and_no_console_leak(self):
        destination = self.root / 'exposure.txt'
        destination.write_text('old report must disappear')
        path, stop = self.redirect('show exposure', destination.name)
        text = path.read_text(encoding='utf-8')
        for expected in ('Potential attack targets', 'fixture://example.test/café', 'Link-launchable',
                         'test.fixture.ExportedActivity', 'test.fixture.LaunchAlias', 'test.fixture.ExportedService',
                         'test.fixture.ExportedReceiver', 'test.fixture.ExportedProvider', 'test.fixture.CUSTOM'):
            self.assertIn(expected, text)
        self.assertNotIn('test.fixture.PrivateActivity', text)
        self.assertNotIn('old report', text)
        self.assertNotIn('\x1b', text)
        self.assertEqual(self.console.getvalue(), '')
        self.assertEqual(self.errors.getvalue(), '')
        self.assertFalse(stop)
        self.assertIs(self.app.stdout, self.console)

    def test_append_and_quoted_unicode_filename(self):
        path, _ = self.redirect('show exposure', 'exposure café space.txt')
        first = path.read_text()
        self.redirect('show exposure', path.name, '>>')
        self.assertEqual(path.read_text(), first + first)

    def test_original_relative_path_command(self):
        with contextlib.chdir(self.root):
            self.app.onecmd_plus_hooks('show exposure > ./exposure.txt')
        self.assertIn('test.fixture.ExportedActivity', (self.root / 'exposure.txt').read_text())
        self.assertEqual(self.console.getvalue(), '')

    def test_pipe_receives_the_complete_report(self):
        cat = shutil.which('cat')
        if not cat:
            self.skipTest('cat is required for this shell-pipe test')
        baseline, _ = self.redirect('show exposure')
        target = self.root / 'pipe café.txt'
        # Real file descriptors are needed by cmd2's subprocess pipeline.
        # StringIO cannot be passed as a child process's stdout/stderr.
        with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as out, \
                tempfile.TemporaryFile(mode='w+', encoding='utf-8') as err, contextlib.redirect_stderr(err):
            self.app.stdout = out
            try:
                stop = self.app.onecmd_plus_hooks(f'show exposure | {shlex.quote(cat)} > {shlex.quote(str(target))}')
                self.assertIs(self.app.stdout, out)
                out.seek(0)
                err.seek(0)
                self.assertEqual(out.read(), '')
                self.assertEqual(err.read(), '')
            finally:
                self.app.stdout = self.console
        self.assertFalse(stop)
        self.assertEqual(target.read_bytes(), baseline.read_bytes())
        self.assertEqual(self.console.getvalue(), '')
        self.assertIs(self.app.stdout, self.console)

    def test_normal_output_and_redirection_restore_the_same_report(self):
        self.app.onecmd_plus_hooks('show exposure')
        original = self.console.getvalue()
        self.console.seek(0)
        self.console.truncate()
        path, _ = self.redirect('show exposure')
        self.assertEqual(path.read_text(), original)
        self.assertEqual(self.console.getvalue(), '')
        self.app.onecmd_plus_hooks('show exposure')
        self.assertEqual(self.console.getvalue(), original)

    def test_terminal_styles_spacing_and_print_arguments_are_preserved(self):
        terminal = TerminalBuffer()
        self.app.stdout = terminal
        self.app._report(lib_mango.Fore.GREEN + 'café' + lib_mango.Style.RESET_ALL, 7, sep=' | ', end='!')
        self.assertEqual(terminal.getvalue(), '\x1b[32mcafé\x1b[0m | 7!')
        self.app.stdout = self.console
        self.app._report(lib_mango.Fore.GREEN + 'café' + lib_mango.Style.RESET_ALL, 7, sep=' | ', end='!')
        self.assertEqual(self.console.getvalue(), 'café | 7!')

    def test_other_show_reports_redirect(self):
        for command, expected in (
            ('show activities', 'test.fixture.PrivateActivity'),
            ('show activities -e', 'test.fixture.ExportedActivity'),
            ('show activityAlias', 'test.fixture.LaunchAlias'),
            ('show services', 'test.fixture.ExportedService'),
            ('show receivers', 'test.fixture.ExportedReceiver'),
            ('show providers', 'test.fixture.ExportedProvider'),
            ('show permissions', 'test.fixture.CUSTOM'),
            ('show intentFilters', 'android.intent.action.VIEW'),
            ('show deeplinks', 'fixture://example.test/café'),
            ('show strings', '[literal]'),
            ('show libraries', 'libfixture.so'),
            ('show manifest', '<manifest package="test.fixture">'),
            ('show info', 'note café'),
            ('show database', 'Column Name'),
        ):
            with self.subTest(command=command):
                path, stop = self.redirect(command)
                self.assertIn(expected, path.read_text())
                self.assertNotIn('\x1b', path.read_text())
                self.assertFalse(stop)
                self.assertEqual(self.console.getvalue(), '')

    def test_report_commands_and_search_results_redirect(self):
        for command, expected in (
            ('man patch', 'patch gadget'),
            ('note show', 'note café'),
            ('decodeflag 0x10000000', 'FLAG_ACTIVITY_NEW_TASK'),
            ('search fixture', 'test.fixture.ExportedActivity'),
            ('search no-match', 'No Activities found'),
        ):
            with self.subTest(command=command):
                path, stop = self.redirect(command)
                self.assertIn(expected, path.read_text())
                self.assertFalse(stop)
                self.assertEqual(self.console.getvalue(), '')

    def test_query_results_redirect_and_errors_stay_on_stderr(self):
        path, _ = self.redirect('query SELECT packageName FROM Application')
        self.assertIn('row café', path.read_text())
        self.app.database.query_db.side_effect = RuntimeError('fixture query error')
        path, stop = self.redirect('query invalid query')
        self.assertNotIn('fixture query error', path.read_text())
        self.assertIn('fixture query error', self.errors.getvalue())
        self.assertFalse(stop)

    def test_manifest_diff_redirects(self):
        self.app.database.get_manifests_for_package.return_value = [
            (1, b'<manifest package="test.fixture"><application/></manifest>'),
            (2, b'<manifest package="test.fixture" xmlns:android="http://schemas.android.com/apk/res/android"><application><activity android:name="test.fixture.AddedActivity" android:exported="true"/></application></manifest>'),
        ]
        path, stop = self.redirect('diff test.fixture')
        self.assertIn('+ Added: test.fixture.AddedActivity', path.read_text())
        self.assertNotIn('\x1b', path.read_text())
        self.assertFalse(stop)
        self.assertEqual(self.console.getvalue(), '')

    def test_secrets_report_redirects_without_running_analysis(self):
        self.app.secrets = [(1, 'sha', json.dumps([{'DetectorName': 'Fixture detector', 'Verified': True,
                                                  'Raw': 'synthetic value', 'ExtraData': {'text': 'café'}}]))]
        with patch.object(self.app, 'init_application_info'):
            path, _ = self.redirect('show secrets -v')
        self.assertIn('Secrets stored', path.read_text())
        self.assertIn('Fixture detector', path.read_text())
        self.assertIn('café', path.read_text())
        self.assertNotIn('\x1b', path.read_text())
        self.assertEqual(self.console.getvalue(), '')

    def test_verbose_exposure_includes_helper_results_without_network(self):
        self.app.strings = '<string name="project_id">fixture-project</string>'
        row = firebase_tests.Row('Fixture probe', 'Synthetic result', '✅ N/A')
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(firebase_tests, 'spinner', side_effect=lambda *a, **k: contextlib.nullcontext()))
            for name in vars(firebase_tests):
                if name.startswith('probe_'):
                    returned = (row, None) if name == 'probe_anonymous_auth' else row
                    stack.enter_context(patch.object(firebase_tests, name, return_value=returned))
            requests = stack.enter_context(patch.object(firebase_tests.requests, 'get', side_effect=AssertionError('network forbidden')))
            posts = stack.enter_context(patch.object(firebase_tests.requests, 'post', side_effect=AssertionError('network forbidden')))
            with patch.object(lib_mango.logger, 'info'):
                path, _ = self.redirect('show exposure -v')
            requests.assert_not_called()
            posts.assert_not_called()
        self.assertIn('fixture-project', path.read_text())
        self.assertIn('Security Test Results', path.read_text())
        self.assertIn('Fixture probe', path.read_text())
        self.assertIn('Synthetic result', path.read_text())
        self.assertNotIn('\x1b', path.read_text())
        self.assertEqual(self.console.getvalue(), '')

    def test_helper_defaults_keep_existing_console_behavior(self):
        describe_flags(1, {'SAMPLE_FLAG': 1})
        self.assertIn('SAMPLE_FLAG', self.console.getvalue())
        device = AndroidDevice.__new__(AndroidDevice)
        device.properties = ['[ro.product.name]: [FixturePhone]']
        device.print_dev_properties()
        self.assertIn('FixturePhone', self.console.getvalue())
        firebase_tests.print_security_report_lines([firebase_tests.Row('Sample', 'Result', '✅ N/A')])
        self.assertIn('Sample', self.console.getvalue())

    def test_device_properties_and_dynamic_receivers_redirect_without_adb(self):
        self.app._device = SimpleNamespace(id='fixture-device')
        device = AndroidDevice.__new__(AndroidDevice)
        device.properties = ['[ro.product.name]: [FixturePhone]']
        with patch.object(lib_mango, 'AndroidDevice', return_value=device):
            path, _ = self.redirect('show device')
        self.assertIn('FixturePhone', path.read_text())
        self.assertNotIn('\x1b', path.read_text())
        with patch.object(lib_mango.subprocess, 'Popen', return_value=SimpleNamespace(stdout=[b'fixture dynamic receiver\n'])):
            path, _ = self.redirect('show receivers -d')
        self.assertIn('fixture dynamic receiver', path.read_text())
        self.assertEqual(self.console.getvalue(), '')

    def test_subprocess_report_output_is_captured(self):
        self.app._device = SimpleNamespace(id='fixture-device')
        process = subprocess.CompletedProcess(['aapt2'], 0, 'resource 0x7f000001\n  "fixture resource"\n', '')
        with patch.object(lib_mango.subprocess, 'run', return_value=process), patch.object(lib_mango.logger, 'info'):
            path, _ = self.redirect('search 0x7f000001 /tmp/fixture.apk')
        self.assertIn('fixture resource', path.read_text())
        self.assertEqual(self.console.getvalue(), '')

    def test_proxy_report_captures_subprocess_stdout(self):
        self.app._device = SimpleNamespace(id='fixture-device')
        process = subprocess.CompletedProcess('fixture iptables command', 0, 'fixture NAT table\n')
        with patch.object(lib_mango.os, 'popen') as popen, patch.object(lib_mango.subprocess, 'run', return_value=process) as run:
            popen.return_value.read.return_value = 'proxy.example:8080\n'
            path, _ = self.redirect('proxy get')
        self.assertIn('proxy.example:8080', path.read_text())
        self.assertIn('fixture NAT table', path.read_text())
        self.assertEqual(run.call_args.kwargs['stdout'], subprocess.PIPE)
        self.assertEqual(self.console.getvalue(), '')

    def test_application_selection_menu_stays_visible(self):
        self.app.database.query_db.side_effect = None
        self.app.database.query_db.return_value = [('fixture-sha', 'test.fixture', '1.0', 'Android', self.app.manifest[0][0])]
        for method in ('get_exported_activities', 'get_exported_activity_aliases', 'get_exported_services',
                       'get_exported_receivers', 'get_exported_providers'):
            getattr(self.app.database, method).return_value = []
        with patch.object(lib_mango, 'Polar') as polar, patch.object(lib_mango, 'Numeric') as numeric, \
                patch.object(firebase_tests, 'spinner', side_effect=lambda *a, **k: contextlib.nullcontext()):
            polar.return_value.ask.return_value = False
            numeric.return_value.ask.return_value = 2
            path, _ = self.redirect('show applications')
        self.assertIn('Available applications', self.console.getvalue())
        self.assertIn('test.fixture', self.console.getvalue())
        self.assertEqual(path.read_text(), '')

    def test_prompts_and_operational_feedback_stay_on_console(self):
        self.app.guava = Mock()
        def read_input(prompt):
            print(prompt, end='')
            return 'synthetic note'
        with patch('builtins.input', side_effect=read_input), patch.object(lib_mango.logger, 'info') as feedback:
            path, _ = self.redirect('note add')
        self.assertIn('Note (press enter to commit)', self.console.getvalue())
        self.assertEqual(path.read_text(), '')
        feedback.assert_called_once_with('Note added.')
        self.app.guava.insert_note.assert_called_once_with('fixture-sha', 'synthetic note')

    def test_missing_app_and_bad_output_path_restore_streams(self):
        self.app.current_app_sha256 = None
        path, stop = self.redirect('show exposure')
        self.assertEqual(path.read_text(), '')
        self.assertIn(self.app.NO_APP_LOADED_MSG, self.errors.getvalue())
        self.assertIs(self.app.stdout, self.console)
        self.assertFalse(stop)
        self.app.current_app_sha256 = 'fixture-sha'
        path, _ = self.redirect('show exposure', 'absent-directory/out.txt')
        self.assertFalse(path.exists())
        self.assertIs(self.app.stdout, self.console)
        self.app.onecmd_plus_hooks('show exposure')
        self.assertIn('Potential attack targets', self.console.getvalue())

    def test_report_handles_closed_pipe(self):
        stream = Mock()
        stream.isatty.return_value = False
        stream.write.side_effect = BrokenPipeError()
        self.app.stdout = stream
        self.app._report('consumer already finished')
        self.assertEqual(self.errors.getvalue(), '')


if __name__ == '__main__':
    unittest.main()

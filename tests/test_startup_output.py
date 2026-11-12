"""Original startup transcript ordering with fixture catalogs and fake devices."""
import contextlib
import importlib
import io
import json
import logging
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

import frida
import cmd2
from libraries.cli.app import argument_parser, create_application, main
from libraries.cli.banner import render_logo
from libraries.logging_config import LoggerConsoleOutputFormat


class StartupOutputTests(unittest.TestCase):
    def test_default_startup_selecting_ios_never_initializes_adb(self):
        from libraries.platforms import android, ios
        device = SimpleNamespace(
            id='iphone-fixture', name='iPhone', type='usb',
            query_system_parameters=lambda: {'os': {'id': 'ios'}},
            enumerate_applications=lambda **kwargs: [],
        )
        visited = []
        def commands(app):
            visited.append(app)
            self.assertIs(app.device, device)
            self.assertFalse(hasattr(app, 'do_dexload'))
            self.assertEqual(len(app.modManager.available), 1)
            self.assertTrue(app.modManager.available[0].path.endswith('.imed'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'modules').mkdir()
            for filename in ('android.med', 'ios.imed'):
                (root / 'modules' / filename).write_text(json.dumps(
                    {'Name': filename, 'Description': '', 'Help': '', 'Code': '// fixture'}))
            with patch.object(android.Parser, 'base_directory', str(root)), \
                    patch.object(ios.Parser, 'base_directory', str(root)), \
                    patch.object(ios, 'agent_script', ios.agent_script), \
                    patch('libraries.cli.app.ROOT', root), \
                    patch.object(frida, 'enumerate_devices', return_value=[device]), \
                    patch.object(frida, 'get_device', return_value=device), \
                    patch('builtins.input', return_value='0'), \
                    patch.object(android, 'AndroidDevice') as adb, \
                    patch.object(cmd2.Cmd, '_cmdloop', commands), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([]), 0)
                adb.assert_not_called()
            self.assertEqual(len(visited), 1)
            self.assertEqual(list(root.glob('*_agent_script')), [])

    def test_original_loading_messages_logo_and_picker_transcript(self):
        timestamp = '2026-11-01 19:58:45,000'
        for platform, argv, extension in [('android', [], '.med'), ('ios', ['--platform', 'ios'], '.imed')]:
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as directory:
                backend = importlib.import_module('libraries.platforms.' + platform)
                root = Path(directory)
                (root / 'modules').mkdir()
                for name in ('one', 'two'):
                    (root / 'modules' / (name + extension)).write_text(json.dumps(
                        {'Name': name, 'Description': '', 'Help': '', 'Code': '// fixture'}))
                device = Mock()
                device.query_system_parameters.return_value = {'os': {'id': platform}}
                device.__str__ = Mock(return_value="Device(id='fixture', name='Fixture', dtype='usb')")
                output = io.StringIO()
                handler = logging.StreamHandler(output)
                formatter = LoggerConsoleOutputFormat()
                formatter.formatTime = lambda *args: timestamp
                handler.setFormatter(formatter)
                def choose(prompt):
                    output.write(prompt)
                    return '0'
                with patch.object(backend.Parser, 'base_directory', str(root)), \
                        patch.object(logging.getLogger(), 'handlers', [handler]), \
                        patch.object(logging.getLogger(), 'level', logging.INFO), \
                        patch.object(frida, 'enumerate_devices', return_value=[device]), \
                        patch('builtins.input', side_effect=choose), \
                        patch('libraries.cli.app.configure_readline'), \
                        patch('libraries.cli.app.run_application_loop', return_value=0) as run, \
                        contextlib.redirect_stdout(output):
                    self.assertEqual(main(argv), 0)
                transcript = re.sub(r'\x1b\[[0-9;]*m', '', output.getvalue())
                if platform == 'android':
                    prefix = ''.join(f'[{timestamp} - INFO] -  {line}\n' for line in (
                        'Loading modules...', 'Total modules available 2', 'All one....'))
                    heading = f'[{timestamp} - INFO] -  Available devices:\n\n'
                else:
                    prefix = '[i] Loading modules...\n[i] Done....\n[i] Total modules available 2\n'
                    heading = 'Available devices:\n\n'
                expected = (prefix + render_logo('ios' if argv else None) + '\n' + heading
                            + "0) Device(id='fixture', name='Fixture', dtype='usb')\n"
                            + '\nEnter the index of the device to use: ')
                self.assertEqual(transcript, expected)
                app = run.call_args.args[0]
                self.assertTrue(app.catalog_ready)
                self.assertIs(app.startup_device, device)
                self.assertEqual(app.state.session.agent_files, {})

    def test_preloaded_catalog_is_reused_after_selection(self):
        for platform in ('android', 'ios'):
            backend = importlib.import_module('libraries.platforms.' + platform)
            app = create_application(platform, Mock(), argument_parser().parse_args([]), Mock())
            with tempfile.TemporaryDirectory() as directory, \
                    patch('libraries.cli.app.ROOT', Path(directory)), \
                    patch.object(backend, 'agent_script', backend.agent_script), \
                    patch.object(app, 'do_reload') as reload, patch.object(app, 'activate_device'):
                app.load_startup_catalog()
                app.preloop()
                reload.assert_called_once_with('')
                app.finalize_agent_files()


if __name__ == '__main__':
    unittest.main()

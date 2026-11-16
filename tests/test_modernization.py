"""Differential host checks for service extraction; no device access."""
import contextlib
import importlib
import io
import json
from pathlib import Path
import tempfile
import tomllib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from libraries.core.modules import Module
from libraries.core.paths import ROOT



class ModernizationTests(unittest.TestCase):
    def test_retired_entry_files_and_aliases_are_not_packaged(self):
        removed = (
            'medusa_ios.py', 'medusa_unified.py', 'libraries/cli_app.py',
            'libraries/cli_common.py', 'libraries/banner.py',
            'libraries/device_selection.py', 'libraries/frida_compat.py',
            'agent_ios.js',
        )
        for relative in removed:
            self.assertFalse((ROOT / relative).exists(), relative)
        metadata = tomllib.loads((ROOT / 'pyproject.toml').read_text())
        self.assertEqual(set(metadata['tool']['setuptools']['py-modules']), {'medusa', 'medusa_android_mcp'})

    def test_explicit_imports_preserve_legacy_bindings(self):
        reference = json.loads((Path(__file__).parent / 'fixtures' / 'platform_import_bindings.json').read_text())
        for platform, bindings in reference.items():
            backend = importlib.import_module('libraries.platforms.' + platform)
            for name, provider in bindings.items():
                self.assertIs(getattr(backend, name), getattr(importlib.import_module(provider), name))

    def test_module_serialization_and_staging_order_remain_compatible(self):
        from libraries.core.modules import ModuleManager
        with tempfile.TemporaryDirectory() as directory:
            manager = ModuleManager()
            for name in ('first', 'second'):
                path = Path(directory) / (name + '.med')
                module = Module(str(path), name, 'description', 'help', '// ' + name, {'enabled': True})
                module.save()
                data = json.loads(path.read_text())
                self.assertEqual(set(data), {'Name', 'Description', 'Help', 'Code', 'Options'})
                self.assertEqual(data['Options'], {'enabled': True})
                manager.add(str(path))
            with contextlib.redirect_stdout(io.StringIO()):
                manager.stage('second')
                manager.stage('first')
            self.assertEqual([module.Name for module in manager.staged], ['second', 'first'])
            compiled = manager.compile()
            self.assertLess(compiled.index('// second'), compiled.index('// first'))

    def test_platform_reload_reports_failure_without_losing_current_script(self):
        from libraries.core.sessions import ScriptLifecycleError
        for platform in ('android', 'ios'):
            backend = importlib.import_module('libraries.platforms.' + platform)
            parser = backend.Parser()
            script = object()
            parser.script = script
            with patch.object(backend, 'reload_session_script', side_effect=ScriptLifecycleError('cleanup', 'observer failed')), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertFalse(parser.reload_script(object()))
            self.assertIs(parser.script, script)
            self.assertIn('observer failed', output.getvalue())

    def test_mcp_script_callback_order_and_error_propagation(self):
        from libraries.core.sessions import load_created_script
        for failure in (None, 'message', 'detached', 'load'):
            events = []
            def event(name, *args):
                events.append(name)
                if name == failure:
                    raise RuntimeError(name)
            script = SimpleNamespace(on=event, load=lambda: event('load'))
            session = SimpleNamespace(on=event)
            if failure:
                with self.assertRaisesRegex(RuntimeError, failure):
                    load_created_script(session, script, lambda: None, lambda: None)
                self.assertEqual(events, ['message', 'detached', 'load'][:['message', 'detached', 'load'].index(failure) + 1])
            else:
                self.assertIs(load_created_script(session, script, lambda: None, lambda: None), script)
                self.assertEqual(events, ['message', 'detached', 'load'])

    def test_compatibility_modules_share_identity(self):
        aliases = {
            'libraries.questions': 'libraries.cli.prompts',
            'libraries.modules': 'libraries.core.modules',
            'medusa_android_mcp': 'libraries.integrations.mcp_android',
        }
        for old, new in aliases.items():
            self.assertIs(importlib.import_module(old), importlib.import_module(new))

    def test_state_and_legacy_attributes_have_one_owner(self):
        from libraries.platforms import android, ios
        for backend in (android, ios):
            first, second = backend.Parser(), backend.Parser()
            first.pid = 123
            self.assertEqual(first.state.session.pid, 123)
            first.state.session.pid = 456
            self.assertEqual(first.pid, 456)
            first.packages.append('first')
            first.state.device.app_info = object()
            self.assertIs(first.app_info, first.state.device.app_info)
            self.assertEqual(second.packages, [])
            self.assertIsNone(second.pid)
            first.agent_script_path = 'agent-one.js'
            self.assertEqual(first.state.session.agent_script_path, 'agent-one.js')
            self.assertIsNone(second.agent_script_path)
            self.assertIsNot(first.modManager, second.modManager)

    def test_compilation_preserves_legacy_body_and_adds_cleanup_prelude(self):
        reference = json.loads((Path(__file__).parent / 'fixtures' / 'compilation_before_services.json').read_text())
        scenarios = [([], '', False, False),
                     (['one', 'two'], '-t 10', False, False),
                     (['JNICalls/one', 'JNICalls/two'], '', True, False),
                     (['one'], '-t 5', False, True)]
        for platform in ('android', 'ios'):
            backend = importlib.import_module('libraries.platforms.' + platform)
            for version in ('16.7.19', '17.25.0'):
                for names, options, reset, fallback in scenarios:
                    with self.subTest(platform=platform, version=version, names=names, fallback=fallback), \
                            tempfile.TemporaryDirectory() as directory:
                        expected, actual = Path(directory) / 'expected.js', Path(directory) / 'actual.js'
                        old, new = backend.Parser(), backend.Parser()
                        for app in (old, new):
                            for name in names:
                                app.modManager.staged.append(Module(name, name, '', '', '// ' + name))
                        namespace = dict(vars(backend))
                        namespace['agent_script'] = str(expected)
                        # Preserve indentation inside embedded JS strings in the fixture.
                        exec(compile('if True:\n' + reference[platform], '<frozen-compiler>', 'exec'), namespace)
                        kwargs = {'from_fallback': fallback} if platform == 'android' else {}
                        old_output, new_output = io.StringIO(), io.StringIO()
                        with patch.object(backend.frida, '__version__', version), \
                                patch.object(backend, 'agent_script', str(actual)):
                            with contextlib.redirect_stdout(old_output):
                                namespace['do_compile'](old, options, reset, **kwargs)
                            with contextlib.redirect_stdout(new_output):
                                new.do_compile(options, reset, **kwargs)
                        self.assertTrue(expected.is_file(), old_output.getvalue())
                        self.assertTrue(actual.is_file(), new_output.getvalue())
                        prelude = (ROOT / 'libraries' / 'js' / 'managed_lifecycle.js').read_bytes() + b'\n'
                        self.assertTrue(actual.read_bytes().startswith(prelude))
                        self.assertEqual(actual.read_bytes()[len(prelude):], expected.read_bytes())
                        self.assertEqual(new_output.getvalue(), old_output.getvalue())
                        self.assertEqual(new.modified, old.modified)
                        self.assertEqual(new.agent_script_path, str(actual))

    def test_resources_remain_at_repository_root(self):
        from libraries.core import bridges
        self.assertEqual(ROOT, Path(__file__).resolve().parents[1])
        self.assertEqual(bridges.GENERATED, ROOT / 'libraries' / 'js' / 'generated')


if __name__ == '__main__':
    unittest.main()

"""Host-only regression checks: fake devices, no attach/spawn or device commands."""
import ast
import asyncio
import contextlib
import importlib
import hashlib
import inspect
import io
import json
from pathlib import Path
import tempfile
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from libraries.cli.device_picker import DeviceSelectionError, detect_platform, select_device
from libraries.core.bridges import load_runtime_bridge
from libraries.cli.app import argument_parser, configure_readline, create_application, run_application_loop, validate_options


def fake_device(os_id='android', device_id='test-device', transport='usb'):
    return SimpleNamespace(id=device_id, name='Test device', type=transport,
                           query_system_parameters=lambda: {'os': {'id': os_id}})


def method_ast(method):
    method = inspect.unwrap(method)
    source = Path(inspect.getsourcefile(method)).read_text()
    start = inspect.getsourcelines(method)[1]
    return next(n for n in ast.walk(ast.parse(source))
                if isinstance(n, ast.FunctionDef) and n.name == method.__name__
                and min([n.lineno] + [d.lineno for d in n.decorator_list]) == start)


class DeviceTests(unittest.TestCase):
    def test_os_metadata_independent_of_transport(self):
        for transport in ('usb', 'remote'):
            for os_id in ('android', 'ios'):
                self.assertEqual(detect_platform(fake_device(os_id, transport=transport)), os_id)

    def test_unknown_os_requires_override(self):
        with self.assertRaises(DeviceSelectionError):
            detect_platform(fake_device('darwin'))
        self.assertEqual(detect_platform(fake_device('darwin'), 'ios'), 'ios')

    def test_conflicting_override_rejected(self):
        with self.assertRaises(DeviceSelectionError):
            detect_platform(fake_device('ios'), 'android')

    def test_metadata_failure_requires_override(self):
        device = Mock()
        device.query_system_parameters.side_effect = RuntimeError('unavailable')
        with self.assertRaises(DeviceSelectionError):
            detect_platform(device)
        self.assertEqual(detect_platform(device, 'android'), 'android')

    def test_invalid_selection_reprompts_like_original_without_fallback(self):
        api = Mock()
        api.enumerate_devices.return_value = [fake_device()]
        read = Mock(side_effect=['-1', '2', 'abc', '0'])
        selected = select_device(api, input_fn=read, output=lambda _: None)
        self.assertIs(selected, api.enumerate_devices.return_value[0])
        self.assertEqual(read.call_count, 4)
        api.get_remote_device.assert_not_called()

    def test_original_picker_output_prompt_and_indexes(self):
        class DisplayDevice:
            def __init__(self, id, name, type):
                self.id, self.name, self.type = id, name, type

            def __str__(self):
                return f"Device(id='{self.id}', name='{self.name}', dtype='{self.type}')"

        devices = [DisplayDevice('local', 'Local System', 'local'),
                   DisplayDevice('socket', 'Local Socket', 'remote'),
                   DisplayDevice('barebone', 'GDB Remote Stub', 'remote'),
                   DisplayDevice('iphone', 'iPhone', 'usb')]
        api = Mock()
        api.enumerate_devices.return_value = devices
        output, read = Mock(), Mock(return_value='3')
        self.assertIs(select_device(api, input_fn=read, output=output), devices[3])
        self.assertEqual([call.args[0] for call in output.call_args_list],
                         ['Available devices:\n',
                          "0) Device(id='local', name='Local System', dtype='local')",
                          "1) Device(id='socket', name='Local Socket', dtype='remote')",
                          "2) Device(id='barebone', name='GDB Remote Stub', dtype='remote')",
                          "3) Device(id='iphone', name='iPhone', dtype='usb')"])
        read.assert_called_once_with('\nEnter the index of the device to use: ')

    def test_remote_address_uses_device_manager(self):
        api = Mock()
        result = select_device(api, host='127.0.0.1:27042')
        self.assertIs(result, api.get_device_manager().add_remote_device.return_value)
        api.get_device_manager().add_remote_device.assert_called_once_with('127.0.0.1:27042')


class ParserTests(unittest.TestCase):
    def test_shared_scratchpad_edits_remain_platform_isolated(self):
        from libraries.modules import Module
        with tempfile.TemporaryDirectory() as directory:
            apps = {}
            for platform, suffix in [('android', '.med'), ('ios', '.imed')]:
                app = self.app(platform)
                path = Path(directory) / ('scratchpad' + suffix)
                module = Module(str(path), 'scratchpad', '', '', '// original\n')
                module.save()
                app.modManager.available.append(module)
                apps[platform] = app, path
            with contextlib.redirect_stdout(io.StringIO()):
                apps['android'][0].edit_scratchpad('// android\n')
                apps['ios'][0].edit_scratchpad('// ios\n', mode='a')
            self.assertEqual(json.loads(apps['android'][1].read_text())['Code'], '// android\n')
            self.assertEqual(json.loads(apps['ios'][1].read_text())['Code'], '// original\n// ios\n')
            for app, path in apps.values():
                before = path.read_bytes()
                with self.assertRaises(Exception):
                    app.edit_scratchpad('invalid', mode='invalid')
                self.assertEqual(path.read_bytes(), before)

    def test_shared_session_overwrite_and_scratchpad_prompts_preserved(self):
        for platform in ('android', 'ios'):
            app = self.app(platform)
            with tempfile.TemporaryDirectory() as directory:
                app.base_directory = directory
                saved = Path(directory) / 'existing.session'
                saved.write_text('keep this session')
                with patch('libraries.cli.base.Polar') as prompt, patch.object(app, 'do_export') as export, \
                        patch.object(app, 'edit_scratchpad') as edit:
                    prompt.return_value.ask.return_value = False
                    app.save_session('existing')
                    app.scratchreset()
                    export.assert_not_called()
                    edit.assert_not_called()
                    self.assertEqual(saved.read_text(), 'keep this session')
                    prompt.return_value.ask.return_value = True
                    app.save_session('existing')
                    export.assert_called_once_with('existing.session')

    def test_logo_precedes_device_picker_once(self):
        for platform, argv in [('android', []), ('ios', ['--platform', 'ios'])]:
            from libraries.cli.app import main
            events = []
            with patch('libraries.cli.app.print_logo', side_effect=lambda _: events.append('logo')) as logo, \
                    patch('libraries.cli.app.select_device', side_effect=lambda *args, **kwargs: events.append('picker') or fake_device(platform)), \
                    patch('libraries.cli.app.create_application'), \
                    patch('libraries.cli.app.run_application_loop', return_value=0), \
                    patch('libraries.cli.app.configure_readline'):
                self.assertEqual(main(argv), 0)
            self.assertEqual(events, ['logo', 'picker'])
            logo.assert_called_once_with('ios' if argv else None)

    def test_shared_banner_preserves_original_platform_artwork(self):
        from libraries.cli.banner import render_logo
        expected = json.loads((Path(__file__).parent / 'fixtures' / 'legacy_banners.json').read_text())
        for platform, digest in expected.items():
            self.assertEqual(hashlib.sha256(render_logo(platform).encode()).hexdigest(), digest)
        self.assertIn('(Android / iOS)', render_logo())

    def test_direct_python_entry_points_use_unified_startup(self):
        from libraries.cli.app import main
        for name in ('medusa',):
            self.assertIs(importlib.import_module(name).main, main)

    def test_removed_startup_flags_are_rejected_before_device_access(self):
        from libraries.cli.app import main
        for flag in ('--legacy-android', '--legacy-ios', '--ios'):
            with self.subTest(flag=flag), contextlib.redirect_stderr(io.StringIO()), \
                    patch('libraries.cli.app.create_application') as create, \
                    patch('libraries.cli.app.select_device') as select:
                with self.assertRaises(SystemExit) as error:
                    main([flag])
                self.assertEqual(error.exception.code, 2)
                create.assert_not_called()
                select.assert_not_called()


    def test_tab_binding_for_libedit_and_gnu_readline(self):
        for documentation, expected in [('libedit readline', 'bind ^I rl_complete'),
                                        ('GNU readline', 'tab: complete'), (None, 'tab: complete')]:
            with patch('libraries.cli.app.readline.__doc__', documentation), \
                    patch('libraries.cli.app.readline.parse_and_bind') as bind:
                configure_readline()
                bind.assert_called_once_with(expected)

    def test_android_named_entry_routes_iphone_without_android_controller(self):
        import medusa
        device = fake_device('ios')
        app = Mock()
        app.pending_switch = None
        app.cmdloop.return_value = 0
        with patch('libraries.cli.app.select_device', return_value=device), \
                patch('libraries.cli.app.create_application', return_value=app) as create, \
                patch('libraries.cli.app.configure_readline') as completion, \
                patch.object(medusa, 'AndroidDevice') as android_controller:
            self.assertEqual(medusa.main([]), 0)
            self.assertEqual(create.call_args.args[0], 'ios')
            completion.assert_called_once()
            app.cmdloop.assert_called_once()
            android_controller.assert_not_called()

    def test_every_legacy_command_and_completion_is_retained(self):
        fixture = Path(__file__).parent / 'fixtures' / 'legacy_commands.json'
        baseline = json.loads(fixture.read_text())
        for platform, methods in baseline.items():
            app = self.app(platform)
            for name, expected in methods.items():
                with self.subTest(platform=platform, method=name):
                    node = method_ast(getattr(app, name))
                    self.assertEqual(ast.dump(node.args, include_attributes=False), expected['arguments'])
                    # Device selection is unified; iOS compile uses the new bridge build.
                    # Dedicated tests exercise these two intentional changes.
                    if name in {'do_loaddevice', 'do_compile', 'do_exit'}:
                        continue
                    actual = hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
                    self.assertEqual(actual, expected['ast_sha256'])

    def app(self, platform):
        args = argument_parser().parse_args([])
        return create_application(platform, fake_device(platform), args, Mock())

    def test_platform_commands_are_separate_and_preserved(self):
        for platform, module_name in (('android', 'medusa'), ('ios', 'libraries.platforms.ios')):
            backend = importlib.import_module(module_name)
            expected = {n for n in dir(backend.Parser) if n.startswith('do_')}
            actual = {n for n in dir(self.app(platform)) if n.startswith('do_')}
            self.assertEqual(actual, expected)
        self.assertTrue(hasattr(self.app('android'), 'do_dexload'))
        self.assertFalse(hasattr(self.app('ios'), 'do_dexload'))

    def test_mutable_state_is_instance_owned(self):
        first, second = self.app('android'), self.app('android')
        first.packages.append('example')
        first.modManager.staged.append('example')
        first.app_info['example'] = True
        self.assertEqual(second.packages, [])
        self.assertEqual(second.modManager.staged, [])
        self.assertEqual(second.app_info, {})
        self.assertIsNone(self.app('ios').device)

    def test_ios_device_assignment_updates_prompt(self):
        app = self.app('ios')
        app.device = fake_device('ios', device_id='selected-ios')
        self.assertIn('selected-ios', app.prompt)

    def test_module_catalogs_remain_platform_specific(self):
        for platform, suffix in (('android', '.med'), ('ios', '.imed')):
            app = self.app(platform)
            with contextlib.redirect_stdout(io.StringIO()):
                app.do_reload('')
            self.assertTrue(app.modManager.available)
            self.assertTrue(all(m.path.endswith(suffix) for m in app.modManager.available))

    def test_preloop_uses_selected_device_and_loads_recipe(self):
        for platform, module_name in (('android', 'medusa'), ('ios', 'libraries.platforms.ios')):
            backend = importlib.import_module(module_name)
            args = argument_parser().parse_args(['-r', 'example.recipe'])
            device = fake_device(platform)
            app = create_application(platform, device, args, Mock())
            with tempfile.TemporaryDirectory() as directory, patch('libraries.cli.app.ROOT', Path(directory)), \
                    patch.object(backend, 'agent_script', backend.agent_script), \
                    patch.object(backend, 'AndroidDevice', create=True), \
                    patch.object(app, 'do_reload'), patch.object(app, 'write_recipe') as recipe, \
                    patch.object(app, 'init_packages') as packages, \
                    contextlib.redirect_stdout(io.StringIO()):
                app.preloop()
                self.assertIs(app.device, device)
                recipe.assert_called_once_with('example.recipe')
                packages.assert_called_once_with('-3' if platform == 'android' else '')
                self.assertTrue(Path(backend.agent_script).is_file())

    def test_ios_noninteractive_rejected_before_startup(self):
        with tempfile.NamedTemporaryFile() as recipe:
            args = argument_parser().parse_args(['--not-interactive', '-r', recipe.name,
                '-t', '1', '-p', 'test', '-s', 'test.log', '-d', 'fake'])
            validate_options(args, 'android')
            with self.assertRaises(DeviceSelectionError):
                validate_options(args, 'ios')

    def test_missing_recipe_and_partial_noninteractive_rejected(self):
        for argv in (['-r', '/nonexistent-medusa-recipe'], ['--not-interactive'], ['-t', '1']):
            with self.assertRaises(DeviceSelectionError):
                validate_options(argument_parser().parse_args(argv))

    def test_platform_override_and_recipe_are_accepted(self):
        args = argument_parser().parse_args(['--platform', 'ios', '-r', 'saved.recipe'])
        self.assertEqual(args.platform, 'ios')
        self.assertEqual(args.recipe, 'saved.recipe')

    def test_platform_switch_requested_without_losing_current_state(self):
        app = self.app('ios')
        original = fake_device('ios')
        app.device = original
        with patch('libraries.cli.app.select_device', return_value=fake_device('android')) as select, \
                patch.object(app, 'perror') as error:
            self.assertTrue(app.do_loaddevice(''))
            self.assertIs(app.device, original)
            self.assertEqual(app.pending_switch[0], 'android')
            error.assert_not_called()
            select.reset_mock()
            app.script = object()
            app.do_loaddevice('')
            select.assert_not_called()

    def test_platform_round_trip_keeps_staging_agent_history_and_changes_commands(self):
        args = argument_parser().parse_args(['-r', 'startup.recipe'])
        first = create_application('ios', fake_device('ios'), args, Mock())
        second = create_application('android', fake_device('android'), args, Mock())
        first.modManager.staged.append('ios-work')
        second.modManager.staged.append('android-work')
        first.agent_script_path, second.agent_script_path = 'ios-agent', 'android-agent'
        first.initialized = second.initialized = True
        def to_android():
            self.assertFalse(hasattr(first, 'do_dexload'))
            first.pending_switch = ('android', fake_device('android'))
            return 0
        def to_ios():
            self.assertTrue(hasattr(second, 'do_dexload'))
            second.pending_switch = ('ios', fake_device('ios', 'returned-iphone'))
            return 0
        def finish():
            self.assertEqual(first.modManager.staged, ['ios-work'])
            self.assertEqual(first.agent_script_path, 'ios-agent')
            return 0
        steps = iter([to_android, finish])
        with patch.object(first, 'cmdloop', side_effect=lambda: next(steps)()) as run_first:
            with patch.object(second, 'cmdloop', side_effect=to_ios), \
                    patch.object(second, 'preloop'), patch.object(first, 'activate_device') as activate, \
                    patch('libraries.cli.app.create_application', return_value=second) as create:
                self.assertEqual(run_application_loop(first, 'ios', args, Mock()), 0)
        self.assertEqual(run_first.call_count, 2)
        self.assertEqual(create.call_count, 1)
        self.assertIsNone(create.call_args.args[2].recipe)
        self.assertEqual(activate.call_args.args[0].id, 'returned-iphone')
        self.assertIs(first.history, second.history)
        self.assertEqual(second.modManager.staged, ['android-work'])

    def test_real_command_loops_switch_platforms_and_restore_work(self):
        import cmd2
        from libraries.platforms import android, ios
        args = argument_parser().parse_args([])
        initial = create_application('ios', fake_device('ios'), args, Mock())
        phases = iter(['ios-first', 'android', 'ios-return'])
        saved = {}

        def commands(app):
            phase = next(phases)
            if phase == 'ios-return':
                self.assertIs(app, initial)
                self.assertFalse(hasattr(app, 'do_dexload'))
                self.assertEqual(app.modManager.staged, [saved['module']])
                self.assertEqual(app.agent_script_path, saved['agent'])
                self.assertTrue(Path(saved['agent']).is_file())
                self.assertEqual(app.prompt, saved['prompt'])
                return
            self.assertEqual(hasattr(app, 'do_dexload'), phase == 'android')
            if phase == 'ios-first':
                saved.update(module=app.modManager.available[0], agent=app.agent_script_path, prompt=app.prompt)
                app.modManager.staged.append(saved['module'])
            else:
                self.assertNotIn(saved['module'], app.modManager.available)
            self.assertTrue(app.onecmd_plus_hooks('loaddevice'))

        with tempfile.TemporaryDirectory() as directory, patch('libraries.cli.app.ROOT', Path(directory)), \
                patch.object(android, 'agent_script', android.agent_script), \
                patch.object(ios, 'agent_script', ios.agent_script), \
                patch.object(android, 'AndroidDevice'), \
                patch.object(android.Parser, 'init_packages', lambda self, option='': None), \
                patch.object(ios.Parser, 'init_packages', lambda self, option='': None), \
                patch('libraries.cli.app.select_device', side_effect=[fake_device('android'), fake_device('ios')]), \
                patch.object(cmd2.Cmd, '_cmdloop', commands), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(run_application_loop(initial, 'ios', args, Mock()), 0)
        self.assertEqual([item.raw for item in initial.history].count('loaddevice'), 2)

    def test_backend_paths_and_legacy_imports_survive_relocation(self):
        from libraries.platforms import android, ios
        root = Path(__file__).resolve().parents[1]
        self.assertIs(importlib.import_module('medusa'), android)
        for backend in (android, ios):
            self.assertEqual(Path(backend.Parser.base_directory), root)
            self.assertTrue((Path(backend.Parser.base_directory) / 'modules').is_dir())

    def test_failed_platform_switch_returns_to_current_prompt(self):
        first = self.app('ios')
        first.modManager.staged.append('keep')
        next_app = Mock()
        next_app.preloop.side_effect = RuntimeError('device unavailable')
        def switch():
            first.pending_switch = ('android', fake_device('android'))
            return 0
        steps = iter([switch, lambda: 0])
        with patch.object(first, 'cmdloop', side_effect=lambda: next(steps)()) as loop, \
                patch('libraries.cli.app.create_application', return_value=next_app), patch.object(first, 'perror') as error:
            self.assertEqual(run_application_loop(first, 'ios', argument_parser().parse_args([]), Mock()), 0)
        self.assertEqual(loop.call_count, 2)
        self.assertEqual(first.modManager.staged, ['keep'])
        error.assert_called_once_with('device unavailable')

    def test_completed_session_can_switch_and_clear_old_device_state(self):
        for platform in ('android', 'ios'):
            app = self.app(platform)
            app.script = SimpleNamespace(is_destroyed=True)
            app.native_handler = object()
            app.pid = 123
            app.app_libraries = ['old-library']
            staged = app.modManager.staged
            selected = fake_device(platform, 'replacement')
            with patch('libraries.cli.app.select_device', return_value=selected), \
                    patch('medusa.AndroidDevice'), patch.object(app, 'init_packages') as packages:
                app.do_loaddevice('')
            self.assertIs(app.device, selected)
            self.assertIsNone(app.script)
            self.assertIsNone(app.native_handler)
            self.assertIsNone(app.pid)
            self.assertEqual(app.app_libraries, [])
            self.assertIs(app.modManager.staged, staged)
            packages.assert_called_once_with('-3' if platform == 'android' else '')

    def test_failed_device_switch_restores_previous_state(self):
        app = self.app('ios')
        original = fake_device('ios', 'original')
        app.device = original
        app.packages = ['previous-app']
        app.script = SimpleNamespace(is_destroyed=True)
        previous_script = app.script
        with patch('libraries.cli.app.select_device', return_value=fake_device('ios', 'replacement')), \
                patch.object(app, 'init_packages', side_effect=RuntimeError('enumeration failed')), \
                patch.object(app, 'perror') as error:
            app.do_loaddevice('')
        self.assertIs(app.device, original)
        self.assertEqual(app.packages, ['previous-app'])
        self.assertIs(app.script, previous_script)
        self.assertIn('original', app.prompt)
        error.assert_called_once_with('enumeration failed')


class CompatibilityTests(unittest.TestCase):
    def test_dead_assignment_cleanup_changes_only_recorded_statements(self):
        fixture = Path(__file__).parent / 'fixtures' / 'cleanup_methods.json'
        for record in json.loads(fixture.read_text()):
            cls = getattr(importlib.import_module(record['module']), record['class'])
            node = method_ast(getattr(cls, record['method']))
            digest = hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
            self.assertEqual(digest, record['expected_sha256'], record['method'])

    def test_all_original_class_methods_have_only_reviewed_changes(self):
        baseline = json.loads((Path(__file__).parent / 'fixtures' / 'legacy_class_methods.json').read_text())
        cleanup = {(r['group'], r['method']): r for r in json.loads(
            (Path(__file__).parent / 'fixtures' / 'cleanup_methods.json').read_text())}
        classes = {
            'android': type(create_application('android', fake_device(), argument_parser().parse_args([]), Mock())),
            'ios': type(create_application('ios', fake_device('ios'), argument_parser().parse_args([]), Mock())),
            'native': importlib.import_module('libraries.natives').nativeHandler,
            'mcp': importlib.import_module('medusa_android_mcp').MedusaAndroidBridge,
        }
        reviewed_changes = {
            ('android', '__init__'), ('ios', '__init__'),
            ('android', 'preloop'), ('ios', 'preloop'),
            ('android', 'do_loaddevice'), ('ios', 'do_loaddevice'),
            ('ios', 'do_compile'),
            ('android', 'do_compile'),
            ('android', 'reload_script'), ('ios', 'reload_script'),
            ('mcp', '_reload_active_script'), ('mcp', 'attach_app'),
            ('android', 'do_exit'), ('ios', 'do_exit'),
            ('mcp', '__init__'), ('mcp', '_capture_console_output'), ('mcp', '_uninstall_stdout_proxy'),
            ('native', 'load_java_bridge'), ('native', 'add_js_bridge_if_needed'),
        }
        differences = set()
        for platform, record in baseline.items():
            for identifier, expected in record['methods'].items():
                with self.subTest(platform=platform, method=identifier):
                    name, _, accessor = identifier.partition(':')
                    if accessor:
                        descriptor = inspect.getattr_static(classes[platform], name)
                        method = descriptor.fget if accessor == 'get' else descriptor.fset
                    else:
                        method = getattr(classes[platform], name)
                    digest = hashlib.sha256(ast.dump(method_ast(method), include_attributes=False).encode()).hexdigest()
                    if (platform, identifier) in cleanup:
                        record = cleanup[platform, identifier]
                        self.assertEqual(expected, record['baseline_sha256'])
                        self.assertEqual(digest, record['expected_sha256'])
                        continue
                    if digest != expected:
                        differences.add((platform, identifier))
        self.assertEqual(differences, reviewed_changes)

    def test_tab_key_completes_module_names_through_prompt_toolkit(self):
        from cmd2.pt_utils import Cmd2Completer
        from prompt_toolkit import PromptSession
        from prompt_toolkit.input import create_pipe_input
        from prompt_toolkit.output import DummyOutput

        async def complete(platform):
            app = create_application(platform, fake_device(platform), argument_parser().parse_args([]), Mock())
            app.modManager.available = [SimpleNamespace(Name='helpers/example_module')]
            with create_pipe_input() as pipe:
                session = PromptSession(
                    input=pipe, output=DummyOutput(), completer=Cmd2Completer(app),
                    complete_while_typing=False, complete_in_thread=False,
                    key_bindings=app._create_key_bindings('tab'),
                )
                result = asyncio.create_task(session.prompt_async())
                try:
                    pipe.send_text('use helpers/ex\t')
                    async def wait_for_completion():
                        while session.default_buffer.text != 'use helpers/example_module ':
                            await asyncio.sleep(0.01)
                    await asyncio.wait_for(wait_for_completion(), 2)
                    pipe.send_text('\r')
                    self.assertEqual(await asyncio.wait_for(result, 2), 'use helpers/example_module ')
                finally:
                    if not result.done():
                        result.cancel()
                        with contextlib.suppress(asyncio.CancelledError):
                            await result

        for platform in ('android', 'ios'):
            with self.subTest(platform=platform):
                asyncio.run(complete(platform))

    def test_generated_agents_parse_with_current_bridges(self):
        for platform, module_name in (('android', 'medusa'), ('ios', 'libraries.platforms.ios')):
            backend = importlib.import_module(module_name)
            app = backend.Parser()
            app.device = fake_device(platform)
            with tempfile.TemporaryDirectory() as directory:
                agent = Path(directory) / 'agent.js'
                with patch.object(backend, 'agent_script', str(agent)), contextlib.redirect_stdout(io.StringIO()):
                    app.do_compile('')
                self.assertTrue(agent.is_file())
                subprocess.run(['node', '--check', str(agent)], check=True, capture_output=True, text=True)

    def test_compiled_runtime_bridges_exist(self):
        for runtime, symbol in (('java', 'Java'), ('objc', 'ObjC')):
            content = load_runtime_bridge(runtime)
            self.assertGreater(len(content), 1000)
            self.assertIn(symbol, content)
        with self.assertRaises(ValueError):
            load_runtime_bridge('unknown')

    def test_mcp_tool_registration_and_transport_configuration(self):
        with contextlib.redirect_stdout(io.StringIO()):
            adapter = importlib.import_module('medusa_android_mcp')
        tools = asyncio.run(adapter.mcp.list_tools())
        self.assertIn('list_devices', {t.name for t in tools})
        self.assertIn('ensure_session', {t.name for t in tools})
        try:
            for transport in ('stdio', 'streamable-http', 'sse'):
                with patch.dict('os.environ', {'MEDUSA_MCP_TRANSPORT': transport, 'MEDUSA_MCP_PORT': '8111'}), \
                        patch.object(adapter.signal, 'signal'), patch.object(adapter.mcp, 'run') as run:
                    adapter.main()
                    options = {} if transport == 'stdio' else {'host': '127.0.0.1', 'port': 8111}
                    run.assert_called_once_with(transport=transport, **options)
        finally:
            adapter.bridge.cleanup()


if __name__ == '__main__':
    unittest.main()

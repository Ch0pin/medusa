"""Catalog refresh/import checks using isolated module trees only."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from libraries.core.modules import ModuleLoadError, ModuleManager, configured_module_roots
from libraries.core.compiler import AgentLayout, assemble_agent
import test_mcp_lifecycle as fixtures


def write_module(path, name, code='// fixture', options=None, **fields):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(Name=name, Description='fixture', Help='help', Code=code, Options=options, **fields)))
    return path


class CatalogTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.builtin = self.root / 'modules'
        self.builtin.mkdir()
        self.extra = self.root / 'external'
        self.extra.mkdir()
        self.manager = ModuleManager()

    def test_bad_modules_are_skipped_with_diagnostics_and_never_none(self):
        cases = ('{"Name":', '[]', '{"Name": "missing fields"}',
                 json.dumps(dict(Name='bad', Description='', Help='', Code=4)))
        for index, content in enumerate(cases):
            path = self.builtin / f'bad{index}.med'
            path.write_text(content)
        good = write_module(self.builtin / 'good.med', 'helpers/good', options=[{'name': 'enabled', 'value': True}])
        with self.assertLogs('libraries.core.modules', level='WARNING'):
            report = self.manager.refresh([self.builtin])
        self.assertEqual(report['count'], 1)
        self.assertEqual(report['load_error_count'], len(cases))
        self.assertEqual(self.manager.findModule('good'), ['helpers/good'])
        self.assertNotIn(None, self.manager.available)
        self.assertEqual(self.manager.getModule('helpers/good').path, str(good))
        self.assertIn('line', next(error for error in report['load_errors'] if error['code'] == 'invalid_json'))

    def test_import_returns_exact_json_error_location(self):
        path = self.extra / 'broken.med'
        path.write_text('{"Name":"test","Description":"","Help":"","Code":"\\d"}')
        with self.assertRaises(ModuleLoadError) as error:
            self.manager.import_file(path)
        self.assertEqual(error.exception.details['code'], 'invalid_json')
        self.assertEqual(error.exception.details['line'], 1)
        self.assertEqual(self.manager.available, [])

    def test_legacy_multiline_code_and_options_forms_remain_supported(self):
        for index, options in enumerate((None, {}, [])):
            path = write_module(self.extra / f'legacy{index}.med', f'legacy/{index}', 'line1\nline2', options)
            path.write_text(path.read_text().replace('line1\\nline2', 'line1\nline2'))
            self.assertEqual(self.manager.import_file(path).Code, 'line1\nline2')

    def test_builtin_order_and_platform_filter_are_preserved(self):
        write_module(self.builtin / 'first.med', 'first')
        write_module(self.builtin / 'second.med', 'second')
        write_module(self.builtin / 'ios.imed', 'ios-only')
        expected = [str(Path(folder) / name) for folder, dirs, files in os.walk(self.builtin)
                    for name in files if name.endswith('.med')]
        self.manager.refresh([self.builtin])
        self.assertEqual([mod.path for mod in self.manager.available], expected)
        ios = ModuleManager()
        ios.refresh([self.builtin], suffix='.imed')
        self.assertEqual(ios.findModule(''), ['ios-only'])

    def test_roots_use_checkout_anchor_and_deduplicate_aliases(self):
        with patch.dict(os.environ, MEDUSA_MODULE_ROOTS='external' + os.pathsep + str(self.extra)):
            roots = configured_module_roots(self.root)
        self.assertEqual(roots, [str(self.builtin), str(self.extra)])
        self.assertEqual(configured_module_roots(self.root, []), [str(self.builtin)])

    def test_duplicate_name_does_not_shadow_builtin(self):
        original = write_module(self.builtin / 'base.med', 'same/name', '// original')
        incoming = write_module(self.extra / 'other.med', 'same/name', '// replacement')
        with self.assertLogs('libraries.core.modules', level='WARNING'):
            report = self.manager.refresh([self.builtin, self.extra])
        self.assertEqual(self.manager.getModule('same/name').Code, '// original')
        self.assertEqual(report['load_errors'][0]['existing_path'], str(original))
        with self.assertRaises(ModuleLoadError):
            self.manager.import_file(incoming)

    def test_refresh_preserves_staged_objects_edits_order_and_scratchpad(self):
        first = write_module(self.builtin / 'first.med', 'first')
        write_module(self.builtin / 'second.med', 'second')
        scratch = write_module(self.builtin / 'scratchpad.med', 'scratchpad', '// human')
        self.manager.refresh([self.builtin])
        self.manager.stage('second')
        self.manager.stage('first')
        staged = list(self.manager.staged)
        staged[1].Code = '// unsaved operator edit'
        self.manager.getModule('scratchpad').Code = '// unsaved scratchpad'
        write_module(first, 'first', '// changed on disk')
        scratch.unlink()
        report = self.manager.refresh([self.builtin])
        self.assertEqual(self.manager.staged, staged)
        self.assertIs(self.manager.getModule('first'), staged[1])
        self.assertEqual(staged[1].Code, '// unsaved operator edit')
        self.assertEqual(self.manager.getModule('scratchpad').Code, '// unsaved scratchpad')
        self.assertEqual({r['name'] for r in report['retained_staged']}, {'first', 'scratchpad'})
        self.assertEqual(json.loads(first.read_text())['Code'], '// changed on disk')

    def test_deleted_or_invalid_staged_source_is_retained(self):
        path = write_module(self.builtin / 'active.med', 'active')
        self.manager.refresh([self.builtin])
        self.manager.stage('active')
        old = self.manager.getModule('active')
        path.write_text('invalid json')
        with self.assertLogs('libraries.core.modules', level='WARNING'):
            report = self.manager.refresh([self.builtin])
        self.assertIs(self.manager.getModule('active'), old)
        self.assertEqual(report['retained_staged'][0]['reason'], 'source_missing_or_invalid')

    def test_selected_only_module_is_preserved_during_refresh(self):
        path = write_module(self.builtin / 'pending.med', 'pending')
        self.manager.refresh([self.builtin])
        old = self.manager.getModule('pending')
        path.unlink()
        self.manager.refresh([self.builtin], preserve_names=['pending'])
        self.assertIs(self.manager.getModule('pending'), old)
        self.assertEqual(self.manager.staged, [])

    def test_unstaged_sources_refresh_and_imports_survive_rescan(self):
        path = write_module(self.extra / 'module.med', 'declared/name', '// first')
        self.manager.import_file(path)
        write_module(path, 'declared/name', '// updated')
        self.manager.refresh([self.builtin])
        self.assertEqual(self.manager.getModule('declared/name').Code, '// updated')
        self.assertEqual(self.manager.imported_paths, [str(path)])

    def test_import_is_idempotent_but_preserves_staged_edits(self):
        path = write_module(self.extra / 'module.med', 'module')
        old = self.manager.import_file(path)
        self.manager.stage('module')
        self.assertIs(self.manager.import_file(path), old)
        write_module(path, 'module', '// changed')
        with self.assertRaises(ModuleLoadError) as error:
            self.manager.import_file(path)
        self.assertEqual(error.exception.details['code'], 'staged_module')
        self.assertEqual(old.Code, '// fixture')

    def test_external_jni_module_uses_declared_category_for_compilation(self):
        mod = self.manager.import_file(write_module(self.extra / 'hook.med', 'JNICalls/fixture'))
        self.manager.stage(mod.Name)
        (self.root / 'managed_lifecycle.js').write_text('// lifecycle')
        text = assemble_agent(self.manager, AgentLayout((), 'PRE', 'POST', 'JNI_MARKER'), self.root, '')
        self.assertIn('JNI_MARKER', text)
        self.assertLess(text.index('JNI_MARKER'), text.index('// fixture'))

    def test_symlink_files_keep_legacy_path_context_and_are_not_duplicated(self):
        source = write_module(self.extra / 'source.med', 'linked/module')
        folder = self.builtin / 'JNICalls'
        folder.mkdir()
        alias = folder / 'alias.med'
        alias.symlink_to(source)
        self.manager.refresh([self.builtin, self.extra])
        self.assertEqual(len(self.manager.available), 1)
        self.assertEqual(self.manager.available[0].path, str(alias))
        self.assertEqual(self.manager.sources[str(alias)]['canonical_path'], str(source))

    def test_fatal_refresh_error_leaves_previous_catalog_and_staging(self):
        path = write_module(self.builtin / 'active.med', 'active')
        mod = self.manager.import_file(path)
        self.manager.stage('active')
        with self.assertRaises(TypeError):
            self.manager.refresh([object()])
        self.assertEqual(self.manager.available, [mod])
        self.assertEqual(self.manager.staged, [mod])


    def test_interactive_reload_keeps_commands_and_platform_filtering(self):
        from libraries.platforms import android, ios
        write_module(self.root / 'modules/android.med', 'android-only')
        write_module(self.root / 'modules/ios.imed', 'ios-only')
        write_module(self.extra / 'external.med', 'external-android')
        write_module(self.extra / 'external.imed', 'external-ios')
        with patch.dict(os.environ, MEDUSA_MODULE_ROOTS=str(self.extra)), contextlib.redirect_stdout(io.StringIO()):
            for backend, expected in ((android, ['android-only', 'external-android']), (ios, ['ios-only', 'external-ios'])):
                parser = backend.Parser()
                parser.base_directory = str(self.root)
                parser.do_reload('')
                self.assertEqual([mod.Name for mod in parser.modManager.available], expected)
                self.assertEqual(parser.modManager.roots, configured_module_roots(self.root))


class MCPCatalogTests(unittest.TestCase):
    def setUp(self):
        fixtures.MCPLifecycleTests.setUp(self)
        self.root = self.bridge.agent_script_path.parent.resolve()
        self.bridge.parser.base_directory = str(self.root)
        (self.root / 'modules').mkdir()

    def test_import_stages_exact_name_without_copying_code_to_scratchpad(self):
        code = '// external code\n' * 4000
        path = write_module(self.root / 'private/module.med', 'private/declared', code)
        before_script, overlay, scratch = self.bridge.script, self.bridge.agent_overlay_script, self.scratchpad.Code
        result = self.bridge.import_module(str(path))
        self.assertTrue(result['imported'])
        self.assertEqual(result['name'], 'private/declared')
        self.assertEqual(result['code_length'], len(code))
        self.assertNotIn('code', result)
        self.assertIn('private/declared', self.bridge.selected_modules)
        self.assertIn(code, self.bridge.parser.modManager.compile())
        self.assertIs(self.bridge.script, before_script)
        self.assertEqual(self.bridge.agent_overlay_script, overlay)
        self.assertEqual(self.scratchpad.Code, scratch)
        self.assertEqual(self.session.detach_calls, 0)

    def test_refresh_finds_new_file_and_preserves_active_state(self):
        self.assertEqual(self.bridge.search_modules('new-module'), [])
        write_module(self.root / 'modules/new.med', 'new-module')
        before_script = self.bridge.script
        result = self.bridge.refresh_modules([])
        self.assertEqual(self.bridge.search_modules('new-module'), ['new-module'])
        self.assertFalse(result['active_session_changed'])
        self.assertIs(self.bridge.script, before_script)
        self.assertIs(self.bridge.parser.modManager.getModule('scratchpad'), self.scratchpad)
        self.assertEqual(self.session.detach_calls, 0)

    def test_additional_roots_and_diagnostics_are_visible(self):
        private = self.root / 'private'
        write_module(private / 'module.med', 'private/one')
        (private / 'bad.med').write_text('invalid json')
        with self.assertLogs('libraries.core.modules', level='WARNING'):
            result = self.bridge.refresh_modules([str(private)])
        self.assertEqual(result['load_error_count'], 1)
        source = self.bridge.get_module_source('private/one')
        self.assertEqual(source['path'], str(private / 'module.med'))
        self.assertIn('source_sha256', source['source'])
        listing = self.bridge.list_modules(pattern='private/')
        self.assertEqual(listing['modules'], ['private/one'])
        self.assertIn(str(private), listing['roots'])
        self.assertEqual(listing['load_error_count'], 1)

    def test_failed_import_preserves_catalog_and_selected_modules(self):
        old = list(self.bridge.parser.modManager.available)
        result = self.bridge.import_module(str(self.root / 'missing.med'))
        self.assertFalse(result['imported'])
        self.assertEqual(result['error']['code'], 'read_error')
        self.assertEqual(self.bridge.parser.modManager.available, old)
        self.assertEqual(self.bridge.selected_modules, [])

    def test_refresh_and_import_are_blocked_during_runtime_operations(self):
        self.bridge.attach_in_progress = {'id': 'pending', 'phase': 'attaching'}
        with self.assertRaisesRegex(RuntimeError, 'still in progress'):
            self.bridge.refresh_modules([])
        with self.assertRaisesRegex(RuntimeError, 'still in progress'):
            self.bridge.import_module('/tmp/unused.med')
        self.bridge.attach_in_progress = None

if __name__ == '__main__':
    unittest.main()

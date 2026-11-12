"""Regression for synchronous agent logging while the reload caller owns its lock."""
from pathlib import Path
import contextlib
import io
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch


class ConsoleLockTests(unittest.TestCase):
    def test_console_lines_and_partial_line_survive_proxy_cleanup(self):
        from libraries.integrations import mcp_android
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(mcp_android, 'ROOT', Path(directory)), \
                patch.object(mcp_android.medusa_app, 'agent_script', mcp_android.medusa_app.agent_script), \
                patch.object(mcp_android.medusa_app.Parser, 'do_reload', lambda self, line: None):
            bridge = mcp_android.MedusaAndroidBridge()
            output = io.StringIO()
            try:
                with contextlib.redirect_stdout(output):
                    bridge._install_stdout_proxy()
                    sys.stdout.write('first ')
                    sys.stdout.write('line\npartial')
                    bridge._uninstall_stdout_proxy()
                    self.assertIs(sys.stdout, output)
                self.assertEqual(output.getvalue(), 'first line\npartial')
                self.assertEqual([event['payload'] for event in bridge.events], ['first line', 'partial'])
            finally:
                bridge.cleanup()

    def test_reload_logging_does_not_wait_for_session_lock(self):
        from libraries.integrations import mcp_android
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(mcp_android, 'ROOT', Path(directory)), \
                patch.object(mcp_android.medusa_app, 'agent_script', mcp_android.medusa_app.agent_script), \
                patch.object(mcp_android.medusa_app.Parser, 'do_reload', lambda self, line: None):
            bridge = mcp_android.MedusaAndroidBridge()
            callback_finished = threading.Event()
            class Script:
                def on(self, *args):
                    pass
                def load(self):
                    bridge._capture_console_output('runtime reload marker\n')
                    callback_finished.set()
                def unload(self):
                    pass
            replacement = Script()
            bridge.script = Script()
            bridge.session = SimpleNamespace(create_script=lambda source: replacement, on=lambda *args: None)
            bridge.current_target = {'attached': True}
            try:
                with bridge.lock:
                    result = bridge._reload_active_script(timeout=0.5)
                self.assertTrue(callback_finished.wait(2))
                self.assertTrue(result, 'Reload timed out while its logging callback waited for the caller lock')
                self.assertIs(bridge.script, replacement)
                self.assertIs(bridge.parser.script, replacement)
                self.assertTrue(bridge.current_target['attached'])
                self.assertTrue(any(e.get('payload') == 'runtime reload marker' for e in bridge.events))
            finally:
                bridge.cleanup()


if __name__ == '__main__':
    unittest.main()

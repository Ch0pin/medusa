#!/usr/bin/env python3
"""Unified startup with platform-specific command backends and shared CLI helpers."""
import argparse
import importlib
from pathlib import Path
import secrets
import sys
import readline

from libraries.cli.device_picker import DeviceSelectionError, detect_platform, select_device
from libraries.cli.banner import print_logo
from libraries.cli.prompts import Polar
from libraries.core.agent_files import cleanup_agent_files

from libraries.core.paths import ROOT


def configure_readline():
    """Enable Tab completion on both macOS libedit and GNU readline."""
    binding = 'bind ^I rl_complete' if 'libedit' in (readline.__doc__ or '') else 'tab: complete'
    readline.parse_and_bind(binding)


def argument_parser():
    parser = argparse.ArgumentParser(description="Medusa: select a device to load Android or iOS commands.")
    parser.add_argument('--platform', choices=('android', 'ios'))
    device = parser.add_mutually_exclusive_group()
    device.add_argument('-d', '--device', help='Frida device ID')
    device.add_argument('--host', help='Remote Frida address (host:port)')
    parser.add_argument('-r', '--recipe')
    parser.add_argument('--not-interactive', action='store_true')
    parser.add_argument('-t', '--time', type=int)
    parser.add_argument('-p', '--package-name')
    parser.add_argument('-s', '--save')
    return parser


def validate_options(args, platform=None):
    if args.not_interactive:
        if not all((args.recipe, args.time, args.package_name, args.save, args.device or args.host)):
            raise DeviceSelectionError('Non-interactive mode requires --recipe, --time, --package-name, --save and --device or --host.')
        if args.time <= 0:
            raise DeviceSelectionError('--time must be greater than zero.')
        if platform == 'ios':
            raise DeviceSelectionError('Non-interactive mode is currently supported by the Android backend only.')
    elif any(value is not None for value in (args.time, args.package_name, args.save)):
        raise DeviceSelectionError('--time, --package-name and --save require --not-interactive.')
    if args.recipe and not Path(args.recipe).is_file():
        raise DeviceSelectionError(f'Recipe does not exist: {args.recipe}')


def create_application(platform, device, args, frida_api):
    backend = importlib.import_module('libraries.platforms.android' if platform == 'android' else 'libraries.platforms.ios')

    class Application(backend.Parser):
        """Only the selected backend contributes platform commands to cmd2."""

        def load_startup_catalog(self):
            if not self.catalog_ready:
                self.do_reload('')
                self.catalog_ready = True

        def announce_devices(self):
            if platform == 'android':
                backend.logger.info('Available devices:\n')
            else:
                print('Available devices:\n')

        def preloop(self):
            if self.initialized:
                backend.agent_script = self.agent_script_path
                return
            self.load_startup_catalog()
            self.agent_script_path = str(ROOT / f'{secrets.token_hex(8)}_agent_script')
            backend.agent_script = self.agent_script_path
            Path(backend.agent_script).touch(exist_ok=False)
            self.state.session.agent_files[self.agent_script_path] = None
            self.interactive = not args.not_interactive
            self.time_to_run = args.time
            self.package_name = args.package_name
            self.save_to_file = args.save
            if args.recipe:
                self.write_recipe(args.recipe)
            self.activate_device(self.startup_device)
            self.initialized = True
            if not self.interactive:
                self.do_compile('')
                self.run_frida_n_interactive(True, False, self.package_name, self.device)

        def activate_device(self, selected):
            # Keep staged modules and agent files for this platform. Replace only
            # device-specific state, restoring it if application discovery fails.
            replacement = {
                'device': selected, 'device_id': selected.id, 'packages': [],
                'app_info': {}, 'currentPackage': None, 'script': None,
                'pid': None, 'detached': True, 'native_handler': None,
                'native_functions': [], 'system_libraries': [],
                'app_libraries': [], 'libname': None, 'package_range': '',
            }
            if platform == 'android':
                replacement['device_controller'] = backend.AndroidDevice(selected.id)
            previous = {key: getattr(self, key, None) for key in replacement}
            try:
                for key, value in replacement.items():
                    setattr(self, key, value)
                if self.interactive:
                    if platform == 'android':
                        self.device_controller.print_dev_properties()
                    else:
                        print(f"Using device: {selected}")
                    self.init_packages('-3' if platform == 'android' else '')
            except Exception:
                for key, value in previous.items():
                    setattr(self, key, value)
                raise

        def do_loaddevice(self, line):
            """Select a device and load its Android or iOS commands."""
            if self.script is not None and not getattr(self.script, 'is_destroyed', False):
                self.perror('Exit the active session before selecting another device.')
                return
            try:
                selected = select_device(frida_api, announce=self.announce_devices)
                selected_platform = detect_platform(selected)
                if selected_platform != platform:
                    self.pending_switch = (selected_platform, selected)
                    return True
                self.activate_device(selected)
            except Exception as exc:
                self.perror(str(exc))

        def finalize_agent_files(self, prompt=False):
            choose_keep = None
            if prompt and self.interactive:
                def choose_keep(path):
                    return Polar(f'Do you want to keep the agent script at "{path}" ?').ask()
            result = cleanup_agent_files(self.state.session.agent_files, choose_keep)
            for path in result.removed:
                backend.logger.info(f'Agent script deleted: {path}')
            for path, error in result.errors.items():
                self.perror(f'Failed to delete agent script {path}: {error}')

    application = Application()
    application.initialized = False
    application.catalog_ready = False
    application.startup_device = device
    application.interactive = not args.not_interactive
    application.pending_switch = None
    return application


def run_application_loop(app, platform, args, frida_api):
    """Switch command backends inside one process, retaining each platform's work."""
    applications = {platform: app}
    instances = [app]
    normal_exit = False

    def finalize_all(prompt=False):
        for instance in instances:
            instance.finalize_agent_files(prompt=prompt)

    app._before_cli_exit = lambda: finalize_all(prompt=True)
    try:
        while True:
            try:
                result = app.cmdloop()
            except SystemExit:
                normal_exit = True
                raise
            request = app.pending_switch
            app.pending_switch = None
            if request is None:
                normal_exit = True
                return result or 0
            next_platform, selected = request
            previous = app
            try:
                if next_platform in applications:
                    candidate = applications[next_platform]
                    candidate.activate_device(selected)
                else:
                    # A startup recipe belongs to the initial platform; do not replay
                    # it when switching to a different platform's module catalog.
                    switch_args = argparse.Namespace(**vars(args))
                    switch_args.recipe = None
                    candidate = create_application(next_platform, selected, switch_args, frida_api)
                    candidate._before_cli_exit = lambda: finalize_all(prompt=True)
                    instances.append(candidate)
                    candidate.preloop()
                    applications[next_platform] = candidate
                # Keep shell history continuous while commands/completion are owned
                # by the active platform's parser.
                candidate.history = previous.history
                candidate.main_session.history = previous.main_session.history
                candidate.main_session.default_buffer.history = previous.main_session.history
                app = candidate
            except Exception as exc:
                previous.perror(str(exc))
                app = previous
    finally:
        finalize_all(prompt=normal_exit)


def main(argv=None):
    parser = argument_parser()
    args = parser.parse_args(argv)
    try:
        validate_options(args, args.platform)
        import frida
        initial_platform = args.platform or 'android'
        prepared = create_application(initial_platform, None, args, frida)
        prepared.load_startup_catalog()
        print_logo(args.platform)
        device = select_device(frida, args.device, args.host, announce=prepared.announce_devices)
        platform = detect_platform(device, args.platform)
        validate_options(args, platform)
        configure_readline()
        if platform == initial_platform:
            app = prepared
            app.startup_device = device
        else:
            app = create_application(platform, device, args, frida)
        return run_application_loop(app, platform, args, frida)
    except (DeviceSelectionError, EOFError, KeyboardInterrupt) as exc:
        print(f'Medusa: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

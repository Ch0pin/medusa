#!/usr/bin/env python3

# Standard library imports
from pathlib import Path
import json
import os
import re
import subprocess
import sys
import time
from packaging.version import  parse as parse_version, Version

# Third-party imports
import click
import frida
import requests
import yaml
from pick import pick

# Local application/library specific imports
from libraries.core.bridges import load_runtime_bridge
from libraries.cli.app import main as main
from libraries.cli.banner import render_logo
from libraries.core.compiler import AgentLayout, assemble_agent
from libraries.core.sessions import reload_script as reload_session_script
from libraries.cli.base import SharedParser
from libraries.core.modules import ModuleManager
from libraries.lib_adb import logger
from libraries.cli.prompts import Numeric, Polar

RED = "\033[1;31m"
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
WHITE = "\033[1;37m"
YELLOW = "\033[1;33m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD = "\033[;1m"
REVERSE = "\033[;7m"
agent_script = "agent_ios.js"
scratchpad_module = 'modules/scratchpad.imed'
medusa_logo = render_logo('ios')



AGENT_LAYOUT = AgentLayout(
    headers=('globals.js', 'beautifiers.js', 'utils.js', 'ios_core.js'),
    preamble='try \n{\n',
    epilog='}\n    catch(error){\n        colorLog("------------Error Log start-------------",{ c:Color.Red })\n        console.log(error.stack);\n        colorLog("------------Error Log EOF---------------",{ c:Color.Red })\n     };',
    jni_prolog=None,
)

class Parser(SharedParser):
    base_directory = str(Path(__file__).resolve().parents[2])
    show_commands = ['mods', 'categories', 'all']
    prompt = BLUE + '(ios) medusa➤' + RESET



    def observe_device_change(self, _device):
        if self._device is not None:
            self.prompt = f'({self._device.id}) '+ BLUE + '(ios) medusa➤' + RESET

    def refreshPackages(self, option=""):
        self.package_range = "- Installed applications"
        self.packages = frida.get_device(self.device.id).enumerate_applications(scope="full")


    ###################################################### do_ defs start ############################################################

    def do_agent(self, line) -> None:
        """
            Open the agent script in your default editor.
            Usage: 
                agent
        """
        config_path = os.path.join(self.base_directory, 'config.yaml')
        editor = "vim"  # fallback default

        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                cfg = yaml.safe_load(f) or {}
                editor = cfg.get("default_editor", editor)

        subprocess.run(f'{editor} "{agent_script}"', shell=True)

        logger.info(f'Current agent script path: {os.path.abspath(agent_script)}')

    def do_clear(self, line) -> None:
        """
        Clear the screen (no args)
        """
        subprocess.run('clear', shell=True)

    def do_compile(self, line, rs=False) -> None:
        """Compile staged modules using the shared agent assembly service."""
        try:
            installed = parse_version(getattr(frida, "__version__", "0.0.0"))
            bridge = load_runtime_bridge("objc") if installed >= Version("17.0.0") else None
            headers = ("frida_module_bridge.js",) if installed >= Version("17.0.0") else ()
            code = assemble_agent(self.modManager, AGENT_LAYOUT,
                                  Path(self.base_directory) / 'libraries' / 'js', line,
                                  runtime_bridge=bridge, extra_headers=headers)
            # Keep the legacy module global as the public compatibility boundary.
            self.agent_script_path = os.path.join(self.base_directory, agent_script)
            with open(self.agent_script_path, 'w') as agent:
                agent.write(code)
            if rs:
                print("\nScript has been reset\n")
            else:
                print("\nScript is compiled\n")
            self.modified = False
        except Exception as e:
            print(e)
        self.modified = False

    def do_exit(self, line) -> None:
        """
        Exit MEDUSA
        """
        agent_path = self.agent_script_path or os.path.join(self.base_directory, agent_script)
        scratchpad_path = os.path.join(self.base_directory, scratchpad_module)

        if os.path.exists(agent_path) and os.path.getsize(agent_path) != 0:
            reset_agent = Polar('Do you want to reset the agent script?').ask()
            if agent_path in self.state.session.agent_files:
                self.state.session.agent_files[agent_path] = not reset_agent
            if reset_agent:
                if agent_path in self.state.session.agent_files:
                    Path(agent_path).unlink(missing_ok=True)
                else:
                    open(agent_path, 'w').close()

        if os.path.getsize(scratchpad_path) != 119:
            if Polar('Do you want to reset the scratchpad?').ask():
                self.edit_scratchpad('')

        cleanup = getattr(self, '_before_cli_exit', None)
        if cleanup:
            cleanup()
        print('Bye!!')
        sys.exit()

    def do_export(self, line) -> None:
        """
        Exports the current loaded modules and scratchpad contents for later usage.
        Usage: 
        export  'filename' 
        To reload the same list of scripts, type 'medusa -r saved_file'
        """
        try:
            with open(line, 'w') as file:
                for mod in filter(lambda mod: mod.Name != 'scratchpad', self.modManager.staged):
                    file.write('MODULE ' + mod.Name + '\n')
                file.write(self.modManager.getModule('scratchpad').Code)
            if os.path.splitext(line)[1] == '.session':
                print(
                    f"Current session mod list saved as: {os.path.splitext(line)[0]}, use session --load to reload it")
            else:
                print(f'Recipe exported to dir: {os.getcwd()} as {line}')
        except Exception as e:
            print(e)
            print("[i] Usage: export filename")

    def do_hook(self, line) -> None:
        """
        Hook a method or methods
        Usage:
        hook [options] where option can be one of the following:
            -a [class name] [--color] : Set hooks for all the methods of the given class.  
                                        (optional) Use the --color option to set different color output 
                                        (default is purple)
        """
        option = line.split(' ')[0]
        if option == '-a':
            aclass = line.split(' ')[1].strip()
            if aclass == '':
                print('[i] Usage hook -a class_name')
            else:
                if len(line.split(' ')) > 2:
                    if line.split(' ')[2].strip() == '--color':
                        colors = ['black', 'blue', 'brown', 'cyan', 'gold', 'gray', 'green', 'lime', 'magenta', 'maroon', 'navy', 'olive', 'orange', 'pink', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                        option, index = pick(colors, "Available colors:", indicator="=>", default_index=0)
                        self.hookall(aclass, option)
                    else:
                        self.hookall(aclass)
                else:
                    self.hookall(aclass)
        elif option == '-r':
            self.scratchreset()
        else:
            print("[i] Invalid option")

    def do_info(self, mod) -> None:
        """
        Provides information about a module.
        Usage: 
        info  'module name' 
        """
        for m in self.modManager.available:
            if m.Name == mod:
                print(m.Help)
        return

    def do_list(self, line) -> None:
        """
        List available packages 
        Use list <identifier> to print info about an installed application
        """
        try:
            options = len(line.split())
            if options == 0:
                self.init_packages()
            elif options == 1:
                if len(self.packages) == 0:
                    self.init_packages()
                else:
                    for app in self.packages:
                        if app.identifier == line.split()[0]:
                            self.fill_app_info(app)
                            self.print_app_info()
            else:
                print("Invalid option, use 'help list for options'")

        except Exception as e:
            print(e)

    def do_loaddevice(self, line) -> None:
        """
        Load a device in order to interact.
        Use with app identifier
        """
        try:
            print('Available devices:\n')
            devices = frida.enumerate_devices()
            for i in range(len(devices)):
                print(f'{i}) {devices[i]}')
            self.device = devices[
                int(Numeric('\nEnter the index of the device to use:', lbound=0, ubound=len(devices) - 1).ask())]
            print(f"Using device: {self.device}")

        except:
            self.device = frida.get_remote_device()
        finally:
            # lets start by loading all packages and let the user to filter them out
            self.init_packages()

    def do_pad(self, line) -> None:
        """
        Edit the scratchpad module using the configured editor.
        The editor is loaded from config.yaml (key: favorite_editor).
        Defaults to 'vim' if not configured.
        """

        # config_path = os.path.join(self.base_directory, 'config.yaml')
        editor = "vim"  # fallback default

        # if os.path.exists(config_path):
        #     with open(config_path, 'r') as f:
        #         cfg = yaml.safe_load(f) or {}
        #         editor = cfg.get("default_editor", editor)

        scratchpad = self.modManager.getModule('scratchpad')
        draft_path = os.path.join(self.base_directory, '.idraft')

        with open(draft_path, 'w') as draft:
            draft.write(scratchpad.Code)

        subprocess.run(f'{editor} "{draft_path}"', shell=True)

        with open(draft_path, 'r') as draft:
            code = draft.read()
        self.edit_scratchpad(code)


    def do_reload(self, line) -> None:
        """
        Reload the medusa modules (in case of a module edit)
        Use the -r filename option to load a saved session or recipe 
        """
        print("[i] Loading modules...")
        self.modManager = ModuleManager()
        for root, directories, filenames in os.walk(os.path.join(self.base_directory, 'modules')):
            for filename in filenames:
                if filename.endswith('.imed'):
                    self.modManager.add(os.path.join(root, filename))

        if "-r" in line.split(' ')[0]:
            self.modManager.reset()
            self.write_recipe(line.split(' ')[1])
        print(f"[i] Done....\n[i] Total modules available {self.modManager.get_number_of_modules()}")

    def do_rem(self, mod, redirect_output=False) -> None:
        """
        Remove one or more staged modules
        rem [module]
        The command will remove stage modules starting with or equal to the argument given
        Example: rem http_communications/ , will remove all the modules starting with "http_communications/"

        """
        try:
            if self.modManager.unstage(mod):
                if redirect_output:
                    sys.stderr.write(f"\nRemoved module(s) starting with : {mod}")
                else:
                    print(f"\nRemoved module(s) starting with : {mod}")
                self.modified = True
            else:
                if redirect_output:
                    sys.stderr.write("\nModule(s) is not active.")
                else:
                    print("Module(s) is not active.")
            print()
        except Exception as e:
            print(e)


    def do_run(self, line) -> None:
        """
        Initiate a Frida session and attach to the selected package

        Options:

        run [package name]       : Initiate a Frida session and attach to the selected package
             -f [package name]   : Initiate a Frida session and spawn the selected package
             -n [package number] : Initiate a Frida session and spawn the 3rd party package using its index returned by the 'list' command
             -p [pid]            : Initiate a Frida session using a process id
        """
        try:
            if self.modified:
                if Polar('Module list has been modified, do you want to recompile?').ask():
                    self.do_compile(line)
            flags = line.split(' ')
            length = len(flags)

            if length == 1:
                if flags[0] == '-p':
                    processes = self.device.enumerate_processes(scope="full")
                    procs = []
                    title = "Running processes: "
                    for proc in processes:
                        procs.append(f'pid:{proc.pid} name:{proc.name}')
                    option, index = pick(procs, title, indicator="=>", default_index=0)
                    click.echo(click.style(option, bg='blue', fg='white'))
                    self.run_frida(False, False, '', self.device, processes[index].pid)

                else:
                    self.run_frida(False, False, line, self.device)

            elif length == 2:

                if flags[0] == '-f':
                    self.run_frida(True, False, flags[1], self.device)
                elif flags[0] == '-n':
                    try:
                        if len(self.packages) == 0:
                            self.refreshPackages()
                        # print(flags[1])
                        package_name = self.packages[int(flags[1])].identifier
                        # print("package name: ", package_name)
                        self.run_frida(True, False, package_name, self.device)
                    except (IndexError, TypeError) as error:
                        print('Invalid package number')
                elif flags[0] == '-p':
                    self.run_frida(False, False, '', self.device, flags[1])
                else:
                    print('Invalid flag given!')

            else:
                pass
        except Exception as e:
            print(e)

    def do_search(self, pattern, redirect_output=False) -> None:
        """
        Search for modules related to a given keyword
        Usage:
        search http
        """
        matches = self.modManager.findModule(pattern)
        if not matches:
            if redirect_output:
                sys.stderr.write(f'\nNo modules found containing: {pattern}!')
            else:
                print(f'No modules found containing: {pattern}!')
        else:
            for match in matches:
                if redirect_output:
                    sys.stderr.write(match.replace(pattern, GREEN + pattern + RESET) + '\n')
                else:
                    print(match.replace(pattern, GREEN + pattern + RESET))

    def do_shell(self, line) -> None:
        """
        Get a local shell
        """
        shell = os.environ['SHELL']
        subprocess.run(f'{shell}', shell=True)

    def do_show(self, what) -> None:
        """
        Show available modules
        """
        try:
            if what == 'categories':
                self.show_categories()
            elif what == 'all':
                self.show_all()
            elif what == 'mods':
                self.show_mods()
            elif what.split(' ')[0] == 'mods' and len(what.split(' ')) == 2:
                self.show_mods_by_category(what.split(' ')[1])
            else:
                print('Invalid command!')
        except Exception as e:
            print(e)
            print('Invalid command - please check usage!')

    def do_swap(self, line) -> None:
        """
        As some modules have to run first, this command can help you to swap their possition in the final compiled script.
        Usage:
        swap index1 index2 
        Example:
        swap 0 5
        """
        try:
            old_index = int(line.split(' ')[0])
            new_index = int(line.split(' ')[1])
            self.modManager.staged[old_index], self.modManager.staged[new_index] = self.modManager.staged[new_index], \
            self.modManager.staged[old_index]
            print('New arrangement:')
            self.show_mods()

            self.modified = True
        except Exception as e:
            print(e)

    def do_use(self, mod, redirect_output=False) -> None:
        """
        Stage a module or modules
        Usage:
        use [module]
        The command will stage modules starting with or equal to the argument given
        Example: use http_communications/ , will load all the modules starting with "http_communications/"
        """
        self.modManager.stage(mod)
        self.show_mods(redirect_output)
        self.modified = True
        print()

    ###################################################### do_ defs end ############################################################

    ###################################################### complete_ defs start ############################################################


    def complete_list(self, text, line, begidx, endidx):
        if len(self.packages) == 0:
            self.refreshPackages()
        return self._completion_matches(
            text, [package.identifier for package in self.packages]
        )


    def complete_use(self, text, line, begidx, endidx):
        return self._completion_matches(text, [mod.Name for mod in self.modManager.available])

    def complete_info(self, text, line, begidx, endidx):
        return self._completion_matches(text, [mod.Name for mod in self.modManager.available])


    ###################################################### complete_ defs end ############################################################

    ###################################################### implementations start ############################################################

    def check_using_vt(self, hosts, vtkey):
        vt_address = 'https://www.virustotal.com/api/v3/domains/'
        if os.path.isfile(vtkey):
            with open(vtkey, 'r') as file:
                key = file.read()
        else:
            click.secho("VT key was not found !", fg='red')
            return
        headers = {'x-apikey': key}
        for host in hosts:
            # click.secho("Checking {}".format(host),fg='green')
            response = requests.get(vt_address + host, headers=headers)
            if response.status_code == 200:
                json_data = json.loads(response.text)
                last_analysis_stats = json_data['data']['attributes']['last_analysis_stats']
                malicious_count = last_analysis_stats['malicious']
                if int(malicious_count) == 0:
                    click.secho(f"✅ {host} ", fg='green')
                    # click.secho("Clean",fg='yellow')
                else:
                    click.secho(f"❌ {host} detected by {malicious_count} vendors ❗", bg='white', fg='red')
                    # click.secho(f" Detected by {malicious_count} vendors:",fg='red',bg='white')
                    for key, value in json_data['data']['attributes']['last_analysis_results'].items():
                        verdict = json_data['data']['attributes']['last_analysis_results'][key]['category']
                        if verdict not in ['harmless', 'undetected']:
                            print(
                                f"[🚩] {key} ({verdict.upper()}) Ref:{'https://www.virustotal.com/gui/domain/' + host}")
            else:
                click.secho(f"[?] {host} return {response.status_code}", fg='blue')

    def del_session(self) -> None:
        try:
            session = self.get_selected_session()
            if session is not None:
                print("Deleting: ")
                click.echo(click.style(session, bg='red', fg='white'))
                os.remove(session + '.session')
            else:
                return
        except Exception as e:
            print("An error occurred:", str(e))


    def fill_app_info(self, data) -> None:
        self.app_info = data


    def hookall(self, className, color='purple') -> None:
        codejs = "setImmediate(ios_run_hook_all_methods_of_specific_ios_class('" + className + "','" + color + "'));\n"
        self.edit_scratchpad(codejs, 'a')
        print(
            "\nHooks have been added to the" + GREEN + " scratchpad" + RESET + " run 'compile' to include it in your final script")

    def frida_session_handler(self, con_device, force, pkg, pid=-1):
        time.sleep(1)
        if not force:
            if pid == -1:
                apps = self.device.enumerate_applications(scope="full")
                for app in apps:
                    if app.identifier == pkg and app.pid is not None:
                        self.pid = str(app.pid)
                        break
                    else:
                        self.pid = ''
            else:
                self.pid = pid
            # pid = con_device.attach(self.pid)
            if self.pid == '':
                print("[!] Could not find process with this name.")
                return None
            frida_session = con_device.attach(int(self.pid))
            # frida_session = con_device.attach(int(self.pid))
            if frida_session:
                print(WHITE + "Attaching frida session to PID - {0}".format(frida_session._impl.pid))
            else:
                print("Could not attach the requested process" + RESET)
        elif force:
            self.pid = con_device.spawn(pkg)
            if self.pid:
                frida_session = con_device.attach(self.pid)
                print(WHITE + "Spawned package : {0} on pid {1}".format(pkg, frida_session._impl.pid))
                # resume app after spawning
                # con_device.resume(pid)
            else:
                print(RED + "Could not spawn the requested package")
                return None
        else:
            return None
        return frida_session


    def init_packages(self, option="") -> None:
        self.refreshPackages(option)
        click.secho(f'\n{self.package_range}:', fg='green', bg='blue')
        print()
        for i in range(len(self.packages)):
            print(f'[{i}] {self.packages[i].identifier}')


    def load_session(self) -> None:
        try:
            session = self.get_selected_session()
            if session is not None:
                print("Restoring: ")
                click.echo(click.style(session, bg='blue', fg='white'))
                self.do_reload(f'-r {session}.session')
            else:
                return
        except Exception as e:
            print(f"An error occurred: {e}")


    def my_message_handler(self, message, payload) -> None:
        if message["type"] == "send":

            data = message["payload"].split(":")[0].strip()
            if "trscrpt|" in data:
                result = self.translator.translate(data[data.index("trscrpt|") + len("trscrpt|"):])
                self.script.post({"my_data": result})
            else:
                self.fill_app_info(message["payload"])

    def on_detached(self, reason) -> None:
        print("Session is detached due to:", reason)
        self.detached = True

    def prepare_native(self, operation) -> None:
        with open(os.path.join(self.base_directory, 'libraries/native.med'), 'r') as file:
            script = file.read() + 'Java.perform(function() {\n' + operation + ' \n});'
        with open(os.path.join(self.base_directory, 'libraries/js/native.js'), 'w') as file:
            file.write(script)

    def print_app_info(self) -> None:
        if self.app_info:
            print(RESET + f"""\nName: {self.app_info.name}
Identifier: {self.app_info.identifier}
App path: {self.app_info.parameters['path']}
Version: {self.app_info.parameters['version']}
Build: {self.app_info.parameters['build']}
Data container: {self.app_info.parameters['containers']['data']}\n""" + RESET)
        else:
            print("[!] No available info.")

    def run_frida(self, force, detached, package_name, device, pid=-1) -> None:
        in_session_menu = WHITE + '(in-session)' + GREEN + ' type ' + YELLOW + '?' + GREEN + ' for options' + WHITE + ':➤' + RESET
        creation_time = modified_time = None
        self.detached = False
        session = self.frida_session_handler(device, force, package_name, pid)
        try:
            creation_time = self.modification_time(os.path.join(self.base_directory, agent_script))
            with open(os.path.join(self.base_directory, agent_script)) as f:
                self.script = session.create_script(f.read())

            session.on('detached', self.on_detached)
            self.script.on("message", self.my_message_handler)  # register the message handler
            self.script.load()
            if force:
                device.resume(self.pid)
            s = ""

            while (s != 'e') and (not self.detached):
                s = input(in_session_menu)
                if s == 'r':
                    # handle changes during runtime

                    modified_time = self.modification_time(os.path.join(self.base_directory, agent_script))
                    if modified_time != creation_time:
                        print(RED + "Script changed, reloading ...." + RESET)
                        creation_time = modified_time
                        self.reload_script(session)
                        # self.script.unload()
                        # with open(os.path.join(self.base_directory, agent_script)) as f:
                        #     self.script = session.create_script(f.read())
                        # session.on('detached',self.on_detached)
                        # self.script.on("message",self.my_message_handler)  # register the message handler
                        # self.script.load()
                    else:
                        print(GREEN + "Script unchanged, nothing to reload ...." + RESET)
                elif s == '?':
                    print(RESET + """\nAvailable commands: 
    'c'     clear the screen 
    'e'     exit the session
    'r'     reload the script in case it changed
    'rs'    reset the scratchpad
    'sus'   suspend the output 
    'i'     print information about the application
    't'     trace a method and print the stack trace (e.g. t com.foo.bar.func)
    '?'     print this help message\n""" + RESET)
                elif s == 'i':
                    self.do_list(package_name)
                elif s == 'c':
                    self.do_clear('')
                elif s == 'rs':
                    self.scratchreset()
                    self.do_compile('')
                    self.reload_script(session)
                elif s == 'sus':
                    original_stdout = sys.stdout
                    from io import StringIO
                    temp_stdout = StringIO()
                    sys.stdout = temp_stdout
                    in_mute_cmd = ''

                    while True:
                        mod = False
                        sys.stderr.write("(muted-mode) type ? for options:➤")
                        in_mute_cmd = input()
                        if in_mute_cmd == '?':
                            sys.stderr.write("""\nAvailable commands:
    'use module_name'   add an additional module
    'rm  module_name'   remove a module
    'show mods'         show active modules
    'search keyword'    search for a module using a keyword
    'con'               continue the session
    '?'                 print this message\n""")
                        elif in_mute_cmd.startswith('use '):
                            self.do_use(in_mute_cmd.split(' ')[1], True)
                            mod = True
                        elif in_mute_cmd.startswith('rm '):
                            self.do_rem(in_mute_cmd.split(' ')[1], True)
                            mod = True
                        elif in_mute_cmd == 'show mods':
                            self.show_mods(True)
                        elif in_mute_cmd.startswith('search '):
                            self.do_search(in_mute_cmd.split(' ')[1], True)
                        elif in_mute_cmd == 'con':
                            break
                        if mod:
                            sys.stderr.write("\nCompiling....\n")
                            self.do_compile('')
                            sys.stderr.write("Reloading....\n")
                            self.reload_script(session)

                    sys.stdout = original_stdout
                    print(
                        "-" * 10 + "Here is what you missed while suspended" + "-" * 10 + "\n" + temp_stdout.getvalue())
                elif s.split(' ')[0] == 't':
                    try:

                        self.do_jtrace(s.split(' ')[1])
                        self.do_compile('')
                        self.reload_script(session)
                    except Exception:
                        pass

                elif s.split(' ')[0] == 'dc':
                    try:
                        self.do_compile('')
                        self.reload_script(session)
                    except Exception:
                        pass

            if self.script:
                self.script.unload()

        except Exception as e:
            print(e)
        print(RESET)


    def reload_script(self, session) -> None:
        reload_session_script(session, self.state.session,
                              Path(os.path.join(self.base_directory, agent_script)),
                              self.my_message_handler, self.on_detached)




    def scan_for_secrets(self, string_list):
        try:
            sigs = {}
            matches = []
            results = []
            sig_file = os.path.join(self.base_directory, 'assets', 'sigs.json')
            logger.info(f'Using signature file: {sig_file}')

            if os.path.isfile(sig_file):
                with open(sig_file, 'r') as file:
                    sigs = json.load(file)

            for key, pattern in sigs.items():
                for entry in string_list:
                    matches = re.findall(pattern, entry)
                    if matches:
                        for match in matches:
                            results.append(f'{key}:{match}')
            for result in list(dict.fromkeys(results)):
                print(f'{result}')
        except Exception as e:
            print(e)




    def write_recipe(self, filename) -> None:
        try:
            data = ''
            click.echo(click.style("[+] Loading a recipe....", bg='blue', fg='white'))
            if os.path.exists(filename):
                with open(filename, 'r') as file:
                    for line in file:
                        if line.startswith('MODULE'):
                            module = line[7:-1]
                            click.echo(click.style(f'\tLoading {module}', fg='yellow'))
                            self.modManager.stage_verbadim(module)
                        else:
                            data += line
                self.modified = True
                if data != '':
                    click.echo(click.style("[+] Writing to scratchpad...", bg='blue', fg='white'))
                    self.edit_scratchpad(data)
            else:
                click.echo(click.style("[!] Recipe not found !", bg='red', fg='white'))
        except Exception as e:
            print(e)

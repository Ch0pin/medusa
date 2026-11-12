"""Platform-neutral CLI helpers shared by the Android and iOS backends."""
import json
import os
import platform
import re
import sys
import time
from urllib.parse import urlparse

import click
import cmd2
import yaml
from pick import pick
from cmd2.completion import CompletionItem, Completions
from libraries.core.modules import ModuleManager as ModuleManager
from libraries.core.state import ApplicationState, StateAttribute
from libraries.cli.prompts import Alternative, Numeric, Open, Polar

GREEN = "\033[0;32m"
BLUE = "\033[1;34m"
RESET = "\033[0;0m"


class SharedParser(cmd2.Cmd):
    _device = StateAttribute('device', 'connection')
    device_id = StateAttribute('device', 'identity')
    device_controller = StateAttribute('device', 'controller')
    packages = StateAttribute('device', 'packages')
    package_range = StateAttribute('device', 'package_range')
    app_info = StateAttribute('device', 'app_info')
    system_libraries = StateAttribute('device', 'system_libraries')
    app_libraries = StateAttribute('device', 'app_libraries')
    script = StateAttribute('session', 'script')
    pid = StateAttribute('session', 'pid')
    detached = StateAttribute('session', 'detached')
    currentPackage = StateAttribute('session', 'current_package')
    native_handler = StateAttribute('session', 'native_handler')
    native_functions = StateAttribute('session', 'native_functions')
    libname = StateAttribute('session', 'libname')
    agent_script_path = StateAttribute('session', 'agent_script_path')
    modManager = StateAttribute('modules')
    snippets = StateAttribute('snippets')
    modified = StateAttribute('modified')

    def __init__(self):
        self.state = ApplicationState()
        super().__init__(allow_cli_args=False)
        self._callback = None
        self.bind_to(self.observe_device_change)

    @property
    def device(self):
        return self._device

    @device.setter
    def device(self, new_device):
        self._device = new_device
        if self._callback:
            self._callback(new_device)

    def bind_to(self, callback):
        self._callback = callback

    def _completion_matches(self, text, candidates):
        return Completions(
            items=[
                CompletionItem(candidate)
                for candidate in candidates
                if candidate.startswith(text)
            ]
        )


    def complete_rem(self, text, line, begidx, endidx):
        return self._completion_matches(text, [mod.Name for mod in self.modManager.staged])


    def complete_reload(self, text, line, begidx, endidx):
        if "-r" in line.split():
            return self.path_complete(text, line, begidx, endidx)
        else:
            return Completions()


    def complete_run(self, text, line, begidx, endidx) -> list:
        return self.complete_list(text, line, begidx, endidx)


    def complete_show(self, text, line, begidx, endidx):
        return self._completion_matches(text, self.show_commands)


    def is_valid_url(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False


    def load_snippet(self, snippet) -> None:
        try:
            with open(snippet) as file:
                data = file.read()
            click.secho(data, fg='green')
        except Exception as e:
            print(e)


    def modification_time(self, path_to_file):
        if platform.system() == 'Windows':
            return os.path.getmtime(path_to_file)
        else:
            stat = time.ctime(os.path.getmtime(path_to_file))  # os.stat(path_to_file)
            try:
                return stat
            except AttributeError:
                # We're probably on Linux. No easy way to get creation dates here,
                # so we'll settle for when its content was last modified.
                return stat


    def print_list(self, listName, message) -> None:
        print(GREEN + message + RESET)
        for item in listName:
            print(f"""       {item}""")


    def show_all(self) -> None:
        for mod in self.modManager.available:
            print(mod.Name)


    def show_categories(self) -> None:
        print('\nAvailable module categories:\n')
        for category in self.modManager.categories:
            print(category)
        print()


    def show_mods(self, redirect_output=False) -> None:
        for i in range(len(self.modManager.staged)):
            if redirect_output:
                if i == 0:
                    sys.stderr.write('\nCurrent Mods:\n')
                sys.stderr.write(f'{i}) {self.modManager.staged[i].Name}\n')
            else:
                if i == 0:
                    print("\nCurrent Mods:")
                print(f'{i}) {self.modManager.staged[i].Name}')
        print()


    def show_mods_by_category(self, category) -> None:
        mods = [mod for mod in self.modManager.available if mod.getCategory() == category]
        if len(mods) == 0:
            print('No such category or this category does not contain modules')
        else:
            width = max(map(lambda mod: len(mod.Name), mods)) + 2
            print(f"{'Name': <{width}}Description")
            for name, description in zip([mod.Name for mod in mods], [mod.Description for mod in mods]):
                print(GREEN + f"{name: <{width}}" + BLUE + f"{description}" + RESET)

    def do_reset(self, line) -> None:
        """
        Empty the staged module list
        """
        self.modManager.reset()
        self.modified = False
        self.do_compile('', True)
        self.scratchreset()


    def get_selected_session(self) -> str:
        try:
            session_files = ['Cancel']
            for filename in os.listdir(self.base_directory):
                if filename.endswith(".session"):
                    session_files.append(os.path.splitext(filename)[0])
            if len(session_files) == 0:
                print("No saved sessions found !")
                return None
            option, index = pick(session_files, "Saved sessions:", indicator="=>", default_index=0)
            if option == 'Cancel':
                return None
            return option
        except Exception as e:
            print(f"An error occurred: {e}")
            return None


    def scratchreset(self) -> None:
        if Polar('Do you want to reset the scratchpad?').ask():
            self.edit_scratchpad('')


    def save_session(self, session_name):
        try:
            session_files = []
            for filename in os.listdir(self.base_directory):
                if filename.endswith(".session"):
                    session_files.append(os.path.splitext(filename)[0])

            if session_name == "":
                print("Missing session name !")
            else:
                if session_name in session_files:
                    if not Polar("Session already exists, do you want to overwrite ?").ask():
                        return
                session_name += ".session"
                self.do_export(session_name)
            return
        except Exception as e:
            print("An error occurred:", str(e))


    def yaml_to_json(self, yaml_file):
        # Read the YAML file
        try:
            with open(yaml_file, 'r') as file:
                yaml_data = file.read()

            # Load the YAML data
            data = yaml.safe_load(yaml_data)

            # Convert it to JSON
            json_data = json.dumps(data, indent=2)
            return json_data
        except Exception as e:
            print(f"Error converting YAML to JSON: {e}")
            return None

    def edit_scratchpad(self, code, mode='w') -> None:
        scratchpad = self.modManager.getModule('scratchpad')
        if mode == 'a':
            scratchpad.Code += code
        elif mode == 'w':
            scratchpad.Code = code
        else:
            raise Exception(f'Attempted to open scratchpad in invalid mode {mode}')
        scratchpad.save()
        if code != '':
            self.modManager.stage('scratchpad')
        self.modified = True


    def hook_native(self) -> None:
        library = Open('Library name (e.g. libnative.so):').ask()
        type_ = Alternative('[(i)mported] / [(e)xported] / [(a)ny - requires the function\'s offset] function:', 'i',
                            'e', 'a').ask()
        function = Open('Function name or offset (e.g. 0x1234):').ask()
        number_of_args = Numeric('Number of arguments (enter 0 to disable logging):', lbound=0).ask()
        backtraceEnable = Polar('Do you want to log the stack trace:', False).ask()
        hexdumpEnable = Polar('Do you want to dump the address pointed by the return value:', False).ask()
        uuid = str(int(time.time()))
        header = "console.log('[*][*] Waiting for " + library + " ...');\n"
        header += "waitForModule('" + library + "').then((lib) => {"
        header += """
            console.log(`[*][+] Found library at: ${ lib.base }`)
            hook_any_native_func_""" + uuid + """();
        });\n
        function hook_any_native_func_""" + uuid + """(){
        """
        argread = ''

        #         for i in range(int(number_of_args)):
        #             argread += '\n\n try { var arg'+str(i)+" = Memory.readUtf8String(ptr(args["+str(i)+"]));\n"+"""console.log('Arg("""+str(i)+"""):'+arg"""+str(i)+""");\n }
        # catch (err) {
        #     console.log('Error:'+err);
        # }"""

        for i in range(number_of_args):
            argread += '\n\n try { var arg' + str(i) + " = Memory.readByteArray(ptr(args[" + str(
                i) + "]),128);\n" + """console.log('------ Arg(""" + str(
                i) + """) memory dump: ------');""" + """\nconsole.log(hexdump(arg""" + str(i) + """,{ offset: 0, length: 128, header: false, ansi: false}));\n } 
catch (err) {
    console.log('Error:'+err);
}"""

        if hexdumpEnable:
            buffersize = Numeric('Read Buffer size (0-1024):').ask()
            hexdump = """
            var buf = Memory.readByteArray(ptr(retval),""" + str(buffersize) + """);
            console.log(hexdump(buf, {
                offset: 0, 
                    length: """ + str(buffersize) + """, 
                    header: true,
                    ansi: false
                }));"""
        else:
            hexdump = ''

        if backtraceEnable:
            tracejs = """
            try {
                colorLog("Backtrace: ", { c: Color.Green });
                var trace = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    for (var j in trace)
                colorLog('\t b_trace->'+DebugSymbol.fromAddress( trace[j]),{c: Color.Blue});
                }
            catch(err){
                console.log('Error:'+err);
            }"""
        else:
            tracejs = ''

        if function.startswith('0x') or type_ == 'a':
            header += "\nInterceptor.attach(Module.findBaseAddress('" + library + "').add(" + function + "), {"
        elif type_ == 'e':
            header += "\nInterceptor.attach(Module.getExportByName('" + library + "', '" + function + "'), {"
        else:
            header += "\nvar func = undefined;\n" + 'var imports = Module.enumerateImportsSync("' + library + '");\n'
            header += 'for(var i = 0; i < imports.length; i++){\nif (imports[i].name=="' + function + '") \n{ func = imports[i].address; break; } }'
            header += "Interceptor.attach(func, {\n"

        codejs = header + """
    onEnter: function(args) {
      console.log();
      colorLog("[--->] Entering Native function: " +" """ + function + '",{ c: Color.Red });' + argread + tracejs + """
    },
    onLeave: function(retval) {

      try{
            colorLog("Return Value @" + retval , {c: Color.Green});""" + hexdump + """
            colorLog("[<---] Leaving Native function: " +" """ + function + """ ",{ c: Color.Red });
            //retval.replace();
            }
      catch(err){
          console.log('Error:'+err);
      }
    }
}) };
"""
        self.edit_scratchpad(codejs, 'a')
        print(
            "\nHooks have been added to the" + GREEN + " scratchpad" + RESET + " run 'compile' to include it in your final script")


    def scan_using_nuclei_template(self, string_list, path_to_templates):
        found = False
        if os.path.isfile(path_to_templates):
            entries = json.loads(self.yaml_to_json(path_to_templates))
            found = self.scan_do_scan(string_list, entries)

        elif os.path.isdir(path_to_templates):

            for root, dirs, files in os.walk(path_to_templates):
                for file in files:
                    file_path = os.path.join(root, file)
                    # print(f'- Checking: {file_path}')
                    if os.path.isfile(file_path):
                        entries = json.loads(self.yaml_to_json(file_path))
                        if self.scan_do_scan(string_list, entries):
                            found = True
        else:
            print(f"{path_to_templates} is neither a file nor a directory.")
            return

        if not found:
            click.secho("[!] No matches found.")


    def scan_do_scan(self, string_list, entries):
        found = False
        try:
            id_value = entries['id']
            severity_value = entries['info']['severity']
            regexes = entries['file'][0]['extractors'][0]['regex']
            for regex in regexes:
                for entry in string_list:
                    matches = re.findall(regex, entry)
                    if matches:
                        found = True
                        for match in matches:
                            click.secho(f'[+] Match found for {id_value}', fg='white', bg='red')
                            click.secho(f'  \\_[+] Severity: {severity_value}', fg='red')
                            click.secho(f'  \\_[+] Match value: {id_value}: {match}', fg='red')
            return found
        except Exception as e:
            print(f'Error while parsing the json data:{e}')
            return found

#!/usr/bin/env python3
import subprocess, platform, os, sys, readline, time, argparse,requests,re,json
from urllib.parse import urlparse
import cmd2, click, frida,random,yaml
from libraries.natives import *
from libraries.libadb import *
from libraries.Questions import *
from libraries.Modules import *
from pick import pick

RED     = "\033[1;31m"
BLUE    = "\033[1;34m"
CYAN    = "\033[1;36m"
WHITE   = "\033[1;37m"
YELLOW  = "\033[1;33m"
GREEN   = "\033[0;32m"
RESET   = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"
#readline.set_completer_delims(readline.get_completer_delims().replace('/', ''))

class Parser(cmd2.Cmd):
    base_directory = os.path.dirname(__file__)
    packages = []
    system_libraries = []
    app_libraries = []
    app_info = {}
    show_commands = ['mods', 'categories', 'all']
    prompt = BLUE + '(ios) medusa➤' + RESET
    device = None
    modified = False
    script = None
    detached = True
    pid = None
    native_handler = None
    native_functions = []
    currentPackage = None
    libname = None
    modManager = ModuleManager()
    package_range = ''

    def __init__(self):
        super().__init__(
            allow_cli_args=False
        )

    def refreshPackages(self, option=""):
        self.package_range="- Installed applications"
        self.packages = frida.get_device(self.device.id).enumerate_applications(scope="full")

    def preloop(self):
        self.do_reload("dummy")
    
        parser = argparse.ArgumentParser(
                            prog = 'Medusa',
                            description = 'An extensible and modularized framework that automates processes and techniques practiced during the dynamic analysis of Android Applications.')
        parser.add_argument('-r','--recipe', help='Use this option to load a session/recipe')
        args = parser.parse_args()

        if args.recipe:
            self.write_recipe(args.recipe)
                        
        randomized_fg = lambda: tuple(random.randint(0, 255) for _ in range(3))
                     
        click.secho("""                                                                                                                      
    ███╗   ███╗███████╗██████╗ ██╗   ██╗███████╗ █████╗ 
    ████╗ ████║██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗    
    ██╔████╔██║█████╗  ██║  ██║██║   ██║███████╗███████║
    ██║╚██╔╝██║██╔══╝  ██║  ██║██║   ██║╚════██║██╔══██║
    ██║ ╚═╝ ██║███████╗██████╔╝╚██████╔╝███████║██║  ██║
    ╚═╝     ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝ (ios) Version: 2.0 
                                    
 🪼 Type help for options 🪼 \n\n""", fg=randomized_fg(),bold=True)
        self.do_loaddevice("dummy")

###################################################### do_ defs start ############################################################
 
    def do_clear(self, line) -> None:
        """
        Clear the screen (no args)
        """
        subprocess.run('clear', shell=True)

    def do_compile(self, line, rs=False) -> None:
        """
        Compile the current staged modules to a single js frida script. Use '-t' to add a delay.
        compile [-t X], where X is a value in milisec
        """
        try:
            hooks = []
            jni_prolog_added = False
            # with open(os.path.join(self.base_directory, 'libraries', js'utils.js'), 'r') as file:
            #     header = file.read()
            js_directory = os.path.join(self.base_directory, 'libraries', 'js')
            js_files=['globals.js','beautifiers.js','utils.js','ios_core.js']
            for filename in js_files:
                js_file_path = os.path.join(js_directory, filename)
                
                # Check if the file exists before attempting to read it
                if os.path.isfile(js_file_path):
                    with open(js_file_path, 'r') as file:
                        header = file.read()
                        hooks.append(header)
            #add delay
            delay = ''
            options = len(line.split())
            if options == 2 and ('-t' in line.split()[0]):             
                delay = line.split()[1]
                hooks.append("\n\nsetTimeout(function() {\n")

            hooks.append("try \n{\n")
            hooks.append(self.modManager.compile())
            epilog = """}
    catch(error){
        colorLog("------------Error Log start-------------",{ c:Color.Red })
        console.log(error.stack);
        colorLog("------------Error Log EOF---------------",{ c:Color.Red })
     };"""
            if delay != '':
                hooks.append(epilog[:-1])
                hooks.append("}}, {});".format(delay))
            else:
                hooks.append(epilog)

            with open(os.path.join(self.base_directory, 'agent_ios.js'), 'w') as agent:
                for hook_line in hooks:
                    agent.write('%s\n' % hook_line)
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
        agent_path = os.path.join(self.base_directory, 'agent_ios.js')
        scratchpad_path = os.path.join(self.base_directory, 'modules/scratchpad.imed')

        if os.path.getsize(agent_path) != 0:
            if Polar('Do you want to reset the agent script?').ask():
                    open(os.path.join(self.base_directory, 'agent_ios.js'), 'w').close()

        if os.path.getsize(scratchpad_path) != 119:
            if Polar('Do you want to reset the scratchpad?').ask():
                    self.edit_scratchpad('')

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
                print("Current session mod list saved as: {}, use session --load to reload it".format(os.path.splitext(line)[0]))
            else:
                print('Recipe exported to dir: {} as {}'.format(os.getcwd(), line))
        except Exception as e:
            print(e) 
            print("[i] Usage: export filename")



        except Exception as e:
            print(e)

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
        if option=='-a':
            aclass = line.split(' ')[1].strip()
            if aclass == '':
                print('[i] Usage hook -a class_name')
            else:
                if len(line.split(' ')) > 2:
                    if line.split(' ')[2].strip()=='--color':
                        collors = ['Blue','Cyan','Gray','Green','Purple','Red','Yellow']
                        option, index = pick(collors,"Available colors:",indicator="=>",default_index=0)
                        self.hookall(aclass,option)
                    else:
                        self.hookall(aclass)
                else:
                    self.hookall(aclass)
        elif option=='-r':
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
                print('{}) {}'.format(i, devices[i]))
            self.device = devices[int(Numeric('\nEnter the index of the device to use:', lbound=0,ubound=len(devices)-1).ask())] 
            print(f"Using device: {self.device}")
 
        except:
            self.device = frida.get_remote_device()
        finally:
            #lets start by loading all packages and let the user to filter them out 
            self.init_packages()    
         
    def do_pad(self, line) -> None:
        """
        Manualy edit scratchpad using vi
        """
        scratchpad = self.modManager.getModule('scratchpad')
        with open(os.path.join(self.base_directory, '.idraft'), 'w') as draft:
            draft.write(scratchpad.Code)
        subprocess.run('vim ' + os.path.join(self.base_directory, '.idraft'), shell=True)
        with open(os.path.join(self.base_directory, '.idraft'), 'r') as draft:
            code = draft.read()
        self.edit_scratchpad(code)
   
    #partially_finished --> implement -r
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
                    sys.stderr.write("\nRemoved module(s) starting with : {}".format(mod))
                else:
                    print("\nRemoved module(s) starting with : {}".format(mod))
                self.modified = True
            else:
                if redirect_output:
                    sys.stderr.write("\nModule(s) is not active.")
                else:
                    print("Module(s) is not active.")
            print()  
        except Exception as e:
            print(e)
    
    def do_reset(self, line) -> None:
        """
        Empty the staged module list
        """
        self.modManager.reset()
        self.modified = False
        self.do_compile('',True)
        self.scratchreset()

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
                    option, index = pick(procs,title,indicator="=>",default_index=0)
                    click.echo(click.style(option,bg='blue', fg='white'))
                    self.run_frida(False,False,'',self.device,processes[index].pid)
                   
                else: 
                    self.run_frida(False, False, line, self.device)
            
            elif length == 2:
                
                if flags[0] == '-f':
                    self.run_frida(True, False, flags[1], self.device)
                elif flags[0] == '-n':
                    try:
                        if len(self.packages) == 0:
                            self.refreshPackages()
                        #print(flags[1])
                        package_name = self.packages[int(flags[1])].identifier
                        #print("package name: ", package_name)
                        self.run_frida(True, False, package_name, self.device)
                    except (IndexError, TypeError) as error:
                        print('Invalid package number')
                elif flags[0] == '-p':
                    self.run_frida(False,False,'',self.device,flags[1])
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
                sys.stderr.write('\nNo modules found containing: {}!'.format(pattern))
            else:
                print('No modules found containing: {}!'.format(pattern))
        else:
            for match in matches:
                if redirect_output:
                    sys.stderr.write(match.replace(pattern, GREEN + pattern + RESET)+'\n')
                else:
                    print(match.replace(pattern, GREEN + pattern + RESET))

    def do_shell(self, line) -> None:
        """
        Get a local shell
        """
        shell = os.environ['SHELL']
        subprocess.run('{}'.format(shell), shell=True)

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
            self.modManager.staged[old_index], self.modManager.staged[new_index] = self.modManager.staged[new_index], self.modManager.staged[old_index]
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

    def complete_list(self, text, line, begidx, endidx) -> list:
        if len(self.packages) == 0:
            self.refreshPackages()
        return [package.identifier for package in self.packages if package.identifier.startswith(text)]

    def complete_rem(self, text, line, begidx, endidx) -> list:
        return [mod.Name for mod in self.modManager.staged if mod.Name.startswith(text)]

    def complete_run(self, text, line, begidx, endidx) -> list:
        return self.complete_list(text, line, begidx, endidx)

    def complete_show(self, text, line, begidx, endidx):
        return [f for f in self.show_commands if f.startswith(text)]

    def complete_use(self, text, line, begidx, endidx) -> list:
        return [mod.Name for mod in self.modManager.available if mod.Name.startswith(text)]
    
    def complete_info(self, text, line, begidx, endidx) -> list:
        return [mod.Name for mod in self.modManager.available if mod.Name.startswith(text)]

###################################################### complete_ defs end ############################################################

###################################################### implementations start ############################################################

    def check_using_vt(self, hosts, vtkey):
        vt_address = 'https://www.virustotal.com/api/v3/domains/'
        if os.path.isfile(vtkey):
            with open(vtkey,'r') as file:
                key = file.read()
        else:
            click.secho("VT key was not found !", fg='red')
            return
        headers = {'x-apikey': key}
        for host in hosts:
           # click.secho("Checking {}".format(host),fg='green')
            response = requests.get(vt_address+host, headers=headers)
            if response.status_code == 200:
                json_data = json.loads(response.text)
                last_analysis_stats = json_data['data']['attributes']['last_analysis_stats']
                malicious_count = last_analysis_stats['malicious']
                if int(malicious_count) == 0: 
                    click.secho("✅ {} ".format(host),fg='green')
                    #click.secho("Clean".format(malicious_count),fg='yellow')
                else:
                    click.secho("❌ {} detected by {} vendors ❗".format(host,malicious_count),bg='white',fg='red')
                    #click.secho(" Detected by {} vendors:".format(malicious_count),fg='red',bg='white')
                    for key,value in json_data['data']['attributes']['last_analysis_results'].items():
                        verdict = json_data['data']['attributes']['last_analysis_results'][key]['category']
                        if verdict not in ['harmless','undetected']:
                            print('[🚩] {} ({}) Ref:{}'.format(key,verdict.upper(),'https://www.virustotal.com/gui/domain/'+host))
            else:
                click.secho("[?] {} return {}".format(host,response.status_code),fg='blue')

    def del_session(self) -> None:
        try:
            session = self.get_selected_session()
            if session is not None:
                print("Deleting: ")
                click.echo(click.style(session,bg='red', fg='white'))
                os.remove(session+'.session')
            else:
                return
        except Exception as e:
            print("An error occurred:", str(e))    

    def edit_scratchpad(self, code, mode='w') -> None:
        scratchpad = self.modManager.getModule('scratchpad')
        if mode == 'a':
            scratchpad.Code += code
        elif mode == 'w':
            scratchpad.Code = code
        else:
            raise Exception('Attempted to open scratchpad in invalid mode {}'.format(mode))
        scratchpad.save()
        if code != '':
            self.modManager.stage('scratchpad')
        self.modified = True

    def fill_app_info(self, data) -> None:
        self.app_info = data

    def get_selected_session(self) -> str:
        try:
            session_files = ['Cancel']
            for filename in os.listdir(self.base_directory):
                if filename.endswith(".session"):
                    session_files.append(os.path.splitext(filename)[0])
            if len(session_files)==0:
                print("No saved sessions found !")
                return None
            option, index = pick(session_files,"Saved sessions:",indicator="=>",default_index=0)
            if option=='Cancel':
                return None
            return option  
        except Exception as e:
            print("An error occurred:", str(e))   
            return None    

    def hookall(self, className, color='Purple') -> None:
        codejs = "setImmediate(ios_run_hook_all_methods_of_specific_ios_class('"+className+"','"+color+"'));\n"
        self.edit_scratchpad(codejs, 'a')
        print("\nHooks have been added to the" + GREEN + " scratchpad" + RESET + " run 'compile' to include it in your final script")

    def frida_session_handler(self,con_device,force,pkg,pid=-1):
        time.sleep(1)
        if force == False:
            if pid == -1:
                apps = self.device.enumerate_applications(scope="full")
                for app in apps:
                    if app.identifier == pkg and app.pid != None:
                        self.pid = str(app.pid)
                        break
                    else:
                        self.pid=''
            else:
                self.pid = pid
            #pid = con_device.attach(self.pid) 
            if self.pid == '':
                print("[!] Could not find process with this name.")
                return None
            frida_session = con_device.attach(int(self.pid))   
            #frida_session = con_device.attach(int(self.pid))
            if frida_session:
                print(WHITE+"Attaching frida session to PID - {0}".format(frida_session._impl.pid))
            else:
                print("Could not attach the requested process"+RESET)
        elif force == True:
            self.pid = con_device.spawn(pkg)
            if self.pid:
                frida_session = con_device.attach(self.pid)
                print(WHITE+"Spawned package : {0} on pid {1}".format(pkg,frida_session._impl.pid))
                    # resume app after spawning
                #con_device.resume(pid)
            else:
                print(RED+"Could not spawn the requested package")
                return None
        else:
            return None
        return frida_session

    def hook_native(self) -> None:
        library = Open('Library name (e.g. libnative.so):').ask()
        type_ = Alternative('[(i)mported] / [(e)xported] / [(a)ny - requires the function\'s offset] function:', 'i', 'e','a').ask()
        function = Open('Function name or offset (e.g. 0x1234):').ask()
        number_of_args = Numeric('Number of arguments (enter 0 to disable logging):', lbound=0).ask()
        backtraceEnable = Polar('Do you want to log the stack trace:', False).ask()
        hexdumpEnable = Polar('Do you want to dump the address pointed by the return value:', False).ask()
        uuid = str(int(time.time()))
        header = "console.log('[*][*] Waiting for "+library+" ...');\n"
        header+="waitForModule('" +library+"').then((lib) => {"
        header+="""
            console.log(`[*][+] Found library at: ${ lib.base }`)
            hook_any_native_func_"""+uuid+"""();
        });\n
        function hook_any_native_func_"""+uuid+"""(){
        """
        argread = ''

#         for i in range(int(number_of_args)):
#             argread += '\n\n try { var arg'+str(i)+" = Memory.readUtf8String(ptr(args["+str(i)+"]));\n"+"""console.log('Arg("""+str(i)+"""):'+arg"""+str(i)+""");\n } 
# catch (err) {
#     console.log('Error:'+err);
# }""" 

        for i in range(number_of_args):
            argread += '\n\n try { var arg'+str(i)+" = Memory.readByteArray(ptr(args["+str(i)+"]),128);\n"+"""console.log('------ Arg("""+str(i)+""") memory dump: ------');"""+"""\nconsole.log(hexdump(arg"""+str(i)+""",{ offset: 0, length: 128, header: false, ansi: false}));\n } 
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
        print("\nHooks have been added to the" + GREEN + " scratchpad" + RESET + " run 'compile' to include it in your final script")

    def init_packages(self, option="") -> None:
        self.refreshPackages(option)
        click.secho(f'\n{self.package_range}:',fg='green',bg='blue')
        print()
        for i in range(len(self.packages)):
            print('[{}] {}'.format(i, self.packages[i].identifier))

    def is_valid_url(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False

    def load_session(self) -> None:
        try:
            session = self.get_selected_session()
            if session is not None:
                print("Restoring: ")
                click.echo(click.style(session,bg='blue', fg='white'))
                self.do_reload('-r {}.session'.format(session))
            else:
                return
        except Exception as e:
            print("An error occurred:", str(e))

    def load_snippet(self, snippet) -> None:
        try:
            with open(snippet) as file:
                data = file.read()
            click.secho(data, fg = 'green')
        except Exception as e:
            print(e)

    def modification_time(self, path_to_file):
        if platform.system() == 'Windows':
            return os.path.getmtime(path_to_file)
        else:
            stat = time.ctime(os.path.getmtime(path_to_file)) #os.stat(path_to_file)
            try:
                return stat
            except AttributeError:
                # We're probably on Linux. No easy way to get creation dates here,
                # so we'll settle for when its content was last modified.
                return stat
            
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
            print(RESET+f"""\nName: {self.app_info.name}
Identifier: {self.app_info.identifier}
App path: {self.app_info.parameters['path']}
Version: {self.app_info.parameters['version']}
Build: {self.app_info.parameters['build']}
Data container: {self.app_info.parameters['containers']['data']}\n"""+RESET)
        else:
            print("[!] No available info.")

    def run_frida(self, force, detached, package_name, device, pid=-1) -> None:
        in_session_menu = WHITE + '(in-session)'+GREEN+' type '+YELLOW+'?'+GREEN+' for options'+WHITE+':➤'+RESET
        creation_time = modified_time = None
        self.detached = False
        session = self.frida_session_handler(device,force,package_name,pid)
        try:
            creation_time = self.modification_time(os.path.join(self.base_directory, "agent_ios.js"))
            with open(os.path.join(self.base_directory, "agent_ios.js")) as f:
                self.script = session.create_script(f.read())
            
            session.on('detached',self.on_detached)
            self.script.on("message",self.my_message_handler)  # register the message handler
            self.script.load()  
            if force:
                device.resume(self.pid)
            s = ""
            
            while (s!='e') and (not self.detached):
                s = input(in_session_menu)
                if s == 'r':
                    #handle changes during runtime

                    modified_time = self.modification_time(os.path.join(self.base_directory, "agent_ios.js"))
                    if modified_time != creation_time:
                        print(RED + "Script changed, reloading ...." + RESET)
                        creation_time = modified_time
                        self.reload_script(session)
                        # self.script.unload()
                        # with open(os.path.join(self.base_directory, "agent_ios.js")) as f:
                        #     self.script = session.create_script(f.read())
                        # session.on('detached',self.on_detached)
                        # self.script.on("message",self.my_message_handler)  # register the message handler
                        # self.script.load()  
                    else:
                         print(GREEN + "Script unchanged, nothing to reload ...." + RESET)
                elif s == '?':
                    print(RESET+"""\nAvailable commands: 
    'c'     clear the sreen 
    'e'     exit the session
    'r'     reload the script in case it changed
    'rs'    reset the scratchpad
    'sus'   suspend the output 
    'i'     print information about the application
    't'     trace a method and print the stack trace (e.g. t com.foo.bar.func)
    '?'     print this help message\n"""+RESET)
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
                            self.do_use(in_mute_cmd.split(' ')[1],True)
                            mod = True
                        elif in_mute_cmd.startswith('rm '):
                            self.do_rem(in_mute_cmd.split(' ')[1],True)
                            mod = True
                        elif in_mute_cmd == 'show mods':
                            self.show_mods(True)
                        elif in_mute_cmd.startswith('search '):
                            self.do_search(in_mute_cmd.split(' ')[1],True)
                        elif in_mute_cmd == 'con':
                            break
                        if mod:
                            sys.stderr.write("\nCompiling....\n")
                            self.do_compile('')
                            sys.stderr.write("Reloading....\n")
                            self.reload_script(session)


                    sys.stdout = original_stdout
                    print("-"*10+"Here is what you missed while suspended"+"-"*10+"\n"+temp_stdout.getvalue())

                         
                elif s.split(' ')[0] == 't':
                    try:
                      
                        self.do_jtrace(s.split(' ')[1])
                        self.do_compile('')
                        self.reload_script(session)
                    except Exception as e:
                        pass

                elif s.split(' ')[0] == 'dc':
                    try: 
                        self.do_compile('')
                        self.reload_script(session)
                    except Exception as e:
                        pass
                                 
            
            if self.script:
                self.script.unload()

        except Exception as e:
            print(e)
        print(RESET)
        
    def print_list(self, listName, message) -> None:
        print(GREEN+message+RESET)
        for item in listName:
            print("""       {}""".format(item))

    def reload_script(self, session) -> None:
        self.script.unload()
        with open(os.path.join(self.base_directory, "agent_ios.js")) as f:
            self.script = session.create_script(f.read())
            session.on('detached',self.on_detached)
            self.script.on("message",self.my_message_handler)  # register the message handler
            self.script.load()  

    def scratchreset(self) -> None:
        if Polar('Do you want to reset the scratchpad?').ask():
            self.edit_scratchpad('')

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
                sys.stderr.write('{}) {}\n'.format(i, self.modManager.staged[i].Name))
            else:
                if i == 0: 
                    print("\nCurrent Mods:")
                print('{}) {}'.format(i, self.modManager.staged[i].Name))
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
                session_name+=".session"
                self.do_export(session_name)
            return
        except Exception as e:
            print("An error occurred:", str(e))   

    def scan_for_secrets(self, string_list):
        try:
            sigs={}
            matches = []
            results = []
            sig_file = os.getcwd()+os.path.sep+'sigs.json'
            print(f'Using signature file: {sig_file}')

            if os.path.isfile(sig_file):
                with open(sig_file,'r') as file:
                    sigs = json.load(file)
            
            for key,pattern in sigs.items():
                for entry in string_list:
                    matches = re.findall(pattern,entry)
                    if matches:
                        for match in matches:
                            results.append(f'{key}:{match}')
            for result in list(dict.fromkeys(results)):
                print(f'{result}')             
        except Exception as e:
            print(e)

    def scan_using_nuclei_template(self, string_list, path_to_templates):
        found = False
        if os.path.isfile(path_to_templates):
            entries =json.loads(self.yaml_to_json(path_to_templates))
            found = self.scan_do_scan(string_list,entries)

        elif os.path.isdir(path_to_templates):
          
            for root, dirs, files in os.walk(path_to_templates):
                for file in files:
                    file_path = os.path.join(root, file)
                    #print(f'- Checking: {file_path}')
                    if os.path.isfile(file_path):
                        entries = json.loads(self.yaml_to_json(file_path))
                        if self.scan_do_scan(string_list,entries):
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
                    matches = re.findall(regex,entry)
                    if matches:
                        found = True
                        for match in matches:
                            click.secho(f'[+] Match found for {id_value}',fg='white',bg='red')
                            click.secho(f'  \_[+] Severity: {severity_value}',fg='red')
                            click.secho(f'  \_[+] Match value: {id_value}: {match}',fg='red')
            return found              
        except Exception as e:
            print(f'Error while parsing the json data:{e}')
            return found

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

    def write_recipe(self, filename) -> None:
        try:
            data = ''
            click.echo(click.style("[+] Loading a recipe....",bg='blue', fg='white'))
            if os.path.exists(filename):
                with open(filename, 'r') as file:
                    for line in file:
                        if line.startswith('MODULE'):
                            module = line[7:-1]
                            click.echo(click.style('\tLoading {}'.format(module), fg='yellow'))
                            self.modManager.stage_verbadim(module)
                        else:
                            data += line
                self.modified = True
                if data != '':
                    click.echo(click.style("[+] Writing to scratchpad...",bg='blue', fg='white'))
                    self.edit_scratchpad(data)
            else:
                click.echo(click.style("[!] Recipe not found !",bg='red', fg='white'))
        except Exception as e:
            print(e)
        
if __name__ == '__main__':
    if 'libedit' in readline.__doc__:
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")
    Parser().cmdloop()

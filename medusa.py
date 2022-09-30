#!/usr/bin/env python3
import subprocess
import platform
import cmd2
import os, sys
import readline
import time
import frida
import click
from libraries.dumper import dump_pkg
from google_trans_new import google_translator  
from libraries.natives import *
from libraries.libadb import *
from libraries.Questions import *
from libraries.Modules import *

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
    snippets = []
    packages = []
    system_libraries = []
    app_libraries = []
    app_info = {}
    show_commands = ['mods', 'categories', 'all', 'snippets']
    prompt = BLUE + 'medusa> ' + RESET
    device = None
    modified = False
    translator = google_translator()  
    script = None
    detached = True
    pid = None
    native_handler = None
    native_functions = []
    currentPackage = None
    libname = None
    modManager = ModuleManager()

    def __init__(self):
        super().__init__(
            allow_cli_args=False
        )


    def refreshPackages(self):
        self.packages = []
        for line in os.popen('adb -s {} shell pm list packages -3'.format(self.device.id)):
            self.packages.append(line.split(':')[1].strip('\n'))

    def preloop(self):
        self.do_reload("dummy")
        # for root, directories, filenames in os.walk(os.path.join(self.base_directory, 'modules')):
        #     for filename in filenames:
        #         if filename.endswith('.med'):
        #             self.modManager.add(os.path.join(root, filename))

        # for root, directories, filenames in os.walk(os.path.join(self.base_directory, 'snippets')):
        #     for filename in sorted(filenames):
        #         if filename.endswith('.js'):
        #             filepath = os.path.join(root, filename)
        #             self.snippets.append(filepath.split(os.path.sep)[-1].split('.')[0])
        try:
            if len(sys.argv) > 1:
                data = ''
                if '-r' in sys.argv[1]:
                    print('[+] Loading a recipe....')
                    with open(sys.argv[2], 'r') as file:
                        for line in file:
                            if line.startswith('MODULE'):
                                module = line[7:-1]
                                print('- Loading {}'.format(module))
                                self.modManager.stage(module)
                            else:
                                data += line
                    self.modified = True
                if data != '':
                    print("[+] Writing to scratchpad...")
                    self.editScratchpad(data)
                        
        except Exception as e:
            print(e)

        click.secho(""" Welcome to:


  ███▄ ▄███▓▓█████ ▓█████▄  █    ██   ██████  ▄▄▄      
 ▓██▒▀█▀ ██▒▓█   ▀ ▒██▀ ██▌ ██  ▓██▒▒██    ▒ ▒████▄    
 ▓██    ▓██░▒███   ░██   █▌▓██  ▒██░░ ▓██▄   ▒██  ▀█▄  
 ▒██    ▒██ ▒▓█  ▄ ░▓█▄   ▌▓▓█  ░██░  ▒   ██▒░██▄▄▄▄██ 
 ▒██▒   ░██▒░▒████▒░▒████▓ ▒▒█████▓ ▒██████▒▒ ▓█   ▓██▒
 ░ ▒░   ░  ░░░ ▒░ ░ ▒▒▓  ▒ ░▒▓▒ ▒ ▒ ▒ ▒▓▒ ▒ ░ ▒▒   ▓▒█░
 ░  ░      ░ ░ ░  ░ ░ ▒  ▒ ░░▒░ ░ ░ ░ ░▒  ░ ░  ▒   ▒▒ ░
 ░      ░      ░    ░ ░  ░  ░░░ ░ ░ ░  ░  ░    ░   ▒   
        ░      ░  ░   ░       ░           ░        ░  ░


 Type help for options\n\n""", fg='green')
        self.do_loaddevice("dummy")




    def do_reload(self,line):
        print("[i] Loading modules...")
        self.modManager = ModuleManager()
        self.snippets = []
        for root, directories, filenames in os.walk(os.path.join(self.base_directory, 'modules')):
            for filename in filenames:
                if filename.endswith('.med'):
                    self.modManager.add(os.path.join(root, filename))

        for root, directories, filenames in os.walk(os.path.join(self.base_directory, 'snippets')):
            for filename in sorted(filenames):
                if filename.endswith('.js'):
                    filepath = os.path.join(root, filename)
                    self.snippets.append(filepath.split(os.path.sep)[-1].split('.')[0])
        try:
             
            if "-r" in line.split(' ')[0]:
                self.modManager.reset()
                data = ''
                print('[+] Loading a recipe....')
                recipe = line.split(' ')[1]
                if os.path.exists(recipe):
                    with open(recipe, 'r') as file:
                        for line in file:
                            if line.startswith('MODULE'):
                                module = line[7:-1]
                                print('- Loading {}'.format(module))
                                self.modManager.stage(module)
                            else:
                                data += line
                    self.modified = True
                    if data != '':
                        print("[+] Writing to scratchpad...")
                        self.editScratchpad(data)
                else:
                    print("[!] Recipe file was not found !")
                        
        except Exception as e:
            print(e)

        print("[i] Done....")


    def do_loaddevice(self,line):

        try:
            print('Available devices:\n')
            devices = frida.enumerate_devices()

            for i in range(len(devices)):
                print('{}) {}'.format(i, devices[i]))

            self.device = devices[int(Numeric('\nEnter the index of the device to use:', lbound=0,ubound=len(devices)-1).ask())] 
 
            android_dev = android_device(self.device.id)
            android_dev.print_dev_properties()
        except:
            self.device = frida.get_remote_device()
        finally:
            self.init_packages()


    def do_snippet(self, line):
        try:
            selected_snippet = line.split(' ')[0]
            self.load_snippet(os.path.join(self.base_directory, 'snippets', selected_snippet + '.js'))
        except Exception as e:
            print(e)


    def show_snippets(self):
        print("[i] Available snippets:")
        print('------------------------\n')
        try:
            for snippet in self.snippets:
                print('> ' + snippet)
        except Exception as e:
            print(e)


    def do_import(self, line):
        try:
            with open(os.path.join(self.base_directory, 'snippets', line + '.js'), 'r') as file:
                data = file.read()
            self.editScratchpad(data, 'a')

            print("\nSnippet has been added to the" + GREEN + " scratchpad" + RESET + " run 'compile' to include it in your final script or 'pad' to edit it")
        except Exception as e:
            print(e)


    def complete_import(self, text, line, begidx, endidx):
        return self.complete_snippet(text, line, begidx, endidx)


    def load_snippet(self, snippet):
        try:
            with open(snippet) as file:
                data = file.read()
            click.secho(data, fg = 'green')
        except Exception as e:
            print(e)


    def complete_snippet(self, text, line, begidx, endidx):
        return [f for f in self.snippets if f.startswith(text)]


    def do_memops(self,line):

        self.native_handler = nativeHandler(self.device)
        self.native_handler.memops(line)


#------------------------cut here
    def do_load(self,line):
        self.native_handler = nativeHandler(self.device)
        self.native_handler.loadLibrary(line.split()[0],line.split()[1])



    def do_describe_java_class(self,line):
        class_path = line.split(' ')[0]
        codejs = '\n'
        codejs += """console.log("-----------dumping:'"""+class_path+"""'-------------------");\n"""
        codejs += "console.log(describeJavaClass('"+class_path+"'));\n"
        codejs += """console.log("-----------End of dumping:'"""+class_path+"""'------------");"""

        self.editScratchpad(codejs, 'a')
        print("Stack trace have been added to the" + GREEN + " scratchpad" + RESET + " run 'compile' to include it in your final script")

    def do_jtrace(self,line):
        function_path = line.split(' ')[0]
        class_name = '.'.join(function_path.split('.')[:-1])
        function_name = function_path.split('.')[-1]       
        codejs = '\n'
        codejs += """var hook = Java.use('""" + class_name + """');"""

        codejs += """
    var overloadCount = hook['""" + function_name + """'].overloads.length;
                                       
    for (var i = 0; i < overloadCount; i++) {
        hook['""" + function_name + """'].overloads[i].implementation = function() {
            colorLog("*** Entering " +'""" + function_name + """',{ c: Color.Green });

            Java.perform(function() {
                var bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
                    console.log("-----------Printing Stack Trace-------");
                    colorLog(bt,{c: Color.Blue});
                    console.log("--------------------------------------")
            });   

            var retval = this['""" + function_name + """'].apply(this, arguments); 
            
            colorLog("*** Exiting " + '""" + function_name + """',{ c: Color.Green });
            return retval;
        }
    }
"""
        self.editScratchpad(codejs, 'a')
        print("Stack trace have been added to the" + GREEN + " scratchpad" + RESET + " run 'compile' to include it in your final script")


#----------------------------
    def complete_load(self, text, line, begidx, endidx):
        return self.complete_list(text, line, begidx, endidx)


    def complete_memops(self, text, line, begidx, endidx):
        return self.complete_list(text, line, begidx, endidx)


    def do_status(self,line):
        print('[+] Dumping processed data:')
        if(self.device):
            print('   --> Current Device:'+self.device.id)
        if(self.currentPackage):
            print('   --> Current Package:'+self.currentPackage)
        if(self.app_libraries):
            self.print_list(self.app_libraries,"   --> Application Libraries:")
        if(self.libname):
            print('   --> Current Library:'+self.libname)
        if(self.native_functions):
            self.print_list(self.native_functions,'   --> Current Native Functions:')


#==================START OF NATIVE OPERATIONS=============================

    def hook_native(self):
        library = Open('Libary name (e.g.: libnative.so):').ask()
        type_ = Alternative('Hook an imported or exported function?', 'i', 'e').ask()
        function = Open('Function name or offset (e.g.: 0x1234):').ask()
        number_of_args = Numeric('Number of function arguments (0 to disable trace):', lbound=0).ask()
        backtraceEnable = Polar('Enable backtrace?', False).ask()
        hexdumpEnable = Polar('Enable memory read?', False).ask()

        header = ''
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

        if function.startswith('0x'):
            header = "\nInterceptor.attach(Module.findBaseAddress('" + library + "').add(" + function + "), {"
        elif type_ == 'e':
            header = "\nInterceptor.attach(Module.getExportByName('" + library + "', '" + function + "'), {"
        else:
            header = "\nvar func = undefined;\n" + 'var imports = Module.enumerateImportsSync("' + library + '");\n'
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
});
"""
        self.editScratchpad(codejs, 'a')
        print("\nHooks have been added to the" + GREEN + " scratchpad" + RESET + " run 'compile' to include it in your final script")


    def do_enumerate(self, line):
        try:
            libname = line.split(' ')[1].strip()
            package = line.split(' ')[0].strip()
            self.libname = libname
            self.currentPackage = package
            if libname == '' or package == '':
                print('[i] Usage: exports com.foo.com libname.so')
            else:
                self.prepare_native("enumerateExportsJs('"+libname+"');\n")

            self.native_functions = []
            self.native_handler = nativeHandler(self.device)
            #self.native_handler.device = self.device

            if len(line.split(' ')) > 2:
                if '--attach' in line.split(' ')[2]:
                    modules = self.native_handler.getModules(package,False)
                else:
                    print("[i] Usage: enumerate package libary [--attach]")
            else:
                modules = self.native_handler.getModules(package,True)

            for function in modules:
                self.native_functions.append(function)
            self.native_functions.sort()
            self.print_list(self.native_functions,"[i] Printing lib's: "+libname+" exported functions:")

        except Exception as e:
            print(e)
            print("[i] Usage: enumerate package libary [--attach]")


    def complete_enumerate(self, text, line, begidx, endidx):
        return self.complete_list(text, line, begidx, endidx)


    def prepare_native(self, operation):
        with open(os.path.join(self.base_directory, 'libraries/native.med'), 'r') as file:
            script = file.read() + 'Java.perform(function() {\n' + operation + ' \n});'

        with open(os.path.join(self.base_directory, 'libraries/native.js'), 'w') as file:
            file.write(script)


    def do_libs(self, line):
        try:
            self.prepare_native("enumerateModules();")

            self.system_libraries = []
            self.app_libraries = []

            option = line.split(' ')[0]
            self.native_handler = nativeHandler(self.device)
            #self.native_handler.device = self.device
            package = line.split(' ')[1].strip()
            self.currentPackage = package

            if len(line.split(' ')) > 2:
                if '--attach' in line.split(' ')[2]:
                    modules = self.native_handler.getModules(package, False)
                else:
                    print("[i] Usage: libs [option] package [--attach]")
            else:
                modules = self.native_handler.getModules(package, True)
               
            for library in modules:
                if library.startswith('/data/app'):
                    self.app_libraries.append(library)
                else:
                    self.system_libraries.append(library)

            self.app_libraries.sort()
            self.system_libraries.sort()
            if '-a' in option:
                self.print_list(self.system_libraries,"[i] Printing system loaded modules:")
                self.print_list(self.app_libraries,"[i] Printing Application modules:")
            elif '-s' in option:
                self.print_list(self.system_libraries, "[i] Printing system loaded modules:")
            elif '-j' in option:
                self.print_list(self.app_libraries,"[i] Printing Application modules:")
            else:
                print('[i] Command was not understood.')
            
        except Exception as e:
            print(e)
            print('[i] Usage: libs [option] package [--attach]')


    def print_list(self, listName, message):
        print(GREEN+message+RESET)
        for item in listName:
            print("""       {}""".format(item))


    def complete_libs(self, text, line, begidx, endidx):
        return self.complete_list(text, line, begidx, endidx)

#-------------------------END OF NATIVE OPERATIONS------------------


    def scratchreset(self):
        if Polar('Do you want to reset the scratchpad?').ask():
            self.editScratchpad('')


    def editScratchpad(self, code, mode='w'):
        scratchpad = self.modManager.getModule('scratchpad')
        if mode == 'a':
            scratchpad.Code += code
        elif mode == 'w':
            scratchpad.Code = code
        else:
            raise Exception('Attempted to open scratchpad in invalid mode {}'.format(mode))
        scratchpad.save()
        self.modManager.stage('scratchpad')
        self.modified = True


    def do_export(self, line):
        try:
            with open(line, 'w') as file:
                for mod in filter(lambda mod: mod.Name != 'scratchpad', self.modManager.staged):
                    file.write('MODULE ' + mod.Name + '\n')
                file.write(self.modManager.getModule('scratchpad').Code)
            print('Recipe exported to dir: {} as {}'.format(os.getcwd(), line))
        except Exception as e:
            print(e) 
            print("[i] Usage: export filename")


    def hookall(self, line):
        aclass = line.split(' ')[0]
        if  aclass == '':
            print('[i] Usage: hookall [class name]')
        else:
            className = aclass
            codejs = "traceClass('"+className+"');\n"
            self.editScratchpad(codejs, 'a')
            print("\nHooks have been added to the" + GREEN + " scratchpad" + RESET + " run 'compile' to include it in your final script")


    def do_hook(self,line):
        option = line.split(' ')[0]
        codejs = '\n'
        if '-f' in option:
            className = input("Enter the full name of the function(s) class: ")

            codejs = """var hook = Java.use('""" + className + """');"""
            functionName = input("Enter a function name (CTRL+C to Exit): ")

            while (True):
                try:
                    codejs += """
                    var overloadCount = hook['""" + functionName + """'].overloads.length;
                    colorLog("Tracing " +'""" + functionName + """' + " [" + overloadCount + " overload(s)]",{ c: Color.Green });
                        
                        for (var i = 0; i < overloadCount; i++) {
                            hook['""" + functionName + """'].overloads[i].implementation = function() {
                            colorLog("*** entered " +'""" + functionName + """',{ c: Color.Green });

                    Java.perform(function() {
                        var bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
                            console.log("Backtrace:" + bt);
                    });   

                    if (arguments.length) console.log();
                    for (var j = 0; j < arguments.length; j++) {
                        console.log("arg[" + j + "]: " + arguments[j]);
                    }
                    var retval = this['""" + functionName + """'].apply(this, arguments); 
                    console.log("retval: " + retval);
                    colorLog("*** exiting " + '""" + functionName + """',{ c: Color.Green });
                    return retval;
                    }
                    }
                    """
                    print('[+] Function: {} hook added !'.format(functionName))
                    functionName = input("Enter a function name (CTRL+C to Exit): ")

                except KeyboardInterrupt:
                    self.editScratchpad(codejs, 'a')
                    print("\nHooks have been added to the" + GREEN + " scratchpad" + RESET + " run 'compile' to include it in your final script")
                    break

        elif "-a" in option:
            aclass = line.split(' ')[1].strip()
            if aclass == '':
                print('[i] Usage hook -a class_name')
            else:
                self.hookall(aclass)
        elif '-r' in option:
            self.scratchreset()
        elif '-n' in option:
            self.hook_native()


#---------------------------------------------------------------------------------------------------------------

    def do_search(self, pattern):
        matches = self.modManager.findModule(pattern)
        if not matches:
            print('No modules found containing: {}!'.format(pattern))
        else:
            for match in matches:
                print(match.replace(pattern, GREEN + pattern + RESET))

#------------------

    def do_dexload(self,line):
        try:
            codejs = '\n\nJava.openClassFile("'+line.split(' ')[0]+'").load();'
            self.editScratchpad(codejs,'a')
        except Exception as e:
            print(e)



    def do_swap(self, line):
        try:
            old_index = int(line.split(' ')[0])
            new_index = int(line.split(' ')[1])
            self.modManager.staged[old_index], self.modManager.staged[new_index] = self.modManager.staged[new_index], self.modManager.staged[old_index]
            print('New arrangement:')
            self.show_mods()
        
            self.modified = True
        except Exception as e:
            print(e)


    def do_clear(self, line):
        subprocess.run('clear', shell=True)


    def do_c(self, line):
        subprocess.run(line, shell=True)


    def do_cc(self, line):
        subprocess.run('adb -s {} shell {}'.format(self.device.id, line), shell=True)


    def init_packages(self):
        self.refreshPackages()
        print('\nInstalled packages:\n')
        for i in range(len(self.packages)):
            print('[{}] {}'.format(i, self.packages[i]))

    def do_dump(self, line):
        pkg = line.split(' ')[0].strip()
        if pkg == '':
            print('[i] Usage: dump package_name')
        else:
            dump_pkg(pkg)


    def complete_dump(self, text, line, begidx, endidx):
        return self.complete_list(text, line, begidx, endidx)


    def do_reset(self,line):
        self.modManager.reset()
        self.modified = False


    def complete_show(self, text, line, begidx, endidx):
        return [f for f in self.show_commands if f.startswith(text)]


    def complete_run(self, text, line, begidx, endidx):
        return self.complete_list(text, line, begidx, endidx)


    def complete_use(self, text, line, begidx, endidx):
        return [mod.Name for mod in self.modManager.available if mod.Name.startswith(text)]


    def do_EOF(self, line):
        return True


    def do_rem(self, mod):
        try:
            self.modManager.unstage(mod)
            print("\nRemoved: {}".format(mod) )
            self.modified = True
            print()  
        except Exception as e:
            print(e)


    def complete_rem(self, text, line, begidx, endidx):
        return [mod.Name for mod in self.modManager.staged if mod.Name.startswith(text)]


    def do_add(self, mod):
        try:
            self.modManager.add(mod)
        except FileNotFoundError:
            print('Module not found!')
        except (AttributeError, json.decoder.JSONDecodeError):
            print("Module file has an incorrect format")


    def do_use(self, mod):
        self.modManager.stage(mod)
        self.show_mods()
        self.modified = True
        print()


    def do_show(self, what):
        try:
            if what == 'categories':
                self.show_categories()
            elif what == 'all':
                self.show_all()
            elif what == 'mods':
                self.show_mods()
            elif what == 'snippets':
                self.show_snippets()
            elif what.split(' ')[0] == 'mods' and len(what.split(' ')) == 2:
                self.show_mods_by_category(what.split(' ')[1])
            else:
                print('Invalid command!')
        except Exception as e:
            print(e)
            print('Invalid command - please check usage!')


    def show_mods(self):
        print("\nCurrent Mods:")
        for i in range(len(self.modManager.staged)):
            print('{}) {}'.format(i, self.modManager.staged[i].Name))
        print()


    def show_categories(self):
        print('\nAvailable module categories:\n')
        for category in self.modManager.categories:
            print(category)
        print()


    def show_all(self):
        for mod in self.modManager.available:
            print(mod.Name)


    def do_exit(self,line):
        with open(os.path.join(self.base_directory, 'agent.js'), 'r') as agent:
            agent.seek(0)
            if agent.read(1):
                if Polar('Do you want to reset the agent script?').ask():
                    open(os.path.join(self.base_directory, 'agent.js'), 'w').close()
    
        self.scratchreset()
        print('Bye!!')
        sys.exit()



    def do_shell(self, line):
        shell = os.environ['SHELL']
        subprocess.run('{}'.format(shell), shell=True)


    def show_mods_by_category(self, category):
        mods = [mod for mod in self.modManager.available if mod.getCategory() == category]
        if len(mods) == 0:
            print('No such category or this category does not contain modules')
        else:
            width = max(map(lambda mod: len(mod.Name), mods)) + 2
            print(f"{'Name': <{width}}Description")
            for name, description in zip([mod.Name for mod in mods], [mod.Description for mod in mods]):
                print(GREEN + f"{name: <{width}}" + BLUE + f"{description}" + RESET)

    
    def do_strace(self, line):
        
        self.detached = False
        session = self.frida_session_handler(self.device,True,line.split(' ')[0])
        try:

            with open(os.path.join(self.base_directory, 'libraries', 'strace.js'), 'r') as file:
                self.script = session.create_script(file.read())
       
            session.on('detached',self.on_detached)
            self.script.on("message",self.my_message_handler)  # register the message handler
            self.script.load()  
            self.device.resume(self.pid)
            s = ""
            print(RED+"----- Credits @FrenchYeti -----")
            print("[i] Type 'e' to exit the strace "+RESET)
            while (s!='e') and (not self.detached):
                s = input("Type 'e' to exit:")          
            
            if self.script:
                self.script.unload()

        except Exception as e:
            print(e)
        print(RESET)
        
        return

    def complete_strace(self, text, line, begidx, endidx):
        self.refreshPackages()
        return [package for package in self.packages if package.startswith(text)]


    def do_compile(self, line):
        try:
            hooks = []
            jni_prolog_added = False
            with open(os.path.join(self.base_directory, 'libraries', 'utils.js'), 'r') as file:
                header = file.read()
            hooks.append(header)

            #add delay
            delay = ''
            options = len(line.split())
            if options == 2 and ('-t' in line.split()[0]):             
                delay = line.split()[1]
                hooks.append("\n\nsetTimeout(function() {\n")

            hooks.append("Java.perform(function() { \ntry {\ndisplayAppInfo();\n")
            for mod in self.modManager.staged:
                if 'JNICalls' in mod.path and not jni_prolog_added:
                    hooks.append("""
                        var jnienv_addr = 0x0;
                        try{
                            Java.perform(function(){jnienv_addr = Java.vm.getEnv().handle.readPointer();});
                            console.log("[+] Hooked successfully, JNIEnv base address: " + jnienv_addr);
                        }
                        catch(err){
                            console.log('Error:'+err);
                        }
                    """)
                    jni_prolog_added = True
            hooks.append(self.modManager.compile())
            epilog = """}
    catch(error){
        colorLog("------------Error Log start-------------",{ c:Color.Red })
        console.log(error);
        colorLog("------------Error Log EOF---------------",{ c:Color.Red })
     } });"""
            if delay != '':
                hooks.append(epilog[:-1])
                hooks.append("}}, {});".format(delay))
            else:
                hooks.append(epilog)

            with open(os.path.join(self.base_directory, 'agent.js'), 'w') as agent:
                for line in hooks:
                    agent.write('%s\n' % line)
            print("\nScript is compiled\n")
            self.modified = False

        except Exception as e:
            print(e)
        self.modified = False
        return


    def do_pad(self, line):
        scratchpad = self.modManager.getModule('scratchpad')
        with open(os.path.join(self.base_directory, '.draft'), 'w') as draft:
            draft.write(scratchpad.Code)
        subprocess.run('vim ' + os.path.join(self.base_directory, '.draft'), shell=True)
        with open(os.path.join(self.base_directory, '.draft'), 'r') as draft:
            code = draft.read()
        self.editScratchpad(code)


    def do_run(self, line):
        try:
            if self.modified:
                if Polar('Module list has been modified, do you want to recompile?').ask():
                    self.do_compile(line)
 
            flags = line.split(' ')
            length = len(flags)
            if length == 1:
                self.run_frida(False, False, line, self.device)
            elif length == 2:
                
                if '-f' in flags[0]:
                    self.run_frida(True, False, flags[1], self.device)
                elif '-n' in flags[0]:
                    try:
                        if len(self.packages) == 0:
                            self.refreshPackages()
                        #print(flags[1])
                        package_name = self.packages[int(flags[1])]
                        #print("package name: ", package_name)
                        self.run_frida(True, False, package_name, self.device)
                    except (IndexError, TypeError) as error:
                        print('Invalid package number')

                else:
                    print('Invalid flag given!')

            else:
                pass
        except Exception as e:
            print(e)

    def fill_app_info(self,data):
        self.app_info = json.loads(data)


    def my_message_handler(self, message, payload):
        if message["type"] == "send":
            
            data = message["payload"].split(":")[0].strip()
            if "trscrpt|" in data:
                result = self.translator.translate(data[data.index("trscrpt|") + len("trscrpt|"):])
                self.script.post({"my_data": result}) 
            else:
                self.fill_app_info(message["payload"])


    def on_detached(self, reason):
        print("Session is detached due to:", reason)
        self.detached = True
    
    def print_app_info(self):

        if self.app_info:
            appname = self.app_info["applicationName"]
            filesDirectory = self.app_info["filesDirectory"]
            cacheDirectory = self.app_info["cacheDirectory"]
            externalCacheDirectory = self.app_info["externalCacheDirectory"]
            codeCacheDirectory = self.app_info["codeCacheDirectory"]
            obbDir = self.app_info["obbDir"]
            packageCodePath = self.app_info["packageCodePath"]


            print(RESET+"""\nApplication Name: {}
Data Directory: {}
Cache Directory: {}
External Cache Directory: {}
Code Cache Directory: {}
Obb Directory: {}
Apk Directory: {}\n""".format(appname,filesDirectory,cacheDirectory,externalCacheDirectory,codeCacheDirectory,obbDir,packageCodePath)+RESET)
        else:
            print("[!] No availlable info.")


    def run_frida(self, force, detached, package_name, device):
        in_session_menu = WHITE + '[in-session] |'+ GREEN + 'c:' + WHITE + 'clear |'  + GREEN + 'e:' + WHITE + 'exit |' + GREEN + 'r:' + WHITE + 'reload | \n' + '| '+ GREEN + 'rs:' + WHITE + 'reset scratchpad |' +  GREEN + 'i:' + WHITE + 'info |' + GREEN + 't:' + WHITE + 'trace  |' + GREEN +'?:'+WHITE +'help |:'+RESET
        creation_time = modified_time = None
        self.detached = False
        session = self.frida_session_handler(device,force,package_name)
        try:
            creation_time = self.modification_time(os.path.join(self.base_directory, "agent.js"))
            with open(os.path.join(self.base_directory, "agent.js")) as f:
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

                    modified_time = self.modification_time(os.path.join(self.base_directory, "agent.js"))
                    if modified_time != creation_time:
                        print(RED + "Script changed, reloading ...." + RESET)
                        creation_time = modified_time
                        self.reload_script(session)
                        # self.script.unload()
                        # with open(os.path.join(self.base_directory, "agent.js")) as f:
                        #     self.script = session.create_script(f.read())
                        # session.on('detached',self.on_detached)
                        # self.script.on("message",self.my_message_handler)  # register the message handler
                        # self.script.load()  
                    else:
                         print(GREEN + "Script unchanged, nothing to reload ...." + RESET)
                elif s == '?':
                    print(RESET+"""\nHelp: 
    'e' to exit the session 
    'r' to reload the script (use if script changed)
    'i' to read information about the application
    't' to trace a function and print the stac trace (e.g. t com.foo.bar.func)
    '?' to print this message\n"""+RESET)
                elif s == 'i':
                    self.print_app_info()
                elif s == 'c':
                    self.do_clear('')
                elif s == 'rs':
                    self.scratchreset()
                    self.do_compile('')
                    self.reload_script(session)

                elif s.split(' ')[0] == 't':
                    try:
                      
                        self.do_jtrace(s.split(' ')[1])
                        self.do_compile('')
                        self.reload_script(session)
                    except Exception as e:
                        pass

                elif s.split(' ')[0] == 'dc':
                    try: 
                        self.do_describe_java_class(s.split(' ')[1])
                        self.do_compile('')
                        self.reload_script(session)
                    except Exception as e:
                        pass
                                 
            
            if self.script:
                self.script.unload()

        except Exception as e:
            print(e)
        print(RESET)
        return

    def reload_script(self,session):
        self.script.unload()
        with open(os.path.join(self.base_directory, "agent.js")) as f:
            self.script = session.create_script(f.read())
            session.on('detached',self.on_detached)
            self.script.on("message",self.my_message_handler)  # register the message handler
            self.script.load()  


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


    def frida_session_handler(self,con_device,force,pkg):
        time.sleep(1)
        if force == False:

            self.pid = os.popen("adb -s {} shell pidof {}".format(self.device.id,pkg)).read().strip()
            #pid = con_device.attach(self.pid) 
            if self.pid == '':
                print("[+] Could not find process with this name.")
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


    def do_list(self,line):
        if len(line.split()) == 0:
            self.init_packages()
        else:
            try:    
                package = line.split()[0]
                option = line.split()[1]
                dumpsys = os.popen('adb -s {} shell dumpsys package {}'.format(self.device.id,package))
                if option == "path":
                    print('-'*20+package+' '+"paths"+'-'*20)
                    for ln in dumpsys:
                        for keyword in ["resourcePath","codePath","legacyNativeLibraryDir","primaryCpuAbi"]:
                            if keyword in ln:
                                print(ln,end='')

                print("-"*31+'EOF'+'-'*len(package)+'-'*12)
            except Exception as e:
                print(e)


    def complete_list(self, text, line, begidx, endidx):
        self.refreshPackages()
        return [package for package in self.packages if package.startswith(text)]


    def do_type(self,text):
        os.popen("adb -s {} shell input text {}".format(self.device.id,text))


    # Use and help are always in sync
    def complete_help(self, text, line, begidx, endidx):
        return self.complete_use(text, line, begidx, endidx)


    def do_help(self,line):
        if line != '':
            print('\n' + BLUE + self.modManager.getModule(line).Help + RESET)
        else:
            print("""
                MODULE OPERATIONS:

                        - search [keyword]          : Search for a module containing a specific keyword
                        - help [module name]        : Display help for a module
                        - add [fullpath]            : Adds the module specified by fullpath to the list of available modules
                        - snippet [tab]             : Show / display available frida script snippets
                        - use [module name]         : Select a module to add to the final script
                        - show mods                 : Show selected modules
                        - show categories           : Display the available module categories (start here)
                        - show mods [category]      : Display the available modules for the selected category
                        - show snippets             : Display available snippets of frida scripts
                        - show all                  : Show all available modules
                        - import [snippet]          : Import a snippet to the scratchpad
                        - rem [module name]         : Remove a module from the list that will be loaded
                        - swap old_index new_index  : Change the order of modules in the compiled script
                        - reset                     : Remove all modules from the list that will be loaded
                        - reload                    : Reload all the existing modules
                ===================================================================================================

                SCRIPT OPERATIONS:

                        - export  'filename'        : Save session modules and scripts to 'filename'
                        - import [tab]              : Import frida script from available snippet
                        - pad                       : Edit the scratchpad using vi
                        - jtrace function_path      : Prints the stack trace of a function
                        - compile [-t X millisec]   : Compile the modules to a frida script, use '-t' to add a load delay 
                        - hook [option]
                    
                            -a [class name]         : Set hooks for all the functions of the given class
                            -f                      : Initiate a dialog for hooking a Java function
                            -n                      : Initiate a dialog for hooking a native function
                            -r                      : Reset the hooks setted so far
                ===================================================================================================

                NATIVE OPERATIONS:

                        - memops package_name lib.so    : READ/WRITE/SEARCH process memory
                        - strace package_name           : logs system calls, signal deliveries, and changes of process state 

                        - load package_name full_library_path
                                                        : Manually load a library in order to explore using memops
                                                          Tip: run "list package_name path" to get the application's
                                                          directories

                        - libs (-a, -s, -j) package_name [--attach]  

                            -a                          : List ALL loaded libraries
                            -s                          : List System loaded libraries
                            -j                          : List Application's Libraries
                            --attach                    : Attach to the process (Default is spawn) 
                        - enumerate pkg_name libname [--attach]    
                        
                        Enumerate a library's exported functions (e.g. - enumerate com.foo.gr libfoo)
                ===================================================================================================

                FRIDA SESSION:

                        - run        [package name] : Initiate a Frida session and attach to the selected package
                        - run -f     [package name] : Initiate a Frida session and spawn the selected package
                        - run -n     [package num]  : Initiate a Frida session and spawn the 3rd party package 
                                                      number num (listed by "list")
                        - dump       [package_name] : Dump the requested package name (works for most unpackers)
                        - loaddevice                : Load or reload a device
                ====================================================================================================
                    
                HELPERS:

                        - type 'text'               : Send a text to the device
                        - list                      : List 3rd party packages
                        - list 'package_name' path  : List data/app paths of 3rd party packages 
                        - status                    : Print Current Package/Libs/Native-Functions
                        - shell                     : Open an interactive shell
                        - clear                     : Clear the screen
                        - c [command]               : Run a shell command
                        - cc [command]              : Run a shell command on the mobile device
                ==============================================================================================

                        Tip: Use the /modules/scratchpad.med to insert your own hooks and include them to the agent.js 
                        using the 'compile script' command""")

if __name__ == '__main__':
    if 'libedit' in readline.__doc__:
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")
    Parser().cmdloop()

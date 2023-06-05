#!/usr/bin/env python3
import subprocess, platform, os, sys, readline, time, argparse,requests,re
from urllib.parse import urlparse
import cmd2, click, frida
from libraries.dumper import dump_pkg
from google_trans_new import google_translator  
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
        for line in os.popen('adb -s {} shell pm list packages'.format(self.device.id)):
            self.packages.append(line.split(':')[1].strip('\n'))

    def preloop(self):
        self.do_reload("dummy")
    
        parser = argparse.ArgumentParser(
                            prog = 'Medusa',
                            description = 'An extensible and modularized framework that automates processes and techniques practiced during the dynamic analysis of Android Applications.')
        parser.add_argument('-r','--recipe', help='Use this option to load a session/recipe')
        args = parser.parse_args()

        if args.recipe:
            self.write_recipe(args.recipe)

            # if len(sys.argv) > 1:
            #     data = ''
            #     if '-r' in sys.argv[1]:
            #         print('[+] Loading a recipe....')
            #         with open(sys.argv[2], 'r') as file:
            #             for line in file:
            #                 if line.startswith('MODULE'):
            #                     module = line[7:-1]
            #                     print('- Loading {}'.format(module))
            #                     self.modManager.stage_verbadim(module)
            #                 else:
            #                     data += line
            #         self.modified = True
            #     if data != '':
            #         print("[+] Writing to scratchpad...")
            #         self.edit_scratchpad(data)
                        


        click.secho(""" 
                                                                                                                        
                                                       ////                                                             
                                                       *////*                                                           
                                       .******,         ,****           *****                                           
                                      ***********      .*****         ******                                            
                                             *****   .*****.          *****                                             
                                             .****.  ****,    .****,   ********        ..                               
                         **********           *****  ******************.  ,*****,  ,*******,                            
                          ,**********         .*****  .********.   ,****    .****..****.                                
                                .****   ******  ******.                     *****  ******                               
                               *****. **********  *******.       ***************    .*****,                             
                              *****  .****  .***     ,****     ******,..,***.         .****,                            
                  ********   *****   *****         .,*****     *****         ,****,   .****,  ********                  
                ,**********  .***********    ,*  .*******       *******  *.   ,***********, ,**********                 
                .****  *****.   ,*****.       .*.                  **, **        .******   ,****. ,****                 
                        ,*******.   ,******     ***********************,    ,******    .*******                         
                           *****. *********  *****************************.  ********* *****,                           
                 .**********.   .*****    ,**********************************.    *****    ,**********                  
               ,**************, *****   ,******,  .******************   *******.   ****, ***************                
              .****. .**,  **,  ****,  ********,  ,******************   *********  *****  **.  ***  ,****               
         ,*********  ******,   *****. ******************************************** ,****,   ******,  *********.         
          ,*****,      ,***********  *********************************************,  ***********.     .,****,.          
                            ,,,.    .,*,,,,,,,,,,,,,*,*,,,,,,,,,*,,,,,*,*,,,,,,,,,,     .,,.""", fg='green',bold=True)                           
        click.secho("""                                                                                                                      
                                                           ####                                                         
                                                           ####                                                         
             ##################      #########      ###########   ####     ####   .#########    ##########              
            ####    ####    ####   ####    .###.  #####    ####   ####     ####  .###.                 ####             
            ####    ####    ####   ############# .####     ####   ####     ####   #########     ###########             
            ####    ####    ####   ####           ####     ####   ####     ####         ####.  ####    ####             
            ####    ####    ####    ###########    ############    ############  .##########  ############             
                                         ...            ...            ...           ...           ....     

 Type help for options\n\n""", fg=(204, 255, 204),bold=True)
        self.do_loaddevice("dummy")


###################################################### do_ defs start ############################################################

    def do_add(self, mod) -> None:
        """
        Add a module which is not indexed/added in the existing modules. 
        Usage:
        add /full/path/to/module
        """
        try:
            self.modManager.add(mod)
        except FileNotFoundError:
            print('Module not found!')
        except (AttributeError, json.decoder.JSONDecodeError):
            print("Module file has an incorrect format")

    def do_c(self, line) -> None:
        """Usage: c [shell command]
        Run a shell command on the local host."""
        subprocess.run(line, shell=True)

    def do_c2check(self, line) -> None:
        """Usage: c2check [package name]
        Searches the application's memory for C2 addresses"""      
        try:
            pkg = line.split(' ')[0]
            click.secho('Starting app:'.format(pkg), fg = 'green')
            os.popen("adb -s {} shell  monkey -p {} -c 'android.intent.category.LAUNCHER 1'".format(self.device.id,pkg)).read()
            pid = os.popen("adb -s {} shell pidof {}".format(self.device.id,pkg)).read().strip()
           
            if pid == "":
                click.secho("Can't find pid !",fg='red')
                return
            elif len(pid.split(' ')) > 1:
                option, index = pick(pid.split(' '),"More than one processes found running with that name:",indicator="=>",default_index=0)
                pid = option
            else:
                 click.secho('Process pid:{}'.format(pid),fg='green')

            maps = os.popen("""adb -s {} shell 'echo "cat /proc/{}/maps" | su'""".format(self.device.id, pid)).read().split('\n')
            for linein in maps:
                if 'dalvik-main space' in linein:
                    range1 = int(linein.split(' ')[0].split('-')[0],16)
                    range2 = int(linein.split(' ')[0].split('-')[1],16)
                    sz = range2 - range1
                    print('Starting addres: {}, size: {}'.format(hex(range1),range2-range1))
                    self.native_handler = nativeHandler(self.device)
                    self.native_handler.memraw(pkg + ' ' + pid + ' ' + hex(range1) + ' ' + str(sz),True)

            hosts = []
            output = []
            all_strings=[]
            script_path = os.path.abspath(__file__)
            script_dir = os.getcwd()
            dump_dir = script_dir+os.path.sep+'dump'+os.path.sep+pkg
            for filename in os.listdir(dump_dir):
                file_path = os.path.join(dump_dir, filename)
                if os.path.isfile(file_path):
                    cmd = "strings {}".format(file_path)
                    result = subprocess.run(cmd,shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    if result.returncode == 0:
                        output = result.stdout.decode().strip().split('\n')
                        for entry in output:
                            all_strings.append(entry)
                            if self.is_valid_url(entry):
                               hosts.append(urlparse(entry).netloc)

            hosts = list(dict.fromkeys(hosts))
            whitelist = script_dir+os.path.sep+'whitelist.txt'
            whitelist_urls = []
            if os.path.isfile(whitelist):
                with open(whitelist,'r') as file:
                    whitelist_urls = file.readlines()

            whitelist_urls_strip=[x.strip() for x in whitelist_urls]
            hosts =[x for x in hosts if not any(y in x for y in whitelist_urls_strip)]

            click.secho('Scanning for web addresses',fg='yellow')
            self.check_using_vt(hosts,script_dir+os.path.sep+'vt.key')
            click.secho('Scanning for secrets',fg='yellow')
            self.scan_for_secrets(list(dict.fromkeys(all_strings)))
            
        except Exception as e:
            print(e) 

    def do_cc(self, line) -> None:
        """
        Get an adb shell to the connected device (no args)
        """
        subprocess.run('adb -s {} shell {}'.format(self.device.id, line), shell=True)

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
            with open(os.path.join(self.base_directory, 'libraries', 'utils.js'), 'r') as file:
                header = file.read()
            hooks.append(header)

            #add delay
            delay = ''
            options = len(line.split())
            if options == 2 and ('-t' in line.split()[0]):             
                delay = line.split()[1]
                hooks.append("\n\nsetTimeout(function() {\n")

            hooks.append("Java.perform(function() { \ntry {\nsetTimeout(displayAppInfo,500);\n")
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
            if rs:
                print("\nScript has been reset\n")
            else:
                print("\nScript is compiled\n")
            self.modified = False

        except Exception as e:
            print(e)
        self.modified = False

    def do_describe_java_class(self,line) -> None:
        """
        Adds relevant code to scratchpad which will print details about a class. 
        Usage:
        describe_java_class [class path]
        """
        class_path = line.split(' ')[0]
        codejs = '\n'
        codejs += """console.log("-----------dumping:'"""+class_path+"""'-------------------");\n"""
        codejs += "console.log(describeJavaClass('"+class_path+"'));\n"
        codejs += """console.log("-----------End of dumping:'"""+class_path+"""'------------");"""
        self.edit_scratchpad(codejs, 'a')
        print("Stack trace have been added to the" + GREEN + " scratchpad" + RESET + " run 'compile' to include it in your final script")

    def do_dexload(self,line) -> None:
        """
        Force the android application to load a dex file
        Usage:
        dexload /device/path/to/dex
        """
        try:
            codejs = '\n\nJava.openClassFile("'+line.split(' ')[0]+'").load();'
            self.edit_scratchpad(codejs,'a')
        except Exception as e:
            print(e)
    
    def do_dump(self, line) -> None:
        """
        Dump the memory of a package name 
        Usage:
        dump [package name]
        """
        pkg = line.split(' ')[0].strip()
        if pkg == '':
            print('[i] Usage: dump package_name')
        else:
            dump_pkg(pkg)

    def do_enumerate(self, line) -> None:
        """
        Enumerates the exported functions of a native library.
        Usage: exports com.foo.com libname.so
        Using '--attach' will attach to the already running process (gives better results)
        """
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
                    print("[i] Usage: enumerate package library [--attach]")
            else:
                modules = self.native_handler.getModules(package,True)

            for function in modules:
                self.native_functions.append(function)
            self.native_functions.sort()
            self.print_list(self.native_functions,"[i] Printing lib's: "+libname+" exported functions:")

        except Exception as e:
            print(e)
            print("[i] Usage: enumerate package library [--attach]")

    def do_exit(self,line) -> None:
        """
        Exit MEDUSA
        """
        with open(os.path.join(self.base_directory, 'agent.js'), 'r') as agent:
            agent.seek(0)
            if agent.read(1):
                if Polar('Do you want to reset the agent script?').ask():
                    open(os.path.join(self.base_directory, 'agent.js'), 'w').close()
    
        self.scratchreset()
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
            print('Recipe exported to dir: {} as {}'.format(os.getcwd(), line))
        except Exception as e:
            print(e) 
            print("[i] Usage: export filename")
    
    def do_get(self,line):
        """
        Print the current value of a fields of a class instance
        Usage: get package_name full.path.to.class.field
        """
        try:
            package_name = line.split(' ')[0]
            class_field_path = line.split(' ')[1]
            field = class_field_path.split('.')[-1]
            clazz = '.'.join(class_field_path.split('.')[:-1])
            if field == '*':
                codeJs = """
                Java.perform(function() { 
                    try {
                        var jClass = Java.use('"""+clazz+"""');
                        var _fields = jClass.class.getFields().map(f => {
                        return f.toString()
                        })  
                        Java.choose('"""+clazz+"""', {
                        onMatch: function(instance) {
                            for(var i = 0; i < _fields.length; i++){
                            var field = _fields[i].substring(_fields[i].lastIndexOf(".") + 1);                
                            console.log('var '+field+ ' ='+JSON.stringify(instance[field].value))
                            }
                        }, onComplete: function() {
                        }
                        })
                    }
                        catch(e){console.log(e)}
                    });
                    """
        
            else:
                codeJs = "Java.perform(function() { try { Java.choose('"+clazz+"',{"
                codeJs+="onMatch: function(instance) {"
                codeJs+= "console.log('Current field value of '+instance+ ' is:'+JSON.stringify(instance."+field+'.value))'
                codeJs+="}, onComplete: function() { }});} catch (e){console.log(e)}})"
        
            self.detached = False

            session = self.frida_session_handler(self.device,False,package_name)
            if session is None:
                print("[!] Can't create session for the given package name. Is it running ?")

            script = session.create_script(codeJs)
            session.on('detached',self.on_detached)
            script.load()
            input()
            if script:
                script.unload()
        except Exception as e:
            print(e)

    def do_man(self,line) -> None:
        """
        Display the manual 
        """
        try:
            print(BOLD+"""
                Module Stashing / Un-Stashing:

                        - add [fullpath]            : Adds the module, specified by the "fullpath" option, to a 
                                                      list of stashed modules
                        - compile [-t X ms]         : Compile the stashed modules. Use -t X to add X ms delay
                        - import [snippet]          : Import a snippet to the scratchpad
                        - info [module name]        : Display info about a module
                        - rem [module name]         : Remove a module from the stashed ones
                        - reload                    : Reload all the medusa modules
                        - reset                     : Remove all modules from the list of the stashed ones
                        - search [keyword]          : Search for a module containing a specific keyword in its name

                        - show [option]
                                all                 : Show all available modules
                                categories          : Display the available module categories
                                mods                : Show stashed modules
                                mods [category]     : Display the available modules for the selected category
                                snippets            : Display available snippets of frida scripts

                        - snippet [tab]             : Show / display available frida script snippets
                        - swap old_index new_index  : Change the order of modules in the compiled script
                        - use [module name]         : Select a module to add to the final script

                ===================================================================================================

                Hooking beyond the modules:

                        - hook [option]
                            -a [class name]         : Set hooks for all the methods of the given class
                            -f                      : Initiate a dialog for hooking a Java method
                            -n                      : Initiate a dialog for hooking a native method
                            -r                      : Reset the hooks set so far
                        - jtrace method_path        : Prints the stack trace of a method (similar to hook -f)
                        - pad                       : Edit the scratchpad using vim
                        - import [tab]              : Import a frida script from the snippets folder

                ===================================================================================================

                Starting a session:

                        - run        [package name] : Initiate a Frida session and attach to the selected package
                        - run -f     [package name] : Initiate a Frida session and spawn the selected package
                        - run -n     [package num]  : Initiate a Frida session and spawn the 3rd party package 
                                                      number num (listed by "list")

                ===================================================================================================

                Working with native libraries:

                        - libs (-a, -s, -j) package_name [--attach]  

                            -a                          : List aLL loaded libraries
                            -s                          : List system's loaded libraries
                            -j                          : List application's Libraries
                            --attach                    : Attach to the process (default is to first run the app) 
                        
                        - enumerate pkg_name libname [--attach]    
                        
                            Enumerate a library's exported functions (e.g. enumerate com.foo.gr libfoo.so)

                        - load package_name full_library_path

                                                        : Force the application to load a native library 
                                            
                ===================================================================================================

                Working with the application's memory:

                        - memops package_name lib.so    : read/write/search/dump a native library
                        - memmap package_name           : read/dump read or dump a memory region

                ====================================================================================================

                Getting Class and Object snapshots:

                        - describe_java_class full.path.to.class.name   : Log details about the given class
                        - get package_name full.path.to.class.field     : Get the current value of a field of an 
                                                                          instnatiated java class. 
                ====================================================================================================

                Usefull utilities:

                        - c [command]               : Run a shell command
                        - cc [command]              : Run a shell command on the mobile device
                        - clear                     : Clear the screen
                        - shell                     : Open an interactive shell
                ----------------------------------------------------------------------------------------------------
                        - dump [package_name]       : Dump the requested package name (works for most unpackers)
                        - list                      : List 3rd party packages
                        - list 'package_name' path  : List data/app paths of 3rd party packages
                        - loaddevice                : Load or reload a device
                        - reload [-r recipe]        : Reload the modules. Use -r to load a recipe (see export command)
                        - status                    : Print Current Package/Libs/Native-Functions
                        - strace package_name       : logs system calls, signal deliveries, and changes of process state 
                        - type 'text'               : Send a text to the device

                ==============================================================================================
                
                Saving a session:

                        - export 'filename'         : Save session modules and scripts to 'filename'. 
                        
                          (-) To load this file when starting medusa, add the -r option followed by the filename
                          (-) To load this file while running medusa, type 'reload -r filename'                                      
"""+RESET)

        except Exception as e:
            print(e)

    def do_hook(self,line) -> None:
        """
        Hook a method or methods
        Usage:
        hook [options] where option can be one of the following:
            -a [class name]: Set hooks for all the methods of the given class
            -f              : Initiate a dialog for hooking a Java method
            -n              : Initiate a dialog for hooking a native method
            -r              : Reset the hooks setted so far
        """
        option = line.split(' ')[0]
        codejs = '\n'
        if '-f' in option:
            className = input("Enter the full name of the method(s) class: ")
            uuid = str(int(time.time()))

            codejs = """let hook_"""+uuid+""" = Java.use('""" + className + """');"""
            functionName = input("Enter a method name (CTRL+C to Exit): ")
            enable_backtrace =  Polar('Enable backtrace?', False).ask()

            while (True):
                try:
                    codejs += """
                    let overloadCount_"""+uuid+""" = hook_"""+uuid+"""['""" + functionName + """'].overloads.length;
                    colorLog("Tracing " +'""" + functionName + """' + " [" + overloadCount_"""+uuid+""" + " overload(s)]",{ c: Color.Green });
                        
                        for (let i = 0; i < overloadCount_"""+uuid+"""; i++) {
                            hook_"""+uuid+"""['""" + functionName + """'].overloads[i].implementation = function() {
                            colorLog("*** entered " +'""" + functionName + """',{ c: Color.Green });"""
                    if enable_backtrace:
                        codejs+="""
                    Java.perform(function() {
                        let bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
                            console.log("Backtrace:" + bt);
                    });   """
                    codejs +="""

                    if (arguments.length) console.log();
                    for (let j = 0; j < arguments.length; j++) {
                        console.log("arg[" + j + "]: " + arguments[j]);
                    }
                    let retval = this['""" + functionName + """'].apply(this, arguments); 
                    console.log("retval: " + retval);
                    colorLog("*** exiting " + '""" + functionName + """',{ c: Color.Green });
                    return retval;
                    }
                    }
                    """
                    print('[+] Method: {} hook added !'.format(functionName))
                    functionName = input("Enter a method name (CTRL+C to Exit): ")

                except KeyboardInterrupt:
                    self.edit_scratchpad(codejs, 'a')
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
    
    def do_jtrace(self,line) -> None:
        """
        Prints the stacktrace of a specified function
        Usage: 
        jtrace [full class path]
        """
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
        self.edit_scratchpad(codejs, 'a')
        print("Stack trace have been added to the" + GREEN + " scratchpad" + RESET + " run 'compile' to include it in your final script")

    def do_import(self, line) -> None:
        """
        Imports a script from a predefined directory and adds it to the scratchpad.
        Usage: 
        import [tab] #pressing tab will show the availlable scripts.
        """
        try:
            with open(os.path.join(self.base_directory, 'snippets', line + '.js'), 'r') as file:
                data = file.read()
            self.edit_scratchpad(data, 'a')

            print("\nSnippet has been added to the" + GREEN + " scratchpad" + RESET + " run 'compile' to include it in your final script or 'pad' to edit it")
        except Exception as e:
            print(e)
    
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

    def do_libs(self, line) -> None:
        """
        Enumerates loaded native libraries 
        Usage:
        libs (-a, -s, -j) package_name [--attach]
            -a  : List ALL loaded libraries
            -s  : List System loaded libraries
            -j  : List Application's Libraries
            --attach    : Attach to the process (Default is spawn)
        """
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

    def do_list(self,line) -> None:
        """
        List installed 3rd party applications of the android device 
        """
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

    def do_load(self,line) -> None:
        """
        Force the application to manually load a library in order to explore using memops. 
        Usage:
        load package_name full_library_path
        Tip: run "list package_name path" to get the application's directories
        """
        self.native_handler = nativeHandler(self.device)
        self.native_handler.loadLibrary(line.split()[0],line.split()[1])

    def do_loaddevice(self,line) -> None:
        """
        Load a device in order to interact
        """
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

    def do_memops(self,line) -> None:
        """
        READ/WRITE/SEARCH process memory
        Usage:
        memops package_name libfoo.so
        """
        self.native_handler = nativeHandler(self.device)
        self.native_handler.memops(line)

    def do_memmap(self,line) -> None:
        """
        READ process memory
        Usage:
        Make sure the application is running and then type:
        memmap package_name 
        """
        try:

            pkg = line.split(' ')[0]
            pid = os.popen("adb -s {} shell pidof {}".format(self.device.id,pkg)).read().strip()

            if pid == "":
                print("Can't find  pid. Is the application running ?")
                return
            elif len(pid.split(' ')) > 1:
                option, index = pick(pid.split(' '),"More than one processes found running with that name:",indicator="=>",default_index=0)
                pid = option

            maps = os.popen("""adb -s {} shell 'echo "cat /proc/{}/maps" | su'""".format(self.device.id, pid)).read().strip().split('\n')
            title = "Please choose a memory address range: "
            option, index = pick(maps,title,indicator="=>",default_index=0)
            print("Selected:")
            click.echo(click.style(option,bg='blue', fg='white'))

            range1 = int(option.split(' ')[0].split('-')[0],16)
            range2 = int(option.split(' ')[0].split('-')[1],16)
            sz = range2 - range1
            print('Starting addres: {}, size: {}'.format(hex(range1),range2-range1))

            self.native_handler = nativeHandler(self.device)
            self.native_handler.memraw(pkg + ' ' + pid + ' ' + hex(range1) + ' ' + str(sz))
            
        except Exception as e:
            print(e)
            
    def do_pad(self, line) -> None:
        """
        Manualy edit scratchpad using vi
        """
        scratchpad = self.modManager.getModule('scratchpad')
        with open(os.path.join(self.base_directory, '.draft'), 'w') as draft:
            draft.write(scratchpad.Code)
        subprocess.run('vim ' + os.path.join(self.base_directory, '.draft'), shell=True)
        with open(os.path.join(self.base_directory, '.draft'), 'r') as draft:
            code = draft.read()
        self.edit_scratchpad(code)

    def do_reload(self,line) -> None:
        """
        Reload the medusa modules (in case of a module edit)
        Use the -r filename option to load a saved session or recipe 
        """
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
    
             
        if "-r" in line.split(' ')[0]:
            self.modManager.reset()
            self.write_recipe(line.split(' ')[1])
        print(f"[i] Done....\n[i] Total modules available {self.modManager.get_number_of_modules()}")

    def do_rem(self, mod) -> None:
        """
        Remove one or more staged modules
        rem [module]
        The command will remove stage modules starting with or equal to the argument given
        Example: rem http_communications/ , will remove all the modules starting with "http_communications/"

        """
        try:
            if self.modManager.unstage(mod):
                print("\nRemoved module(s) starting with : {}".format(mod) )
                self.modified = True
            else:
                print("Module(s) is not active.")
            print()  
        except Exception as e:
            print(e)

    def do_reset(self,line) -> None:
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

        run [package name]      : Initiate a Frida session and attach to the selected package
        run -f [package name]   : Initiate a Frida session and spawn the selected package
        run -n [package number] : Initiate a Frida session and spawn the 3rd party package using its index returned by the 'list' command
        """
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

    def do_snippet(self, line) -> None:
        """
        Print code examples from the snippets directory
        Usage:
        snippet [tab] 
        """
        try:
            selected_snippet = line.split(' ')[0]
            self.load_snippet(os.path.join(self.base_directory, 'snippets', selected_snippet + '.js'))
        except Exception as e:
            print(e)

    def do_search(self, pattern) -> None:
        """
        Search for modules related to a given keyword
        Usage:
        search http
        """
        matches = self.modManager.findModule(pattern)
        if not matches:
            print('No modules found containing: {}!'.format(pattern))
        else:
            for match in matches:
                print(match.replace(pattern, GREEN + pattern + RESET))

    def do_shell(self, line) -> None:
        """
        Get a tmp local shell
        """
        shell = os.environ['SHELL']
        subprocess.run('{}'.format(shell), shell=True)

    def do_show(self, what) -> None:
        """
        Show availlable modules
        """
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

    def do_status(self,line) -> None:
        """
        Prints the loaded device id, libraries, native functions of the last loaded package.
        """
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
    
    def do_strace(self, line) -> None:
        """
        Pseudo strace implemented via a frida script
        Usage:
        strace package_name
        """
        
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

    def do_type(self,text) -> None:
        """
        Send keystrokes to the device
        Usage:
        type 'text to send to the device'
        """
        os.popen("adb -s {} shell input text {}".format(self.device.id,text))

    def do_use(self, mod) -> None:
        """
        Stage a module or modules
        Usage:
        use [module]
        The command will stage modules starting with or equal to the argument given
        Example: use http_communications/ , will load all the modules starting with "http_communications/"
        """
        self.modManager.stage(mod)
        self.show_mods()
        self.modified = True
        print()
        
###################################################### do_ defs end ############################################################

###################################################### complete_ defs start ############################################################
    def complete_c2check(self, text, line, begidx, endidx) -> list:
        return self.complete_list(text, line, begidx, endidx)
    
    def complete_dump(self, text, line, begidx, endidx) -> list:
        return self.complete_list(text, line, begidx, endidx)
    
    def complete_get(self, text, line, begidx, endidx) -> list:
        return self.complete_list(text, line, begidx, endidx)

    def complete_enumerate(self, text, line, begidx, endidx) -> list:
        return self.complete_list(text, line, begidx, endidx)

    def complete_import(self, text, line, begidx, endidx) -> list:
        return self.complete_snippet(text, line, begidx, endidx)

    def complete_list(self, text, line, begidx, endidx) -> list:
        self.refreshPackages()
        return [package for package in self.packages if package.startswith(text)]

    def complete_load(self, text, line, begidx, endidx) -> list:
        return self.complete_list(text, line, begidx, endidx)

    def complete_libs(self, text, line, begidx, endidx) -> list:
        return self.complete_list(text, line, begidx, endidx)

    def complete_memops(self, text, line, begidx, endidx) -> list:
        return self.complete_list(text, line, begidx, endidx)
    
    def complete_memmap(self, text, line, begidx, endidx) -> list:
        return self.complete_list(text, line, begidx, endidx)

    def complete_rem(self, text, line, begidx, endidx) -> list:
        return [mod.Name for mod in self.modManager.staged if mod.Name.startswith(text)]

    def complete_run(self, text, line, begidx, endidx) -> list:
        return self.complete_list(text, line, begidx, endidx)

    def complete_show(self, text, line, begidx, endidx):
        return [f for f in self.show_commands if f.startswith(text)]

    def complete_snippet(self, text, line, begidx, endidx) -> list:
        return [f for f in self.snippets if f.startswith(text)]

    def complete_strace(self, text, line, begidx, endidx) -> list:
        self.refreshPackages()
        return [package for package in self.packages if package.startswith(text)]

    def complete_use(self, text, line, begidx, endidx) -> list:
        return [mod.Name for mod in self.modManager.available if mod.Name.startswith(text)]
    
    def complete_info(self, text, line, begidx, endidx) -> list:
        return [mod.Name for mod in self.modManager.available if mod.Name.startswith(text)]

###################################################### complete_ defs end ############################################################

###################################################### implementations start ############################################################

    def check_using_vt(self,hosts,vtkey):
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

    def edit_scratchpad(self, code, mode='w') -> None:
        scratchpad = self.modManager.getModule('scratchpad')
        if mode == 'a':
            scratchpad.Code += code
        elif mode == 'w':
            scratchpad.Code = code
        else:
            raise Exception('Attempted to open scratchpad in invalid mode {}'.format(mode))
        scratchpad.save()
        #if code != '':
        self.modManager.stage('scratchpad')
        self.modified = True

    def fill_app_info(self,data) -> None:
        self.app_info = json.loads(data)

    def hookall(self, line) -> None:
        aclass = line.split(' ')[0]
        if  aclass == '':
            print('[i] Usage: hookall [class name]')
        else:
            className = aclass
            codejs = "traceClass('"+className+"');\n"
            self.edit_scratchpad(codejs, 'a')
            print("\nHooks have been added to the" + GREEN + " scratchpad" + RESET + " run 'compile' to include it in your final script")

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

    def hook_native(self) -> None:
        library = Open('Library name (e.g.: libnative.so):').ask()
        type_ = Alternative('Imported or exported function?', 'i', 'e').ask()
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
        self.edit_scratchpad(codejs, 'a')
        print("\nHooks have been added to the" + GREEN + " scratchpad" + RESET + " run 'compile' to include it in your final script")

    def init_packages(self) -> None:
        self.refreshPackages()
        print('\nInstalled packages:\n')
        for i in range(len(self.packages)):
            print('[{}] {}'.format(i, self.packages[i]))

    def is_valid_url(self,url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False

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
        with open(os.path.join(self.base_directory, 'libraries/native.js'), 'w') as file:
            file.write(script)

    def print_app_info(self) -> None:
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

    def run_frida(self, force, detached, package_name, device)->None:
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
    'c'  (c)lear the sreen 
    'e'  (e)xit the session
    'r'  (r)eload the script in case it changed
    'rs' (r)e(s)et the scratchpad
    'i'  print (i)nformation about the application
    't'  (t)race a method and print the stack trace (e.g. t com.foo.bar.func)
    '?'  print this help message\n"""+RESET)
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
        
    def print_list(self, listName, message) -> None:
        print(GREEN+message+RESET)
        for item in listName:
            print("""       {}""".format(item))

    def reload_script(self,session) -> None:
        self.script.unload()
        with open(os.path.join(self.base_directory, "agent.js")) as f:
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

    def show_mods(self) -> None:
        print("\nCurrent Mods:")
        for i in range(len(self.modManager.staged)):
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

    def show_snippets(self) -> None:
        print("[i] Available snippets:")
        print('------------------------\n')
        try:
            for snippet in self.snippets:
                print('> ' + snippet)
        except Exception as e:
            print(e)

    def scan_for_secrets(self,string_list):
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

    def write_recipe(self,filename) -> None:
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

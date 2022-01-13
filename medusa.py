#!/usr/bin/env python3
import subprocess
import platform
import cmd
import os, sys
import readline
import logging
import rlcompleter
import time
import frida
import click
from libraries.dumper import dump_pkg
from google_trans_new import google_translator  
from libraries.natives import *
from Questions import *

RED     = "\033[1;31m"  
BLUE    = "\033[1;34m"
CYAN    = "\033[1;36m"
WHITE   = "\033[1;37m"
YELLOW  = "\033[1;33m"
GREEN   = "\033[0;32m"
RESET   = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"

class Parser(cmd.Cmd):
    snippets = []
    all_mods = []
    packages = []
    system_libraries = []
    app_libraries = []
    show_commands = ['mods', 'categories', 'all', 'snippets']
    module_list = []
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

    def preloop(self):
        for root, directories, filenames in os.walk('modules/'):
            for filename in sorted(filenames):
                if filename.endswith('.med'):
                    filepath = os.path.join(root,filename)
                    self.all_mods.append(filepath)
    
        for root, directories, filenames in os.walk('snippets/'):
            for filename in sorted(filenames):
                if filename.endswith('.js'):
                    filepath = os.path.join(root,filename)
                    self.snippets.append(filepath.split('/')[1].split('.')[0])
        try:
            if len(sys.argv) > 1:
                data = ''
                if '-r' in sys.argv[1]:
                    print('[+] Loading a recipe....')
                    with open(sys.argv[2],'r') as file:
                        for line in file:
                            if "modules/" in line:
                                module = line[:-1]
                                print('- Loading {}'.format(module))
                                self.module_list.append(module)
                            else:
                                data += line
                    p.modified = True
                if data != '':
                    print("[+] Writing to scratchpad...")
                    with open('modules/scratchpad.med','w') as file:
                        file.write(data)
                        
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

        try:
            print('Available devices:\n')
            devices = frida.enumerate_devices()
            i = 0

            for dv in devices:
                print('{}) {}'.format(i,dv))
                i += 1
            j = input('\nEnter the index of the device to use:')
            device = devices[int(j)] 
        except:
            device = frida.get_remote_device()



        self.device = device
        self.init_packages()


    def do_snippet(self,line):
        try:
            
            selected_snippet = line.split(' ')[0]
            self.load_snippet('snippets/'+selected_snippet+'.js')
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
            with open('snippets/'+line.split(' ')[0]+'.js','r') as file:
                data = file.read()
            with open('modules/scratchpad.med','a') as file:
                file.write(data) 

            print("\nSnippet has been added to the"+GREEN+ " modules/schratchpad.me"+ RESET+" run 'compile' to include it in your final script or 'pad' to edit it")
        except Exception as e:
            print(e)
    
    def complete_import(self, text, line, begidx, endidx):
        if not text:
            completions = self.snippets[:]
        else:
            completions = [ f
                            for f in self.snippets
                            if f.startswith(text)
                            ]
        return completions



    
    def load_snippet(self,snippet):
        try:
            with open(snippet) as file:
                data = file.read()
            click.secho(data,fg = 'green')
        except Exception as e:
            print(e)


    def complete_snippet(self, text, line, begidx, endidx):
        if not text:
            completions = self.snippets[:]
        else:
            completions = [ f
                            for f in self.snippets
                            if f.startswith(text)
                            ]
        return completions


    def do_memops(self,line):

        self.native_handler = nativeHandler(self.device)
        self.native_handler.memops(line)


#------------------------cut here
    def do_load(self,line):
        self.native_handler = nativeHandler(self.device)
        self.native_handler.loadLibrary(line.split()[0],line.split()[1])
        
#----------------------------

    def complete_load(self, text, line, begidx, endidx):
        self.packages = []

        for line1 in os.popen('adb -s {} shell pm list packages -3'.format(self.device.id)):
            self.packages.append(line1.split(':')[1].strip('\n'))
        #----------------- 
        if not text:
            completions = self.packages[:]
        else:
            completions = [ f
                            for f in self.packages
                            if f.startswith(text)
                            ]
        return completions


    def complete_memops(self, text, line, begidx, endidx):
        self.packages = []

        for line1 in os.popen('adb -s {} shell pm list packages -3'.format(self.device.id)):
            self.packages.append(line1.split(':')[1].strip('\n'))
        #----------------- 
        if not text:
            completions = self.packages[:]
        else:
            completions = [ f
                            for f in self.packages
                            if f.startswith(text)
                            ]
        return completions
  


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

        with open('modules/scratchpad.med','a') as script:
            script.write(codejs)
        module_x = 'modules/scratchpad.med'
        if module_x not in self.module_list:
            self.module_list.append('modules/scratchpad.med')
        self.modified = True
        print("\nHooks have been added to the" + GREEN + " modules/schratchpad.me" + RESET + " run 'compile' to include it in your final script")
        
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

        self.packages = []

        for line1 in os.popen('adb -s {} shell pm list packages -3'.format(self.device.id)):
            self.packages.append(line1.split(':')[1].strip('\n'))
        #-----------------
        if not text:
            completions = self.packages[:]
        else:
            completions = [ f
                            for f in self.packages
                            if f.startswith(text)
                            ]
        return completions

    def prepare_native(self,operation):

        with open('libraries/native.med','r') as file:
            precode = file.read()
        script = precode + 'Java.perform(function() {\n'+operation+' \n});'

        with open('libraries/native.js','w') as file:
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
                    modules = self.native_handler.getModules(package,False)
                else:
                    print("[i] Usage: libs [option] package [--attach]")
            else:
                modules = self.native_handler.getModules(package,True)
               
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

        self.packages = []

        for line1 in os.popen('adb -s {} shell pm list packages -3'.format(self.device.id)):
            self.packages.append(line1.split(':')[1].strip('\n'))
        #-----------------
        if not text:
            completions = self.packages[:]
        else:
            completions = [ f
                            for f in self.packages
                            if f.startswith(text)
                            ]
        return completions

#-------------------------EOF NATIVE OPERATIONS------------------


    def scratchreset(self):
        if Polar('Do you want to reset the scratchpad?').ask():
            with open('modules/scratchpad.med', 'w') as scratchpad:
                scratchpad.write("#Description: 'Use this module to add your hooks'\n#Help: 'N/A'\n#Code:")
                scratchpad.close()

    def do_export(self,line):
        scratchDat = ''
        try:
            filename = line.split(' ')[0];

            with open(filename,'w') as file:
                for module in self.module_list:
                    if 'scratchpad' in module:
                        with open('modules/scratchpad.med','r') as file1:
                            scratchDat = file1.read()
                    file.write('%s\n' % module)
                file.write(scratchDat)
            print('Recipe exported to dir: {} as {}'.format(os.getcwd(),filename))
        except Exception as e:
            print(e) 
            print("[i] Usage: export filename")


    def hookall(self,line):

        aclass = line.split(' ')[0]

        if  aclass == '':
            print('[i] Usage: hookall [class name]')
        else:
            className = aclass
            codejs = "traceClass('"+className+"');\n"
            with open('modules/scratchpad.med','a') as script:
                script.write(codejs)

        module_x = 'modules/scratchpad.med'
        if module_x not in self.module_list:
            self.module_list.append('modules/scratchpad.med')
        self.modified = True
        print("\nHooks have been added to the"+GREEN+ " modules/schratchpad.me"+ RESET+" run 'compile' to include it in your final script")


    

    def do_hook(self,line):

        option = line.split(' ')[0]

        codejs = '\n'

        if '-f' in option:
            className = input("Enter the full name of the function(s) class: ")

            codejs = """var hook = Java.use('"""+className+"""');"""
            functionName = input("Enter a function name (CTRL+C to Exit): ")

            while (True):
                
                try:

                    codejs += """
                    var overloadCount = hook['"""+functionName+"""'].overloads.length;
                    colorLog("Tracing " +'"""+ functionName+"""' + " [" + overloadCount + " overload(s)]",{ c: Color.Green });
                        
                        for (var i = 0; i < overloadCount; i++) {
                            hook['"""+functionName+"""'].overloads[i].implementation = function() {
                            colorLog("*** entered " +'"""+ functionName+ """',{ c: Color.Green });

                    Java.perform(function() {
                        var bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
                            console.log("Backtrace:" + bt);
                    });   

                    if (arguments.length) console.log();
                    for (var j = 0; j < arguments.length; j++) {
                        console.log("arg[" + j + "]: " + arguments[j]);
                    }
                    var retval = this['"""+functionName+"""'].apply(this, arguments); 
                    console.log("retval: " + retval);
                    colorLog("*** exiting " + '"""+functionName+"""',{ c: Color.Green });
                    return retval;
                    }
                    }
                    """
                    print('[+] Function: {} hook added !'.format(functionName))
                    functionName = input("Enter a function name (CTRL+C to Exit): ")

                except KeyboardInterrupt:
                    with open('modules/scratchpad.med','a') as script:
                        script.write(codejs)


                    module_x = 'modules/scratchpad.med'
                    if module_x not in self.module_list:
                        self.module_list.append('modules/scratchpad.med')

                    self.modified = True
                    print("\nHooks have been added to the"+GREEN+ " modules/schratchpad.me"+ RESET+" run 'compile' to include it in your final script")
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

    def do_search(self, line):
        found = False
        try:
            what = line.split(' ')[0]
            for module in self.all_mods:
                if what.lower() in module.lower():
                    print(module[:str(module.lower()).find(what.lower())]+GREEN+what+RESET+module[str(module.lower()).find(what.lower())+len(what.lower()):])
                    found = True
            if not found:
                print('No modules found containing: {} !'.format(what))
                
        except Exception as e:
            print(e)

#------------------

    def do_swap(self,line):
        try:      
            old_index = int(line.split(' ')[0])
            new_index = int(line.split(' ')[1])
            self.module_list[old_index], self.module_list[new_index] = self.module_list[new_index], self.module_list[old_index]
            print('New arrangement:')
            self.show_mods()
        
            self.modified = True
        except Exception as e:
            print(e)
             
    
    def do_clear(self,line):
        subprocess.run('clear', shell=True)
    
    def do_c(self,line):
        subprocess.run(line, shell=True)

    def do_cc(self,line):
        subprocess.run('adb  -s {} shell {}'.format(self.device.id,line), shell=True)
    
    def init_packages(self):
        j=0
        for line1 in os.popen('adb -s {} shell pm list packages -3'.format(self.device.id)):
            self.packages.append(line1.split(':')[1].strip('\n'))
        print('\nInstalled packages:\n')
        for pkg in self.packages:
            print('[{}] {}'.format(j,pkg))
            j +=1


    def do_dump(self,line):
        
        pkg = line.split(' ')[0].strip()
        if pkg == '':
            print('[i] Usage: dump package_name')
        else:
            dump_pkg(pkg)


    def complete_dump(self, text, line, begidx, endidx):

        #refresh installed packages
        self.packages = []

        for line1 in os.popen('adb -s {} shell pm list packages -3'.format(self.device.id)):
            self.packages.append(line1.split(':')[1].strip('\n'))
        #-----------------
        if not text:
            completions = self.packages[:]
        else:
            completions = [ f
                            for f in self.packages
                            if f.startswith(text)
                            ]
        return completions

    def do_reset(self,line):
        self.module_list = []
        self.modified = False

    def complete_show(self, text, line, begidx, endidx):
        if not text:
            completions = self.show_commands[:]
        else:
            completions = [ f
                            for f in self.show_commands
                            if f.startswith(text)
                            ]
        return completions

    def complete_run(self, text, line, begidx, endidx):  
        
        #refresh installed packages
        self.packages = []

        for line1 in os.popen('adb -s {} shell pm list packages -3'.format(self.device.id)):
            self.packages.append(line1.split(':')[1].strip('\n'))
        #----------------- 
        if not text:
            completions = self.packages[:]
        else:
            completions = [ f
                            for f in self.packages
                            if f.startswith(text)
                            ]
        return completions

    def complete_use(self, text, line, begidx, endidx):
        if not text:
            completions = self.all_mods[:]
        else:
            completions = [ f
                            for f in self.all_mods
                            if f.startswith(text)
                            ]
        return completions


    def do_EOF(self, line):
        return True

    def do_rem(self,mod):
        try:
            self.module_list.remove(mod)
            print("\nRemoved: {}".format(mod) )
            self.modified = True
            print()  
        except Exception as e:
            print(e)


    def complete_rem(self, text, line, begidx, endidx):
        if not text:
            completions = self.module_list[:]
        else:
            completions = [ f
                            for f in self.module_list
                            if f.startswith(text)
                            ]
        return completions

    def do_use(self,mod):
        if mod not in self.module_list:
            self.module_list.append(mod)
        print("\nCurrent Mods:")
        self.show_mods()
        # for module in self.module_list:
        #     print(module)
        self.modified = True
        print()

    def do_show(self,what):
        try:
            if what == 'categories':
                self.show_categories()
            elif what == 'all':
                self.show_all()
            elif what == 'mods':
                self.show_mods()
            elif what == 'snippets':
                self.show_snippets()
            elif what.split(' ')[0] == 'modules':
                self.show_modules(what.split(' ')[1])
            else:
                print('Invalid command!')
        except Exception as e:
            print(e)
            print('Invalid command - please check usage !')
            
    def show_mods(self):
        print("\nCurrent Mods:")
        j = 0
        for mod in self.module_list:
            print('{}) {}'.format(j,mod))
            j +=1
        print()

    def show_categories(self):
        folders = list(os.walk('modules/'))
        print('\nAvailable module categories:\n')
        for f in folders[1:]:
            module=f[0].split('/')
            print(module[1])
        print()


    def show_all(self):
        for root, directories, filenames in os.walk('modules/'):
            for filename in sorted(filenames):
                if filename.endswith('.med'):
                    filepath = os.path.join(root,filename)
                    print(filepath)

    
    def do_exit(self,line):
        with open('agent.js') as agent:
            agent.seek(0)
            if agent.read(1):
                if Polar('Do you want to reset the agent script?').ask():
                    open('agent.js', 'w').close()
    
        self.scratchreset()

        print('Bye !!')
        exit()
    
    def do_shell(self,line):
        shell = os.environ['SHELL']
        subprocess.run('{}'.format(shell), shell=True)

    def show_modules(self,category):
        try:
            presentation = {}
            
            for root, directories, filenames in os.walk('modules/{}'.format(category)):
                for filename in filenames:
                    if filename.endswith('.med'):
                        filepath = os.path.join(root,filename)
                        presentation.update({filepath: self.display_tag(filepath,'Description')})
            
            if len(presentation) == 0:
                print('No such category or this category does not contain modules')
            else:
                print('\nModules in this category:\n')
                for key,value in presentation.items():
                    print('Name: '+GREEN+key+' '+BLUE+value+RESET, end = '')
        except Exception as e:
            print(e)
            print('Usage: show modules [category]')

    def display_tag(self,file, what_tag):
        tag_content = ''
        with open(file) as fl:
            content = fl.readlines();

        for i in range(len(content)):
            if content[i].startswith('#{}'.format(what_tag)):
                tag_content += content[i]
                i +=1
                while not content[i].startswith('#'):
                    tag_content+=content[i]
                    i+=1
            
        return tag_content

    def do_compile(self,line):
        self.parse_module(self.module_list)
        self.modified = False
        return

    def parse_module(self,mods):
        try:
            hooks = []
            jni_prolog_added=False
            with open('libraries/utils.js','r') as file:
                header = file.read();
            hooks.append(header);
            hooks.append("\n\nJava.perform(function() {")
            for file in mods:
                codeline_found = False
                if 'JNICalls' in file and not jni_prolog_added:
                    hooks.append("""
    var jnienv_addr = 0x0
                    
    try{
        
        Java.perform(function(){jnienv_addr = Java.vm.getEnv().handle.readPointer();});
        console.log("[+] Hooked successfully, JNIEnv base adress :" + jnienv_addr);
    }
    catch(err){
        console.log('Error:'+err);
    }
        
                    """)
                    jni_prolog_added = True

                with open(file) as mod:
                    content = mod.readlines()
                    hooks.append(' try { ')

                for i in range(len(content)):
                    if content[i].startswith('#Code:'):
                        codeline_found = True
                        continue
                    if codeline_found:
                        hooks.append('\t\t'+content[i].strip('\n'))
            

                hooks.append("""    } catch (err) {
                            console.log('Error loading module %s, Error:'+err);
                    }"""%file)
                
            hooks.append('});')

            with open('agent.js','w') as agent:
                for line in hooks:
                    agent.write('%s\n' % line)
            print("\nScript is compiled\n")
            self.modified = False

        except Exception as e:
            print(e)

    def do_pad(self,line):
        subprocess.run('vi modules/scratchpad.med', shell=True)

    def do_run(self,line):
   
        try:
            if self.modified:
                if Polar('Module list has been modified, do you want to recompile?').ask():
                    self.parse_module(self.module_list)
 
            flags = line.split(' ')
            length = len(flags)
            if length == 1:
                self.run_frida(False,False,line,self.device)
            elif length == 2:
                print(flags[1])
                if '-f' in flags[0]:
                    self.run_frida(True,False,flags[1],self.device)

                else:
                    print('Invalid flag given!')

            else:
                print('Invalid flags given')
        except Exception as e:
            print(e)





    def my_message_handler(self,message,payload):

        if message["type"] == "send":
            data = message["payload"].split(":")[0].strip()
            if "trscrpt|" in data:
                result = self.translator.translate(data[data.index("trscrpt|")+len("trscrpt|"):])
                self.script.post({"my_data": result}) 
            else:
                print(data)

    def on_detached(self,reason):
        print("Session is detached due to:", reason)
        self.detached = True
        
    
    def run_frida(self,force, detached, package_name, device):
        creation_time = modified_time = None
        self.detached = False
        session = self.frida_session_handler(device,force,package_name)
        try:
            creation_time = self.modification_time("agent.js")
            with open("agent.js") as f:
                self.script = session.create_script(f.read())
            
            session.on('detached',self.on_detached)
            self.script.on("message",self.my_message_handler)  # register the message handler
            self.script.load()  
            if force:
                device.resume(self.pid)
            s = input(WHITE+'in-session-commands |' +GREEN+'e:'+ WHITE+ 'exit |'+GREEN+ 'r:'+ WHITE+'reload | ' + GREEN + '?:' + WHITE + 'help'+WHITE+'|:')
            
            while ('e' not in s) and (not self.detached):
                s = input(WHITE+'[in-session] |' +GREEN+'e:'+ WHITE+ 'exit |'+GREEN+ 'r:'+ WHITE+'reload | ' + GREEN + '?:' + WHITE + 'help'+WHITE+'|:')
                if 'r' in s:
                    #handle changes during runtime
                 
                    modified_time = self.modification_time("agent.js")
                
                    if modified_time != creation_time:
                        print(RED+"Script changed, reloading ...."+RESET)
                        creation_time = modified_time
                        self.script.unload()
                        with open("agent.js") as f:
                            self.script = session.create_script(f.read())
                        session.on('detached',self.on_detached)
                        self.script.on("message",self.my_message_handler)  # register the message handler
                        self.script.load()  
                    else:
                         print(GREEN+"Script unchanged, nothing to reload ...."+RESET)
                if '?' in s:
                    print(WHITE+'|' +GREEN+'e:'+ WHITE+ 'exit |'+GREEN+ 'r:'+ WHITE+'reload | ' + GREEN + '?:' + WHITE + 'help'+WHITE+'|')                
            
            if self.script:
                self.script.unload()

        except Exception as e:
            print(e)
        print(RESET)
        return





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
        self.packages = []

        for line1 in os.popen('adb -s {} shell pm list packages -3'.format(self.device.id)):
            self.packages.append(line1.split(':')[1].strip('\n'))
        #----------------- 
        if not text:
            completions = self.packages[:]
        else:
            completions = [ f
                            for f in self.packages
                            if f.startswith(text)
                            ]
        return completions


    def do_type(self,text):
        os.popen("adb -s {} shell input text {}".format(self.device.id,text))

    def complete_help(self, text, line, begidx, endidx):
        if not text:
            completions = self.all_mods[:]
        else:
            completions = [ f
                            for f in self.all_mods
                            if f.startswith(text)
                            ]
        return completions


    def do_help(self,line):
        if line != '':
            print('\n'+BLUE+self.display_tag(line,'Help')+RESET)
        else:
            print("""
                MODULE OPERATIONS:

                        - search [keyword]          : Search for a module containing a specific keyword 
                        - help [module name]        : Display help for a module
                        - snippet [tab]             : Show / display available frida script snippets
                        - use [module name]         : Select a module to add to the final script
                        - show mods                 : Show selected modules
                        - show categories           : Display the available module categories (start here)
                        - show modules [category]   : Display the available modules for the selected category
                        - show snippets             : Display available snippets of frida scripts
                        - show all                  : Show all available modules
                        - import [snippet]          : Import a snippet to the scratchpad
                        - rem [module name]         : Remove a module from the list that will be loaded
                        - swap old_index new_index  : Change the order of modules in the compiled script
                        - reset                     : Remove all modules from the list that will be loaded
                ===================================================================================================

                SCRIPT OPERATIONS:

                        - export  'filename'        : Save session modules and scripts to 'filename'
                        - import [tab]              : Import frida script from available snippet
                        - pad                       : Edit the scratchpad using vi
                        - compile                   : Compile the modules to a frida script
                        - hook [option]
                    
                            -a [class name]         : Set hooks for all the functions of the given class
                            -f                      : Initiate a dialog for hooking a Java function
                            -n                      : Initiate a dialog for hooking a native function
                            -r                      : Reset the hooks setted so far
                ===================================================================================================

                NATIVE OPERATIONS:

                        - memops package_name lib.so    : READ/WRITE/SEARCH process memory

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
                        - dump       [package_name] : Dump the requested package name (works for most unpackers)
                ====================================================================================================
                    
                HELPERS:

                        - type 'text'               : Send a text to the device
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

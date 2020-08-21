import subprocess
import platform
import cmd
import os, sys
import readline
import logging
import rlcompleter
import time
import frida
from libraries.dumper import dump_pkg
from googletrans import Translator

if 'libedit' in readline.__doc__:
    readline.parse_and_bind("bind ^I rl_complete")
else:
    readline.parse_and_bind("tab: complete")

RED   = "\033[1;31m"  
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
WHITE = "\033[1;37m"
YELLOW= "\033[1;33m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"

class parser(cmd.Cmd):

    all_mods = []
    packages = []
    show_commands=['mods','categories','all']
    module_list=[]
    prompt = BLUE+'medusa>'+RESET
    device = None
    modified = False
    device_index =0
    translator = Translator()
    script = None
    detached = True
    pid = None


    def __init__(self):
        super(parser,self).__init__()
        for root, directories, filenames in os.walk('modules/'):
            for filename in sorted(filenames):
                if filename.endswith('.med'):
                    filepath = os.path.join(root,filename)
                    self.all_mods.append(filepath)
        print('\nTotal modules: ' + str(len(self.all_mods)))


    def do_export(self,line):
        try:

            with open('recipe.txt','w') as file:
                for module in self.module_list:
                    file.write('%s\n' % module)
            print('Recipe exported to dir: {} as recipe.txt'.format(os.getcwd()))
        except Exception as e:
            print(e) 

#------------------------------ON THE FLY HOOK--------------------------------------------------
    # classes = []
    # def do_classdump(self,line,package):
    #     js = """Java.perform(function(){Java.enumerateLoadedClasses({"onMatch":function(c){send(c);}});});"""
    #     try:
    #         pid = self.device.spawn(package)
    #         print("[i] Starting process {} [pid:{}] to dump classes ".format(package,pid))
    #         session = self.device.attach(pid)
    #         self.device.resume(pid)
    #         script = session.create_script(js)
    #         script.on('message', on_classdump_result)
    #         script.load()
    #     except Exception as e:
    #         print(e)

    #     with open('classes.txt','w') as file:
    #         for clazz in self.classes:
    #             file.write('%s\n' % clazz)
    #         print('Recipe exported to dir: {} as classes.txt'.format(os.getcwd()))

    # def on_classdump_result(message,data):
    #     try:
    #         if message["type"] == "send":
    #             self.classes.append( message["payload"].split(":")[0].strip())
    #     except Exception as e:
    #         print('exception: ' + e) 
    



    def do_hook(self,line):
        className = input("Enter the full name of the function's class: ")
        functionName = input("Enter the function name: ")
        codejs = """
        var hook = Java.use('"""+className+"""');
                    var overloadCount = hook['"""+functionName+"""'].overloads.length;
                    console.log("Tracing " +'"""+ functionName+"""' + " [" + overloadCount + " overload(s)]");
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
        var retval = this['"""+functionName+"""'].apply(this, arguments); // rare crash (Frida bug?)
        console.log("nretval: " + retval);
        colorLog("*** exiting " + '"""+functionName+"""',{ c: Color.Green });
        return retval;
    }
}
"""
        with open('modules/scratchpad.med','a') as script:
            script.write(codejs)
            
        print("Hook has been added to the"+GREEN+ " modules/schratchpad.me"+ RESET+" ,you may inlude it in the final script")


#---------------------------------------------------------------------------------------------------------------

    def do_search(self, line):
        found = False
        try:
            what = line.split(' ')[0]
            for module in self.all_mods:
                if what in module:
                    print(module[:str(module).find(what)]+GREEN+what+RESET+module[str(module).find(what)+len(what):])
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


    
    def do_trigger(self,line):
        with open('triger.js','r') as file:
            data = file.read()
            a = data.replace('class_name',line.split(' ')[0])
        params = ''
        j = 'a'
        for i in range(int(line.split(' ')[1])):
            params +=  j 
            j = chr(ord(j)+1)
            params += ','
 
            b = a.replace('params',params[:-1])

        print(b)
             
    
    def do_clear(self,line):
        subprocess.run('clear', shell=True)
    
    def init_packages(self):
        j=0
        for line1 in os.popen('adb -s {} shell pm list packages -3'.format(self.device.id)):
            self.packages.append(line1.split(':')[1].strip('\n'))
        print('\nInstalled packages:\n')
        for pkg in self.packages:
            print('[{}] {}'.format(j,pkg))
            j +=1


    def do_dump(self,line):
      
        dump_pkg(line.split(' ')[0])

    def do_translate(self,line):
        t = translation(line.split(' ')[0])
        # translate_ui(line.split(' ')[0])

    def complete_translate(self, text, line, begidx, endidx):
        if not text:
            completions = self.packages[:]
        else:
            completions = [ f
                            for f in self.packages
                            if f.startswith(text)
                            ]
        return completions

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
            completions = self.all_mods[:]
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
        self.module_list.remove(mod)
        print("\nRemoved: {}".format(mod) )
        # for module in self.module_list:
        #      print(mod)
        self.modified = True
        print()  

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
        print('\nAvaillable module categories:\n')
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
            if not agent.read(1):
                pass
            else:
                agent_del = input('Do you want to reset the agent script ? (yes/no) ')
                if 'yes' in agent_del:
                    with open('agent.js','w'):
                        pass

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
        hooks = []
        with open('libraries/utils.js','r') as file:
            header = file.read();
        hooks.append(header);
        hooks.append("\n\nJava.perform(function() {")
        for file in mods:
            codeline_found = False

            with open(file) as mod:
                content = mod.readlines()
                hooks.append(' try { ')

            for i in range(len(content)):
                if content[i].startswith('#Code:'):
                    codeline_found = True
                    i += 1
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
    
    def do_run(self,line):
   
        try:
        
            if self.modified == True:
                comp = input('Module list has been modified, do you want to recompile ? (yes/no)')
                if 'yes' in comp:
                    self.parse_module(self.module_list)
                else:
                    pass
 
            flags = line.split(' ');
            length = len(flags)
            if length == 1:
                self.run_frida(False,False,line,self.device)
            elif length == 2:
                print(flags[1])
                if '-f' in flags[0]:
                    self.run_frida(True,False,flags[1],self.device)
                # elif '-d' in flags[0]:
                #     self.run_frida(False,True,flags[1],self.device)
                else:
                    print('Invalid flag given!')
            # elif length == 3:
            #     print(' {} {} {}'.format(flags[0],flags[1],flags[2]))
            #     if '-f' in flags[0] and '-d' in flags[1]:
            #         self.run_frida(True,True,flags[2],self.device)
            else:
                print('Invalid flags given')
        except Exception as e:
            print(e)





    def my_message_handler(self,message,payload):

        if message["type"] == "send":
            data = message["payload"].split(":")[0].strip()
            result = self.translator.translate(data)
            self.script.post({"my_data": result.text}) 

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
            s = input(WHITE+'in-session-commands |' +GREEN+'e:'+ WHITE+ 'exit |'+GREEN+ 'r:'+ WHITE+'reload | ' + GREEN + '?:' + WHITE + 'help'+WHITE+'|>')
            
            while ('e' not in s) and (not self.detached):
                s = input(WHITE+'in-session (? for help):>')
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
            frida_session = con_device.attach(pkg)
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

    # def run_frida(self,force, detached, package_name, device):
    #     if detached == True:
    #         path = os.getcwd()
    #         if force == True:
    #             os.system("""osascript -e 'tell application "Terminal" to do script "frida -D {} -l {}/agent.js -f {} --no-pause"' """.format(device.id,path,package_name))
    #         else:
    #             os.system("""osascript -e 'tell application "Terminal" to do script "frida -D {} -l {}/agent.js {}"' """.format(device.id,path,package_name))
    #     else:
    #         if force == True:
    #             subprocess.run('frida -D {} -l agent.js -f {} --no-pause'.format(device.id,package_name), shell=True)
    #         else:
    #             subprocess.run('frida -D {} -l agent.js {}'.format(device.id,package_name), shell=True)



    def do_list(self,line):
        self.packages = []
        j=0
        if 'packages' in line:
            for line1 in os.popen('adb -s {} shell pm list packages -3'.format(self.device.id)):
                self.packages.append(line1.split(':')[1].strip('\n'))
            print('Installed packages:\n')
            for pkg in self.packages:
                print('[{}] {}'.format(j,pkg))
                j +=1
        else:
            print('Invalid flag !')

        


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
                Module operations:
                        - search [keyword]          : Search for a module containing a specific keyword 
                        - help [module name]        : Display help for a module
                        - use [module name]         : Select a module to add to the final script
                        - show mods                 : Show selected modules
                        - show categories           : Display the availlable module categories (start here)
                        - show modules [category]   : Display the availlable modules for the selected category
                        - show all                  : Show all availlable modules
                        - rem [module name]         : Remove a module from the list that will be loaded
                        - swap old_index new_index  : Change the order of modules in the compiled script
                        - reset                     : Remove all modules from the list that will be loaded

                    Script operations:
                        - export                    : Save the current module list to 'recipe.txt'
                        - compile                   : Compile the modules to a frida script
                        - hook                      : Initiates a dialog for hooking a function

                    Frida Session:
                        - run        [package name] : Initiate a Frida session and attache to the sellected package
                        - run -f     [package name] : Initiate a Frida session and spawn the sellected package
                        - dump  package_name        : dump the requested package name
                    
                    Helpers:
                        - type 'text'               : send a text to the device
                        - list packages             : List 3rd party packages in the mobile device 
                        - shell                     : Open an interactive shell
                        - clear                     : Clear the screen

                        Tip: Use the /modules/scratchpad.med to insert your own hooks and include them to the agent.js 
                        using the 'compile script' command""")
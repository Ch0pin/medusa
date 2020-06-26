import subprocess
import cmd
import os, sys
import readline
import rlcompleter

if 'libedit' in readline.__doc__:
    readline.parse_and_bind("bind ^I rl_complete")
else:
    readline.parse_and_bind("tab: complete")

RED   = "\033[1;31m"  
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
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
    device = ''
    modified = False

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
        for line1 in os.popen('adb -s {} shell pm list packages -3'.format(self.device)):
            self.packages.append(line1.split(':')[1].strip('\n'))
        print('Installed packages:\n')
        for pkg in self.packages:
            print('[{}] {}'.format(j,pkg))
            j +=1

    def __init__(self):
        super(parser,self).__init__()
        for root, directories, filenames in os.walk('modules/'):
            for filename in sorted(filenames):
                if filename.endswith('.med'):
                    filepath = os.path.join(root,filename)
                    self.all_mods.append(filepath)
        print('Total modules: ' + str(len(self.all_mods)))
        



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
        print("\nCurrent Mods:")
        for module in self.module_list:
            print(mod.replace('_',' '))
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
        for module in self.module_list:
            print(module.replace('_',' '))
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
        for mod in self.module_list:
            print(mod.replace('_',' '))
        print()

    def show_categories(self):
        folders = list(os.walk('modules/'))
        print('\nAvaillable module categories:\n')
        for f in folders[1:]:
            module=f[0].split('/')
            print(module[1].replace('_',' '))
        print()


    def show_all(self):
        for root, directories, filenames in os.walk('modules/'):
            for filename in sorted(filenames):
                if filename.endswith('.med'):
                    filepath = os.path.join(root,filename)
                    print(BLUE+filepath.replace('_',' ')+RESET)

    
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
        with open(file) as fl: 
            for line in fl:
                if line.startswith('#{}'.format(what_tag)):
                    return line

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
            with open(file) as mod:
                hooks.append(' try { ')
                for line in mod:
                    if not line.startswith('#'):
                        hooks.append('\t\t'+line.strip('\n'))

                hooks.append("""    } catch (err) {
                    console.log('Error loading module %s');
            }"""%file)
        
        hooks.append('});')

        with open('agent.js','w') as agent:
            for line in hooks:
                agent.write('%s\n' % line)
        print("\nScript is compiled\n")
        self.modified = False
    
    def do_run(self,line):
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
            elif '-d' in flags[0]:
                self.run_frida(False,True,flags[1],self.device)
            else:
                print('Invalid flag given!')
        elif length == 3:
            print(' {} {} {}'.format(flags[0],flags[1],flags[2]))
            if '-f' in flags[0] and '-d' in flags[1]:
                self.run_frida(True,True,flags[2],self.device)



    def run_frida(self,force, detached, package_name, device):
        if detached == True:
            path = os.getcwd()
            if force == True:
                os.system("""osascript -e 'tell application "Terminal" to do script "frida -D {} -l {}/agent.js -f {} --no-pause"' """.format(device,path,package_name))
            else:
                os.system("""osascript -e 'tell application "Terminal" to do script "frida -D {} -l {}/agent.js {}"' """.format(device,path,package_name))
        else:
            if force == True:
                subprocess.run('frida -D {} -l agent.js -f {} --no-pause'.format(device,package_name), shell=True)
            else:
                subprocess.run('frida -D {} -l agent.js {}'.format(device,package_name), shell=True)

    def do_list(self,line):
        self.packages = []
        j=0
        if 'packages' in line:
            for line1 in os.popen('adb -s {} shell pm list packages -3'.format(self.device)):
                self.packages.append(line1.split(':')[1].strip('\n'))
            print('Installed packages:\n')
            for pkg in self.packages:
                print('[{}] {}'.format(j,pkg))
                j +=1
        else:
            print('Invalid flag !')

        


    def do_type(self,text):
        os.popen("adb -s {} shell input text {}".format(self.device,text))



    def do_help(self,line):
        if line != '':
            print('\n'+BLUE+self.display_tag(line,'Help')+RESET)
        else:
            print("""Available commands:
                            - show categories           : Displays the availlable module categories (start here)
                            - show modules [category]   : Displays the availlable modules for the selected category
                            - show all                  : Show all availlable modules
                            - show mods                 : Shows loaded modules
                            - use [module name]         : Selects a module which will be added to the final script
                            - rem [module name]         : Removes a module from the list that will be loaded
                            - reset                     : Removes all modules from the list that will be loaded
                            - help [module name]        : Displays help for the 
                            - compile                   : Compiles the modules to a frida script
                            - run        [package name] : Initiates a Frida session and attaches to the sellected package
                            - run -f    [package name]  : Initiates a Frida session and spawns the sellected package

                            **Adding '-d' in the options above will run Frida detached from the current shell,
                            (works only on macOS)

                            - type 'text'               : sends the text to the device
                            - list packages             : Lists 3rd party packages in the mobile device 
                            - shell                     : Opens an interactive shell
                            - clear                     : Clears the screen

                            Tip: Use the /modules/myModules/scratchpad.med to insert your own hooks and include them to the agent.js 
                            using the 'compile script' command""")
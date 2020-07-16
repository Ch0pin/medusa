import subprocess
import cmd
import os
import sys
import platform
import readline
import logging
import rlcompleter
import time
import frida

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

    prompt = BLUE+'apkutils>'+RESET
    INSTALL = False
    device = None
    package = None
    permissions = None
    activities = None
    services = None
    receivers = None
    providers = None
    filters = None

    classes = []
    packages = []



    def do_trace(self,line):

        opsys = platform.system()
        script = self.create_script(opsys,line)
    
        if 'Darwin' in opsys:
            subprocess.run("""osascript -e 'tell application "Terminal" to do script "{}" ' """.format(script), shell=True)
        elif 'Linux' in opsys:
            subprocess.run("""x-terminal-emulator -e {}""".format(script)) 
        elif 'Windows' in opsys:
            subprocess.call('start /wait {}'.format(script), shell=True)


    def create_script(self,opsys,line):
        param1 = line.split(' ')[0]+ '*!*'
        param = """frida-trace -D {} {} --runtime=v8 -j '{}' """.format(self.device.id,self.package,param1)
        path = os.getcwd()

        if 'Windows' in opsys:
            script = path + '/script.bat'
            with open(script,'w') as file:
                file.write(param) 
        else:
            script = path + '/script.sh'
            with open(script,'w') as file:
                file.write(param) 
            os.chmod(script, 0o775)

        return script
        
        
    def complete_trace(self, text, line, begidx, endidx):
        if not text:
            completions = self.classes[:]
            self.packages = []
        else:
            completions = [ f
                            for f in self.classes
                            if f.startswith(text)
                            ]
            self.packages = []
        return completions

    def init_packages(self):
        for line1 in os.popen('adb -s {} shell pm list packages -3'.format(self.device.id)):
            self.packages.append(line1.split(':')[1].strip('\n'))
   
    def do_uninstall(self,package):
        try:         
            output=os.popen("adb -s {} uninstall {}".format(self.device.id,package.split(' ')[0])).read()
            print(output)
        except Exception as e:
            print(e)
            return


    def do_kill(self,package):

        try:         
            print(package)
            output=os.popen("adb -s {} shell  am force-stop {}".format(self.device.id,package.split(' ')[0])).read()
            print(output)
        except Exception as e:
            print(e)
            return

    def complete_kill(self, text, line, begidx, endidx):

        self.init_packages()
        if not text:
            completions = self.packages[:]
            self.packages = []
        else:
            completions = [ f
                            for f in self.packages
                            if f.startswith(text)
                            ]
            self.packages = []
        return completions

    def complete_uninstall(self, text, line, begidx, endidx):

        self.init_packages()
        if not text:
            completions = self.packages[:]
            self.packages = []
        else:
            completions = [ f
                            for f in self.packages
                            if f.startswith(text)
                            ]
            self.packages = []
        return completions


    def do_broadcast(self,line):
        try:         
            output=os.popen("adb -s {} shell 'am broadcast {}'".format(self.device.id,line.split(' ')[0])).read()
            print(output)
        except Exception as e:
            print(e)
            return
    
    def complete_broadcast(self, text, line, begidx, endidx):
        
        if not text:
            completions = self.filters[:]
        else:
            completions = [ f
                            for f in self.filters
                            if f.startswith(text)
                            ]
        return completions

    def print_list(self,lst):
        print(GREEN)
        for item in lst:
            if type(item) is str:
                print('\t\t'+item)
        print(RESET)
    
    def do_show(self,line):
        what = line.split(' ')[0]
        if 'permissions' in what:
            self.print_list(self.permissions)
        elif 'activities' in what:
            self.print_list(self.activities)
        elif 'services' in what:
            self.print_list(self.services)
        elif 'receivers' in what:
            self.print_list(self.receivers)
        elif 'filters' in what:
            self.print_list(self.filters)
        elif 'providers' in what:
            self.print_list(self.providers)
        else:
            print('[i] Usage: show [permissions, activities, services, receivers, filters, providers]')


    def complete_show(self, text, line, begidx, endidx):
        components = ['permissions', 'activities', 'services', 'receivers', 'filters','providers']
        if not text:
            completions = components[:]
        else:
            completions = [ f
                            for f in components
                            if f.startswith(text)
                            ]
        return completions


    def do_adb(self,line):
        print("[i] Type 'exit' to return ")
        cmd = ''
        while cmd != 'exit':
            cmd = input(GREEN+'{}:adb:'.format(self.device.id)+RESET)
            if cmd != 'exit':
                subprocess.run('adb -s {} {}'.format(self.device.id,cmd), shell=True)

    def do_proxy(self,line):

        command = line.split(' ')[0]
        try:
            if 'get' in command:
                self.print_proxy()
            elif 'reset' in command:
                os.popen("adb -s {} shell settings put global http_proxy :0".format(self.device.id))  
                time.sleep(2) 
                self.print_proxy()
            elif 'set' in command:
                ip = line.split(' ')[1].split(':')[0]
                port = line.split(' ')[1].split(':')[1]
                os.popen("adb -s {} shell settings put global http_proxy {}:{}".format(self.device.id,ip,port)) 
                time.sleep(2) 

                self.print_proxy()
            else:
                print('[!] Usage: proxy [set,get,reset] [<ip>:<port>]')
        except Exception as e:
            print(e)

    def complete_proxy(self, text, line, begidx, endidx):
        proxy_cmd = ['set','get','reset']
        if not text:
            completions = proxy_cmd[:]
        else:
            completions = [ f
                            for f in proxy_cmd
                            if f.startswith(text)
                            ]
        return completions



    def print_proxy(self):
        settings = os.popen("adb -s {} shell settings get global http_proxy".format(self.device.id)).read()
        print ('Current proxy: {}'.format(settings))

    def do_screencap(self, line):
        try:
            if '-o' in line.split(' ')[0]:
                os.popen("adb -s {} exec-out screencap -p > {}".format(self.device.id,line.split(' ')[1]))
                print('[!] Screencap saved successfully to {}'.format(line.split(' ')[1]))
            else:
                print('[!] Usage: screencap -o filename.png')
        except Exception as e:
            print(e)
            print('[!] Usage: screencap -o filename.png')



    def do_start(self,line):
        try:         
            output=os.popen("adb -s {} shell 'am start -n {}/{}'".format(self.device.id,self.package,line.split(' ')[0])).read()
            print(output)
        except Exception as e:
            print(e)
            return


    def complete_start(self, text, line, begidx, endidx):
        if not text:
            completions = self.activities[:]
        else:
            completions = [ f
                            for f in self.activities
                            if f.startswith(text)
                            ]
        return completions

    def do_type(self,line):

        print("Type 'exit' to quit")

        while 'exit' not in line:
            line = input(':')
            os.popen("adb -s {} shell input text {}".format(self.device.id,line))



    def do_clear(self,line):
        os.system('clear')

    def do_shell(self,line):
        shell = os.environ['SHELL']
        subprocess.run('{}'.format(shell), shell=True)

    def do_exit(self,line):
        print('[i] Cleaning working directory: ')
        try:
            if os.path.isfile('./manifest.xml'):
                ask = input('\n[!] do you want to delete the manifest file ? (yes/no) ')
                if 'yes' in ask:
                    os.remove('./manifest.xml')

            if os.path.isfile('./script.sh'):
                ask = input('\n[!] do you want to delete the trace script file ? (yes/no) ')
                if 'yes' in ask:
                    os.remove('./script.sh')
            
            if os.path.isfile('./script.bat'):
                ask = input('\n[!] do you want to delete the trace script file ? (yes/no) ')
                if 'yes' in ask:
                    os.remove('./script.bat')

            if self.INSTALL == True:
                uninstall = input("[!] Do you want to uninstall the apk ? (yes/no)")
                if 'yes' in uninstall:
                    subprocess.run('adb -s {} uninstall {}'.format(self.device.id,self.package),shell=True)
            
            if os.path.exists("__handlers__/"):
                uninstall = input("[!] Do you want to delete the __handlers__ folder? (yes/no)")
                if 'yes' in uninstall:    
                    os.system("rm -r __handlers__/")

        except Exception as e:
            print(e) 

        print('Bye !!')
        exit()

    def do_help(self,line):
        if line != '':
            print('\n'+BLUE+self.display_tag(line,'Help')+RESET)
        else:
            print("""Available commands:

                    [+] TRACE A FUNCTION:
                    ---------------------

                    - trace [tab]               : Traces the functions of a class using frida-trace

                    Using the [tab] after trace presents the user with the classes loaded by the app, giving the
                    option to select the ones to trace."""+GREEN+"""

                    example: trace com.myapp.name* 

                    Will spawn a new terminal window and trace all the functions under the com.myapp.name* class+"""+RESET+""" 

                    ===========================================================================================

                    [+] MANIFEST PARSER:
                    ---------------------

                    - show permissions          : Prints the application's permissions
                    - show activities           : Prints a list with the application's activities
                    - show services             : Prints a list with the application's services
                    - show receivers            : Prints a list with the application's receivers
                    - show providers            : Prints a list with the application's content providers
                    - show filters              : Prints broadcast filters
                    ===========================================================================================

                    [+] TRIGERS:
                    ---------------------

                    - start      [tab]          : Starts and activity 
                    - broadcast  [tab]          : Broadcast an intent 

                    ===========================================================================================

                    [+] UTILITIES:
                    ---------------------
                    - adb [cmd]                 : Send an adb command to the connected device
                    - clear                     : Clears the screen
                    - kill [tab]                : Kill an app by the package name
                    - type                      : Type text to send to the device
                    - screencap -o filename     : Takes a device screenshot and saves it as 'filaname'
                    - shell                     : Opens an interactive shell
                    - proxy set <ip>:<port>     : Sets a global proxy at a given ip and port
                    - proxy get                 : Displays proxy settings of the device
                    - proxy reset               : Resets proxy settings
                    - uninstall [tab]           : Uninstals a packages from the device

                            """)
    

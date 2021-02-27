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
    deeplinks = None
    deeplinks_= []
    strings = []
    filters = []

    # classes = []
    packages = []


    def do_search(self, line):
        found = False
        try:
            what = line.split(' ')[0]
            print(RED+'Searching Activities:'+RESET)
            for module in self.activities:
                if what.lower() in module.lower():
                    print('[+] '+module[:str(module.lower()).find(what.lower())]+GREEN+what+RESET+module[str(module.lower()).find(what.lower())+len(what.lower()):])
                    print("[Original String: {}]\n".format(module))
                    found = True
            if not found:
                print('No Activities found containing: {} !'.format(what))
            found = False
            
            print(RED+'Searching Services:'+RESET)
            for module in self.services:
                if what.lower() in module.lower():
                    print('[+] '+module[:str(module.lower()).find(what.lower())]+GREEN+what+RESET+module[str(module.lower()).find(what.lower())+len(what.lower()):])
                    print("[Original String: {}]\n".format(module))
                    found = True
            if not found:
                print('No Services found containing: {} !'.format(what))
            found = False

            print(RED+'Searching Receivers:'+RESET)
            for module in self.receivers:
                if what.lower() in module.lower():
                    print('[+] '+module[:str(module.lower()).find(what.lower())]+GREEN+what+RESET+module[str(module.lower()).find(what.lower())+len(what.lower()):])
                    print("[Original String: {}]\n".format(module))
                    found = True
            if not found:
                print('No Receivers found containing: {} !'.format(what))
            found = False

            print(RED+'Searching Providers:'+RESET)
            for module in self.providers:
                if what.lower() in module.lower():
                    print('[+] '+module[:str(module.lower()).find(what.lower())]+GREEN+what+RESET+module[str(module.lower()).find(what.lower())+len(what.lower()):])
                    print("[Original String: {}]\n".format(module))
                    found = True
            if not found:
                print('No Providers found containing: {} !'.format(what))
            found = False  

            print(RED+'Searching Strings.xml:'+RESET)
            for module in self.strings:
                if what.lower() in module.lower():
                    print('[+] '+module[:str(module.lower()).find(what.lower())]+GREEN+what+RESET+module[str(module.lower()).find(what.lower())+len(what.lower()):])
                    print("[Original String: {}]\n".format(module))
                    found = True
            if not found:
                print('No Strings found containing: {} !'.format(what))
            found = False  

        except Exception as e:
            print(e)




    def do_deeplink(self,line):

        output=os.popen("adb -s {} shell am start -W -a android.intent.action.VIEW -d {}".format(self.device.id,line.split(' ')[0])).read()
        print(output)

    def complete_deeplink(self, text, line, begidx, endidx):

        if not text:
            completions = self.deeplinks_[:]
        else:
            completions = [ f
                            for f in self.deeplinks_
                            if f.startswith(text)
                            ]
        return completions

    def printDeepLinksMap(self):
        a = 0
        print(GREEN+'\n------------DeepLinks Map--------------:'+RESET)
        try:
            for key in self.deeplinks:
                print(BLUE+key+RESET)
                for value in self.deeplinks[key]:
                    self.deeplinks_.append(value)
                    print('\t|-> '+RED+value+RESET)
                    a = a+1
            print(GREEN+'----------Total Deeplinks:{}-------------'.format(a))
        except Exception as e:
            print(e)


    def do_trace(self,line):

        opsys = platform.system()
        script = self.create_script(opsys,line)

        if not 'Error' in script:
   
            if 'Darwin' in opsys:
                subprocess.run("""osascript -e 'tell application "Terminal" to do script "{}" ' """.format(script), shell=True)
            elif 'Linux' in opsys:
                subprocess.run("""x-terminal-emulator -e {}""".format(script)) 
            elif 'Windows' in opsys:
                subprocess.call('start /wait {}'.format(script), shell=True)

    def do_pull(self, line):
        try:
            base_apk = os.popen("adb -s {} shell pm path {} | grep apk".format(self.device.id,line.split(' ')[0])).read()
            base_apk = base_apk[ base_apk.find(':')+1:]
            print("Extracting: "+base_apk)
            output = os.popen("adb -s {} pull {}".format(self.device.id,base_apk)).read()
            print(output)
        except Exception as e:
            print(e)

    def complete_pull(self, text, line, begidx, endidx):
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


    def create_script(self,opsys,line):

        switch = line.split(' ')[0].strip()
        valid = True

        if '-j' in switch:
            param1 = line.split(' ')[1]+ '*!*'
            param = """frida-trace -D {} {} -j '{}' """.format(self.device.id,self.package,param1)
        elif '-n' in switch:
            param1 = line.split(' ')[1]+ '*'
            param = """frida-trace -D {} -i '{}' {}""".format(self.device.id,param1,self.package)
        elif '-a' in switch:
            param1 = line.split(' ')[1].strip()
            param = """frida-trace -D {} -I '{}' {}""".format(self.device.id,param1,self.package)
        else:
            print('[E] Invalid command, run help for options!')  
            valid = False        

        if valid:
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
        else:
            script = 'Error'

        return script
        

    def do_notify(self,line):
        try:         
            output=os.popen("adb -s {} shell am broadcast  -a com.medusa.NOTIFY --es subject {} --es body {}".format(self.device.id,line.split(' ')[0],line.split(' ')[1])).read()
            print(output)
        except Exception as e:
            print(e)
            return
        


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


    def do_spawn(self,package):
        try:         
            print('[+] Starting {}'.format(package))
            os.popen("adb -s {} shell  monkey -p {} -c 'android.intent.category.LAUNCHER 1'".format(self.device.id,package.split(' ')[0])).read()
            print('[+] {} started'.format(package))
        except Exception as e:
            print(e)
            return

    
    def complete_spawn(self, text, line, begidx, endidx):

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
            output=os.popen("adb -s {} shell 'am broadcast -a {}'".format(self.device.id,line.split(' ')[0])).read()
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
    
    def print_strings(self,lst):
       
        for item in lst:
            print(GREEN+'KEY:' +RESET+'{}'.format(item.split('=')[0],) + GREEN+'\t,VAL:'+RESET+' {}'.format(item.split('=')[1] ))
    
    
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
        elif 'strings' in what:
            self.print_strings(self.strings)
        else:
            print('[i] Usage: show [permissions, activities, services, receivers, filters, providers, strings]')


    def complete_show(self, text, line, begidx, endidx):
        components = ['permissions', 'activities', 'services', 'receivers', 'filters','providers', 'strings']
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
                os.popen("adb -s {} shell iptables -t nat -F".format(self.device.id))
                time.sleep(2) 
                self.print_proxy()
            elif 'set' in command:
                switch = ip = line.split(' ')[1].split(':')[0]
                if '-t' in switch:
                    ip = line.split(' ')[2].split(':')[0]
                    port = line.split(' ')[2].split(':')[1]
                    self.transproxy(ip,port)
                else:
                    ip = line.split(' ')[1].split(':')[0]
                    port = line.split(' ')[1].split(':')[1]
                    os.popen("adb -s {} shell settings put global http_proxy {}:{}".format(self.device.id,ip,port)) 
                    time.sleep(2) 
                    self.print_proxy()
            else:
                print('[!] Usage: proxy [set,get,reset] [<ip>:<port>] [-t]')
        except Exception as e:
            print(e)


    def transproxy(self,ip,port):
        try:
            print('[i] Pushing transproxy script !')
            os.popen("adb -s {} push utils/transproxy.sh /data/local/tmp/transproxy.sh".format(self.device.id)) 
            print('[i] Executing script')
            os.popen("adb -s {} shell 'chmod +x /data/local/tmp/transproxy.sh; /data/local/tmp/transproxy.sh {} {}; rm /data/local/tmp/transproxy.sh'".format(self.device.id,ip,port))
            self.print_proxy()
        except Exception as e:
            print(e)

    def do_installBurpCert(self,line):
        try:
            a = ''
            while a != 'y' and a !='x':
                a = input("""[!] Make sure that burp is running on 127.0.0.1:8080\n\nType 'y' to continue or 'x' to cancel:""")

            if a == 'y':
                os.popen("chmod +x utils/installBurpCert.sh; utils/installBurpCert.sh {}".format(self.device.id)) 
                os.popen("adb -s {} shell am broadcast -a com.medusa.INSTALL_CERTIFICATE -n com.medusa.agent/.Receiver".format(self.device.id))
                time.sleep(1)
                print()
        except Exception as e:
            print('')
        

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
        print (WHITE+"--------------Global proxy settings-----------------:"+RESET)
        print ('Current proxy: {}'.format(settings))
        print (WHITE+"--------------IP tables settings--------------------:"+RESET)
        output = subprocess.run("adb -s {} shell iptables -t nat -L".format(self.device.id), shell=True)
        print(output)
 

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


    def do_jdwp(self,line):
        try:
            pid = os.popen("adb -s {} shell pidof {}".format(self.device.id,line.split(' ')[0])).read()
            output = os.popen("adb -s {} forward tcp:6667 jdwp:{}".format(self.device.id,pid)).read()
            print(output)
            
            subprocess.run('jdb -attach localhost:6667', shell=True)

        except Exception as e:
            print(e)
            print('[!] Usage: jdwp package_name')



    def complete_jdwp(self, text, line, begidx, endidx):

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



    def do_startsrv(self,line):
        try:         
            output=os.popen("adb -s {} shell 'am startservice -n {}/{}'".format(self.device.id,self.package,line.split(' ')[0])).read()
            print(output)
        except Exception as e:
            print(e)
            return

    def complete_startsrv(self, text, line, begidx, endidx):
        if not text:
            completions = self.services[:]
        else:
            completions = [ f
                            for f in self.services
                            if f.startswith(text)
                            ]
        return completions

    def do_stopsrv(self,line):
        try:         
            output=os.popen("adb -s {} shell 'am stopservice -n {}/{}'".format(self.device.id,self.package,line.split(' ')[0])).read()
            print(output)
        except Exception as e:
            print(e)
            return

    def complete_stopsrv(self, text, line, begidx, endidx):
        if not text:
            completions = self.services[:]
        else:
            completions = [ f
                            for f in self.services
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

            if os.path.isfile('./strings.xml'):
                ask = input('\n[!] do you want to delete the strings.xml file ? (yes/no) ')
                if 'yes' in ask:
                    os.remove('./strings.xml')

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


    def do_installagent(self,line):
        try:
            subprocess.run('adb -s {} install -g {}'.format(self.device.id, os.getcwd()+'/dependencies/agent.apk'),shell=True)
        except Exception as e:
            print(e)


    def do_help(self,line):
        if line != '':
            print('\n'+BLUE+self.display_tag(line,'Help')+RESET)
        else:
            print("""Available commands:

                    [+] TRACE Functions using frida-trace:
                    ---------------------

                    - trace -j com.myapp.name*          : Trace all the functions of the com.myapp.name* class
                    - trace -n foo                      : Trace a native function
                    - trace -a library.so               : Trace the functions of the library.so

                    Will spawn a new frida-trace instance with the given options

                    ===========================================================================================

                    [+] MANIFEST PARSER:
                    ---------------------

                    - show permissions          : Print the application's permissions
                    - show activities           : Print a list with the application's activities
                    - show services             : Print a list with the application's services
                    - show receivers            : Print a list with the application's receivers
                    - show providers            : Print a list with the application's content providers
                    - show filters              : Print broadcast filters
                    - show strings              : print application's strings
                    - search [keyword]          : Search components containing the given keyword
                    ===========================================================================================

                    [+] TRIGERS:
                    ---------------------

                    - start      [tab]          : Start and activity 
                    - deeplink   [tab]          : Trigger a deeplink
                    - startsrv   [tab]          : Start a service
                    - stopsrv    [tab]          : Stop a service
                    - broadcast  [tab]          : Broadcast an intent 
                    - spawn      [tab]          : Spawn an application

                    ===========================================================================================

                    [+] UTILITIES:
                    ---------------------
                    - pull       [tab]              : extract apk from the device
                    - installagent                  : Install the Medusa apk
                    - installBurpCert               : Install Burp Certificate
                    - notify subject body           : Display a notification to the phone's notification bar
                    e.g. notify test foo            (Requires the medusa agent to be installed and run)

                    - jdwp  package_name            : Open a jdb session with the debugger attached to the package 
                                                    (Requires the --patch option)

                    - adb [cmd]                     : Send an adb command to the connected device
                    - clear                         : Clears the screen
                    - kill [tab]                    : Kill an app by the package name
                    - type                          : Type text to send to the device
                    - screencap -o filename         : Takes a device screenshot and saves it as 'filaname'
                    - shell                         : Opens an interactive shell
                    - proxy set [-t] <ip>:<port>    : Sets a global proxy at a given ip and port 
                                                    ('-t' for transparent)
                    - proxy get                     : Displays proxy settings of the device
                    - proxy reset                   : Resets proxy settings
                    - uninstall [tab]               : Uninstals a packages from the device

                            """)
    

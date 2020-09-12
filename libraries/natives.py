
import frida
import time
import sys


RED   = "\033[1;31m"  
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
WHITE = "\033[1;37m"
YELLOW= "\033[1;33m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"

class nativeHandler():



    modules = []
    device = None
    script = None

    def __init__(self,device):
        super(nativeHandler,self).__init__()
        self.device = device
        
   

    def on_message(self,message, data):
        try:
            if message["type"] == "send":
                payload = message["payload"]
                self.modules.append(payload.split(":")[0].strip())   
                #self.script.post({'input':'null'}) 
          
        except Exception as e:
            print(e) 

    def getModules(self,package,force):

        print('[i] Using device with id {}'.format(self.device))

        self.modules = []
        try:
            if force:
                pid = self.device.spawn(package)
                print("[i] Starting process {} [pid:{}]".format(package,pid))
                session = self.device.attach(pid)
                script = session.create_script(open("libraries/native.js").read())
                script.on('message', self.on_message)
                script.load()
                self.device.resume(pid)
                time.sleep(5)
                script.unload()
            else:
                pid = self.device.get_process(package).pid
                print("[i] Attaching to process {} [pid:{}]".format(package,pid))
                session = self.device.attach(pid)
                script = session.create_script(open("libraries/native.js").read())
                script.on('message', self.on_message)
                script.load()
                time.sleep(5)
                script.unload()
                
        except Exception as e:
            print(e)
        
        return self.modules

    def __getitem__(self,key):
        return self.modules
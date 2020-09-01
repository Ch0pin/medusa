
import frida
import time

class nativeHandler():

    modules = []
    device = None


    def on_message(self,message, data):
        try:
            if message["type"] == "send":
                payload = message["payload"]
                #print(payload)
                self.modules.append(payload.split(":")[0].strip())
        except Exception as e:
            print( e) 

    def getModules(self,package):
        self.modules = []
        try:
            pid = self.device.spawn(package)
            print('[i] Using device with id {}'.format(self.device))
            print("[i] Starting process {} [pid:{}]".format(package,pid))
            session = self.device.attach(pid)
            script = session.create_script(open("libraries/native.js").read())
            script.on('message', self.on_message)
            script.load()
            self.device.resume(pid)
            time.sleep(5)
            script.unload()
        except Exception as e:
            print(e)




    def __getitem__(self,key):
        return self.modules
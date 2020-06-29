import time
import frida
from googletrans import Translator
import sys





class translation(object):

    translator = Translator()
    script = None
   

    def __init__(self,pkg):
        super().__init__()
        try:
            print('Availlable devices:')
            devices = frida.enumerate_devices()
            i = 0

            for dv in devices:
                print('{}) {}'.format(i,dv))
                i += 1
            j = input('Enter the index of device to use:')
            device = devices[int(j)] 
        except:
            device = frida.get_remote_device()

        pid = device.spawn(pkg)
        device.resume(pid)
        time.sleep(1)
        session = device.attach(pid)
        with open("translator.js") as f:
            self.script = session.create_script(f.read())
        self.script.on("message",self.my_message_handler)  # register the message handler
        self.script.load()  
        input()
      


    def my_message_handler(self,message,payload):

        if message["type"] == "send":
            data = message["payload"].split(":")[0].strip()
            result = self.translator.translate(data)
            self.script.post({"my_data": result.text}) 




# def my_message_handler(message,payload,script):
#     # print('\n---message:{}'.format(message))
#     # print('\n---payload:{}'.format(payload))
#     if message["type"] == "send":
#         # print(message["payload"])
#         data = message["payload"].split(":")[0].strip()
#         # print('DATA RECEIVED:{}'.format(data))
#         result = translator.translate(data)
#         # print 'message:', message
#         # data = data.decode("base64")
#         # user, pw = data.split(":")
#         #data = ("admin" + ":" + pw).encode("base64")
#         # print('Source language: {}'.format(result.src))
#         # print(result.dest)
#         # print('RESULT: {}'.format(result.text))
#         script.post({"my_data": result.text})  # send JSON object


      
# def translate_ui(pkg):
#     try:
#         print('Availlable devices:')
#         devices = frida.enumerate_devices()
#         i = 0

#         for dv in devices:
#             print('{}) {}'.format(i,dv))
#             i += 1
#         j = input('Enter the index of device to use:')
#         device = devices[int(j)] 
#     except:
#         device = frida.get_remote_device()
#     script = None
#     pid = device.spawn(pkg)
#     device.resume(pid)
#     time.sleep(1)
#     session = device.attach(pid)
#     with open("translator.js") as f:
#         script = session.create_script(f.read())
#     script.on("message",my_message_handler)  # register the message handler
#     script.load()  
#     input()
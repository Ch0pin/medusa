import os
import subprocess
import readline

RED   = "\033[1;31m"  
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"






def send_keys(txt,device):
    print("Type :q! to quit")
    type = txt
    while type != ':q!':
        type = input(BLUE+'medusa>'+GREEN+'text_to_send>'+RESET)
        os.popen("adb -s {} shell input text {}".format(device,type))


def screencap(device, filename):
    os.popen("adb -s {} exec-out screencap -p > {}".format(device,filename))


def proxy(device,reset,ip=' ',port= ' ',get = False):
    if get==True:
        settings = os.popen("adb -s {} shell settings get global http_proxy".format(device)).read()
        print ('Current proxy: {}'.format(settings))
        return

    if reset == True:
        os.popen("adb -s {} shell settings put global http_proxy :0".format(device))   
    else:
        os.popen("adb -s {} shell settings put global http_proxy {}:{}".format(device,ip,port)) 

def adb_interactive(device):
    print("Type 'back' to exit!")
    cmd = ''
    while cmd != 'back':
        cmd = input(BLUE+'{}>adb>'.format(device)+RESET)
        if cmd != 'back':
            subprocess.run('adb -s {} {}'.format(device,cmd), shell=True)
        

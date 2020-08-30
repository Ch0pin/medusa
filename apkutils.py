#!/usr/bin/env python3
import sys
import readline
import os
import shutil
import frida
import subprocess
import cmd
import pty
from libraries.xmlUtils import *
from libraries.libapkutils import *
from xml.dom import minidom
from libraries.APKEnum import performRecon

RED   = "\033[1;31m"  
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"

APK = False
INSTALL = False

#enumerate classes
# js = """Java.perform(function(){Java.enumerateLoadedClasses({"onMatch":function(c){send(c);}});});"""
apktool="./Dependencies/apktool.jar"

classes = []
shell = os.environ.get('SHELL', 'sh')


def print_usage():
    print("\nInput file is missing ! \nUsage: \n\t{} path_to_AndroidManifest.xml OR ".format(sys.argv[0]))
    print('\t{} path_to_apk \n\n'.format(sys.argv[0]))

def extract_manifest(file):
    print('Unpacking apk....')

    subprocess.run('java -jar '+ apktool +' d {} -o tmp'.format(file), shell=True)
    subprocess.run('cp tmp/AndroidManifest.xml ./manifest.xml', shell=True)
    performRecon("./tmp")
    shutil.rmtree('./tmp')


# def on_message(message, data):
#     try:
#         if message["type"] == "send":
#             classes.append( message["payload"].split(":")[0].strip())
#     except Exception as e:
#         print('exception: ' + e) 



try:
    if len(sys.argv[1:]) < 1:
        print_usage()
        exit()

    extension = sys.argv[1].split('.')[-1]

    if extension == 'xml':
        xmlDoc = minidom.parse(sys.argv[1])
        filters = get_elements_sub(sys.argv[1])
    elif extension == 'apk':
        APK = True
        print('APK file given as an input')
        extract_manifest(sys.argv[1])
        xmlDoc = minidom.parse('manifest.xml')
        filters = get_elements_sub('manifest.xml')
    else:
        print_usage()
        exit()

except Exception as e:
    print(e)

    

print(GREEN+"""\n-----------Package Details-------------:
Name            :{}
Version code    :{}
Version Name    :{}
Mimimum SDK     :{}
Target  SDK     :{}
App     Name    :{}
Allow   Backup  :{}
---------------------------------------
Debuggable      :{}         

Exported Components:
""".format(get_elements(xmlDoc,'manifest','package')
            ,get_elements(xmlDoc,'manifest','android:versionCode')
            ,get_elements(xmlDoc,'manifest','android:versionName')
            ,get_elements(xmlDoc,'uses-sdk','android:minSdkVersion')
            ,get_elements(xmlDoc,'uses-sdk','android:targetSdkVersion')
            ,get_elements(xmlDoc,'application','android:name')
            ,get_elements(xmlDoc,'application','android:allowBackup')
            ,get_elements(xmlDoc,'application','android:debuggable')))
package = get_elements(xmlDoc,'manifest','package')
permissions = get_element_list(xmlDoc,'uses-permission','android:name')
activities = get_element_list(xmlDoc,'activity','android:name')
services = get_element_list(xmlDoc, 'service','android:name')
receivers = get_element_list(xmlDoc,'receiver','android:name')
providers = get_element_list(xmlDoc,'provider','android:name')







print(RESET)

pty.openpty()

try:
    print('Availlable devices:\n')
    devices = frida.enumerate_devices()
    i = 0

    for dv in devices:
        print('{}) {}'.format(i,dv))
        i += 1
    j = input('\nEnter the index of device to use:')
    device = devices[int(j)] 
    print('[+] Starting adb as root\n\n')
    os.popen("""adb -s {} root""".format(device.id))

    if APK == True:
        install = input("Do you want to install the apk ? (yes/no)")
        if 'yes' in install:
            subprocess.run('adb -s {} install {}'.format(device.id,sys.argv[1]),shell=True)
            INSTALL = True
except Exception as e:
    print(e)




# try:
#     if INSTALL==True:
#         pid = device.spawn(package)
#         print("[i] Starting process {} [pid:{}] to dump classes ".format(package,pid))
#         session = device.attach(pid)
#         device.resume(pid)
#         script = session.create_script(js)
#         script.on('message', on_message)
#         script.load()
# except Exception as e:
#     print(e)




p = parser()
p.package = package
p.permissions = permissions
p.activities = activities
p.services = services
p.receivers = receivers
p.providers = providers
p.device = device
p.INSTALL = INSTALL
p.filters = filters
# p.classes = classes
p.cmdloop()



print('\nBye !!')
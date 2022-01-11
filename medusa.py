#!/usr/bin/env python3
import readline
import os
import cmd
import click
from libraries.defs import *

p = parser()

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
                        p.module_list.append(module)
                    else:
                        data += line
            p.modified = True
        if data != '':
            print("[+] Writing to scratchpad...")
            with open('modules/scratchpad.med','w') as file:
                file.write(data)
                
except Exception as e:
    print(e)

click.secho("""
Welcome to:

 ███▄ ▄███▓▓█████ ▓█████▄  █    ██   ██████  ▄▄▄      
▓██▒▀█▀ ██▒▓█   ▀ ▒██▀ ██▌ ██  ▓██▒▒██    ▒ ▒████▄    
▓██    ▓██░▒███   ░██   █▌▓██  ▒██░░ ▓██▄   ▒██  ▀█▄  
▒██    ▒██ ▒▓█  ▄ ░▓█▄   ▌▓▓█  ░██░  ▒   ██▒░██▄▄▄▄██ 
▒██▒   ░██▒░▒████▒░▒████▓ ▒▒█████▓ ▒██████▒▒ ▓█   ▓██▒
░ ▒░   ░  ░░░ ▒░ ░ ▒▒▓  ▒ ░▒▓▒ ▒ ▒ ▒ ▒▓▒ ▒ ░ ▒▒   ▓▒█░
░  ░      ░ ░ ░  ░ ░ ▒  ▒ ░░▒░ ░ ░ ░ ░▒  ░ ░  ▒   ▒▒ ░
░      ░      ░    ░ ░  ░  ░░░ ░ ░ ░  ░  ░    ░   ▒   
       ░      ░  ░   ░       ░           ░        ░  ░\n\n\n Type help for options\n\n""",fg='green')



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



p.device = device





p.init_packages()
p.cmdloop()
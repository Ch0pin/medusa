#!/usr/bin/env python3
import readline
import os
import cmd

from libraries.defs import *


print(BOLD+GREEN+"""
Welcome to:
                          888                         
                          888                         
                          888                         
88888b.d88b.  .d88b.  .d88888888  888.d8888b  8888b.  
888 "888 "88bd8P  Y8bd88" 888888  88888K         "88b 
888  888  88888888888888  888888  888"Y8888b..d888888 
888  888  888Y8b.    Y88b 888Y88b 888     X88888  888 
888  888  888 "Y8888  "Y88888 "Y88888 88888P'"Y888888\n\n\n Type help for options\n\n"""+RESET)


try:
    print('Availlable devices:\n')
    devices = frida.enumerate_devices()
    i = 0

    for dv in devices:
        print('{}) {}'.format(i,dv))
        i += 1
    j = input('\nEnter the index of device to use:')
    device = devices[int(j)] 
except:
    device = frida.get_remote_device()

p = parser()
# p.device_index = index
# p.device = device_list[index].split()[0]
p.device = device
p.init_packages()
p.cmdloop()
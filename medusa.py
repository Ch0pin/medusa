#!/usr/bin/env python3
import readline
import os
import cmd
from libraries.defs import *


print("""
Welcome to:
                          888                         
                          888                         
                          888                         
88888b.d88b.  .d88b.  .d88888888  888.d8888b  8888b.  
888 "888 "88bd8P  Y8bd88" 888888  88888K         "88b 
888  888  88888888888888  888888  888"Y8888b..d888888 
888  888  888Y8b.    Y88b 888Y88b 888     X88888  888 
888  888  888 "Y8888  "Y88888 "Y88888 88888P'"Y888888\n\n\n Type help for options\n\n""")



device_list = os.popen("adb devices -l").read().split('\n')

device_list.pop()
index = 1

for device in device_list[1:-1]:
    print("{}) {}".format(index,device))
    index+=1

index = int(input('Please choose the device to operate:'))
p = parser()
p.device = device_list[index].split()[0]
p.cmdloop()
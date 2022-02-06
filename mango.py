from androguard.misc import AnalyzeAPK
from androguard.core.bytecodes import apk
from colorama import Fore, Back, Style
from libraries.IntentFilter import *
from libraries.libmango import *
from libraries.db import *
from libraries.Questions import *
from libraries.libguava import *
import hashlib
import sys, os.path





def print_logo():
  print(Style.BRIGHT+"""
  Welcome to:
                                                 .-'''-.     
                                                '   _    \   
 __  __   ___                _..._            /   /` '.   \  
|  |/  `.'   `.            .'     '.   .--./).   |     \  '  
|   .-.  .-.   '          .   .-.   . /.''\\ |   '      |  ' 
|  |  |  |  |  |    __    |  '   '  || |  | |\    \     / /  
|  |  |  |  |  | .:--.'.  |  |   |  | \`-' /  `.   ` ..' /   
|  |  |  |  |  |/ |   \ | |  |   |  | /("'`      '-...-'`    
|  |  |  |  |  |`" __ | | |  |   |  | \ '---.                
|__|  |__|  |__| .'.''| | |  |   |  |  /'""'.\               
                / /   | |_|  |   |  | ||     ||              
                \ \._,\ '/|  |   |  | \'. __//               
                 `--'  `" '--'   '--'  `'---'                """+Style.RESET_ALL)    

def get_device_or_emulator_id():
  try:
      print(Fore.GREEN)
      print("[i] Available devices:\n")
      devices = frida.enumerate_devices()
      i = 0

      for dv in devices:
          print('{}) {}'.format(i,dv))
          i += 1
      print(Fore.RESET)
      j = int(Numeric('\nEnter the index of the device to use:', lbound=0,ubound=i-1).ask())
      device = devices[int(j)] 
      print(Fore.RESET)
      return device
  except Exception as e:
    print(e)
    return None


def start_session(db_session,existing = False):
  application_database = apk_db(db_session)
  guava = Guava(application_database)
  p = parser()   
  p.database = application_database
  p.guava = guava
  if existing:
    p.continue_session(guava)

  p.device = get_device_or_emulator_id() 
  p.cmdloop()



if __name__ == "__main__":

  print_logo()
  menu = {}
  menu['1']="Start a new session" 
  menu['2']="Continue an existing session"
  menu['3']="Exit"
  
  while True: 
    print("-"*50 + "\n[?] What do you want to do ?\n"+"-"*50)
    options=menu.keys()

    for entry in options:
      print(entry, menu[entry])
    selection=input("\n[?] Enter your selection: ") 

    if selection =='1':
      session = input("\n[?] Enter a session name: ") 
      start_session(session)
      break
    elif selection == '2':
      session = input("\n[?] Enter full path to the session file: ")  
      if os.path.exists(session):
        start_session(session, True)
      else:
        print(Fore.RED+"[!] Fatal: can't find: {} ".format(session)+Fore.RESET)
        exit()
      break
    elif selection == '3':
      exit()
    else: 
      print("[!] Unknown Option Selected!")
 






   



  
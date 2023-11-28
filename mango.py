from libraries.libmango import *
from libraries.Questions import *
from libraries.libguava import *
from libraries.libadb import *
import sys, os.path


def print_logo():
  print(Style.BRIGHT+BLUE+"""
  Welcome to
        
    888b     d888                                    
    8888b   d8888                                    
    88888b.d88888                                    
    888Y88888P888  8888b.  88888b.   .d88b.   .d88b. 
    888 Y888P 888     "88b 888 "88b d88P"88b d88""88b
    888  Y8P  888 .d888888 888  888 888  888 888  888
    888   "   888 888  888 888  888 Y88b 888 Y88..88P
    888       888 "Y888888 888  888  "Y88888  "Y88P" 
                                        888         
                                    Y8b d88P         
                                    "Y88P"           """+Style.RESET_ALL+RESET)    

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
      j = int(Numeric('\nEnter the index of the device you want to use:', lbound=0,ubound=i-1).ask())
      device = devices[int(j)] 
      android_dev = android_device(device.id)
      android_dev.print_dev_properties()
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

  if len(sys.argv) > 1:
    session = sys.argv[1]

    if os.path.exists(session):
      start_session(session, True)
    else:
        print(Fore.RED+"[!] Fatal: can't find: {} ".format(session)+Fore.RESET)
        sys.exit()
  else:
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
          sys.exit()
        break
      elif selection == '3':
        sys.exit()
      else: 
        print("[!] Unknown Option Selected!")
 






   



  
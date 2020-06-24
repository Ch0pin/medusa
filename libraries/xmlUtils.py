import os
import xml.etree.ElementTree as tree

RED   = "\033[1;31m"  
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"

# etree.register_namespace('android', 'http://schemas.android.com/apk/res/android')


def get_elements(xmlDoc,node,attrib):
    node = xmlDoc.getElementsByTagName(node)
   
    for  atr in node:
        return atr.getAttribute(attrib)

def get_elements_sub(xmlDoc):

    manifest = tree.parse(xmlDoc)
    root = manifest.getroot()
    broadcasts = []
    for child in root.iter():
        if child.tag == 'intent-filter':
            for action in child:
                broadcasts.append( action.get("{http://schemas.android.com/apk/res/android}name"))
  
    return broadcasts

def get_element_list(xmlDoc,node,attrib):
    elements = []
    node = xmlDoc.getElementsByTagName(node)
   
    for  atr in node:
        elements.append(atr.getAttribute(attrib))
    
    return elements

def start_activity(activity_list,device,package):
    index = 0
    choice = ''
    for activity in activity_list:
        print('{}) {}'.format(index,activity))
        index += 1
    choice = int(input('Enter activity index (0 to {}): '.format(index)))
  
    try:
        while str(choice) != 'exit':
            activities = os.popen("adb -s {} shell 'am start -n {}/{}'".format(device,package,activity_list[choice]))
            print('\nStarting {}'.format(activity_list[choice]))
            choice = int(input(BLUE+'medusa_helper>start activity>'+RESET))
    except:
        return



def print_list(lst):
    for item in lst:
        print('\t\t'+item)
    
def print_help():
    print("""Available commands:
                    - show permissions          : Prints the apps permissions
                    - show activities           : Prints a list with the application's activities
                    - show services             : Prints a list with the application's services
                    - show receivers            : Prints a list with the application's receivers
                    - show providers            : Prints a list with the application's content providers
                    - show filters
                    - start activity            : Starts and activity from a printed list
                    - send broadcast
                    - send keys                 : Sends a text to the device
                    - screencap -o filename     : Takes a device screenshot and saves it as 'filaname'
                    - set proxy <ip>:<port>     : Sets a global proxy at a given ip and port
                    - unset proxy               : resets proxy settings
                    - get proxy                 : displays proxy settings of the device

            Available System commands: clear, ls, nano, cat

                    """)
    


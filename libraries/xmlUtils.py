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

    


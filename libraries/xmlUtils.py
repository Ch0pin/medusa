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

def parse_strings_xml(xmlDoc):
    try:
        stringsXML = tree.parse(xmlDoc)
        root = stringsXML.getroot()
        strings = []
        for child in root.iter():        
            if child.tag=='string':
                attrib = child.attrib['name']
                text = child.text
                if attrib is not None and text is not None:
                    strings.append(attrib+"="+text)
    except Exception as e:
        print(e) 
    return strings


def get_element_list(xmlDoc,node,attrib):
    elements = []
    nod = xmlDoc.getElementsByTagName(node)
   
    for  atr in nod:

        elements.append(atr.getAttribute(attrib))
        if 'true' in atr.getAttribute("android:exported"):
            print(RED + '{:10}'.format(node)+'{:80}'.format(atr.getAttribute(attrib)) + CYAN+' is exported')

       
    
    return elements


def get_deeplinks(xmlDoc):
    
    deeplinksTree = {}
    
    activityNodes = xmlDoc.getElementsByTagName('activity')
    activityNodes +=xmlDoc.getElementsByTagName('activity-alias')
    for act in activityNodes:
        intent_filter = act.getElementsByTagName('intent-filter')
        deeplinks = []
        for i in range(0,intent_filter.length):
            schemes = []
            hosts = []
            paths = []
            patterns = []
            pathPrefixes = []
            port = ''


            for data in intent_filter.item(i).getElementsByTagName('data'):
                if data.hasAttribute('android:scheme') and data.hasAttribute('android:host'):        #scenario 1
                    scheme = data.getAttribute('android:scheme')
                    deeplink = scheme+'://'
                    deeplink+=data.getAttribute('android:host')
                    if data.hasAttribute('android:port'):
                        deeplink+=':'+data.getAttribute('android:port')        
                    if data.hasAttribute('android:path'):
                        deeplink+=data.getAttribute('android:path')
                    if data.hasAttribute('android:pathPattern'):
                        deeplink+=data.getAttribute('android:pathPattern')
                    if data.hasAttribute('android:pathPrefix'):
                            deeplink+= data.getAttribute('android:pathPrefix')
                    #print(deeplink)
                    deeplinks.append(deeplink)

                elif data.hasAttribute('android:scheme') and not data.hasAttribute('android:host'): #scenario 2
                    schemes.append(data.getAttribute('android:scheme'))
                elif not data.hasAttribute('android:scheme'):
                    if data.hasAttribute('android:host'):
                        hosts.append(data.getAttribute('android:host'))
                    elif data.hasAttribute('android:port'):
                        port =data.getAttribute('android:port')  
                    elif data.hasAttribute('android:path'):
                        paths.append(data.getAttribute('android:path'))
                    elif data.hasAttribute('android:pathPattern'):
                        patterns.append(data.getAttribute('android:pathPattern'))
                    elif data.hasAttribute('android:pathPrefix'):
                        pathPrefixes.append(data.getAttribute('android:pathPrefix'))
                
            for schm in schemes: 
                deeplink = schm+"://"
                for hst in hosts:
                    deeplink = schm+"://"
                    deeplink += hst
                    if port != '':
                        deeplink = deeplink+':'+port
                    for path in paths:
                        deeplink += path
                    for pattern in patterns:
                        deeplink += pattern
                    for pathPrefix in pathPrefixes:
                        deeplink+=pathPrefix
                    #print(deeplink)
                    deeplinks.append(deeplink)


                #print(deeplink)
                deeplinks.append(deeplink)
            if deeplinks:
                deeplinksTree[act.getAttribute('android:name')]=deeplinks

    return deeplinksTree


    


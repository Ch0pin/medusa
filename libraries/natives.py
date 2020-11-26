
import frida
import time
import sys
import click

RED   = "\033[1;31m"  
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
WHITE = "\033[1;37m"
YELLOW= "\033[1;33m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"

class nativeHandler():



    modules = []
    device = None
    script = None
    prompt_ = WHITE+'|' +GREEN+'(E)xit '+ WHITE+  '|'+GREEN+ 'r@offset ' + WHITE+'|' +GREEN+ 'w@offset '+ WHITE+'|' +GREEN+'⏎ '+ WHITE+ '|' +GREEN+ 'scan '+ WHITE+'|'+ GREEN + '(h)elp' +WHITE +'|'+ GREEN + ' dump' +WHITE +'|:'


    def __init__(self,device):
        super(nativeHandler,self).__init__()
        self.device = device

   

    def on_message(self,message, data):
        try:
            if message["type"] == "send":
                payload = message["payload"]
                self.modules.append(payload.split(":")[0].strip())   
                #self.script.post({'input':'null'}) 
          
        except Exception as e:
            print(e) 

    def getModules(self,package,force):

        print('[i] Using device with id {}'.format(self.device))

        self.modules = []
        try:
            if force:
                pid = self.device.spawn(package)
                print("[i] Starting process {} [pid:{}]".format(package,pid))
                session = self.device.attach(pid)
                script = session.create_script(open("libraries/native.js").read())
                script.on('message', self.on_message)
                script.load()
                self.device.resume(pid)
                time.sleep(5)
                script.unload()
            else:
                pid = self.device.get_process(package).pid
                print("[i] Attaching to process {} [pid:{}]".format(package,pid))
                session = self.device.attach(pid)
                script = session.create_script(open("libraries/native.js").read())
                script.on('message', self.on_message)
                script.load()
                time.sleep(5)
                script.unload()
                
        except Exception as e:
            print(e)
        
        return self.modules


    def memops(self,line):
        try:

            args = line.split(' ')

            if len(args)<2:
                lib = ''
            elif len(args) >= 2:
                lib = args[1]
            else:
                print('Usage: memops package_name [lib]')
                return


            package = args[0]
            

            

            prolog = 'Java.perform(function () {\n\n'
            if lib != '':
                prolog += 'var module = Process.findModuleByName("'+lib+'");\n'
                prolog += 'var p_foo = Module.findBaseAddress("'+lib+'");'+"""
                if (!p_foo) {
                    console.log("Could not find module....");
                    return 0;
                }"""
            payload = ''
            epilog = '\n\n});'

            codejs = prolog + payload + epilog

            print('[i] Using device with id {}'.format(self.device))
            try:
                pid = self.device.get_process(package).pid
 
            except Exception as e:
                    x = input("Please run the application and press enter....")
                    pid = self.device.get_process(package).pid

            print("[i] Attaching to process {} [pid:{}]".format(package,pid))
            session = self.device.attach(pid)
            script = session.create_script(codejs)
            script.load()
            

            cmd = input(self.prompt_) 
            prev_cmd = 'e'

            while( not cmd.lower().startswith('e')):
                if cmd.startswith('r@'):
                    cmd = self.read_memory(cmd[2:],script,session,codejs,prolog,epilog,payload)
                    continue
                elif cmd.startswith('w@'):
                    in_bytes = input("Bytes to write (in the form of 00 11 22 33):")
                    bytesx = self.form_bytes(in_bytes)
                    print("Bytes in:{}".format(bytesx))
                    self.write_memory(cmd[2:],script,session,codejs,prolog,epilog,payload,bytesx)
                elif cmd.startswith('h'):
                    self.display_help()
                elif cmd.startswith('scan'):
                    in_bytes = input("Enter a text or byte array in form of bytes(DE 00 11 ?? ?? BE AF):")
                    if in_bytes.startswith('bytes('):
                        pattern = in_bytes[6:].strip(')')
                    else:
                        pattern = self.form_scan_input(in_bytes)
                    print("BYTES IN: {}".format(pattern))
                    
                    self.scan_memory(lib,pattern,session,script)
                
                elif cmd.startswith('dump'):
                    script.unload()
                    print("dumping....")
                    self.dump(session,lib)

                cmd = input(self.prompt_) 

            script.unload()
        except Exception as e:
            print(e)   

#############################

    def dump(self,session,lib):

        try:

            path = '.'
            script = session.create_script(open("libraries/memops.js").read())
            script.load()
            api = script.exports
           
            dump_area = api.moduleaddress(lib)
            for area in dump_area:
                bs = api.memorydump(area["addr"],area["size"])
            
            with open(lib + ".dat", 'wb') as out:
                out.write(bs)
            click.secho('[+] dump saved to {}.dat'.format(lib), fg='green')

        except Exception as e:
            click.secho("[Except] - {}:".format(e), bg='red')





    def scan_memory(self,lib,pattern,session,script):
     
        codejs =''
        try:
            if lib != '':
                codejs += "var module = Process.findModuleByName('"+lib+"');\n"

            codejs += "var pattern = '"+pattern+"';"
            codejs += """
                    var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});
                    var range;"""
            if lib != '':
                codejs += """ var baseAddress = parseInt(module.base,16);
                    var endAddress = module.size + baseAddress;

                    console.log('Module base address:'+module.base);
                    console.log('Module end Address: 0x'+endAddress.toString(16));"""
    
            codejs += """
            
            function processNext(){
                        range = ranges.pop();

                        
                        if(!range){
                            // we are done
                            return;
                        }

                        var rangeAddress = parseInt(range.base,16);"""
            if lib != '':
                codejs += """
                    if (baseAddress <= rangeAddress)
                    {"""
            codejs += """
                    //console.log('IN RANGE');
                    Memory.scan(range.base, range.size, pattern, {

                        onMatch: function(address, size){"""
            if lib != '':
                codejs += """
                            if(rangeAddress <= endAddress){"""
            if lib != '':
                codejs +=   """var offset = parseInt(address,16)-baseAddress;"""
            else:
                codejs +=  """var offset = parseInt(address,16)-rangeAddress;"""

            codejs+=            """var buf = Memory.readByteArray(ptr(address),32);
                                console.log(); 
                                console.log('[i] Pattern found at: ' + address.toString() + ' | Offset:' + offset.toString(16)+'\t'+hexdump(buf, {offset: 0, length:16, header: false, ansi: false
                        }));"""
            if lib == '':
                codejs += """
                            var module = Process.findRangeByAddress(range.base);
                            console.log(JSON.stringify(module));
                            """
            if lib != '':
                codejs += '}'
            codejs += """
                            }, 
                        onError: function(reason){
                                console.log('[!] There was an error scanning memory');
                            }, 
                        onComplete: function(){
                                processNext();
                            }
                        });
                    }"""
                    
            if lib != '':   
                codejs += '}'
            codejs += """
        processNext();
"""

            script = session.create_script(codejs)
            script.load()

        except Exception as e:
            print(e)       


    def display_help(self):
        print("""Availlable commands:
        
        (e)xit:     Exit memops
        dump:     Dump loaded module to a file
        r@offset:   Read @ offet (e.g. r@beaf)
        Return:     Read next 296 bytes
        w@offset:   Write @ offset (e.g. w@beaf)
        scan:       Scan a memory region for a pattern
        ?:          Display this message
        """)

    def write_memory(self,offset, script_in,session_in,codejs_in,prolog_in,epilog_in,payload_in,bytes):
        script = script_in
        session = session_in
        codejs = codejs_in
        prolog = prolog_in
        epilog = epilog_in
        payload=payload_in
        offset_in = offset
        arithemetic_offset = int(offset_in,16)
     
        
        try:

            payload += '\nvar address = p_foo.add('+str(arithemetic_offset)+');'
            payload += '\nvar offset = '+str(arithemetic_offset);
            payload += "\nconsole.log('Write op started');"
            payload += '\nMemory.protect(address, 0x5, "rwx");'
            payload += "\nMemory.writeByteArray(ptr(address), {})".format(bytes)
            payload += "\nconsole.log('Write op finished');"
            codejs = prolog + payload + epilog
            script = session.create_script(codejs)
            script.load()
            payload = ''     
        except Exception as e:
            print(e)




    def read_memory(self,offset, script_in,session_in,codejs_in,prolog_in,epilog_in,payload_in):
        
        script = script_in
        session = session_in
        codejs = codejs_in
        prolog = prolog_in
        epilog = epilog_in
        payload=payload_in
        offset_in = offset
        arithemetic_offset_tmp = hex(0)
        cmd = ''

        while cmd == '':
            arithemetic_offset = hex(0) 
            try:
                
                if offset_in == '':
                    arithemetic_offset = hex(int(arithemetic_offset,16)+int(arithemetic_offset_tmp,16))
                    arithemetic_offset_tmp = hex(int(arithemetic_offset,16) + 296)
                else:
                    arithemetic_offset_tmp = hex(int(offset_in,16)+296)
                    arithemetic_offset = hex(int(arithemetic_offset,16) + int(offset_in,16))

                print(BLUE+'[+] Offset:' + arithemetic_offset+RESET)

                payload += '\nvar address = p_foo.add('+str(arithemetic_offset)+');'
                payload += """    
                var baseAddress = parseInt(p_foo,16);
                var endAddress = baseAddress + module.size;
                """
                payload += '\nvar offset = '+str(arithemetic_offset);
                payload += """\nvar buf = Memory.readByteArray(ptr(address),296);
                if(buf){
                
                    console.log('Address Range:'+p_foo+' --> '+endAddress.toString(16));
                    console.log('Module Size:' + module.size+' Dumping at:'+address);
                    console.log(hexdump(buf, {offset: 0, length:296, header: true, ansi: false
                }))};"""
                codejs = prolog + payload + epilog
                script = session.create_script(codejs)
                script.load()
                payload = ''


            except Exception as e:
                print(e)

            cmd = input(self.prompt_)
            offset_in = cmd
        
        return cmd

    def form_scan_input(self,scan_str):
        ret = ''
        for letter in scan_str:
            bt = str(hex(ord(letter)))[2:]
            if not scan_str.endswith(letter):
                ret += bt + ' '
            else:
                ret += bt
        return ret


    def form_bytes(self,bytes):
	    return '[%s]' % ','.join(["0x%02x" % int(x, 16) for x in bytes.split(' ')])

    def __getitem__(self,key):
        return self.modules
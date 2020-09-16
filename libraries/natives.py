
import frida
import time
import sys


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
    prompt_ = WHITE+'|' +GREEN+'(E)xit '+ WHITE+  '|'+GREEN+ 'r@offset ' + WHITE+'|' +GREEN+ 'w@offset '+ WHITE+'|' +GREEN+'⏎ '+ WHITE+ '|' + GREEN + '? (help)' +WHITE + '|:'


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
                print('Usage: readmem package_name libfoo.so')

            package = args[0]
            lib = args[1]

            prolog = 'Java.perform(function () {\n\n'
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
                elif cmd.startswith('?'):
                    self.display_help()
              

                cmd = input(self.prompt_) 

            script.unload()
        except Exception as e:
            print(e)   

    def display_help(self):
        print("""Availlable commands:
        
        exit:       exit memops
        r@offset:   read @ offet (e.g. r@beaf)
        Return:     read next 296 bytes
        w@offset:   write @ offset (e.g. w@beaf)
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

                print(arithemetic_offset)

                payload += '\nvar address = p_foo.add('+str(arithemetic_offset)+');'
                payload += '\nvar offset = '+str(arithemetic_offset);
                payload += """\nvar buf = Memory.readByteArray(ptr(address),296);
    if(buf) console.log('Base Address:'+p_foo+' Dumping at:'+address+' Offset:'+offset.toString(16));
    console.log(hexdump(buf, {offset: 0, length:296, header: true, ansi: false
    }));"""
                codejs = prolog + payload + epilog
                script = session.create_script(codejs)
                script.load()
                payload = ''


            except Exception as e:
                print(e)

            cmd = input(self.prompt_)
            offset_in = cmd
        
        return cmd


    def form_bytes(self,bytes):
	    return '[%s]' % ','.join(["0x%02x" % int(x, 16) for x in bytes.split(' ')])

    def __getitem__(self,key):
        return self.modules
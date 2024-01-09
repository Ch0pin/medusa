import time
import click
import os

RED = "\033[1;31m"
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
WHITE = "\033[1;37m"
YELLOW = "\033[1;33m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD = "\033[;1m"
REVERSE = "\033[;7m"


class nativeHandler:
    base_directory = os.path.dirname(__file__)
    modules = []
    device = None
    script = None
    prompt_ = WHITE + '|' + GREEN + '(E)xit ' + WHITE + '|' + GREEN + 'r@offset ' + WHITE + '|' + GREEN + 'w@offset ' + WHITE + '|' + GREEN + '⏎ ' + WHITE + '|' + GREEN + 'scan ' + WHITE + '|' + GREEN + '(h)elp' + WHITE + '|' + GREEN + ' dump' + WHITE + '|:'

    def __init__(self, device):
        super(nativeHandler, self).__init__()
        self.device = device

    def __getitem__(self, key):
        return self.modules

    def display_help(self):
        print("""Available commands:
        
        (e)xit:     Exit memops
        dump:       Dump the loaded library to a file
        r@offset:   Read @ offet (e.g. r@beaf)
        Return:     Read next 296 bytes
        w@offset:   Write @ offset (e.g. w@beaf)
        scan:       Scan a memory region for a specific match.
                    The input can be a simple text (e.g. "test" without quotes)
                    or a byte array inserted as: bytes(00 11 22 33 ??) where ??
                    represents a wildcard.
        (h)elp:     Display this message
        """)

    # todo add force or attach
    def dump(self, session, lib, free=False, base_address=None, size=None, package_name=''):
        try:
            path = '.'
            script = session.create_script(open(os.path.dirname(__file__) + "/js/memops.js").read())
            script.load()
            api = script.exports
            if not free:
                dump_area = api.moduleaddress(lib)
                for area in dump_area:
                    bs = api.memorydump(area["addr"], area["size"])
            else:
                bs = api.memorydump(base_address, size)

            if package_name == '':
                print("package name empty")
                filepath = './dump' + os.path.sep
            else:
                filepath = './dump' + os.path.sep + package_name + os.path.sep

            if not os.path.exists(filepath):
                os.makedirs(filepath)

            with open(filepath + lib + ".dat", 'wb') as out:
                out.write(bs)
            click.secho(f"[+] dump saved to {filepath + lib + '.dat'}", fg='green')

        except Exception as e:
            click.secho(f"[Except] - {e}:", bg='red')

    def form_bytes(self, bytes):
        return '[%s]' % ','.join(["0x%02x" % int(x, 16) for x in bytes.split(' ')])

    def form_scan_input(self, scan_str):
        ret = ''
        for letter in scan_str:
            bt = str(hex(ord(letter)))[2:]
            if not scan_str.endswith(letter):
                ret += bt + ' '
            else:
                ret += bt
        return ret

    def getModules(self, package, force):
        print(f'[i] Using device with id {self.device}')
        self.modules = []
        try:
            if force:
                pid = self.device.spawn(package)
                print(f"[i] Starting process {package} [pid:{pid}]")
            else:
                pid = int(os.popen(f"adb -s {self.device.id} shell pidof {package}").read().strip())
                if pid is None:
                    print(f"[+] Could not find process with this name {pid_s}.")
                    return
                print(f"[i] Attaching to process {package} [pid:{pid}]")

            print(f"PID:{pid}")
            session = self.device.attach(pid)
            script = session.create_script(open(os.path.join(self.base_directory, "js", "native.js")).read())
            script.on('message', self.on_message)
            script.load()
            self.device.resume(pid)
            time.sleep(5)
            script.unload()
        except Exception as e:
            print(e)

        return self.modules

    def loadLibrary(self, package, libname):
        try:
            scriptContent = "Java.perform(function() {"
            scriptContent += """
            var system = Java.use('java.lang.System');
                Java.scheduleOnMainThread(function(){"""
            scriptContent += "var mod = Module.load('" + libname.replace("'", "") + "');"
            scriptContent += "console.log(JSON.stringify(mod));})});"

            # pid = self.device.spawn(package)
            # pid = os.popen("adb -s {} shell ps -A | grep {} | cut -d ' ' -f 8".format(self.device.id,package)).read().strip()
            pid = os.popen(f"adb -s {self.device.id} shell pidof {package}").read().strip()
            if pid == '':
                print("[+] Could not find process with this name.")
            else:
                session = self.device.attach(package)
                script = session.create_script(scriptContent)
                print("loading script...")
                script.on('message', self.on_message)
                # self.device.resume(pid)
                script.load()
                time.sleep(1)
                script.unload()
        except Exception as e:
            print(e)

    ###-------------------meraw
    def memraw(self, line, autodump=False):
        try:

            args = line.split(' ')
            if len(args) == 4:
                package = args[0]
                pid = args[1]
                size = args[3]
                base_addr = args[2]
            else:
                print('Usage: memdump package_name base_address size')
                return

            prolog = 'Java.perform(function () {\n\n'
            if base_addr != '':
                prolog += 'var size = ' + size + ';\n'
                prolog += 'var p_foo = ptr(' + base_addr + ');' + """
                if (!p_foo) {
                    console.log("Could not find module....");
                    return 0;
                }"""
            payload = ''
            epilog = '\n\n});'
            codejs = prolog + payload + epilog
            print(f'[i] Using device with id {self.device}')
            # try:
            #     pid = os.popen("adb -s {} shell pidof {}".format(self.device.id,package)).read().strip()
            #     if pid == '':
            #         print("[+] Could not find process with this name.")
            #         return None
            # except Exception as e:
            #         print(e)
            #         x = input("Please run the application and press enter....")
            #         pid = self.device.get_frontmost_application().pid
            print(f"[i] Attaching to process {package} [pid:{pid}]")
            session = self.device.attach(int(pid))
            script = session.create_script(codejs)
            script.load()
            prompt = WHITE + '|' + GREEN + '(E)xit ' + WHITE + '|' + GREEN + 'r@offset ' + WHITE + '|' + GREEN + 'dump ' + WHITE + '|:'
            if autodump:
                cmd = 'dump'
            else:
                cmd = input(prompt)
            prev_cmd = 'e'

            while not cmd.lower().startswith('e'):
                if cmd.startswith('r@'):
                    cmd = self.read_memory(cmd[2:], script, session, codejs, prolog, epilog, payload, prompt, True,
                                           size)
                    continue
                # elif cmd.startswith('w@'):
                #     in_bytes = input("Bytes to write (in the form of 00 11 22 33):")
                #     bytesx = self.form_bytes(in_bytes)
                #     print("Bytes in:{}".format(bytesx))
                #     self.write_memory(cmd[2:],script,session,codejs,prolog,epilog,payload,bytesx)
                # elif cmd.startswith('h'):
                #     self.display_help()
                # elif cmd.startswith('scan'):
                #  in_bytes = input("Enter a text or byte array in form of bytes (DE 00 11 ?? ?? BE AF):")
                #  if in_bytes.startswith('bytes('):
                #      pattern = in_bytes[6:].strip(')')
                #  else:
                #      pattern = self.form_scan_input(in_bytes)
                #  print("BYTES IN: {}".format(pattern))
                #  self.scan_memory(lib,pattern,session,script)

                elif cmd.startswith('dump'):
                    k = 0
                    script.unload()
                    print("dumping....")
                    int_size = int(size)
                    chunk = 134217728
                    if int_size > chunk:
                        print("Memory region too large, breaking to chunks...")
                        while int_size > 0:
                            if int_size - chunk > 0:
                                print(f"dumping: {base_addr} to {hex(int(base_addr, 16) + chunk)}")
                                self.dump(session, base_addr + "_dump", True, int(base_addr, 16), chunk, package)
                            else:
                                print(f"dumping: {base_addr} to {hex(int(base_addr, 16) + int_size)}")
                                self.dump(session, base_addr + "_dump", True, int(base_addr, 16), int_size, package)
                                break
                            int_size -= chunk
                            baddr = int(base_addr, 16) + chunk
                            base_addr = hex(baddr)

                    else:
                        self.dump(session, base_addr + "_dump", True, int(base_addr, 16), int_size, package)
                if autodump:
                    return
                cmd = input(prompt)

            script.unload()
        except Exception as e:
            print(e)

    #############################memops
    def memops(self, line):

        try:
            args = line.split(' ')
            if len(args) == 2:
                package = args[0]
                lib = args[1]
            else:
                print('Usage: memops package_name [lib]')
                return

            prolog = 'Java.perform(function () {\n\n'
            if lib != '':
                prolog += 'var module = Process.findModuleByName("' + lib + '");\n'
                prolog += 'var p_foo = Module.findBaseAddress("' + lib + '");' + """
                if (!p_foo) {
                    console.log("Could not find module....");
                    return 0;
                }"""
            payload = ''
            epilog = '\n\n});'

            codejs = prolog + payload + epilog

            print(f'[i] Using device with id {self.device}')
            try:
                pid = os.popen(f"adb -s {self.device.id} shell pidof {package}").read().strip()
                if pid == '':
                    print("[+] Could not find process with this name.")
                    return None
            except Exception as e:
                print(e)
                x = input("Please run the application and press enter....")
                pid = self.device.get_frontmost_application().pid
            print(f"[i] Attaching to process {package} [pid:{pid}]")
            session = self.device.attach(int(pid))

            script = session.create_script(codejs)
            script.load()
            cmd = input(self.prompt_)
            prev_cmd = 'e'

            while not cmd.lower().startswith('e'):
                if cmd.startswith('r@'):
                    cmd = self.read_memory(cmd[2:], script, session, codejs, prolog, epilog, payload, self.prompt_)
                    continue
                elif cmd.startswith('w@'):
                    in_bytes = input("Bytes to write (in the form of 00 11 22 33):")
                    bytesx = self.form_bytes(in_bytes)
                    print(f"Bytes in:{bytesx}")
                    self.write_memory(cmd[2:], script, session, codejs, prolog, epilog, payload, bytesx)
                elif cmd.startswith('h'):
                    self.display_help()
                elif cmd.startswith('scan'):
                    in_bytes = input("Enter a text or a byte array (see help for details):")
                    if in_bytes.startswith('bytes('):
                        pattern = in_bytes[6:].strip(')')
                    else:
                        pattern = self.form_scan_input(in_bytes)
                    print(f"BYTES IN: {pattern}")

                    self.scan_memory(lib, pattern, session, script)

                elif cmd.startswith('dump'):
                    script.unload()
                    print("dumping....")
                    self.dump(session, lib)

                cmd = input(self.prompt_)

            script.unload()
        except Exception as e:
            print(e)

    def on_message(self, message, data):
        try:
            if message["type"] == "send":
                payload = message["payload"]
                self.modules.append(payload.split(":")[0].strip())
                # self.script.post({'input':'null'})
        except Exception as e:
            print(e)

    def read_memory(self, offset, script_in, session_in, codejs_in, prolog_in, epilog_in, payload_in, prompt,
                    free=False, size=None):
        script = script_in
        session = session_in
        codejs = codejs_in
        prolog = prolog_in
        epilog = epilog_in
        payload = payload_in
        offset_in = offset
        arithemetic_offset_tmp = hex(0)
        cmd = ''
        while cmd == '':
            arithemetic_offset = hex(0)
            try:

                if offset_in == '':
                    arithemetic_offset = hex(int(arithemetic_offset, 16) + int(arithemetic_offset_tmp, 16))
                    arithemetic_offset_tmp = hex(int(arithemetic_offset, 16) + 296)
                else:
                    arithemetic_offset_tmp = hex(int(offset_in, 16) + 296)
                    arithemetic_offset = hex(int(arithemetic_offset, 16) + int(offset_in, 16))

                if size is not None:
                    # print("current arithetic offset:{}".format(int(arithemetic_offset,16)))
                    if int(arithemetic_offset, 16) > int(size) - 296:
                        arithemetic_offset = hex(0)

                print(BLUE + '[+] Offset:' + arithemetic_offset + RESET)

                payload += '\nvar address = p_foo.add(' + str(arithemetic_offset) + ');'
                payload += "var baseAddress = parseInt(p_foo,16);"
                if free:
                    payload += "var endAddress = baseAddress + size;"
                else:
                    payload += "var endAddress = baseAddress + module.size;"

                payload += '\nvar offset = ' + str(arithemetic_offset)
                payload += """\nvar buf = Memory.readByteArray(ptr(address),296);
                if(buf){
                    console.log('Address Range:'+p_foo+' --> '+endAddress.toString(16));
                    """
                if free:
                    payload += "console.log('Module Size:' + size+' Dumping at:'+address);"
                else:
                    payload += "console.log('Module Size:' + module.size+' Dumping at:'+address);"
                payload += "console.log(hexdump(buf, { offset: 0, length:296, header: true, ansi: false}))};"
                codejs = prolog + payload + epilog
                script = session.create_script(codejs)
                script.load()
                payload = ''
            except Exception as e:
                print(e)

            cmd = input(prompt)
            offset_in = cmd
        return cmd

    def scan_memory(self, lib, pattern, session, script):
        codejs = ''
        try:
            if lib != '':
                codejs += "var module = Process.findModuleByName('" + lib + "');\n"

            codejs += "var pattern = '" + pattern + "';"
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
                codejs += """var offset = parseInt(address,16)-baseAddress;"""
            else:
                codejs += """var offset = parseInt(address,16)-rangeAddress;"""

            codejs += """var buf = Memory.readByteArray(ptr(address),32);
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

    def write_memory(self, offset, script_in, session_in, codejs_in, prolog_in, epilog_in, payload_in, bytes):
        script = script_in
        session = session_in
        codejs = codejs_in
        prolog = prolog_in
        epilog = epilog_in
        payload = payload_in
        offset_in = offset
        arithemetic_offset = int(offset_in, 16)
        try:

            payload += '\nvar address = p_foo.add(' + str(arithemetic_offset) + ');'
            payload += '\nvar offset = ' + str(arithemetic_offset)
            payload += "\nconsole.log('Write op started');"
            payload += '\nMemory.protect(address, 0x5, "rwx");'
            payload += f"\nMemory.writeByteArray(ptr(address), {bytes})"
            payload += "\nconsole.log('Write op finished');"
            codejs = prolog + payload + epilog
            script = session.create_script(codejs)
            print(codejs)
            script.load()
            payload = ''
        except Exception as e:
            print(e)

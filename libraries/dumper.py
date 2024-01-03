# Author: hluwa <hluwa888@gmail.com>
# HomePage: https://github.com/hluwa
# CreatedTime: 2020/1/7 20:57

import os
import hashlib

import click
import frida
import logging
import hashlib
md5 = lambda bs: hashlib.md5(bs).hexdigest()

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt='%m-%d/%H:%M:%S')

def dump(pkg_name, api,mds=None):
    if mds is None:
        mds = []
    matches = api.scandex()

    for info in matches:
        try:

            bs = api.memorydump(info['addr'], info['size'])
            md = md5(bs)
            if md in mds:
                click.secho("[DEXDump]: Skip duplicate dex {}<{}>".format(info['addr'], md), fg="blue")
                continue
            mds.append(md)

            if not os.path.exists("./" + pkg_name + "/"):
                os.mkdir("./" + pkg_name + "/")
            if bs[:4] != "dex\n":
                bs = b"dex\n035\x00" + bs[8:]
            readable_hash = hashlib.sha256(bs).hexdigest();
            with open(pkg_name + "/" + readable_hash + ".dex", 'wb') as out:
                out.write(bs)
            click.secho("[DEXDump]: DexSize={}, SavePath={}/{}/{}.dex"
                        .format(hex(info['size']), os.getcwd(), pkg_name, readable_hash), fg='green')
        except Exception as e:
            click.secho("[Except] - {}: {}".format(e, info), bg='yellow')

def dump_pkg(pkg):
    try:
        print('Available devices:')
        devices = frida.enumerate_devices()
        i = 0

        for dv in devices:
            print('{}) {}'.format(i,dv))
            i += 1
        j = input('Enter the index of the device you want to use:')
        device = devices[int(j)] 
    except:
        device = frida.get_remote_device()

    bring_to_front = input('Bring the application you want to dump to the front and press enter.....\n')

    target = device.get_frontmost_application()
    
    pkg_name = pkg#target.identifier
    print('[+] Dumping: '+pkg)
    # processes = get_all_process(device, pkg_name)
    # if len(processes) == 1:
    #     target = processes[0]
    # else:
    #     s_processes = ""
    #     for index in range(len(processes)):
    #         s_processes += "\t[{}] {}\n".format(index, str(processes[index]))
    #     input_id = int(input("[{}] has multiprocess: \n{}\nplease choose target process: "
    #                          .format(pkg_name, s_processes)))
    #     target = processes[input_id]
    #     try:
    #         for index in range(len(processes)):
    #             if index == input_id:
    #                 os.system("adb shell \"su -c 'kill -18 {}'\"".format(processes[index].pid))
    #             else:
    #                 os.system("adb shell \"su -c 'kill -19 {}'\"".format(processes[index].pid))
    #     except:
    #         pass

    logging.info("[DEXDump]: found target [{}] {}".format(target.pid, pkg_name))
    session = device.attach(target.pid)
    path = os.path.dirname(__file__)
    #path = path if path else "."
    script = session.create_script(open(path + "/../dexdump.js").read())
    script.load()
    dump(pkg_name, script.exports)

def get_all_process(device, pkgname):
    return [process for process in device.enumerate_processes() if pkgname in process.name]

def search(api, args=None):
    matches = api.scandex()
    for info in matches:
        click.secho("[DEXDump] Found: DexAddr={}, DexSize={}"
                    .format(info['addr'], hex(info['size'])), fg='green')
    return matches
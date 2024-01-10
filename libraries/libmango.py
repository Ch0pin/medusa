#!/usr/bin/env python3
import subprocess, frida, shutil
import cmd2, os, sys, platform, requests
import time
# import readline, logging, time, rlcompleter
from libraries.Questions import Polar
from libraries.libadb import android_device
from libraries.libguava import *
from libraries.Questions import *
from shutil import which
from colorama import Fore, Back, Style

BASE = os.path.dirname(__file__)

APKTOOL_URL = "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.2.jar"
MEDUSA_AGENT_URL = "https://github.com/Ch0pin/medusa/files/13833921/agent.zip"

APKTOOL = os.path.abspath(os.path.join(BASE, '../dependencies/apktool.jar'))
MEDUSA_AGENT = os.path.abspath(os.path.join(BASE, '../dependencies/agent.apk'))

DEBUGGABLE_APK = os.getcwd() + "/debuggable.apk"
ALLIGNED_APK = os.getcwd() + "/debuggable_alligned_signed.apk"
TMP_FOLDER = os.getcwd() + "/tmp_dir"
SIGNATURE = os.path.abspath(os.path.join(BASE, '../dependencies/common.jks'))

RED = "\033[1;31m"
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
WHITE = "\033[1;37m"
YELLOW = "\033[1;33m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD = "\033[;1m"
REVERSE = "\033[;7m"

# readline.set_completer_delims(readline.get_completer_delims().replace('/', ''))
BUSSY_BOX_URL = "https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/"

HELP_MESSAGE = "\nSYNOPSIS:" + """
    mango➤[command] <parameters> <flags> """ + """

DESCRIPTION """ + """

    Mango is Medusa's twin which can help researchers to extract and analyse components of and Android
    Application. The results are saved to a SQLite database which can be reloaded or updated with new samples. 
    Additionally, mango automates various other tasks, like changing proxy settings on the device, force to 
    start/stop services, install/uninstall applications, take screenshots and many more.

    The availlable commands are the follows:

    adb                             Start an interactive adb prompt.

    box                             Start a busybox interactive shell. 

    c [cmd]                         Execute a shell command on the host.
                                    Example: c ls -al ./ , > !ls -al

    cc [cmd]                        Execute a command on the device using the default adb shell.
                                    Example: cc ls -al /sdcard
    
    clear                           Clear the screen

    deeplink [deeplink] [--poc]     Sends an intent which will start the given deeplink. When used with --poc 
                                    it will create an html link to the given deeplink."

    exit                            Exit mango.

    help [mango command]            Displays a help message for the mango command. 

    import [full path to apk]       Imports an apk file for analysis and saves the results to the session's database. 
                                    Example: import /path/to/foo.apk
    
    install [full path to apk]      Install the given apk to the device.

    installagent                    Install the medusa agent to the device.

    installBurpCert                 Install a Burp certificate to the connected mobile device. 

    jdwp [package name]             Create a jdb session. Use it in combination with the tab key to see available packages. 
                                    The app has to have the debuggable flag set to true.
    
    jlog                            Wrapper for: adb logcat -s AndroidRuntime. Displays java crash logs.

    load [package name]             Load an application which allready exists in the current (working) database. 

    logcat [package name]           Wrapper for: adb logcat --pid=`adb shell pidof -s com.app.package`
                                    Display adb's logcat info about an app. The app has to be running. Exit with ctrl^C. 

    man                             Display this message.       

    notify [text] [body]            Send a notification to the device (it is used to trigger notification listeners). The
                                    Medusa Agent must be installed and running on the device (see installagent).
                                    (Example: notify 'Title' 'Lorem ipsum dolor sit amet,....')

    patch [full path to apk]        Change the debuggable flage of the AndroidManifest.xml to true for a given apk. The 
                                    command requires apksigner and zipalign to have been installed.
                                    (Example: patch /path/to/foo.apk)

    proxy [get|reset|set] [ip:port] Change/view the connected device's configuration proxy. If adb runs as root it 
                                    can be used with the '-t' flag to set a transparent proxy. 
                                    Example: proxy set 192.168.1.2:8080 -t

    pull [package name]             Extract an apk from the device and saves it as 'base.apk' in the working directory.
                                    Use it in combination with the tab key to see available packages
                                    Example: pull com.foo.bar

    query [raw query]               Perform a raw query in the session db and returns the results as a list of tuples.
                                    Example: query SELECT * FROM Application

    screencap -o [filename.png]     Capture the device screen and saves it as a png file in the current directory. 
                                    Example: screencap -o 'screen1.png'
    
    search 'string'                 Search for a given string in the extracted components and strings.
                                    Example: search foobar

    show [applications | database | exposure | info | manifest_entry | manifest ] [-e]             

                                    Print info about one of the following options:
                                    - applications: prints the currently loaded applications and allows you to load another one
                                    - database: prints the structure of the loaded database
                                    - exposure: prints the application's exposure points (exported activities, services, deeplinks etc.)
                                    - info: prints information about the loaded application
                                    - manifest_entry: prints information about the loaded application's manifest entries, including:
                                    activities, services, activityAlias, receivers, deeplinks, providers and intentFilters.
                                    Adding the '-e' option the command will print only exported components.  
                  
    start [activity]                Send an intent to start an activity of the currently loaded application. 
                                    Use it in combination with the tab key to see the available activities. 
                                    Plase note that for not exported activities, adb must run with root 
                                    privileges (adb root)

    startsrv, stoprsrv  [service name]        
    
                                    Sends an intent to start or stop a service of the currently loaded application. 
                                    Use it in combination with the tab key to see the available activities. 
                                    Plase note that for not exported activities, adb must run with root 
                                    privileges (adb root)

    trace [-j, -n, -a] [method | class]  

                                    Trace calls using frida-trace (frida-trace wrapper)                                         
    
    uninstall, kill, spawn [application name]     

                                    Uninstalls, kills or starts an app in the device. Use it in combination with the tab 
                                    key to see available packages.
                                    Example: uninstall com.foo.bar , kill com.foo.bar1)

    ------------------------------------------------------------------------------------
    Other features availlable:
    ------------------------------------------------------------------------------------

    - Searchable command history (history command and <Ctrl>+r) - optionally persistent
    - Run a shell command with !
    - Pipe command output to shell commands with |
    - Run shell commands with !
    - Redirect command output to file with >, >>
    - Bare >, >> with no filename send output to paste buffer (clipboard)
 
    """

current_dir = os.getcwd()


class parser(cmd2.Cmd):
    NO_APP_LOADED_MSG = "[i] No application is loaded, type 'import /path/to/foo.apk' to load one"

    base_directory = os.path.dirname(__file__)
    prompt = Fore.BLUE + Style.BRIGHT + 'mango➤' + Fore.RESET + Style.RESET_ALL
    current_app_sha256 = None
    notes = None
    database = None
    guava = None
    INSTALL = False
    device = None
    package = None
    permissions = None
    activities = None
    activity_names = None
    service_names = None
    activityallias = None
    info = None
    services = None
    receivers = None
    providers = None
    total_apps = []
    deeplinks = None
    total_deep_links = []
    intent_filters = None
    hosts = set()
    schemes = set()
    pathPrefixes = set()
    manifest = None

    strings = []
    packages = []

    def __init__(self):
        super().__init__(
            allow_cli_args=False

        )

    ###################################################### do_ defs start ############################################################

    def do_adb(self, line, cmd=None, frombs=False):
        """Start an interactive adb prompt."""

        if cmd is None:
            print("[i] Type 'exit' to return ")
            cmd = input(GREEN + f'{self.device.id}:adb:' + RESET)

        while cmd != 'exit':
            if cmd != 'exit':
                subprocess.run(f'adb -s {self.device.id} {cmd}', shell=True)
                if frombs:
                    return
            cmd = input(GREEN + f'{self.device.id}:adb:' + RESET)

    # mark for tests
    def do_box(self, line):
        """Starts a busybox interactive shell. """

        arch = self.run_command(["adb", "-s", f'{self.device.id}', "shell", "getprop", "ro.product.cpu.abi"])
        if b'v8' in arch:
            binary = "busybox-armv8l"
        elif 'v7' in arch:
            binary = "busybox-armv7l"
        else:
            print("Arch is not supported !")
            return
        output = self.run_command(f"adb -s {self.device.id} shell ls /data/local/tmp/{binary}".split())
        if b'No such file' in output:
            download = Polar("[!] Can't find Bussybox in this device, do you want to download it ?").ask()
            if download:
                try:
                    print("[i] Attempting to download the file...")
                    self.download_file(BUSSY_BOX_URL + binary, './busybox.tmp')
                    # print(self.run_command(["curl", BUSSY_BOX_URL+binary, "--output", "busybox.tmp"]).decode('utf-8'))
                    if os.path.exists("./busybox.tmp"):
                        print(
                            f"[i] Download successful, pushing the binary to the device as '/data/local/tmp/{binary}'")
                        print(self.run_command(["adb", "-s", f"{self.device.id}", "push", "./busybox.tmp",
                                                f"/data/local/tmp/{binary}"]).decode('utf-8'))
                        print("[i] Deleting local file...")
                        print(self.run_command(["rm", "./busybox.tmp"]).decode('utf-8'))
                        print(self.run_command(["adb", "-s", f"{self.device.id}", "shell", "chmod", "+x",
                                                f"/data/local/tmp/{binary}"]).decode('utf-8'))
                        print("[i] Setting the aliases file...")
                        shellfile = os.path.abspath(os.path.join(self.base_directory, '../utils/busybox.sh'))
                        with open(shellfile, 'r') as sf:
                            data = sf.read()
                        data = data.replace('to_be_replaced', binary)
                        with open(shellfile, 'w') as sf:
                            sf.write(data)
                        subprocess.run(f"""adb -s {self.device.id} push {shellfile} /data/local/tmp/busybox.sh""",
                                       shell=True)
                    else:
                        print("[!] Download Failed !")
                        return
                except Exception as e:
                    print(e)
            else:
                return
        print("[i] Busybox support has already been installed.\n[i] Type: source /data/local/tmp/busybox.sh")
        self.do_adb("adb", "shell", True)

    def do_c(self, line):
        """Usage: c [shell command]
        Run a shell command on the local host."""
        subprocess.run(line, shell=True)

    def do_cc(self, line):
        """
        Get an adb shell to the connected device (no args)
        """
        subprocess.run(f'adb -s {self.device.id} shell {line}', shell=True)

    def do_clear(self, line):
        """Clear the screen"""
        os.system('clear')

    def do_note(self, line):
        """Usage: note [add|show|del|update]
        """
        try:
            note_option = line.split()[0]
            if note_option == 'add':
                note = input("Note (press enter to commit): ")
                self.guava.insert_note(self.current_app_sha256, note)
                print("Note added.")
            elif note_option == 'show':
                notes = self.database.get_all_notes(self.current_app_sha256)
                for index, sha256, cmt in notes:
                    print(f'{index}) {cmt}')
            elif note_option == 'del':
                index = input("Enter the index of the note you want to delete:")
                self.guava.delete_note(int(index))
            elif note_option == 'update':
                index = input("Enter the index of the note you want to update:")
                note = input("Note (press enter to commit): ")
                self.guava.update_note(index, note)
                print("Note updated")
            else:
                print("[!] Invalid option !")
                return
        except Exception as e:
            print(e)

    def do_deeplink(self, line):
        """Usage: deeplink [deeplink] [--poc]
        Sends an intent which will start the given deeplink. 
        When used with --poc it will create an html link to the given deeplink."""

        if self.current_app_sha256 is None:
            print(self.NO_APP_LOADED_MSG)
        else:
            try:
                if len(line.split()) > 1 and '--poc' in line.split()[1]:
                    print("[+] Creating POC")
                    poc = '<head></head>' + '<body>' + '<a href="' + line.split()[
                        0] + '">DEEPLINK POC</a></body></html>'
                    f = open("poc.html", 'w')
                    f.write(poc)
                    f.close()
                    print("[+] POC created")

                else:
                    output = os.popen(
                        f"adb -s {self.device.id} shell am start -W -a android.intent.action.VIEW -d {line.split(' ')[0]}").read()
                    print(output)
            except Exception as e:
                print(e)

    def do_exit(self, line):
        """Usage: exit 
        Exits mango."""
        print('Checking the working directory for leftovers... ')
        path = os.getcwd()
        try:
            if os.path.isfile('./script.sh'):
                if Polar(f"\t (!) Delete {path + '/script.sh'} ?").ask():
                    os.remove('script.sh')
            if os.path.isfile('.\script.bat'):
                if Polar('\t(!) Do you want to delete the trace script file?').ask():
                    os.remove('./script.bat')
            if os.path.exists('__handlers__/'):
                if Polar(f"\t(!) Delete the folder {path + '/__handlers__'}?").ask():
                    os.system("rm -r __handlers__/")
            else:
                print("All good !")
        except Exception as e:
            print(e)
        print('Bye !!')
        sys.exit()

    def do_import(self, line):
        """Usage: 
        import /full/path/to/foo.apk
        import /full/path/to/apks/ --mass 
        Imports an apk file for analysis and saves the results to 
        the current session's database. Adding --mass will import 
        all the apks under a directory and its subdirectories."""

        num_of_options = len(line.split(' '))
        if num_of_options == 1:
            apkfile = line.split(' ')[0]
            if os.path.exists(apkfile):
                self.real_import(apkfile)
            else:
                print(Fore.RED + f"[!] Error: can't find: {apkfile} " + Fore.RESET)
        elif num_of_options == 2 and line.split(' ')[1] == '--mass':
            try:
                apk_files = []
                for root, dirs, files in os.walk(line.split(' ')[0]):
                    for file in files:
                        if file.endswith(".apk"):
                            apk_files.append(os.path.join(root, file))

                if len(apk_files) == 0:
                    print("[x] Nothing to import!")
                else:
                    i = 1
                    for apk in apk_files:
                        print(GREEN + f"[{i}] Importing: {apk}" + RESET)
                        self.real_import(apk, False)
                        i += 1
            except Exception as e:
                print(e)
        else:
            print("[!] Invalid option")

    def do_install(self, line):
        """Usage: install /full/path/to/foobar.apk
        Install an apk to the device."""

        try:
            if len(line.split(' ')):
                apk_file = line.split(' ')[0]

                if os.path.exists(apk_file):
                    self.do_adb('adb', f'install {apk_file}', True)
                else:
                    print(Fore.RED + f"[!] Error: can't find: {apk_file} " + Fore.RESET)
        except Exception as e:
            print(e)

    def do_installagent(self, line):
        """Usage: installagent
        Install the medusa agent to the device. The agent can be used to extend the
        framework's functionality."""

        try:
            if not os.path.exists(MEDUSA_AGENT):
                if (Polar('[?] Medusa Agent has not been downloaded, do you want to do it now ?').ask()):
                    self.download_file(MEDUSA_AGENT_URL, MEDUSA_AGENT)
                else:
                    return
            subprocess.run(f'adb -s {self.device.id} install -g {MEDUSA_AGENT}', shell=True)
        except Exception as e:
            print(e)

    def do_installBurpCert(self, line):
        """Usage: installBurpCert
        Install the Burp certificate to the mobile device.
        Please note that the medusa agent must have been installed and running"""

        install_script = os.path.join(self.base_directory, '../utils/installBurpCert.sh')
        self.init_packages()
        if 'com.medusa.agent' not in self.packages:
            print("[!] Medusa Agent must be installed and running on the device, type 'installagent' to install it.")
            return
        try:
            a = ''
            while a != 'y' and a != 'x':
                a = input(
                    """[!] Make sure that burp is running on 127.0.0.1:8080\n\nType 'y' to continue or 'x' to cancel:""")

            if a == 'y':
                os.popen(f"chmod +x {install_script}; {install_script} {self.device.id}").read()
                os.popen(
                    f"adb -s {self.device.id} shell am broadcast -a com.medusa.INSTALL_CERTIFICATE -n com.medusa.agent/.Receiver").read()

                time.sleep(1)
                print(GREEN + """
-------------------------------------------------------------------
Note: Burp certificate has been copied to sdcard/<old_hash>.cer, use the following 
commands to install it as a system certificate:
-------------------------------------------------------------------
$adb remount
#cd /system/etc/security/cacerts
#mv /sdcard/<old_hash>.cer /system/etc/security/cacerts/<old_hash>.0
#chmod 644 /system/etc/security/cacerts/<old_hash>.0
#chown root:root /system/etc/security/cacerts/<old_hash>.0
#reboot

                """ + RESET)
                print()
        except Exception:
            print('')

    def do_jdwp(self, line):
        """Usage: jdwp [package name]
        Debug an app using jdb. Use it in combination with the tab key to see available packages. 
        Please not that the app has to have the debuggable flag set to true."""

        try:
            pid = os.popen(f"adb -s {self.device.id} shell pidof {line.split(' ')[0]}").read()
            output = os.popen(f"adb -s {self.device.id} forward tcp:6667 jdwp:{pid}").read()
            print(output)
            subprocess.run('jdb -attach localhost:6667', shell=True)
        except Exception as e:
            print(e)
            print('[!] Usage: jdwp package_name')

    def do_jlog(self, line):
        """Usage: jlog
        Wrapper for: adb logcat -s AndroidRuntime
        Displays java crash logs."""

        ad = android_device(self.device.id)
        ad.print_java_crash_log()

    def do_kill(self, package):
        """Usage: kill [package name]
        Kills an app running in the device. 
        Use it in combination with the tab key to see available packages."""

        try:
            print(package)
            output = os.popen(f"adb -s {self.device.id} shell  am force-stop {package.split(' ')[0]}").read()
            print(output)
        except Exception as e:
            print(e)

    def do_load(self, line):
        """Usage: load [package_name]
        Load an application which allready exists in the current (working) database."""
        self.real_load_app(line.split(':')[1])
        return

    def do_loaddevice(self, line) -> None:
        """Usage: loaddevice
        Start a new session using the selected device."""
        try:
            print(Fore.GREEN)
            print("[i] Available devices:\n")
            devices = frida.enumerate_devices()
            i = 0

            for dv in devices:
                print(f'{i}) {dv}')
                i += 1
            print(Fore.RESET)
            j = int(Numeric('\nEnter the index of the device you want to use:', lbound=0, ubound=i - 1).ask())
            device = devices[int(j)]
            android_dev = android_device(device.id)
            android_dev.print_dev_properties()
            print(Fore.RESET)
            self.device = device
        except Exception as e:
            print(e)

    def do_logcat(self, line):
        """Usage: logcat [package name]
        Wrapper for: adb logcat --pid=`adb shell pidof -s com.app.package`
        Displays the adb's logcat info about an app. 
        The app has to be running.
        Exit with ctrl^C."""

        ad = android_device(self.device.id)
        ad.print_runtime_logs(line)

    def do_man(self, line):
        """Usage: man [topic]
        Prints extensive help about mango. Use it with a search-keyword to highlight
        the part of the output related with the search"""

        if len(line.split(' ')) > 0:
            topic = line.split(' ')[0]
            h = self.highlight(topic, HELP_MESSAGE)
            if h == '':
                print(f"[i] No help availlable for '{topic}'")
            else:
                print(h)
        else:
            line = " "
            topic = "optionally"
            h = self.highlight(topic, HELP_MESSAGE)
            print(h)

    def do_nlog(self, line):
        """Usage: nlog
        Wrapper for: adb logcat -s libc,DEBUG
        Displays native crash logs."""

        ad = android_device(self.device.id)
        ad.print_native_crash_log()

    def do_notify(self, line):
        """Usage: notify 'notification title' 'Notification body,....'
        Sends a notification to the device (it is used to trigger notification listeners). 
        Please note that the Medusa Agent must be installed and running on the device
        (see installagent)."""

        try:
            self.init_packages()
            if 'com.medusa.agent' in self.packages:
                output = os.popen(
                    f"adb -s {self.device.id} shell am broadcast  -a com.medusa.NOTIFY --es subject {line.split(' ')[0]} --es body {line.split(' ')[1]}").read()
                print(output)
            else:
                print(
                    "[!] Medusa Agent must be installed and running on the device, type 'installagent' to install it.")
        except Exception as e:
            print(e)

    # mark for tests
    def do_patch(self, line):
        """Usage: patch /full/path/to/foo.apk
        Changes the debuggable flage of the AndroidManifest.xml to true for a given apk. 
        The command requires apksigner and zipallign to have been installed."""

        text_to_search = "<application"
        replacement_text = '<application android:debuggable="true" '
        file = line.split(' ')[0]

        if os.path.exists(file):
            try:
                if not self.does_exist("apksigner"):
                    print("[!] apksigner is not installed, quiting !")
                    return
                if not self.does_exist("zipalign"):
                    print("[!] zipalign is not installed, quiting !")
                    return
                if not os.path.exists(APKTOOL):
                    if Polar('[?] apktool has not been downloaded, do you want to do it now ?').ask():
                        self.download_file(APKTOOL_URL, APKTOOL)

                print(GREEN + '[+] Unpacking the apk....' + RESET)
                subprocess.run('java -jar ' + APKTOOL + f' d {file} -o {TMP_FOLDER}', shell=True)

                print(GREEN + '[+] Extracting the manifest....' + RESET)
                with open(TMP_FOLDER + '/AndroidManifest.xml', 'rt') as f:
                    data = f.read()

                print(GREEN + '[+] Setting the debug flag to true...')

                if 'android:debuggable="true"' in data:
                    print(RED + "[!] Application is already debuggable !" + RESET)
                else:
                    data = data.replace(text_to_search, replacement_text)

                    with open(TMP_FOLDER + '/AndroidManifest.xml', 'wt') as f:
                        f.write(data)
                    print(GREEN + '[+] Repacking the app...' + RESET)
                    subprocess.run('java -jar ' + APKTOOL + f' b {TMP_FOLDER} -o {DEBUGGABLE_APK}', shell=True)
                    print(GREEN + '[+] Alligning the apk file.....' + RESET)
                    subprocess.run(f'zipalign -p -v 4 {DEBUGGABLE_APK} {ALLIGNED_APK}', shell=True)
                    print(GREEN + '[+] Signing the apk.....' + RESET)
                    subprocess.run(
                        f'apksigner sign --ks {SIGNATURE} -ks-key-alias common --ks-pass pass:password --key-pass pass:password  {ALLIGNED_APK}',
                        shell=True)
                    print(GREEN + '[+] Removing the unsigned apk.....' + RESET)
                    os.remove(DEBUGGABLE_APK)
                    print(GREEN + '[+] Backing up the original...' + RESET)
                    shutil.move(file, 'original_' + file)
                    shutil.move(ALLIGNED_APK, file)

                    if not Polar('[?] Do you want to keep the extracted resources ?').ask():
                        shutil.rmtree(TMP_FOLDER)
            except Exception as e:
                print(e)

        else:
            print("[!] File doesn't exist.")

    def do_playstore(self, line):
        """Usage: playstore package_name
        Search the playstore for the app with the given id."""
        print(os.popen(
            f"adb -s {self.device.id} shell am start -W -a android.intent.action.VIEW -d market://details?id={line.split(' ')[0]}").read())

    def do_proxy(self, line):
        """Usage: proxy [get | reset | set] [ip:port] 
        Modifies the proxy configuration of the connected device:
        - get, returns the current proxy configuration
        - set ip:port, sets the device's proxy to ip:port
        - reset, resets the proxy settings to the default configuration 
        Please note that if adb runs as root then you can also use the 
        '-t' flag to set a transparent proxy."""

        command = line.split(' ')[0]
        try:
            if 'get' in command:
                self.print_proxy()
            elif 'reset' in command:
                os.popen(f"adb -s {self.device.id} shell settings put global http_proxy :0")
                os.popen(f"adb -s {self.device.id} shell 'echo \"iptables -t nat -F\" | su'")
                time.sleep(2)
                self.print_proxy()
            elif 'set' in command:
                switch = ip = line.split(' ')[1].split(':')[0]
                if '-t' in switch:
                    ip = line.split(' ')[2].split(':')[0]
                    port = line.split(' ')[2].split(':')[1]
                    self.transproxy(ip, port)
                else:
                    ip = line.split(' ')[1].split(':')[0]
                    port = line.split(' ')[1].split(':')[1]
                    os.popen(f"adb -s {self.device.id} shell settings put global http_proxy {ip}:{port}")
                    time.sleep(2)
                    self.print_proxy()
            else:
                print('[!] Usage: proxy [set,get,reset] [<ip>:<port>] [-t]')
        except Exception as e:
            print(e)

    def do_pull(self, line):
        """Usage: pull com.foo.bar
        Extracts an apk from the device and saves it as 'base.apk' in the working directory.
        Use it in combination with the tab key to see available packages"""

        package = line.split(' ')[0]
        try:
            base_apk = os.popen(
                f"adb -s {self.device.id} shell pm path {package} | grep base.apk | cut -d ':' -f 2").read()
            print("Extracting: " + base_apk)
            output = os.popen("adb -s {} pull {}".format(self.device.id, base_apk, package)).read()
            print(output)
            if Polar('Do you want to import the application?').ask():
                self.do_import('base.apk')
        except Exception as e:
            print(e)

    def do_query(self, line):
        """Usage: query SELECT * FROM [table name]
        Performs a raw query to the current (working) db and returns 
        the results as a list of tuples.
        Run: 'show database' to get the db structure including table names"""

        try:
            print(line)
            res = self.database.query_db(str(line))
            print(res)

        except Exception as e:
            print(e)
        return res

    def do_screencap(self, line):
        """Usage: screencap -o '[png_name.png]'
        Captures the device's screen and saves it as a png file in 
        the current directory.
        """

        try:
            if '-o' in line.split(' ')[0]:
                os.popen(f"adb -s {self.device.id} exec-out screencap -p > {line.split(' ')[1]}")
                print(f"[!] Screencap saved successfully to {line.split(' ')[1]}")
            else:
                print('[!] Usage: screencap -o filename.png')
        except Exception as e:
            print(e)
            print('[!] Usage: screencap -o filename.png')

    def do_search(self, line):

        """Usage: search 'string' [APK file]
        Searches for a given string in the apk's extracted xml files.
        Adding an apk file as a third parameter, it will use this (instead
        of the currently loaded app) using aapt2 (supports regular expressions)"""

        if self.current_app_sha256 is None:
            print(self.NO_APP_LOADED_MSG)
        else:
            try:
                inp = line.split(' ')
                what = inp[0]
                if len(inp) > 1:
                    pkg = inp[1]
                    print(RED + 'Searching Strings using aapt2:' + RESET)
                    subprocess.Popen(f'aapt2 dump strings {pkg} | grep {what} --color', shell=True)
                    return

                print(RED + 'Searching Activities:' + RESET)
                if not self.real_search(what, self.activities):
                    print(f'No Activities found containing: {what} !')

                print(RED + 'Searching Services:' + RESET)
                if not self.real_search(what, self.services):
                    print(f'No Services found containing: {what} !')

                print(RED + 'Searching Receivers:' + RESET)
                if not self.real_search(what, self.receivers):
                    print(f'No Receivers found containing: {what} !')

                print(RED + 'Searching Providers:' + RESET)
                if not self.real_search(what, self.providers):
                    print(f'No Providers found containing: {what} !')

                print(RED + 'Searching in res:' + RESET)
                found = False
                for line1 in self.strings.split('\n'):
                    if what.casefold() in line1:
                        print(line1.replace(what.casefold(), Fore.GREEN + what.casefold() + Fore.RESET))
                        found = True
                if not found:
                    print(f'No Strings found containing: {what} !')
            except Exception as e:
                print(e)

    def do_show(self, line):
        """Usage: show [applications | database | exposure | info | manifest_entry | manifest ]
        - applications: prints the currently loaded applications and allows you to load another one
        - database: prints the structure of the loaded database
        - exposure: prints the application's exposure points (exported activities, services, deeplinks etc.)
        - info: prints information about the loaded application
        - manifest_entry: prints information about the loaded application's manifest entries, including:
          activities, services, activityAlias, receivers, deeplinks, providers and intentFilters.
          Adding the '-e' option the command will print only exported components.
        - receivers -d: prints dynamically registered receivers"""

        what = line.split(' ')[0]
        if len(line.split(' ')) > 1:
            flag = line.split(' ')[1]
        else:
            flag = ''

        if 'database' in what:
            self.print_database_structure()
        elif 'applications' in what:
            self.load_or_remove_application()
        else:
            if self.current_app_sha256 is None:
                print(self.NO_APP_LOADED_MSG)
            else:
                if 'permissions' in what:
                    self.print_permissions()

                elif 'activities' in what:
                    if '-e' in flag:
                        self.print_activities(False)
                    else:
                        self.print_activities()

                elif 'services' in what:
                    if '-e' in flag:
                        self.print_services(False)
                    else:
                        self.print_services()

                elif 'activityAlias' in what:
                    if '-e' in flag:
                        self.print_activity_alias(False)
                    else:
                        self.print_activity_alias()

                elif 'receivers' in what:
                    if '-e' in flag:
                        self.print_receivers(False)
                    elif '-d' in flag:
                        self.print_receivers(True, '-d')
                    else:
                        self.print_receivers()

                elif 'info' in what:
                    self.print_application_info(self.info)

                elif 'deeplinks' in what:
                    self.print_deeplinks()

                elif 'providers' in what:
                    if '-e' in flag:
                        self.print_providers(False)
                    else:
                        self.print_providers()
                elif 'intentFilters' in what:
                    self.print_intent_filters()
                elif 'manifest' in what:
                    print(self.manifest[0][0].decode('utf-8'))
                elif 'strings' in what:
                    self.print_strings()
                elif 'exposure' in what:
                    print(
                        "|----------------------------------- [ ⚠️  ] Potential attack targets [ ⚠️  ] ---------------------------------------|\n[+] Deeplinks:")
                    self.print_deeplinks()
                    print("\n[+] Exported activities and activity aliases:")
                    self.print_activities(False)
                    self.print_activity_alias(False)
                    print("[+] Exported services:")
                    self.print_services(False)
                    print("[+] Exported receivers:")
                    self.print_receivers(False)
                    print("[+] Exported providers:")
                    self.print_providers(False)

                else:
                    print(
                        '[i] Usage: show [activities, activityAlias, applications, database, deeplinks, exposure, info, intentFilters, manifest, permissions, providers, receivers, services, strings]')

    def do_spawn(self, package):
        """Usage: spawn [package name]
        Starts an app in the device. 
        Use it in combination with the tab key to see available packages. """

        try:
            print(f'[+] Starting {package}')
            os.popen(
                f"adb -s {self.device.id} shell  monkey -p {package.split(' ')[0]} -c 'android.intent.category.LAUNCHER 1'").read()
            print(f'[+] {package} started')
        except Exception as e:
            print(e)

    def do_start(self, line):
        """Usage: start [full activity name]
        Sends an intent to start an activity of the currently loaded application. 
        Use it in combination with the tab key to see the available activities. 
        Plase note that for not exported activities, adb must run with root 
        privileges (adb root)."""

        if self.current_app_sha256 is None:
            print(self.NO_APP_LOADED_MSG)
        else:
            try:
                cmd = f"adb -s {self.device.id} shell 'su -c \"am start -n {self.info[0][2]}/{line.split(' ')[0]}\"'"
                print(f"adb command: {cmd}")
                output = os.popen(cmd).read()
                print(output)
            except Exception as e:
                print(e)

    def do_startsrv(self, line):
        """Usage: startsrv [full class name]'
        Sends an intent to start a service of the currently loaded application. 
        Use it in combination with the tab key to see the available activities. 
        Plase note that for not exported activities, adb must run with root 
        privileges (adb root)."""

        if self.current_app_sha256 is None:
            print(self.NO_APP_LOADED_MSG)
        else:
            cmd = f"adb -s {self.device.id} shell 'echo \"am startservice -n {self.info[0][2]}/{line.split(' ')[0]}\" | su'"
            print(f"adb command: {cmd}")
            try:
                output = os.popen(cmd).read()
                print(output)
            except Exception as e:
                print(e)

    def do_stopsrv(self, line):
        """Usage: stopsrv [service name]
        Uses the am in order to force the currently loaded app to stop a service. 
        Use it in combination with the tab key to see the available services. 
        Plase note that for not exported services, adb must run with root 
        privileges (adb root)."""

        if self.current_app_sha256 is None:
            print(self.NO_APP_LOADED_MSG)
        else:
            try:
                output = os.popen(
                    f"adb -s {self.device.id} shell 'echo \"am stopservice -n {self.info[0][2]}/{line.split(' ')[0]}\" | su'").read()
                print(output)
            except Exception as e:
                print(e)

    def do_trace(self, line):
        """Usage: trace -j, -n, -a [full class name]
        Examples:
        trace -j com.myapp.name*:\tTrace all the functions of the com.myapp.name* class
        trace -n foo:\t\t\tTrace a native function
        trace -a library.so:\t\tTrace the functions of the library.so
        Starts a new frida-trace instance with the given options (it opens a new window)
        """

        if self.current_app_sha256 is None:
            print(self.NO_APP_LOADED_MSG)
        else:
            try:

                opsys = platform.system()
                script = self.create_script(opsys, line)

                if 'Error' not in script:
                    if 'Darwin' in opsys:
                        subprocess.run(f"""osascript -e 'tell application "Terminal" to do script "{script}" ' """,
                                       shell=True)
                    elif 'Linux' in opsys:
                        subprocess.run(f"""x-terminal-emulator -e {script}""")
                    elif 'Windows' in opsys:
                        subprocess.call(f'start /wait {script}', shell=True)
            except Exception as e:
                print(e)

    def do_type(self, line):
        """Usage: type
        Starts an interactive prompt where you can send keys from the host 
        to the connected mobile device"""

        print("Type 'exit' to quit")
        while 'exit' not in line:
            line = input(':')
            os.popen(f"adb -s {self.device.id} shell input text {line}")

    def do_uninstall(self, package):
        """Usage: uninstall [package name]
        Uninstalls an application from the device. 
        Use it in combination with the tab key to see available packages."""

        try:
            output = os.popen(f"adb -s {self.device.id} uninstall {package.split(' ')[0]}").read()
            print(output)
        except Exception as e:
            print(e)

    ###################################################### complete defs start ############################################################

    # mark for tests, improve completes
    def complete_note(self, text, line, begidx, endidx):
        if self.current_app_sha256 is None:
            components = []
        else:
            components = sorted(['add', 'del', 'show', 'update'])
        if not text:
            completions = components[:]
        else:
            completions = [f for f in components if f.startswith(text)]
        return completions

    def complete_deeplink(self, text, line, begidx, endidx):
        if not text:
            completions = self.total_deep_links[:]
        else:
            completions = [f for f in self.total_deep_links if f.startswith(text)]
        return completions

    def complete_jdwp(self, text, line, begidx, endidx):
        return self.get_packages_starting_with(text)

    def complete_kill(self, text, line, begidx, endidx):
        return self.get_packages_starting_with(text)

    def complete_load(self, text, line, begidx, endidx):
        res = self.database.query_db("SELECT packageName,sha256 from Application order by packagename asc;")
        appSha256 = []
        for entry in res:
            appSha256.append(entry[0] + ':' + entry[1])

        if not text:
            completions = appSha256[:]
            appSha256 = []
        else:
            completions = [f for f in appSha256 if f.startswith(text)]
            appSha256 = []
        return completions

    def complete_logcat(self, text, line, begidx, endidx):
        return self.get_packages_starting_with(text)

    def complete_proxy(self, text, line, begidx, endidx):
        proxy_cmd = ['set', 'get', 'reset']
        if not text:
            completions = proxy_cmd[:]
        else:
            completions = [f for f in proxy_cmd if f.startswith(text)]
        return completions

    def complete_pull(self, text, line, begidx, endidx):
        return self.get_packages_starting_with(text)

    def complete_show(self, text, line, begidx, endidx):
        if self.current_app_sha256 is None:
            components = ['database', 'applications']
        else:
            components = sorted(
                ['exposure', 'applications', 'activityAlias', 'info', 'permissions', 'activities', 'services',
                 'receivers', 'intentFilters', 'providers', 'deeplinks', 'strings', 'database', 'manifest'])
        if not text:
            completions = components[:]
        else:
            completions = [f for f in components if f.startswith(text)]
        return completions

    def complete_start(self, text, line, begidx, endidx):
        if not text:
            completions = self.activity_names[:]
        else:
            completions = [f for f in self.activity_names if f.startswith(text)]
        return completions

    def complete_startsrv(self, text, line, begidx, endidx):
        if not text:
            completions = self.service_names[:]
        else:
            completions = [f for f in self.service_names if f.startswith(text)]
        return completions

    def complete_stopsrv(self, text, line, begidx, endidx):
        if not text:
            completions = self.services[:]
        else:
            completions = [f for f in self.services if f.startswith(text)]
        return completions

    def complete_spawn(self, text, line, begidx, endidx):
        return self.get_packages_starting_with(text)

    def complete_uninstall(self, text, line, begidx, endidx):
        return self.get_packages_starting_with(text)

    ###################################################### print defs start ############################################################

    def get_packages_starting_with(self, text):
        self.init_packages()
        if not text:
            completions = self.packages[:]
            self.packages = []
        else:
            completions = [f for f in self.packages if f.startswith(text)]
            self.packages = []
        return completions

    def print_activities(self, all=True):
        display_text = ''
        for attribs in self.activities:
            display_text = attribs[1]
            if attribs[2]:
                display_text += Fore.RED + ' | enabled = ' + attribs[2] + ' |' + Fore.RESET
            if attribs[3]:
                display_text += Fore.GREEN + ' | exported = ' + attribs[3] + Fore.RESET
            if (not all) and (not attribs[3] or ('true' not in attribs[3])):
                continue
            else:
                print(display_text)
        print(Style.RESET_ALL)

    def print_activity_alias(self, all=True):
        display_text = ''
        for attribs in self.activityallias:
            display_text = attribs[1]
            if attribs[2]:
                display_text += Fore.RED + ' | enabled = ' + attribs[2] + ' |' + Fore.RESET
            if attribs[3]:
                display_text += Fore.GREEN + ' | exported = ' + attribs[3] + ' |' + Fore.RESET
            if attribs[5]:
                display_text += Fore.CYAN + ' | Target = ' + attribs[5] + Fore.RESET

            if (not all) and (not attribs[3] or ('true' not in attribs[3])):
                continue
            else:
                print(display_text)
        print(Style.RESET_ALL)

    def print_application_info(self, info):
        print(Back.BLACK + Fore.RED + Style.BRIGHT + """
[------------------------------------Package Details---------------------------------------]:
|    Original Filename :{}
|    Application Name  :{}
|    Package Name      :{}
|    Version code      :{}
|    Version Name      :{}
|    Mimimum SDK       :{}
|    Target  SDK       :{}
|    Max SDK           :{}
|    Sha256            :{}
|    Debuggable        :{}
|    Allow Backup      :{}
|    Evasion Tactics   :{}
[------------------------------------------------------------------------------------------]
|                          Type 'help' or 'man' for a list of commands                     |
[------------------------------------------------------------------------------------------]
        """.format(info[0][14], info[0][1], info[0][2], info[0][3], info[0][4],
                   info[0][5], info[0][6], info[0][7], info[0][0], info[0][10], info[0][11],
                   info[0][15]) + Style.RESET_ALL)
        print(BLUE + "[i] Notes:" + RESET)
        notes = self.database.get_all_notes(info[0][0])
        if len(notes) == 0:
            print("No notes found!")
        else:
            for index, sha256, cmt in notes:
                print(f'{index}) {cmt}')

    def print_database_structure(self):
        res = self.database.query_db("SELECT name FROM sqlite_master WHERE type='table';")
        for entry in res:
            print(Fore.GREEN + "-" * 40 + f"\nTable Name: {entry[0]}\n" + "-" * 40 + Fore.RESET)
            columns = self.database.query_db(f"PRAGMA table_info({entry[0]});")
            print("{c: <25} {t: <15}".format(c="Column Name", t="Type"))
            for column in columns:
                print("{c: <25} {t: <15}".format(c=column[1], t=column[2]))

    def print_deeplinks(self, quite=False):
        display_text = ''
        component = ''
        schmlst = []
        hostlst = []
        pathPrefixlst = []

        for attribs in self.deeplinks:
            if component != attribs[0]:
                component = attribs[0]
                l = len(component)
                if not quite:
                    print(
                        Fore.GREEN + '-' * l + Fore.YELLOW + '\nDeeplinks that start:' + Fore.CYAN + f'{component}' + Fore.RESET)

            detonate = attribs[1].split('|')

            schemes = ''
            schmlst.clear()
            for ingredient in detonate:
                if 'scheme:' in ingredient:
                    t = ingredient.split(':')[1]
                    schemes += t
                    schemes += ' '
                    schmlst.append(t)

                self.schemes = set.union(self.schemes, set(schmlst))
            # if not quite:
            #     print("Schemes: "+schemes)

            hosts = ''
            hostlst.clear()
            for ingredient in detonate:
                if 'host:' in ingredient:
                    j = ingredient.split(':')[1]
                    hosts += j
                    hosts += ' '
                    hostlst.append(j)

                self.hosts = set.union(self.hosts, set(hostlst))

            # if not quite:
            #     print("Hosts: "+hosts)

            paths = ['path:', 'pathPrefix:', 'pathPattern:']
            pathPrefix = ''
            pathPrefixlst.clear()
            for ingredient in detonate:
                if any(pth in ingredient for pth in paths):
                    # if 'pathPrefix:' in igredient:
                    p = ingredient.split(':')[1]
                    pathPrefix += p
                    pathPrefix += ' '
                    pathPrefixlst.append(p)
                self.pathPrefixes = set.union(self.pathPrefixes, set(pathPrefixlst))

            # if not quite:
            #     print("pathPrefix: "+pathPrefix)

            if not pathPrefixlst:
                pathPrefixlst.append('')
            if not hostlst:
                hostlst.append('')

            tmplst = []
            for s in schmlst:
                for h in hostlst:
                    for p in pathPrefixlst:
                        link = s + '://' + h + p
                        if link not in tmplst:
                            tmplst.append(link)
            if not quite:
                for lnk in tmplst:
                    print(lnk)

            self.total_deep_links += tmplst

    def print_intent_filters(self):
        display_text = ''
        for attribs in self.intent_filters:
            l = len(attribs[0])
            print(Fore.GREEN + '-' * l + f'\nComponent:{attribs[0]}' + Fore.RESET)

            if attribs[1]:
                print('Action(s): ' + attribs[1].replace('|', ' # '))
            if attribs[2]:
                print('Category: ' + attribs[2].replace('|', ' # '))

            print(Fore.GREEN + '-' * l + Fore.RESET)
        print(Style.RESET_ALL)

    def print_permissions(self):
        display_text = ''
        for permission in self.permissions:
            print("#" * 92)
            display_text = Fore.GREEN + 'Name:' + Fore.RESET + permission[1] + '\n'
            display_text += Fore.GREEN + 'Type:' + Fore.RESET + permission[2] + '\n'
            display_text += Fore.GREEN + 'Description:' + Fore.RESET + permission[4] + '\n'
            print(display_text)

    def print_providers(self, all=True):
        try:
            display_text = ''
            for attribs in self.providers:
                display_text = attribs[1]
                if attribs[2]:
                    display_text += Fore.RED + ' | enabled = ' + attribs[2] + ' |' + Fore.RESET
                if attribs[3]:
                    display_text += Fore.GREEN + ' | exported = ' + attribs[3] + ' |' + Fore.RESET
                if attribs[4]:
                    display_text += Fore.CYAN + ' | grandUriPermission = ' + attribs[4] + Fore.RESET
                if attribs[9]:
                    display_text += Fore.CYAN + ' | authorities = ' + attribs[9] + Fore.RESET
                if (not all) and (not attribs[3] or ('true' not in attribs[3])):
                    continue
                else:
                    print(display_text)
            print(Style.RESET_ALL)
        except Exception as e:
            print("An error occured")

    def print_proxy(self):

        settings = os.popen(f"adb -s {self.device.id} shell settings get global http_proxy").read()
        print(WHITE + "--------------Global proxy settings-----------------:" + RESET)
        print(f'Current proxy: {settings}')
        print(WHITE + "--------------IP tables settings--------------------:" + RESET)
        output = subprocess.run(f"""adb -s {self.device.id} shell 'echo "iptables -t nat -L" | su'""", shell=True)
        print(output)

    def print_receivers(self, all=True, flag=None):
        try:
            if flag == '-d':
                p = subprocess.Popen(
                    (["adb", "-s", self.device.id, "shell", "dumpsys", "activity", "broadcasts", self.package]),
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                for line in p.stdout:
                    print(line.decode("utf-8").rstrip())
                return
            display_text = ''
            for attribs in self.receivers:
                display_text = attribs[1]
                if attribs[2]:
                    display_text += Fore.RED + ' | enabled = ' + attribs[2] + ' |' + Fore.RESET
                if attribs[3]:
                    display_text += Fore.GREEN + ' | exported = ' + attribs[3] + ' |' + Fore.RESET
                if attribs[4]:
                    display_text += Fore.CYAN + ' | permission = ' + attribs[4] + Fore.RESET

                if (not all) and (not attribs[3] or ('true' not in attribs[3])):
                    continue
                else:
                    print(display_text)
            print(Style.RESET_ALL)
        except Exception as e:
            print(f"An error occurred: {e}")

    def print_services(self, all=True):
        try:
            display_text = ''
            for attribs in self.services:
                display_text = attribs[1]
                if attribs[2]:
                    display_text += Fore.RED + ' | enabled = ' + attribs[2] + ' |' + Fore.RESET
                if attribs[3]:
                    display_text += Fore.GREEN + ' | exported = ' + attribs[3] + Fore.RESET
                if (not all) and (not attribs[3] or ('true' not in attribs[3])):
                    continue
                else:
                    print(display_text)
            print(Style.RESET_ALL)
        except Exception as e:
            print(f"An error occurred: {e}")

    def print_strings(self):
        for string in self.strings.split('\n'):
            print(string)

    ###################################################### real defs start ############################################################

    def real_import(self, apk_file, print_application_info=True):
        try:
            sha256 = self.guava.sha256sum(apk_file)
            if self.guava.sha256Exists(sha256):
                print("[i] The application has already being analysed !")
                self.info = self.database.get_app_info(sha256)
                self.print_application_info(self.info)
            else:
                if print_application_info:
                    self.guava.full_analysis(apk_file)
                    self.init_application_info(self.database, self.guava.sha256sum(apk_file))
                else:
                    self.guava.full_analysis(apk_file, False)
                    self.info = self.database.get_app_info(self.guava.sha256sum(apk_file))
                    print(f"Package Name: {self.info[0][2]}")
        except Exception as e:
            print(e)
            print(RED + f"There was an error loading {apk_file}" + RESET)

    def real_load_app(self, chosen_sha256):
        self.init_application_info(self.database, chosen_sha256)

    def real_remove_app(self, chosen_sha256):
        self.database.delete_application(chosen_sha256)

    def real_search(self, word, obj):
        found = False
        for module in obj:
            if word.casefold() in module[1].casefold():
                print(module[1].replace(word.casefold(), Fore.GREEN + word.casefold() + Fore.RESET))
                found = True
        return found

    ###################################################### rest of defs start ############################################################

    def continue_session(self, guava):
        self.guava = guava
        res = self.database.query_db("SELECT sha256, packageName from Application order by packagename asc;")
        if res:
            print(
                Fore.GREEN + "[i] Availlable applications:\n" + Fore.RESET + "-" * 7 + " " + "-" * 70 + " " + "-" * 57 + "\n {0} {1:^68} {2:^60}\n".format(
                    "index", "sha256", "Package Name") + "-" * 7 + " " + "-" * 70 + " " + "-" * 57)
            index = 0
            for entry in res:
                sha256, package_name = entry
                print(Fore.CYAN + Style.BRIGHT + "{0:^7} {1:^68}\t {2:<60}".format(index, sha256, package_name))
                index += 1
                self.total_apps.append(package_name + ":" + sha256)

            chosen_index = int(Numeric(Style.RESET_ALL + '\nEnter the index of  application to load:', lbound=0,
                                       ubound=index - 1).ask())
            chosen_sha256 = res[chosen_index][0]
            self.init_application_info(self.database, chosen_sha256)
        else:
            print(Fore.RED + Style.BRIGHT + "[!] No Entries found in the given database !" + Style.RESET_ALL)
        return

    def create_script(self, opsys, line):
        switch = line.split(' ')[0].strip()
        valid = True
        if '-j' in switch:
            param1 = line.split(' ')[1] + '*!*'
            param = f"""frida-trace -D {self.device.id} -f {self.info[0][2]} -j '{param1}' """
        elif '-n' in switch:
            param1 = line.split(' ')[1] + '*'
            param = f"""frida-trace -D {self.device.id} -i '{param1}' {self.info[0][2]}"""
        elif '-a' in switch:
            param1 = line.split(' ')[1].strip()
            param = f"""frida-trace -D {self.device.id} -I '{param1}' {self.info[0][2]}"""
        else:
            print('[E] Invalid command, run help for options!')
            valid = False
        if valid:
            path = os.getcwd()
            if 'Windows' in opsys:
                script = path + '/script.bat'
                with open(script, 'w') as file:
                    file.write(param)
            else:
                script = path + '/script.sh'
                with open(script, 'w') as file:
                    file.write(param)
                os.chmod(script, 0o775)
        else:
            script = 'Error'
        return script

    def does_exist(self, name):
        return which(name) is not None

    def download_file(self, url, to_local_file):
        local_filename = to_local_file
        r = requests.get(url, allow_redirects=True)
        open(local_filename, 'wb').write(r.content)

    def highlight(self, word, str):
        if word.casefold() in str.casefold():
            return str.replace(word.casefold(),
                               Back.WHITE + Style.BRIGHT + Fore.BLACK + word.casefold() + Style.RESET_ALL)
        else:
            return ''

    def init_application_info(self, application_database, app_sha256):
        try:
            self.info = application_database.get_app_info(app_sha256)
            self.print_application_info(self.info)
            self.activities = application_database.get_all_activities(app_sha256)
            self.permissions = application_database.get_all_permissions(app_sha256)
            self.services = application_database.get_all_services(app_sha256)
            self.activityallias = application_database.get_all_alias_activities(app_sha256)
            self.receivers = application_database.get_all_receivers(app_sha256)
            self.providers = application_database.get_all_providers(app_sha256)
            self.intent_filters = application_database.get_intent_filters(app_sha256)
            self.activity_names = list('\n'.join(map(lambda x: str(x[0]), application_database.query_db(
                f"SELECT name from Activities WHERE app_sha256='{app_sha256}'"))).split('\n'))
            self.service_names = list('\n'.join(map(lambda x: str(x[0]), application_database.query_db(
                f"SELECT name from Services WHERE app_sha256='{app_sha256}'"))).split('\n'))
            self.manifest = application_database.query_db(
                f"SELECT androidManifest FROM Application WHERE sha256='{app_sha256}';")
            self.strings = \
            application_database.query_db(f"SELECT stringResources FROM Application WHERE sha256='{app_sha256}';")[0][
                0].decode('utf-8')
            self.total_deep_links = []
            self.package = self.info[0][2]
            self.deeplinks = application_database.get_deeplinks(app_sha256)
            self.notes = application_database.get_all_notes(app_sha256)
            self.print_deeplinks(True)  # propagate the deeplink lists
            self.current_app_sha256 = app_sha256
        except Exception as e:
            print(e)

    def init_packages(self):
        for line1 in os.popen(f'adb -s {self.device.id} shell pm list packages'):
            self.packages.append(line1.split(':')[1].strip('\n'))

    def load_or_remove_application(self):
        res = self.database.query_db("SELECT sha256, packageName from Application order by packageName asc;")
        if res:
            print(
                Fore.GREEN + "[i] Availlable applications:\n" + Fore.RESET + "-" * 7 + " " + "-" * 70 + " " + "-" * 57 + "\n {0} {1:^68} {2:^60}\n".format(
                    "index", "sha256", "Package Name") + "-" * 7 + " " + "-" * 70 + " " + "-" * 57)
            index = 0
            for entry in res:
                sha256, package_name = entry
                print(Fore.CYAN + Style.BRIGHT + "{0:^7} {1:^68}\t {2:<60}".format(index, sha256, package_name))
                index += 1
            task = int(Numeric(
                Style.RESET_ALL + '\n[i] Options: \n\t\t0 - Load an application \n\t\t1 - Delete an application \n\t\t2 - Exit this submenu\n\n[?] Please choose an option:',
                lbound=0, ubound=2).ask())
            if task != 2:
                chosen_index = int(Numeric(Style.RESET_ALL + '\nEnter the index of the application:', lbound=0,
                                           ubound=index - 1).ask())
                chosen_sha256 = res[chosen_index][0]
            if task == 0:
                self.real_load_app(chosen_sha256)
            elif task == 1:
                if self.current_app_sha256 == chosen_sha256:
                    if Polar("[!] The application is currently loaded, do you still want to delete it ?").ask():
                        self.current_app_sha256 = None
                        self.real_remove_app(chosen_sha256)
                    else:
                        return
                else:
                    self.real_remove_app(chosen_sha256)
            elif task == 2:
                return
        else:
            print(Fore.RED + Style.BRIGHT + "[!] No Entries found in the given database !" + Style.RESET_ALL)
        return

    def run_command(self, cmd):
        proccess = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = proccess.communicate()
        if proccess.returncode != 0:
            return error
        else:
            return output

    def transproxy(self, ip, port):
        trasnproxy_path = os.path.join(self.base_directory, '../utils/transproxy.sh')
        try:
            print('[i] Pushing transproxy script !')
            os.popen(f"adb -s {self.device.id} push {trasnproxy_path} /data/local/tmp/transproxy.sh").read()
            print('[i] Executing script')
            os.popen(
                f"adb -s {self.device.id} shell 'chmod +x /data/local/tmp/transproxy.sh; echo \"/data/local/tmp/transproxy.sh {ip} {port}\" | su; rm /data/local/tmp/transproxy.sh'").read()
            self.print_proxy()
        except Exception as e:
            print(e)

import subprocess
import time
from colorama import Fore


class android_device:
    id = None
    properties = []

    def __init__(self, id) -> None:
        super().__init__()
        self.id = id
        self.get_dev_properties()

    def get_dev_properties(self):
        self.properties = list(str(self.run_command(["adb", "-s", self.id, "shell", "getprop"])).split('\\n'))

    def get_process_pid_by_package_name(self, package_name):
        pid = None
        while pid is None:
            try:
                pid_output = subprocess.check_output(["adb", "-s", self.id, "shell", "pidof", package_name], text=True)
                pid = pid_output.strip()
                if pid:
                    print(f"App '{package_name}' PID: {pid}")
                else:
                    print(f"App '{package_name}' is not running yet. Retrying in {2} seconds...")
                    time.sleep(2)
            except subprocess.CalledProcessError:
                print(f"App '{package_name}' is not running yet. Retrying in {2} seconds...")
                time.sleep(2)
        return self.run_command(["adb", "-s", self.id, "shell", "pidof", "-s", f"{package_name}"])

    def print_dev_properties(self):
        print('\nDevice properties:\n')
        self.print_dev_property('ro.product.manufacturer')
        self.print_dev_property('ro.product.name')
        self.print_dev_property('ro.build.version.')
        self.print_dev_property('ro.build.id')
        self.print_dev_property('ro.build.tags')

    def print_dev_property(self, prop):
        for property in self.properties:
            if prop in str(property):
                print(property.split(':')[0] + ':', end='')

                print(Fore.GREEN + property.split(':')[1] + Fore.RESET)

    def print_java_crash_log(self):
        p = subprocess.Popen((["adb", "-s", self.id, "logcat", "-s", "AndroidRuntime"]), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        for line in p.stdout:
            print(line.decode("utf-8").rstrip())

    def print_native_crash_log(self):
        p = subprocess.Popen((["adb", "-s", self.id, "logcat", "-s", "libc,DEBUG"]), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        for line in p.stdout:
            print(line.decode("utf-8").rstrip())

    def print_runtime_logs(self, package_name):
        try:
            pid = self.get_process_pid_by_package_name(package_name).decode('utf-8').rstrip()
            p = subprocess.Popen(["adb", "-s", self.id, "logcat", f"--pid={pid}"], stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            for line in p.stdout:
                print(line.decode("utf-8").rstrip())
        except Exception as e:
            print(f"An error occurred: {e}")

    def run_adb_command(self, cmd):
        self.run_command(["adb", "-s", self.id, cmd])

    def run_pseudo_adb_root_cmd(self, cmd):
        cmdf = ["adb", "-s", f"{self.id}", "shell", f"echo \"{cmd}\" | su"]
        process = subprocess.Popen(cmdf, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        # output, error = process.communicate()
        line = ""
        for b in process.stdout:
            line += b.decode("utf-8")
        return line

    def run_command(self, cmd):
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        if process.returncode != 0:
            return error
        else:
            return output

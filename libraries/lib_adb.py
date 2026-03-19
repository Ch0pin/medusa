import logging
import subprocess
import shutil
import time
from colorama import Fore
from typing import Optional
from libraries.logging_config import setup_logging

logging.getLogger().handlers = []  
setup_logging() 
logger = logging.getLogger(__name__)

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
    
    def get_int_pid(self, pkg: str, suppressWarning = False) -> Optional[int]:
        """
        Retrieves the PID of the specified package.
        """
        try:
            result = subprocess.run(
                ["adb", "-s", self.id, "shell", "pidof", pkg],
                capture_output=True,
                text=True,
                check=True
            )
            pid_str = result.stdout.strip()
            if pid_str:
                return int(pid_str)
            else:
                return None
        except subprocess.CalledProcessError as e:
            if not suppressWarning:
                logger.warning(f"Error retrieving PID for package '{pkg}': {e}")
            return None
        except ValueError:
            if not suppressWarning:
                logger.warning(f"Received invalid PID value for package '{pkg}': '{pid_str}'")
            return None

    def print_dev_properties(self):
        print(Fore.GREEN+'\nDevice properties:\n'+Fore.RESET)
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

    def print_runtime_logs(self, package_name: str):
        """
        Print runtime logs for a package.
        Uses pidcat if available, otherwise falls back to adb logcat.
        """
        try:
            if self._pidcat_available():
                logger.debug("Using pidcat for logcat output")
                self._print_logs_pidcat(package_name)
            else:
                logger.debug("pidcat not found; using adb logcat fallback")
                self._print_logs_logcat(package_name)
        except KeyboardInterrupt:
            pass

    def _pidcat_available(self) -> bool:
        return shutil.which("pidcat") is not None

    def _print_logs_logcat(self, package_name: str):
        try:
            pid = self.get_process_pid_by_package_name(package_name).decode('utf-8').rstrip()
            p = subprocess.Popen(["adb", "-s", self.id, "logcat", f"--pid={pid}"], stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            for line in p.stdout:
                print(line.decode("utf-8").rstrip())
        except Exception as e:
            print(f"An error occurred: {e}")

    def _print_logs_pidcat(self, package_name: str):
        cmd = ["pidcat", "-s", self.id, package_name]

        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            pass


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

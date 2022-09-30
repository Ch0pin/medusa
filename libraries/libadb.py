from ast import For
import subprocess
from colorama import Fore, Back, Style

class android_device:
    id=None
    properties = []


    def __init__(self,id) -> None:
        super().__init__()
        self.id = id
        self.get_dev_properties()
    
    def get_dev_properties(self):
        self.properties = list(str(self.run_command(["adb","-s",self.id,"shell","getprop"])).split('\\n'))
    
    def run_adb_command(self,cmd):
        self.run_command(["adb","-s",self.id,cmd])
    
    def print_runtime_logs(self,package_name):
        pid = self.get_process_pid_by_package_name(package_name).decode('utf-8').rstrip()

        p = subprocess.Popen((["adb","-s",self.id,"logcat","--pid={}".format(pid)]), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout:
            print(line.decode("utf-8").rstrip())
    
    def print_java_crash_log(self):
        p = subprocess.Popen((["adb","-s",self.id,"logcat", "-s","AndroidRuntime"]), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout:
            print(line.decode("utf-8").rstrip())
    
    def print_native_crash_log(self):
        p = subprocess.Popen((["adb","-s",self.id,"logcat","-s","libc,DEBUG"]), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout:
            print(line.decode("utf-8").rstrip())



        #p.wait()
        #status = p.poll()
        #print("process terminate with code: %s" % status)
        # pid = self.get_process_pid_by_package_name(package_name).decode('utf-8').replace('\n','')
        # print(self.run_command(["adb","-s",self.id,"logcat","--pid={}".format(pid)]))

    def get_process_pid_by_package_name(self, package_name):
        return self.run_command(["adb","-s",self.id,"shell", "pidof", "-s", "{}".format(package_name)])


    
    def print_dev_properties(self):
        print('\nDevice properties:\n')
        self.print_dev_property('ro.product.manufacturer')
        self.print_dev_property('ro.product.name')
        self.print_dev_property('ro.build.version.')
        self.print_dev_property('ro.build.id')
        self.print_dev_property('ro.build.tags')

    
    def print_dev_property(self,prop):
        for property in self.properties:
            if prop in str(property):
                print(property.split(':')[0]+':',end='')
              
                print(Fore.GREEN+property.split(':')[1]+Fore.RESET)

    def run_command(self,cmd):
        proccess = subprocess.Popen(cmd,stdout = subprocess.PIPE,stderr=subprocess.PIPE)
        output, error = proccess.communicate()
        if proccess.returncode != 0:
            return error
        else:
            return output








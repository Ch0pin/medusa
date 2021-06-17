import subprocess
import cmd
import os
import sys
import platform
import readline
import logging
import rlcompleter
import time
import frida

if 'libedit' in readline.__doc__:
    readline.parse_and_bind("bind -e")
    readline.parse_and_bind("bind ^I rl_complete")
else:
    readline.parse_and_bind("tab: complete")

RED   = "\033[1;31m"  
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
WHITE = "\033[1;37m"
YELLOW= "\033[1;33m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"
current_dir = os.getcwd()
class parser(cmd.Cmd):

    
    prompt = BLUE+'apkutils>'+RESET
    INSTALL = False
    device = None
    package = None
    permissions = None
    activities = None
    services = None
    receivers = None
    providers = None
    deeplinks = None
    deeplinks_= []
    strings = []
    filters = []

    # classes = []
    packages = []



    def run_command(self,cmd):
        proccess = subprocess.Popen(cmd,stdout = subprocess.PIPE,stderr=subprocess.PIPE)
        output, error = proccess.communicate()

        if proccess.returncode != 0:
            return error
        else:
            return output


    def do_busybox(self,line):

        arch = self.run_command(["adb","-s",'{}'.format(self.device.id),"shell","getprop","ro.product.cpu.abi"])

        if b'v8' in arch:
            binary = "busybox-armv8l"
        elif 'v7' in arch:
            binary = "busybox-armv7l"
        else:
            print("Arch is not supported !")
            return

        output = self.run_command("adb -s {} shell ls /data/local/tmp/{}".format(self.device.id,binary).split())

        if b'No such file' in output:
            print("[!] Can't find Bussybox in /data/local/tmp. Copying it from the dependencies folder...")
            self.run_command(["adb", "-s", "{}".format(self.device.id), "push", "{}/dependencies/{}".format(current_dir,binary), "/data/local/tmp/{}".format(binary)])
            self.run_command(["adb", "-s", "{}".format(self.device.id), "shell", "chmod", "+x", "/data/local/tmp/{}".format(binary)])
            print("[+] Setting the aliases file...")
            bashfile = """#!/bin/sh
alias zcip="/data/local/tmp/{0} zcip"
alias acpid="/data/local/tmp/{0} acpid"
alias add-shell="/data/local/tmp/{0} add-shell"
alias addgroup="/data/local/tmp/{0} addgroup"
alias adduser="/data/local/tmp/{0} adduser"
alias adjtimex="/data/local/tmp/{0} adjtimex"
alias arch="/data/local/tmp/{0} arch"
alias arp="/data/local/tmp/{0} arp"
alias arping="/data/local/tmp/{0} arping"
alias ash="/data/local/tmp/{0} ash"
alias awk="/data/local/tmp/{0} awk"
alias base64="/data/local/tmp/{0} base64"
alias basename="/data/local/tmp/{0} basename"
alias bc="/data/local/tmp/{0} bc"
alias beep="/data/local/tmp/{0} beep"
alias blkdiscard="/data/local/tmp/{0} blkdiscard"
alias blkid="/data/local/tmp/{0} blkid"
alias blockdev="/data/local/tmp/{0} blockdev"
alias bootchartd="/data/local/tmp/{0} bootchartd"
alias brctl="/data/local/tmp/{0} brctl"
alias bunzip2="/data/local/tmp/{0} bunzip2"
alias bzcat="/data/local/tmp/{0} bzcat"
alias bzip2="/data/local/tmp/{0} bzip2"
alias cal="/data/local/tmp/{0} cal"
alias cat="/data/local/tmp/{0} cat"
alias chat="/data/local/tmp/{0} chat"
alias chattr="/data/local/tmp/{0} chattr"
alias chgrp="/data/local/tmp/{0} chgrp"
alias chmod="/data/local/tmp/{0} chmod"
alias chown="/data/local/tmp/{0} chown"
alias chpasswd="/data/local/tmp/{0} chpasswd"
alias chpst="/data/local/tmp/{0} chpst"
alias chroot="/data/local/tmp/{0} chroot"
alias chrt="/data/local/tmp/{0} chrt"
alias chvt="/data/local/tmp/{0} chvt"
alias cksum="/data/local/tmp/{0} cksum"
alias clear="/data/local/tmp/{0} clear"
alias cmp="/data/local/tmp/{0} cmp"
alias comm="/data/local/tmp/{0} comm"
alias conspy="/data/local/tmp/{0} conspy"
alias cp="/data/local/tmp/{0} cp"
alias cpio="/data/local/tmp/{0} cpio"
alias crond="/data/local/tmp/{0} crond"
alias crontab="/data/local/tmp/{0} crontab"
alias cryptpw="/data/local/tmp/{0} cryptpw"
alias cttyhack="/data/local/tmp/{0} cttyhack"
alias cut="/data/local/tmp/{0} cut"
alias date="/data/local/tmp/{0} date"
alias dc="/data/local/tmp/{0} dc"
alias dd="/data/local/tmp/{0} dd"
alias deallocvt="/data/local/tmp/{0} deallocvt"
alias delgroup="/data/local/tmp/{0} delgroup"
alias deluser="/data/local/tmp/{0} deluser"
alias depmod="/data/local/tmp/{0} depmod"
alias devmem="/data/local/tmp/{0} devmem"
alias df="/data/local/tmp/{0} df"
alias dhcprelay="/data/local/tmp/{0} dhcprelay"
alias diff="/data/local/tmp/{0} diff"
alias dirname="/data/local/tmp/{0} dirname"
alias dmesg="/data/local/tmp/{0} dmesg"
alias dnsd="/data/local/tmp/{0} dnsd"
alias dnsdomainname="/data/local/tmp/{0} dnsdomainname"
alias dos2unix="/data/local/tmp/{0} dos2unix"
alias dpkg="/data/local/tmp/{0} dpkg"
alias dpkg-deb="/data/local/tmp/{0} dpkg-deb"
alias du="/data/local/tmp/{0} du"
alias dumpkmap="/data/local/tmp/{0} dumpkmap"
alias dumpleases="/data/local/tmp/{0} dumpleases"
alias echo="/data/local/tmp/{0} echo"
alias ed="/data/local/tmp/{0} ed"
alias egrep="/data/local/tmp/{0} egrep"
alias eject="/data/local/tmp/{0} eject"
alias env="/data/local/tmp/{0} env"
alias envdir="/data/local/tmp/{0} envdir"
alias envuidgid="/data/local/tmp/{0} envuidgid"
alias ether-wake="/data/local/tmp/{0} ether-wake"
alias expand="/data/local/tmp/{0} expand"
alias expr="/data/local/tmp/{0} expr"
alias factor="/data/local/tmp/{0} factor"
alias fakeidentd="/data/local/tmp/{0} fakeidentd"
alias fallocate="/data/local/tmp/{0} fallocate"
alias false="/data/local/tmp/{0} false"
alias fatattr="/data/local/tmp/{0} fatattr"
alias fbset="/data/local/tmp/{0} fbset"
alias fbsplash="/data/local/tmp/{0} fbsplash"
alias fdflush="/data/local/tmp/{0} fdflush"
alias fdformat="/data/local/tmp/{0} fdformat"
alias fdisk="/data/local/tmp/{0} fdisk"
alias fgconsole="/data/local/tmp/{0} fgconsole"
alias fgrep="/data/local/tmp/{0} fgrep"
alias find="/data/local/tmp/{0} find"
alias findfs="/data/local/tmp/{0} findfs"
alias flock="/data/local/tmp/{0} flock"
alias fold="/data/local/tmp/{0} fold"
alias free="/data/local/tmp/{0} free"
alias freeramdisk="/data/local/tmp/{0} freeramdisk"
alias fsck="/data/local/tmp/{0} fsck"
alias fsck.minix="/data/local/tmp/{0} fsck.minix"
alias fsfreeze="/data/local/tmp/{0} fsfreeze"
alias fstrim="/data/local/tmp/{0} fstrim"
alias fsync="/data/local/tmp/{0} fsync"
alias ftpd="/data/local/tmp/{0} ftpd"
alias ftpget="/data/local/tmp/{0} ftpget"
alias ftpput="/data/local/tmp/{0} ftpput"
alias fuser="/data/local/tmp/{0} fuser"
alias getopt="/data/local/tmp/{0} getopt"
alias getty="/data/local/tmp/{0} getty"
alias grep="/data/local/tmp/{0} grep"
alias groups="/data/local/tmp/{0} groups"
alias gunzip="/data/local/tmp/{0} gunzip"
alias gzip="/data/local/tmp/{0} gzip"
alias halt="/data/local/tmp/{0} halt"
alias hd="/data/local/tmp/{0} hd"
alias hdparm="/data/local/tmp/{0} hdparm"
alias head="/data/local/tmp/{0} head"
alias hexdump="/data/local/tmp/{0} hexdump"
alias hexedit="/data/local/tmp/{0} hexedit"
alias hostid="/data/local/tmp/{0} hostid"
alias hostname="/data/local/tmp/{0} hostname"
alias httpd="/data/local/tmp/{0} httpd"
alias hush="/data/local/tmp/{0} hush"
alias hwclock="/data/local/tmp/{0} hwclock"
alias i2cdetect="/data/local/tmp/{0} i2cdetect"
alias i2cdump="/data/local/tmp/{0} i2cdump"
alias i2cget="/data/local/tmp/{0} i2cget"
alias i2cset="/data/local/tmp/{0} i2cset"
alias i2ctransfer="/data/local/tmp/{0} i2ctransfer"
alias id="/data/local/tmp/{0} id"
alias ifconfig="/data/local/tmp/{0} ifconfig"
alias ifdown="/data/local/tmp/{0} ifdown"
alias ifenslave="/data/local/tmp/{0} ifenslave"
alias ifplugd="/data/local/tmp/{0} ifplugd"
alias ifup="/data/local/tmp/{0} ifup"
alias inetd="/data/local/tmp/{0} inetd"
alias init="/data/local/tmp/{0} init"
alias insmod="/data/local/tmp/{0} insmod"
alias install="/data/local/tmp/{0} install"
alias ionice="/data/local/tmp/{0} ionice"
alias iostat="/data/local/tmp/{0} iostat"
alias ip="/data/local/tmp/{0} ip"
alias ipaddr="/data/local/tmp/{0} ipaddr"
alias ipcalc="/data/local/tmp/{0} ipcalc"
alias ipcrm="/data/local/tmp/{0} ipcrm"
alias ipcs="/data/local/tmp/{0} ipcs"
alias iplink="/data/local/tmp/{0} iplink"
alias ipneigh="/data/local/tmp/{0} ipneigh"
alias iproute="/data/local/tmp/{0} iproute"
alias iprule="/data/local/tmp/{0} iprule"
alias iptunnel="/data/local/tmp/{0} iptunnel"
alias kbd_mode="/data/local/tmp/{0} kbd_mode"
alias kill="/data/local/tmp/{0} kill"
alias killall="/data/local/tmp/{0} killall"
alias killall5="/data/local/tmp/{0} killall5"
alias klogd="/data/local/tmp/{0} klogd"
alias last="/data/local/tmp/{0} last"
alias less="/data/local/tmp/{0} less"
alias link="/data/local/tmp/{0} link"
alias linux32="/data/local/tmp/{0} linux32"
alias linux64="/data/local/tmp/{0} linux64"
alias linuxrc="/data/local/tmp/{0} linuxrc"
alias ln="/data/local/tmp/{0} ln"
alias loadfont="/data/local/tmp/{0} loadfont"
alias loadkmap="/data/local/tmp/{0} loadkmap"
alias logger="/data/local/tmp/{0} logger"
alias login="/data/local/tmp/{0} login"
alias logname="/data/local/tmp/{0} logname"
alias logread="/data/local/tmp/{0} logread"
alias losetup="/data/local/tmp/{0} losetup"
alias lpd="/data/local/tmp/{0} lpd"
alias lpq="/data/local/tmp/{0} lpq"
alias lpr="/data/local/tmp/{0} lpr"
alias ls="/data/local/tmp/{0} ls"
alias lsattr="/data/local/tmp/{0} lsattr"
alias lsmod="/data/local/tmp/{0} lsmod"
alias lsof="/data/local/tmp/{0} lsof"
alias lspci="/data/local/tmp/{0} lspci"
alias lsscsi="/data/local/tmp/{0} lsscsi"
alias lsusb="/data/local/tmp/{0} lsusb"
alias lzcat="/data/local/tmp/{0} lzcat"
alias lzma="/data/local/tmp/{0} lzma"
alias lzop="/data/local/tmp/{0} lzop"
alias makedevs="/data/local/tmp/{0} makedevs"
alias makemime="/data/local/tmp/{0} makemime"
alias man="/data/local/tmp/{0} man"
alias md5sum="/data/local/tmp/{0} md5sum"
alias mdev="/data/local/tmp/{0} mdev"
alias mesg="/data/local/tmp/{0} mesg"
alias microcom="/data/local/tmp/{0} microcom"
alias mkdir="/data/local/tmp/{0} mkdir"
alias mkdosfs="/data/local/tmp/{0} mkdosfs"
alias mke2fs="/data/local/tmp/{0} mke2fs"
alias mkfifo="/data/local/tmp/{0} mkfifo"
alias mkfs.ext2="/data/local/tmp/{0} mkfs.ext2"
alias mkfs.minix="/data/local/tmp/{0} mkfs.minix"
alias mkfs.vfat="/data/local/tmp/{0} mkfs.vfat"
alias mknod="/data/local/tmp/{0} mknod"
alias mkpasswd="/data/local/tmp/{0} mkpasswd"
alias mkswap="/data/local/tmp/{0} mkswap"
alias mktemp="/data/local/tmp/{0} mktemp"
alias modinfo="/data/local/tmp/{0} modinfo"
alias modprobe="/data/local/tmp/{0} modprobe"
alias more="/data/local/tmp/{0} more"
alias mount="/data/local/tmp/{0} mount"
alias mountpoint="/data/local/tmp/{0} mountpoint"
alias mpstat="/data/local/tmp/{0} mpstat"
alias mt="/data/local/tmp/{0} mt"
alias mv="/data/local/tmp/{0} mv"
alias nameif="/data/local/tmp/{0} nameif"
alias nanddump="/data/local/tmp/{0} nanddump"
alias nandwrite="/data/local/tmp/{0} nandwrite"
alias nbd-client="/data/local/tmp/{0} nbd-client"
alias nc="/data/local/tmp/{0} nc"
alias netstat="/data/local/tmp/{0} netstat"
alias nice="/data/local/tmp/{0} nice"
alias nl="/data/local/tmp/{0} nl"
alias nmeter="/data/local/tmp/{0} nmeter"
alias nohup="/data/local/tmp/{0} nohup"
alias nologin="/data/local/tmp/{0} nologin"
alias nproc="/data/local/tmp/{0} nproc"
alias nsenter="/data/local/tmp/{0} nsenter"
alias nslookup="/data/local/tmp/{0} nslookup"
alias ntpd="/data/local/tmp/{0} ntpd"
alias nuke="/data/local/tmp/{0} nuke"
alias od="/data/local/tmp/{0} od"
alias openvt="/data/local/tmp/{0} openvt"
alias partprobe="/data/local/tmp/{0} partprobe"
alias passwd="/data/local/tmp/{0} passwd"
alias paste="/data/local/tmp/{0} paste"
alias patch="/data/local/tmp/{0} patch"
alias pgrep="/data/local/tmp/{0} pgrep"
alias pidof="/data/local/tmp/{0} pidof"
alias ping="/data/local/tmp/{0} ping"
alias ping6="/data/local/tmp/{0} ping6"
alias pipe_progress="/data/local/tmp/{0} pipe_progress"
alias pivot_root="/data/local/tmp/{0} pivot_root"
alias pkill="/data/local/tmp/{0} pkill"
alias pmap="/data/local/tmp/{0} pmap"
alias popmaildir="/data/local/tmp/{0} popmaildir"
alias poweroff="/data/local/tmp/{0} poweroff"
alias powertop="/data/local/tmp/{0} powertop"
alias printenv="/data/local/tmp/{0} printenv"
alias printf="/data/local/tmp/{0} printf"
alias ps="/data/local/tmp/{0} ps"
alias pscan="/data/local/tmp/{0} pscan"
alias pstree="/data/local/tmp/{0} pstree"
alias pwd="/data/local/tmp/{0} pwd"
alias pwdx="/data/local/tmp/{0} pwdx"
alias raidautorun="/data/local/tmp/{0} raidautorun"
alias rdate="/data/local/tmp/{0} rdate"
alias rdev="/data/local/tmp/{0} rdev"
alias readahead="/data/local/tmp/{0} readahead"
alias readlink="/data/local/tmp/{0} readlink"
alias readprofile="/data/local/tmp/{0} readprofile"
alias realpath="/data/local/tmp/{0} realpath"
alias reboot="/data/local/tmp/{0} reboot"
alias reformime="/data/local/tmp/{0} reformime"
alias remove-shell="/data/local/tmp/{0} remove-shell"
alias renice="/data/local/tmp/{0} renice"
alias reset="/data/local/tmp/{0} reset"
alias resize="/data/local/tmp/{0} resize"
alias resume="/data/local/tmp/{0} resume"
alias rev="/data/local/tmp/{0} rev"
alias rm="/data/local/tmp/{0} rm"
alias rmdir="/data/local/tmp/{0} rmdir"
alias rmmod="/data/local/tmp/{0} rmmod"
alias route="/data/local/tmp/{0} route"
alias rpm="/data/local/tmp/{0} rpm"
alias rpm2cpio="/data/local/tmp/{0} rpm2cpio"
alias rtcwake="/data/local/tmp/{0} rtcwake"
alias run-init="/data/local/tmp/{0} run-init"
alias run-parts="/data/local/tmp/{0} run-parts"
alias runlevel="/data/local/tmp/{0} runlevel"
alias runsv="/data/local/tmp/{0} runsv"
alias runsvdir="/data/local/tmp/{0} runsvdir"
alias rx="/data/local/tmp/{0} rx"
alias script="/data/local/tmp/{0} script"
alias scriptreplay="/data/local/tmp/{0} scriptreplay"
alias sed="/data/local/tmp/{0} sed"
alias sendmail="/data/local/tmp/{0} sendmail"
alias seq="/data/local/tmp/{0} seq"
alias setarch="/data/local/tmp/{0} setarch"
alias setconsole="/data/local/tmp/{0} setconsole"
alias setfattr="/data/local/tmp/{0} setfattr"
alias setfont="/data/local/tmp/{0} setfont"
alias setkeycodes="/data/local/tmp/{0} setkeycodes"
alias setlogcons="/data/local/tmp/{0} setlogcons"
alias setpriv="/data/local/tmp/{0} setpriv"
alias setserial="/data/local/tmp/{0} setserial"
alias setsid="/data/local/tmp/{0} setsid"
alias setuidgid="/data/local/tmp/{0} setuidgid"
alias sh="/data/local/tmp/{0} sh"
alias sha1sum="/data/local/tmp/{0} sha1sum"
alias sha256sum="/data/local/tmp/{0} sha256sum"
alias sha3sum="/data/local/tmp/{0} sha3sum"
alias sha512sum="/data/local/tmp/{0} sha512sum"
alias showkey="/data/local/tmp/{0} showkey"
alias shred="/data/local/tmp/{0} shred"
alias shuf="/data/local/tmp/{0} shuf"
alias slattach="/data/local/tmp/{0} slattach"
alias sleep="/data/local/tmp/{0} sleep"
alias smemcap="/data/local/tmp/{0} smemcap"
alias softlimit="/data/local/tmp/{0} softlimit"
alias sort="/data/local/tmp/{0} sort"
alias split="/data/local/tmp/{0} split"
alias ssl_client="/data/local/tmp/{0} ssl_client"
alias start-stop-daemon="/data/local/tmp/{0} start-stop-daemon"
alias stat="/data/local/tmp/{0} stat"
alias strings="/data/local/tmp/{0} strings"
alias stty="/data/local/tmp/{0} stty"
alias su="/data/local/tmp/{0} su"
alias sulogin="/data/local/tmp/{0} sulogin"
alias sum="/data/local/tmp/{0} sum"
alias sv="/data/local/tmp/{0} sv"
alias svc="/data/local/tmp/{0} svc"
alias svlogd="/data/local/tmp/{0} svlogd"
alias svok="/data/local/tmp/{0} svok"
alias swapoff="/data/local/tmp/{0} swapoff"
alias swapon="/data/local/tmp/{0} swapon"
alias switch_root="/data/local/tmp/{0} switch_root"
alias sync="/data/local/tmp/{0} sync"
alias sysctl="/data/local/tmp/{0} sysctl"
alias syslogd="/data/local/tmp/{0} syslogd"
alias tac="/data/local/tmp/{0} tac"
alias tail="/data/local/tmp/{0} tail"
alias tar="/data/local/tmp/{0} tar"
alias taskset="/data/local/tmp/{0} taskset"
alias tc="/data/local/tmp/{0} tc"
alias tcpsvd="/data/local/tmp/{0} tcpsvd"
alias tee="/data/local/tmp/{0} tee"
alias telnet="/data/local/tmp/{0} telnet"
alias telnetd="/data/local/tmp/{0} telnetd"
alias test="/data/local/tmp/{0} test"
alias tftp="/data/local/tmp/{0} tftp"
alias tftpd="/data/local/tmp/{0} tftpd"
alias time="/data/local/tmp/{0} time"
alias timeout="/data/local/tmp/{0} timeout"
alias top="/data/local/tmp/{0} top"
alias touch="/data/local/tmp/{0} touch"
alias tr="/data/local/tmp/{0} tr"
alias traceroute="/data/local/tmp/{0} traceroute"
alias traceroute6="/data/local/tmp/{0} traceroute6"
alias true="/data/local/tmp/{0} true"
alias truncate="/data/local/tmp/{0} truncate"
alias ts="/data/local/tmp/{0} ts"
alias tty="/data/local/tmp/{0} tty"
alias ttysize="/data/local/tmp/{0} ttysize"
alias tunctl="/data/local/tmp/{0} tunctl"
alias ubiattach="/data/local/tmp/{0} ubiattach"
alias ubidetach="/data/local/tmp/{0} ubidetach"
alias ubimkvol="/data/local/tmp/{0} ubimkvol"
alias ubirename="/data/local/tmp/{0} ubirename"
alias ubirmvol="/data/local/tmp/{0} ubirmvol"
alias ubirsvol="/data/local/tmp/{0} ubirsvol"
alias ubiupdatevol="/data/local/tmp/{0} ubiupdatevol"
alias udhcpc="/data/local/tmp/{0} udhcpc"
alias udhcpc6="/data/local/tmp/{0} udhcpc6"
alias udhcpd="/data/local/tmp/{0} udhcpd"
alias udpsvd="/data/local/tmp/{0} udpsvd"
alias uevent="/data/local/tmp/{0} uevent"
alias umount="/data/local/tmp/{0} umount"
alias uname="/data/local/tmp/{0} uname"
alias unexpand="/data/local/tmp/{0} unexpand"
alias uniq="/data/local/tmp/{0} uniq"
alias unix2dos="/data/local/tmp/{0} unix2dos"
alias unlink="/data/local/tmp/{0} unlink"
alias unlzma="/data/local/tmp/{0} unlzma"
alias unshare="/data/local/tmp/{0} unshare"
alias unxz="/data/local/tmp/{0} unxz"
alias unzip="/data/local/tmp/{0} unzip"
alias uptime="/data/local/tmp/{0} uptime"
alias users="/data/local/tmp/{0} users"
alias usleep="/data/local/tmp/{0} usleep"
alias uudecode="/data/local/tmp/{0} uudecode"
alias uuencode="/data/local/tmp/{0} uuencode"
alias vconfig="/data/local/tmp/{0} vconfig"
alias vi="/data/local/tmp/{0} vi"
alias vlock="/data/local/tmp/{0} vlock"
alias volname="/data/local/tmp/{0} volname"
alias w="/data/local/tmp/{0} w"
alias wall="/data/local/tmp/{0} wall"
alias watch="/data/local/tmp/{0} watch"
alias watchdog="/data/local/tmp/{0} watchdog"
alias wc="/data/local/tmp/{0} wc"
alias wget="/data/local/tmp/{0} wget"
alias which="/data/local/tmp/{0} which"
alias who="/data/local/tmp/{0} who"
alias whoami="/data/local/tmp/{0} whoami"
alias whois="/data/local/tmp/{0} whois"
alias xargs="/data/local/tmp/{0} xargs"
alias xxd="/data/local/tmp/{0} xxd"
alias xz="/data/local/tmp/{0} xz"
alias xzcat="/data/local/tmp/{0} xzcat"
alias yes="/data/local/tmp/{0} yes"
alias zcat="/data/local/tmp/{0} zcat"
alias zcip="/data/local/tmp/{0} zcip"
alias help="/data/local/tmp/{0}"
echo 'Aliases have been set, type help to see available commands'
""".format(binary)
            f = open("busybox.sh","w")
            f.write(bashfile)
            f.close()
            subprocess.run("""adb -s {} push busybox.sh /data/local/tmp/busybox.sh""".format(self.device.id),shell=True)
            subprocess.run("""adb -s {} shell chmod +x /data/local/tmp/busybox.sh""".format(self.device.id),shell=True)
            print("[+] Busybox support has been installed.\n[+] Type: source /data/local/tmp/busybox.sh")
            os.remove('./busybox.sh')
            self.do_adb("adb","shell",True)
        else:
            print("[+] Busybox support has already been installed.\n[+] Type: source /data/local/tmp/busybox.sh")
            self.do_adb("adb","shell",True)

    def do_search(self, line):
        found = False
        try:
            what = line.split(' ')[0]
            print(RED+'Searching Activities:'+RESET)
            for module in self.activities:
                if what.lower() in module.lower():
                    print('[+] '+module[:str(module.lower()).find(what.lower())]+GREEN+what+RESET+module[str(module.lower()).find(what.lower())+len(what.lower()):])
                    print("[Original String: {}]\n".format(module))
                    found = True
            if not found:
                print('No Activities found containing: {} !'.format(what))
            found = False
            
            print(RED+'Searching Services:'+RESET)
            for module in self.services:
                if what.lower() in module.lower():
                    print('[+] '+module[:str(module.lower()).find(what.lower())]+GREEN+what+RESET+module[str(module.lower()).find(what.lower())+len(what.lower()):])
                    print("[Original String: {}]\n".format(module))
                    found = True
            if not found:
                print('No Services found containing: {} !'.format(what))
            found = False

            print(RED+'Searching Receivers:'+RESET)
            for module in self.receivers:
                if what.lower() in module.lower():
                    print('[+] '+module[:str(module.lower()).find(what.lower())]+GREEN+what+RESET+module[str(module.lower()).find(what.lower())+len(what.lower()):])
                    print("[Original String: {}]\n".format(module))
                    found = True
            if not found:
                print('No Receivers found containing: {} !'.format(what))
            found = False

            print(RED+'Searching Providers:'+RESET)
            for module in self.providers:
                if what.lower() in module.lower():
                    print('[+] '+module[:str(module.lower()).find(what.lower())]+GREEN+what+RESET+module[str(module.lower()).find(what.lower())+len(what.lower()):])
                    print("[Original String: {}]\n".format(module))
                    found = True
            if not found:
                print('No Providers found containing: {} !'.format(what))
            found = False  

            print(RED+'Searching Strings.xml:'+RESET)
            for module in self.strings:
                if what.lower() in module.lower():
                    print('[+] '+module[:str(module.lower()).find(what.lower())]+GREEN+what+RESET+module[str(module.lower()).find(what.lower())+len(what.lower()):])
                    print("[Original String: {}]\n".format(module))
                    found = True
            if not found:
                print('No Strings found containing: {} !'.format(what))
            found = False  

        except Exception as e:
            print(e)




    def do_deeplink(self,line):
        try:
            if len(line.split()) > 1 and '--poc' in line.split()[1]:
                print("[+] Creating POC")
                poc = '<head></head>'+'<body>'+'<a href="'+line.split()[0]+'">DEEPLINK POC</a></body></html>'
                f = open("poc.html",'w')
                f.write(poc)
                f.close()
                print("[+] POC created")

            else:
                output=os.popen("adb -s {} shell am start -W -a android.intent.action.VIEW -d {}".format(self.device.id,line.split(' ')[0])).read()
                print(output)
        except Exception as e:
            print(e)

    def complete_deeplink(self, text, line, begidx, endidx):

        if not text:
            completions = self.deeplinks_[:]
        else:
            completions = [ f
                            for f in self.deeplinks_
                            if f.startswith(text)
                            ]
        return completions

    def printDeepLinksMap(self):
        a = 0
        print(GREEN+'\n'+'-'*40+'DeepLinks Map'+'-'*40+':'+RESET)
        try:
            for key in self.deeplinks:
                print(BLUE+'Deeplinks that trigger: '+GREEN+key+RESET)
                for value in self.deeplinks[key]:
                    self.deeplinks_.append(value)
                    print('\t|-> '+RED+value+RESET)
                    a = a+1
            print(GREEN+'-'*40+'Total Deeplinks:{}'.format(a)+'-'*40+'|')
        except Exception as e:
            print(e)


    def do_trace(self,line):

        opsys = platform.system()
        script = self.create_script(opsys,line)

        if not 'Error' in script:
   
            if 'Darwin' in opsys:
                subprocess.run("""osascript -e 'tell application "Terminal" to do script "{}" ' """.format(script), shell=True)
            elif 'Linux' in opsys:
                subprocess.run("""x-terminal-emulator -e {}""".format(script)) 
            elif 'Windows' in opsys:
                subprocess.call('start /wait {}'.format(script), shell=True)

    def do_pull(self, line):
        try:
            base_apk = os.popen("adb -s {} shell pm path {} | grep apk".format(self.device.id,line.split(' ')[0])).read()
            base_apk = base_apk[ base_apk.find(':')+1:]
            print("Extracting: "+base_apk)
            output = os.popen("adb -s {} pull {}".format(self.device.id,base_apk)).read()
            print(output)
        except Exception as e:
            print(e)

    def complete_pull(self, text, line, begidx, endidx):
        self.init_packages()
        if not text:
            completions = self.packages[:]
            self.packages = []
        else:
            completions = [ f
                            for f in self.packages
                            if f.startswith(text)
                            ]
            self.packages = []
        return completions


    def create_script(self,opsys,line):

        switch = line.split(' ')[0].strip()
        valid = True

        if '-j' in switch:
            param1 = line.split(' ')[1]+ '*!*'
            param = """frida-trace -D {} {} -j '{}' """.format(self.device.id,self.package,param1)
        elif '-n' in switch:
            param1 = line.split(' ')[1]+ '*'
            param = """frida-trace -D {} -i '{}' {}""".format(self.device.id,param1,self.package)
        elif '-a' in switch:
            param1 = line.split(' ')[1].strip()
            param = """frida-trace -D {} -I '{}' {}""".format(self.device.id,param1,self.package)
        else:
            print('[E] Invalid command, run help for options!')  
            valid = False        

        if valid:
            path = os.getcwd()

            if 'Windows' in opsys:
                script = path + '/script.bat'
                with open(script,'w') as file:
                    file.write(param) 
            else:
                script = path + '/script.sh'
                with open(script,'w') as file:
                    file.write(param) 
                os.chmod(script, 0o775)
        else:
            script = 'Error'

        return script
        

    def do_notify(self,line):
        try:         
            output=os.popen("adb -s {} shell am broadcast  -a com.medusa.NOTIFY --es subject {} --es body {}".format(self.device.id,line.split(' ')[0],line.split(' ')[1])).read()
            print(output)
        except Exception as e:
            print(e)
            return
        


    def init_packages(self):
        for line1 in os.popen('adb -s {} shell pm list packages -3'.format(self.device.id)):
            self.packages.append(line1.split(':')[1].strip('\n'))
   
    def do_uninstall(self,package):
        try:         
            output=os.popen("adb -s {} uninstall {}".format(self.device.id,package.split(' ')[0])).read()
            print(output)
        except Exception as e:
            print(e)
            return


    def do_kill(self,package):

        try:         
            print(package)
            output=os.popen("adb -s {} shell  am force-stop {}".format(self.device.id,package.split(' ')[0])).read()
            print(output)
        except Exception as e:
            print(e)
            return


    def do_spawn(self,package):
        try:         
            print('[+] Starting {}'.format(package))
            os.popen("adb -s {} shell  monkey -p {} -c 'android.intent.category.LAUNCHER 1'".format(self.device.id,package.split(' ')[0])).read()
            print('[+] {} started'.format(package))
        except Exception as e:
            print(e)
            return

    
    def complete_spawn(self, text, line, begidx, endidx):

        self.init_packages()
        if not text:
            completions = self.packages[:]
            self.packages = []
        else:
            completions = [ f
                            for f in self.packages
                            if f.startswith(text)
                            ]
            self.packages = []
        return completions

    def complete_kill(self, text, line, begidx, endidx):

        self.init_packages()
        if not text:
            completions = self.packages[:]
            self.packages = []
        else:
            completions = [ f
                            for f in self.packages
                            if f.startswith(text)
                            ]
            self.packages = []
        return completions

    def complete_uninstall(self, text, line, begidx, endidx):

        self.init_packages()
        if not text:
            completions = self.packages[:]
            self.packages = []
        else:
            completions = [ f
                            for f in self.packages
                            if f.startswith(text)
                            ]
            self.packages = []
        return completions


    def do_broadcast(self,line):
        try:         
            output=os.popen("adb -s {} shell 'am broadcast -a {}'".format(self.device.id,line.split(' ')[0])).read()
            print(output)
        except Exception as e:
            print(e)
            return
    
    def complete_broadcast(self, text, line, begidx, endidx):
        
        if not text:
            completions = self.filters[:]
        else:
            completions = [ f
                            for f in self.filters
                            if f.startswith(text)
                            ]
        return completions

    def print_list(self,lst):
        print(GREEN)
        for item in lst:
            if type(item) is str:
                print('\t\t'+item)
        print(RESET)
    
    def print_strings(self,lst):
       
        for item in lst:
            print(GREEN+'KEY:' +RESET+'{}'.format(item.split('=')[0],) + GREEN+'\t,VAL:'+RESET+' {}'.format(item.split('=')[1] ))
    
    
    def do_show(self,line):
        what = line.split(' ')[0]
        if 'permissions' in what:
            self.print_list(self.permissions)
        elif 'activities' in what:
            self.print_list(self.activities)
        elif 'services' in what:
            self.print_list(self.services)
        elif 'receivers' in what:
            self.print_list(self.receivers)
        elif 'filters' in what:
            self.print_list(self.filters)
        elif 'providers' in what:
            self.print_list(self.providers)
        elif 'strings' in what:
            self.print_strings(self.strings)
        else:
            print('[i] Usage: show [permissions, activities, services, receivers, filters, providers, strings]')


    def complete_show(self, text, line, begidx, endidx):
        components = ['permissions', 'activities', 'services', 'receivers', 'filters','providers', 'strings']
        if not text:
            completions = components[:]
        else:
            completions = [ f
                            for f in components
                            if f.startswith(text)
                            ]
        return completions


    def do_adb(self,line,cmd=None,frombs=False):
        
        if cmd == None:
            print("[i] Type 'exit' to return ") 
            cmd =  input(GREEN+'{}:adb:'.format(self.device.id)+RESET)

        while cmd != 'exit':  
            if cmd != 'exit':
                subprocess.run('adb -s {} {}'.format(self.device.id,cmd), shell=True)
            cmd = input(GREEN+'{}:adb:'.format(self.device.id)+RESET)

    def do_proxy(self,line):

        command = line.split(' ')[0]
        try:
            if 'get' in command:
                self.print_proxy()
            elif 'reset' in command:
                os.popen("adb -s {} shell settings put global http_proxy :0".format(self.device.id))  
                os.popen("adb -s {} shell iptables -t nat -F".format(self.device.id))
                time.sleep(2) 
                self.print_proxy()
            elif 'set' in command:
                switch = ip = line.split(' ')[1].split(':')[0]
                if '-t' in switch:
                    ip = line.split(' ')[2].split(':')[0]
                    port = line.split(' ')[2].split(':')[1]
                    self.transproxy(ip,port)
                else:
                    ip = line.split(' ')[1].split(':')[0]
                    port = line.split(' ')[1].split(':')[1]
                    os.popen("adb -s {} shell settings put global http_proxy {}:{}".format(self.device.id,ip,port)) 
                    time.sleep(2) 
                    self.print_proxy()
            else:
                print('[!] Usage: proxy [set,get,reset] [<ip>:<port>] [-t]')
        except Exception as e:
            print(e)


    def transproxy(self,ip,port):
        try:
            print('[i] Pushing transproxy script !')
            os.popen("adb -s {} push utils/transproxy.sh /data/local/tmp/transproxy.sh".format(self.device.id)) 
            print('[i] Executing script')
            os.popen("adb -s {} shell 'chmod +x /data/local/tmp/transproxy.sh; /data/local/tmp/transproxy.sh {} {}; rm /data/local/tmp/transproxy.sh'".format(self.device.id,ip,port))
            self.print_proxy()
        except Exception as e:
            print(e)

    def do_installBurpCert(self,line):
        self.init_packages()
        if 'com.medusa.agent' not in self.packages:
            print("[!] Medusa agent is required, run 'installagent' first.")
            return
        try:
            a = ''
            while a != 'y' and a !='x':
                a = input("""[!] Make sure that burp is running on 127.0.0.1:8080\n\nType 'y' to continue or 'x' to cancel:""")

            if a == 'y':
                os.popen("chmod +x utils/installBurpCert.sh; utils/installBurpCert.sh {}".format(self.device.id)) 
                os.popen("adb -s {} shell am broadcast -a com.medusa.INSTALL_CERTIFICATE -n com.medusa.agent/.Receiver".format(self.device.id))

                time.sleep(1)
                print(GREEN+"""
-------------------------------------------------------------------
Note: Burp certificate has been copied to sdcard, use the following 
commands to install it as a system certificate:
-------------------------------------------------------------------
$adb remount
$cd /system/etc/security/cacerts
$mkdir tmp
$mv * tmp/
$mv /sdcard/*.der /system/etc/security/cacerts/*.0
                """+RESET)
                print()
        except Exception as e:
            print('')
        

    def complete_proxy(self, text, line, begidx, endidx):
        proxy_cmd = ['set','get','reset']
        if not text:
            completions = proxy_cmd[:]
        else:
            completions = [ f
                            for f in proxy_cmd
                            if f.startswith(text)
                            ]
        return completions



    def print_proxy(self):
        
        settings = os.popen("adb -s {} shell settings get global http_proxy".format(self.device.id)).read()
        print (WHITE+"--------------Global proxy settings-----------------:"+RESET)
        print ('Current proxy: {}'.format(settings))
        print (WHITE+"--------------IP tables settings--------------------:"+RESET)
        output = subprocess.run("adb -s {} shell iptables -t nat -L".format(self.device.id), shell=True)
        print(output)
 

    def do_screencap(self, line):
        try:
            if '-o' in line.split(' ')[0]:
                os.popen("adb -s {} exec-out screencap -p > {}".format(self.device.id,line.split(' ')[1]))
                print('[!] Screencap saved successfully to {}'.format(line.split(' ')[1]))
            else:
                print('[!] Usage: screencap -o filename.png')
        except Exception as e:
            print(e)
            print('[!] Usage: screencap -o filename.png')


    def do_jdwp(self,line):
        try:
            pid = os.popen("adb -s {} shell pidof {}".format(self.device.id,line.split(' ')[0])).read()
            output = os.popen("adb -s {} forward tcp:6667 jdwp:{}".format(self.device.id,pid)).read()
            print(output)
            
            subprocess.run('jdb -attach localhost:6667', shell=True)

        except Exception as e:
            print(e)
            print('[!] Usage: jdwp package_name')



    def complete_jdwp(self, text, line, begidx, endidx):

        self.init_packages()
        if not text:
            completions = self.packages[:]
            self.packages = []
        else:
            completions = [ f
                            for f in self.packages
                            if f.startswith(text)
                            ]
            self.packages = []
        return completions


    def do_start(self,line):
        try:         
            output=os.popen("adb -s {} shell 'am start -n {}/{}'".format(self.device.id,self.package,line.split(' ')[0])).read()
            print(output)
        except Exception as e:
            print(e)
            return



    def complete_start(self, text, line, begidx, endidx):
        if not text:
            completions = self.activities[:]
        else:
            completions = [ f
                            for f in self.activities
                            if f.startswith(text)
                            ]
        return completions



    def do_startsrv(self,line):
        try:         
            output=os.popen("adb -s {} shell 'am startservice -n {}/{}'".format(self.device.id,self.package,line.split(' ')[0])).read()
            print(output)
        except Exception as e:
            print(e)
            return

    def complete_startsrv(self, text, line, begidx, endidx):
        if not text:
            completions = self.services[:]
        else:
            completions = [ f
                            for f in self.services
                            if f.startswith(text)
                            ]
        return completions

    def do_stopsrv(self,line):
        try:         
            output=os.popen("adb -s {} shell 'am stopservice -n {}/{}'".format(self.device.id,self.package,line.split(' ')[0])).read()
            print(output)
        except Exception as e:
            print(e)
            return

    def complete_stopsrv(self, text, line, begidx, endidx):
        if not text:
            completions = self.services[:]
        else:
            completions = [ f
                            for f in self.services
                            if f.startswith(text)
                            ]
        return completions

    def do_type(self,line):

        print("Type 'exit' to quit")

        while 'exit' not in line:
            line = input(':')
            os.popen("adb -s {} shell input text {}".format(self.device.id,line))



    def do_clear(self,line):
        os.system('clear')

    def do_shell(self,line):
        shell = os.environ['SHELL']
        subprocess.run('{}'.format(shell), shell=True)

    def do_exit(self,line):
        print('[i] Cleaning working directory: ')
        try:
            if os.path.isfile('./manifest.xml'):
                ask = input('\n[!] do you want to delete the manifest file ? (yes/no) ')
                if 'yes' in ask:
                    os.remove('./manifest.xml')

            if os.path.isfile('./strings.xml'):
                ask = input('\n[!] do you want to delete the strings.xml file ? (yes/no) ')
                if 'yes' in ask:
                    os.remove('./strings.xml')

            if os.path.isfile('./script.sh'):
                ask = input('\n[!] do you want to delete the trace script file ? (yes/no) ')
                if 'yes' in ask:
                    os.remove('./script.sh')
            
            if os.path.isfile('./script.bat'):
                ask = input('\n[!] do you want to delete the trace script file ? (yes/no) ')
                if 'yes' in ask:
                    os.remove('./script.bat')

            if self.INSTALL == True:
                uninstall = input("[!] Do you want to uninstall the apk ? (yes/no)")
                if 'yes' in uninstall:
                    subprocess.run('adb -s {} uninstall {}'.format(self.device.id,self.package),shell=True)
            
            if os.path.exists("__handlers__/"):
                uninstall = input("[!] Do you want to delete the __handlers__ folder? (yes/no)")
                if 'yes' in uninstall:    
                    os.system("rm -r __handlers__/")

        except Exception as e:
            print(e) 

        print('Bye !!')
        exit()


    def do_installagent(self,line):
        try:
            subprocess.run('adb -s {} install -g {}'.format(self.device.id, os.getcwd()+'/dependencies/agent.apk'),shell=True)
        except Exception as e:
            print(e)


    def do_help(self,line):
        if line != '':
            print('\n'+BLUE+self.display_tag(line,'Help')+RESET)
        else:
            print("""Available commands:

                    [+] TRACE Functions using frida-trace:
                    ---------------------

                    - trace -j com.myapp.name*          : Trace all the functions of the com.myapp.name* class
                    - trace -n foo                      : Trace a native function
                    - trace -a library.so               : Trace the functions of the library.so

                    Will spawn a new frida-trace instance with the given options

                    ===========================================================================================

                    [+] MANIFEST PARSER:
                    ---------------------

                    - show permissions          : Print the application's permissions
                    - show activities           : Print a list with the application's activities
                    - show services             : Print a list with the application's services
                    - show receivers            : Print a list with the application's receivers
                    - show providers            : Print a list with the application's content providers
                    - show filters              : Print broadcast filters
                    - show strings              : print application's strings
                    - search [keyword]          : Search components containing the given keyword
                    ===========================================================================================

                    [+] TRIGERS:
                    ---------------------

                    - start      [tab]          : Start and activity 
                    - deeplink   [tab]          : Trigger a deeplink
                                                  Add the --poc to create an html poc file
                    - startsrv   [tab]          : Start a service
                    - stopsrv    [tab]          : Stop a service
                    - broadcast  [tab]          : Broadcast an intent 
                    - spawn      [tab]          : Spawn an application

                    ===========================================================================================

                    [+] UTILITIES:
                    ---------------------
                    - pull       [tab]              : extract apk from the device
                    - busybox                       : Install a busybox binary and set aliases
                    - installagent                  : Install the Medusa apk
                    - installBurpCert               : Install Burp Certificate
                    - notify subject body           : Display a notification to the phone's notification bar
                    e.g. notify test foo            (Requires the medusa agent to be installed and run)

                    - jdwp  package_name            : Open a jdb session with the debugger attached to the package 
                                                    (Requires the --patch option)

                    - adb [cmd]                     : Send an adb command to the connected device
                    - clear                         : Clears the screen
                    - kill [tab]                    : Kill an app by the package name
                    - type                          : Type text to send to the device
                    - screencap -o filename         : Takes a device screenshot and saves it as 'filaname'
                    - shell                         : Opens an interactive shell
                    - proxy set [-t] <ip>:<port>    : Sets a global proxy at a given ip and port 
                                                    ('-t' for transparent)
                    - proxy get                     : Displays proxy settings of the device
                    - proxy reset                   : Resets proxy settings
                    - uninstall [tab]               : Uninstals a packages from the device

                            """)
    

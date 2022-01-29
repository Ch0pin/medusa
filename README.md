<img src="https://raw.githubusercontent.com/Ch0pin/medusa/master/libraries/logo.png" width="150" height="150">

### Description:

**MEDUSA** is an Extensible and Modularised framework that automates processes and techniques practiced during the **dynamic analysis** **of Android Applications**.  

Some of the MEDUSA's features include:

- Tracing and instrumentation of API calls clustered according to their action (e.g. File System, IPC, Encryption)
- Tracing and instrumentation of Java and Native functions 
- Unpacking (effective for most of the weel known packers, including Qihoo, Secshell e.t.c.)
- Patching on the fly or statically (autoset the debugable flag)
- Triggering of various system events in order to initiate a reaction (e.g. send intents / notifications / events to the target app)
- Triggering of application's components (Activities, Services e.t.c.)

**Overview of the MEDUSA workflows (Presentation): [MEDUSA-Usage-workflows.pdf](https://github.com/Ch0pin/medusa/blob/master/MEDUSA-Usage-workflows.pdf)**


### Usage:

MEDUSA's functionality is divided in two basic python scripts: the **medusa.py** and the **apkutils.py** with the last to be more of a helping utility which automates processes like **setting a proxy server for the device**, **parcing the Anroid Manifest, starting/stoping activities and many more**. More specifically:

- **The medusa.py** 

  > Is used to dynamically add or remove tracing of API calls during application's runtime. The tracing 'comes' in a form of modules, where each one of them 'specializes' in an abstract aspect. As an example, to trace the cryptographic procedures of the application (e.g.  fetch AES keys or the plaintext that will be encrypted), simply inject the AES module  and observer the output. 
  >
  > Indicatively some of the  functionalities which are implemented so far, include the following: 
  >
  > -  SSL pinning bypass
  > -  UI restriction bypass (e.g. Flag secure, button enable)
  > -  Class enumeration
  > -  Hook native functions
  > -  Monitoring of:
  >    -  Encryption process (keys, IVs, data to be encrypted)
  >    -  Intents
  >    -  Http communications
  >    -  Websockets
  >    -  Webview events
  >    -  File operations
  >    -  Database interactions
  >    -  Bluetooth operations
  >    -  Clipboard
  > -  Monitoring of API calls used by malware applications, such as:
  >    -  Spyware
  >    -  Click Fraud
  >    -  Toll Fraud
  >    -  Sms Fraud

  


<img src="https://user-images.githubusercontent.com/4659186/87720238-87827e80-c7ac-11ea-989c-fb80b9aa06b6.png" width="7650" height="350">



- **The apkutils.py** 

  > Given a **manifest or and apk file**, the specific script is able to perform the following functionalities:
  >
  > - Display the application's components and technical characteristics, including:
  >   - Activities
  >   - Services
  >   - Receivers
  >   - Permissions
  >   - Intent Filters 
  >   - Content providers
  > - Trace application functions 
  > - Trigger an activity, service or an intent
  > - Automate actions performed during dynamic analysis:
  >   - Change device proxy settings
  >   - Capture screenshots of the device
  >   - Install/Uninstall/kill an application
  > - Patch (set the debug flag to true) / Sign / Install 

  **apkutils.py:**

  <img src="https://user-images.githubusercontent.com/4659186/87721141-e3013c00-c7ad-11ea-843c-66eb34d44c96.png" width="7650" height="490">

### Requirements:

See **requirements.txt** for python requirements as well as **frida** and **adb**. A rooted device or an emulator is highly recomended in order to use the framework's full capabilities.

### Modules:

A module (.med file) consists of three sections. 

    "Name": "foo_bar_dir/module_for_com_foo_bar",
    "Description": "What your module does ?",
    "Help": " How your module works ?",
    "Code": 

- The **'Name'** used in order to reference a module. Default name convention is lower case letters and underscores (e.g. **https_communications/ssl_unpining**)

- The **'Description'** where the usage of the module is described, e.g. *Description: Use this module to perform the following action* . 

- The **'Help'** where a more detailed information message or even a link to a website providing explanations about the module's usage is inserted

- The **Code** is where the javascript code should be inserted in order to hook a specific API call. 

  What follows is an example of the translation module:

For example the module bellow is used to cancel the killProcess, exit and finish of an application. The script itself is a json file using a .med suffix located under the **/medusa/modules/<category/** directory:

```js
{
    "Name": "helpers/cancel_system_exit",
    "Description": "Cancels application exit",
    "Help": "Hooks system.exit, activity.finish to cancel application's exit",
    "Code": "  
console.log(\"-----------Hooking SYSTEM EXIT----------------------\");

  var sysexit = Java.use(\"java.lang.System\");
  var activity = Java.use('android.app.Activity');
  var process = Java.use('android.os.Process');

  process.killProcess.implementation = function(pid){
    colorLog(\"[i] Canceling process kill with pid:\"+pid, {c: Color.Green});

  }
  sysexit.exit.overload(\"int\").implementation = function(var_0) {
    colorLog(\"[i] Canceling system exit\", {c: Color.Green});
  };

  activity.finish.overloads[0].implementation = function(){
    colorLog(\"[+] Canceling activity's finish\" ,{c: Color.Green});
    
  }
"
}


```



### Saving a Session (module recipies):

You can save a set of modules to a file in order to use them in another session. Export a set of used modules using the **export** command followed by the filename: 

**medusa>** export MyModuleRecipe.txt

Continue your session using the -r flag when starting MEDUSA: **./medusa.py** -r MyModuleRecipe.txt



### How To Create a Medusa Module:

A Medusa module is essentially a Frida script on steroids combined with multiple ready-made javascript functions that may enhance the final output. Assume that you found a super cool frida script online or you have many of them that you want to save in a classified manner:

1. **Remove Frida script's prologue / epilogue by changing it**

   **FROM:**

   ```
   	Java.perform(function() {
   
   		var hook = Java.use("com.foo.bar");
       
   		hook.function.implementation = function() {
   			console.log("Info: entered target method");		
       }
   
   	});  
   ```

   **TO:**

   ```
   		var hook = Java.use("com.foo.bar");
       
   		hook.function.implementation = function() {
   			console.log("Info: entered target method");		
       }
   ```

2. **Insert the modified code in the "code" segment of the following json object:**

   ```json
   {
       "Name": "foo_bar_dir/module_for_com_foo_bar",
       "Description": "What your module does ?",
       "Help": " How your module works ?",
       "Code": 
     "
       
       
   		var hook = Java.use(\"com.foo.bar\");
       
   		hook.function.implementation = function() {
   			console.log(\"Info\\n: entered target method\");		
       }
       
        
       
       "
   }
   ```

3. **Save the result to the /medusa/modules directory**

 if you think that your module can be classified in one's of Medusa's categories (e.g. http_communications), save your module as .med under the corresponding folder:

```
/medusa/modules/foo_bar_dir/module_for_com_foo_bar.med
```

 Or if you think your modulde can be classified to an already existing category, add it to the corresponding folder (e.g. /medusa/modules/http_communications)

That's all ... this module is now accessible via the medusa cli:

> medusa> show all
>
> medusa> use foo_bar_dir/module_for_com_foo_bar

4. **Contribute with a PR**

​	if you think that your module can be helpfull to other users, do a pull request

### Show Cases

#### - SSL Unpinning

![Screenshot 2020-09-22 at 16 41 10](https://user-images.githubusercontent.com/4659186/151658672-dc80f37c-f4fb-48b8-a355-1dc0bf2b172c.png)

#### - Intent Monitoring 

<img src="https://user-images.githubusercontent.com/4659186/151658670-2ddac205-4c77-418a-8edd-2035b233387e.png" alt="Screenshot 2020-09-22 at 16 41 10" style="zoom:100%;" />

#### - Passive Monitoring of HTTP Requests

![Screenshot 2020-09-22 at 16 41 10](https://user-images.githubusercontent.com/4659186/93905749-34203580-fcf3-11ea-9f36-8138141c2302.png)

![Screenshot 2020-09-22 at 16 43 37](https://user-images.githubusercontent.com/4659186/93905699-25d21980-fcf3-11ea-85e0-fafd62ea7d28.png)



#### - Native Libraries Enumeration

![Screenshot 2020-09-22 at 16 41 10](https://user-images.githubusercontent.com/4659186/151658663-6c77f2e3-6f42-4424-b593-d8cfe3d3bed3.png)



#### - Memory READ/WRITE/SEARCH (interactive mode):

![Screenshot 2020-09-22 at 16 41 10](https://user-images.githubusercontent.com/4659186/151658659-b4f83296-60ec-4818-a303-5645284b0a67.png)

#### - Personal information exfiltration monitoring

> Hooks api calls which found to be common for this kind of malware, including:
>
> - Contact exfiltration 
> - Call log exfiltration
> - Camera usage
> - Microphone usage
> - Location tracking
> - File uploading
> - Media recording
> - Clipboard tracking
> - Device recon
> - Screenshot capture

<img src="https://user-images.githubusercontent.com/4659186/87245281-1c4b4c00-c43c-11ea-9cad-195ceb42794a.png" width="450" height="460">

#### - Translation 

> Translates the application's UI by hooking 'setText' calls  



<img src="https://user-images.githubusercontent.com/4659186/86785673-e59bbd00-c05a-11ea-8fb0-9c3f86043104.png" width="250" height="450">                             <img src="https://user-images.githubusercontent.com/4659186/86785688-e9c7da80-c05a-11ea-838f-e4c7568c7c2a.png" width="250" height="450">     



<img src="https://user-images.githubusercontent.com/4659186/86785693-eb919e00-c05a-11ea-901e-8cc180d6274a.png" width="550" height="250">



**CREDITS**:

- https://github.com/frida/frida
- https://github.com/dpnishant/appmon
- https://github.com/brompwnie/uitkyk
- https://github.com/hluwa/FRIDA-DEXDump.git
- https://github.com/shivsahni/APKEnum
- https://github.com/0xdea/frida-scripts
- https://github.com/Areizen/JNI-Frida-Hook



### ChangeLog:

**08/05/2021:**

- Added busybox support
- Ability to force native library loading

**07/02/2021:**

- **Medusa agent** was modified to include certificate set up functionality as well as a floating mod
- Burp Certificate installation
- Transparent proxy set up

**27/11/2020:** 

Feature added according to which the user can search for code snippets that may later imported to the current session. 

The code snippets are saved in the 'examples' directory and may be imported using the 'import' command, e.g.:

**medusa> import RegisterClass**

The code will be appended to the scratchpad and later get compiled to the final agent script.

**05/11/2020:** 

Added option to dump a specific module from memory

**05/10/2020:** 

- Introducing **Medusa Agent**, to load and explore dex or jar files dropped by APKs:

<img src="https://user-images.githubusercontent.com/4659186/95062556-1096bb00-06f5-11eb-9dda-62bfacaa0570.png" alt="medusa_agent" width="230" height="430" />

- Spoof the Notification Listeners
- Hook notification events
- Fixes to dynamic code loading module
- Patch an apk by turning the debug flag to true



**04/11/2020:** More native hook options added:

- Hook by offset
- Hook by pattern



**16/09/2020:** READ/WRITE/SEARCH process memory

By issuing  **medusa> memops** **package_name** **module_name**, the framework can be used to perform read/write operations in the process memory.

```
medusa>memops com.foo.app libfoo.so
[i] Using device with id Device(id="192.168.1.5:1111", name="Dev", type='usb')
[i] Attaching to process com.foo.app [pid:19538]
|(E)xit |r@offset |⏎ |w@offset |? (help)|:
```

Issuing a read command (**r@2000**)

```
READ MEMORY:

|(E)xit |r@offset |⏎ |w@offset |? (help)|:r@2000

0x2000
Base Address:0x7b62471000 Dumping at:0x7b62473000 Offset:2000
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  88 0d 00 00 11 00 0c 00 2f ff 02 00 00 00 00 00  ......../.......
00000010  1d 00 00 00 00 00 00 00 a0 22 00 00 10 00 f1 ff  ........."......
00000020  30 20 04 00 00 00 00 00 00 00 00 00 00 00 00 00  0 ..............
00000030  72 0f 00 00 11 00 0c 00 24 fd 02 00 00 00 00 00  r.......$.......
00000040  01 00 00 00 00 00 00 00 42 0d 00 00 12 00 0b 00  ........B.......
00000050  3c 08 01 00 00 00 00 00 a8 0c 00 00 00 00 00 00  <...............
00000060  08 0e 00 00 11 00 0c 00 68 05 03 00 00 00 00 00  ........h.......
00000070  19 00 00 00 00 00 00 00 c2 02 00 00 11 00 0c 00  ................
```

Issuing a write command (**w@2000**)

```
|(E)xit |r@offset |⏎ |w@offset |? (help)|:w@2000
Bytes to write (in the form of 00 11 22 33):90 90 90 90
Bytes in:[0x90,0x90,0x90,0x90]
```

```
Base Address:0x7b62471000 Dumping at:0x7b62473000 Offset:2000
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  90 90 90 90 11 00 0c 00 2f ff 02 00 00 00 00 00  ......../.......
00000010  1d 00 00 00 00 00 00 00 a0 22 00 00 10 00 f1 ff  ........."......
00000020  30 20 04 00 00 00 00 00 00 00 00 00 00 00 00 00  0 ..............
00000030  72 0f 00 00 11 00 0c 00 24 fd 02 00 00 00 00 00  r.......$.......
00000040  01 00 00 00 00 00 00 00 42 0d 00 00 12 00 0b 00  ........B.......
00000050  3c 08 01 00 00 00 00 00 a8 0c 00 00 00 00 00 00  <...............
00000060  08 0e 00 00 11 00 0c 00 68 05 03 00 00 00 00 00  ........h.......
00000070  19 00 00 00 00 00 00 00 c2 02 00 00 11 00 0c 00  ................
00000080  fa ff 02 00 00 00 00 00 19 00 00 00 00 00 00 00  ................
```



**01/09/2020**: Native hook support added:

```
medusa>hook -n
[?] Libary name:libjpeg.so
[?] Function name:jpeg_CreateDecompress
[?] Enable backtrace (yes/no):yes
[?] Enable memory read (yes/no):yes
[?] Buffer read size (0-1024):1024

Entering Native function:  jpeg_CreateDecompress
Backtrace:
	0x7891e6d40c libhwui.so!_ZN7SkCodec13skipScanlinesEi+0xa18
	0x7891e6cd18 libhwui.so!_ZN7SkCodec13skipScanlinesEi+0x324
	0x7891e6d970 libhwui.so!_ZN6SkData17MakeUninitializedEm+0x3e8
	0x7891e6d898 libhwui.so!_ZN6SkData17MakeUninitializedEm+0x310
	0x7891e618c8 libhwui.so!_ZN7SkCodec14MakeFromStreamENSt3__110unique_ptrI8SkStreamNS0_14default_deleteIS2_EEEEPNS_6ResultEP16SkPngChunkReader+0x104
	0x7892326b84 libandroid_runtime.so!_Z38register_android_graphics_ImageDecoderP7_JNIEnv+0x1738
	0x7892325834 libandroid_runtime.so!_Z38register_android_graphics_ImageDecoderP7_JNIEnv+0x3e8
	0x714050e4 boot-framework.oat!0x28b0e4
Leaving Native function:  jpeg_CreateDecompress
Return Value: 0x77a01c6180
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000040  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000050  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000060  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000070  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000080  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000090  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```



**25/08/2020**: Hook all functions of a given class (example):

```
medusa>hook -a com.foo.class

Hook(s) have been added to the modules/schratchpad.me ,you may include it in the final script.
```



**21/08/2020**: Hook a function by giving the name and its class name (example):

```
medusa>hook -f

Enter the full name of the function(s) class: foo.com
Enter a function name (CTRL+C to Exit): onCreate

Hook has been added to the modules/schratchpad.me ,you may include it in the final script.
```







##### About me:

[![Ch0pins's github stats](https://github-readme-stats.vercel.app/api?username=Ch0pin)](https://github.com/anuraghazra/github-readme-stats)


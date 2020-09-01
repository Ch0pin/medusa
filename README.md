

<img src="https://raw.githubusercontent.com/Ch0pin/medusa/master/libraries/logo.png" width="150" height="150">

### Description:

**Medusa** is an extensible framework for **Android applications** which automates processes and techniques practised during the **dynamic analysis** of a malware investigation.  

It's functionality can be summarised as follows:

- Tracing and instrumentation of API calls used by common malware categories

- Unpacking of packed apps (effective for most of the weel known packers, including Qihoo, Secshell e.t.c.)

- Triggering of various system events in order to initiate a malicious behaviour

- Triggering of application's components (Activities, Services e.t.c.)

- Translation of UI to English in order to enhance user interaction

- Wrapping of adb commands (e.g. cchange proxy settings, insert keys e.t.c.)

  

### Updates:

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




### Usage:

Medusa's functionality is based the following scripts:

- **medusa.py** 

  > Is used to dynamically add or remove tracing of API calls during application's runtime. The tracing 'comes' in a form of modules, where each one of them 'specializes' in an abstract aspect. As an example, to trace the cryptographic procedures of the application (e.g.  fetch AES keys or the plaintext that will be encrypted), simply inject the AES module  and observer the output. 
  >
  > Indicatively some of the  functionalities which are implemented so far, include the following: 
  >
  > -  SSL pinning bypass
  > -  UI restriction bypass (e.g. Flag secure, button enable)
  > -  Class enumeration
  > -  Monitoring of:
  >    -  Encryption process (keys, IVs, data to be encrypted)
  >    -  Intents
  >    -  Http operations
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
  >
  > **To be added**: 
  >
  > - Modules for popular frameworks like firebase, cordova e.t.c.
  > - Modules to interact with native calls
  >
  

  

<img src="https://user-images.githubusercontent.com/4659186/87720238-87827e80-c7ac-11ea-989c-fb80b9aa06b6.png" width="7650" height="350">



- **apkutils.py** 

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

  
  
  **apkutils.py:**
  
  <img src="https://user-images.githubusercontent.com/4659186/87721141-e3013c00-c7ad-11ea-843c-66eb34d44c96.png" width="7650" height="490">

### Requirements:

See **requirements.txt** for python requirements. 

Additionally:

- Frida installation (preffered version 12.10.4)
- apktool (included in the dependencies folder)
- adb

A rooted device or an emulator is highly recomended in order to use the framework's full capabilities

### Modules:

A module (.med file) consists of three sections. 

- The **'Description'** where the usage of the module is described, e.g. *Description: Use this module to perform the following action* . 

- The **'Help'** where a more detailed information message or even a link to a website providing explanations about the module's usage is inserted

- The **Code** is where the javascript code should be inserted in order to hook a specific API call. 

  What follows is an example of the translation module:

```js

#Description: 'Use this module to translate UI text to english'
#Help: 
"Hooks the setText, setMessage, setTitle functions of basic android UI components 
 and translates the applied text using google's translation API"
#Code:

console.log('\n----------TRANSLATOR SCRIPT -------------');
console.log('----------twiter:@Ch0pin-------------------');
   
    var textViewClass = Java.use("android.widget.TextView");
    var alertDialog = Java.use("android.app.AlertDialog");
    var String = Java.use("java.lang.String");
   

...
    textViewClass.setText.overload('java.lang.CharSequence').implementation = function (originalTxt) {
        var string_to_send = originalTxt.toString();
        var string_to_recv = "";
        send(string_to_send); // send data to python code
        recv(function (received_json_object) {
            string_to_recv = received_json_object.my_data;
        }).wait(); 
        console.log('Translating: ' + string_to_send +" ---> "+ string_to_recv)
  
        var castTostring = String.$new(string_to_recv);

        return this.setText(castTostring);
 
    }

```



### Recipes:

Save a set of modules to a file in order to be used in another session. Simply, export a set of used modules as a recipe by typing: 

**medusa>** export

Import the recipe by simply typing:

**./medusa.py** -r recipe.txt



### Contribute:

- Create an interesting module or...
- Suggest an improvement or...
- Share this tool or...
- Leave a comment :-)



#### Spyware module

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

#### Translation module

> Translates the application's UI by hooking 'setText' functions 



<img src="https://user-images.githubusercontent.com/4659186/86785673-e59bbd00-c05a-11ea-8fb0-9c3f86043104.png" width="250" height="450">                             <img src="https://user-images.githubusercontent.com/4659186/86785688-e9c7da80-c05a-11ea-838f-e4c7568c7c2a.png" width="250" height="450">     



<img src="https://user-images.githubusercontent.com/4659186/86785693-eb919e00-c05a-11ea-901e-8cc180d6274a.png" width="550" height="250">







**CREDITS**:

- https://github.com/frida/frida
- https://github.com/dpnishant/appmon
- https://github.com/brompwnie/uitkyk
- https://github.com/hluwa/FRIDA-DEXDump.git
- https://github.com/shivsahni/APKEnum
- https://github.com/0xdea/frida-scripts




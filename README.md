

<img src="https://raw.githubusercontent.com/Ch0pin/medusa/master/libraries/logo.png" width="150" height="150">

### Description:

**Medusa** is an extensible framework for **Android Applications** which automates processes and techniques practised during the **dynamic analysis** of an assessment.  It's functionality can be summarised as follows:

- Tracing and instrumentation of API calls using the FRIDA framework

- Dump dex on memory (Credits: https://github.com/hluwa/FRIDA-DEXDump.git)

- Triggering of various system broadcasts

- Translate UI to English

- Triggering of application's components (Activities, services e.t.c.)

- Wrapping of adb commands (e.g. cchange proxy settings, insert keys e.t.c.)

  

### Usage:

Medusa's functionality is based the following two scripts:

- **./medusa.py** 

  > Is used to dynamically add or remove tracing of API calls during application's runtime. The tracing 'comes' in a form of modules, where each one of them 'specializes' in an abstract aspect. **As an example, to trace the cryptographic procedures of the application (e.g.  fetch AES keys or the plaintext that will be encrypted), simply inject the AES module during the application runtime and observer the output**. Since these module are constantly developed it is not possible to enumerate all of them, indicatively though, they include:
  >
  > -  SSL pinning bypass
  > - Logging of encryption processes (keys, IVs, data to be encrypted)
  > - Logging of webview events
  > - Intent monitoring 
  > - HTTP operations monitoring
  > - Database interactions
  > - ...and many more
  >
  > **Malware modules:**
  >
  > - Spyware
  > - click fraud
  > - toll fraud
  >
  > **To be added**: Modules for popular frameworks like firebase, cordova e.t.c.

- **./apkHelper.py** **file.[xml or apk]**

  > The specific module can be used to parse an apk or an AndroidManifest file and based on the results lets the user to create events that may change the applications behaviour. These events include:
  >
  > - Message Broacasting
  > - Intent creation
  > - Activities, services e.t.c. triggering 
  >
  > Additionally, this script autmates tasks like:
  >
  > - Sending text from a host to a mobile device
  > - Changing proxy settings on the fly 
  > - ...and many more

****



### Requirements:

- A rooted device
- Frida framework
- Apktool (in case of processing APKs)
- Adb

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



#### Translation module

> Translates the application's UI by hooking 'setText' functions 



<img src="https://user-images.githubusercontent.com/4659186/86785673-e59bbd00-c05a-11ea-8fb0-9c3f86043104.png" width="250" height="450">                             <img src="https://user-images.githubusercontent.com/4659186/86785688-e9c7da80-c05a-11ea-838f-e4c7568c7c2a.png" width="250" height="450">     



<img src="https://user-images.githubusercontent.com/4659186/86785693-eb919e00-c05a-11ea-901e-8cc180d6274a.png" width="550" height="250">







**CREDITS**:

- https://github.com/frida/frida

- https://github.com/dpnishant/appmon
- https://github.com/brompwnie/uitkyk




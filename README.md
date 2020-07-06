

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
  > - Auto-Click detection 
  > - HTTP operations monitoring
  > - Database interactions
  > - ...and many more
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

  

  What follows is an example of a 'well known' SSL pinning bypass module:

```js
#Description: 'Use this module to bypass certificate pinning implementations based on TrustManagerImpl'
#Help: 'The script will display the message: Bypassing SSL Pinning in case of successful bypass'
#Code:

var array_list = Java.use("java.util.ArrayList");
var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');

ApiClient.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {

    console.log('Bypassing SSL Pinning');
    var k = array_list.$new();

    return k;
}
```



CREDITS:

- https://github.com/frida/frida

- https://github.com/dpnishant/appmon
- https://github.com/brompwnie/uitkyk




<img src="https://raw.githubusercontent.com/Ch0pin/medusa/master/libraries/logo.png" width ="335" height="508">

# **Description**:

**MEDUSA** is an Extensible and Modularised framework that automates processes and techniques practiced during the **dynamic analysis** **of Android Applications**.  

# **Installation**

I keep the requirements.txt updated, so you can install Medusa by simply running:

```
$ pip install -r requirements.txt
```

**Other requirements include:** 

- Linux or macOS (currently we don't support windows)
- Python 3 
- Rooted device 
- adb
- FRIDA server (running on the mobile device)

Medusa has two main scripts: **medusa.py** and **mango.py** which you can run as **$python3 medusa.py** and **$python3 mango.py** . 

# **Using mango.py**

After starting Mango, you can import an apk by simply running: 

**mango>** ***import** com.foo.bar.apk* 

You can also import an apk from the device:

**mango>** ***pull** com.foo.bar* 

and then:

**mango>** ***import** base.apk* 

After this **mango** will analyse the apk and save the analysis results to a SQLite database. It will also parse the manifest file to give you an overview of:

- The application's main components (activities, services, providers, receivers):

  **mango>** **show activities** // to display the activities (use -e to filter only the exported ones), similarly **show services** will display the services e.t.c. 

- The application's deeplinks and the corresponding activities that handles them:

  **mango>** **show deeplinks**

Mango wraps all the "borring tasks" in simple commands. For example you can install a burp certificate by simply running **installBurpCert**, set/reset a proxy (transparent or not) with **proxy set <IP:PORT> ** or you can patch the debuggable flag of the apk by simply running **patch com.foo.bar.apk**

**Here is the full list:**

    adb                         Start an interactive adb prompt.
    box                         Starts a busybox interactive shell.
    c                           Run a local shell command 
    cc                          Run a command using the default adb shell
    exit                        Exits the application.
    help                        Displays this text.
    
    import                      Imports an apk file for analysis and saves the results to the session's database 
    
    installBurpCert             Install the Burp certificate to the mobile device.
    jdwp                        Create a jdb session. Use it in combination with the tab key to see available packages. The app has to have the debuggable flag to true.
    
    notify                      Sends a notification to the device 
                                (Example: > notify 'Title' 'Lorem ipsum dolor sit amet,....')
    
    patch                       Changes the debuggable flage of the AndroidManifest.xml to true for a given apk. 
    
    proxy                       Performs a proxy modification or reads a proxy setting (used for MITM). If adb runs as
                                root it can be used with the '-t' flag to set a transparent proxy.
                                (Example: > proxy set 192.168.1.2:8080 -t)
    
    pull                        Extracts an apk from the device and saves it as 'base.apk' in the working directory.
                                Use it in combination with the tab key to see available packages
                                (Example: > pull com.foo.bar)
    
    query                       Performs a raw query in the session db and returns the results as a list of tuples.
                                (Example: > query SELECT * FROM Application)
    
    screencap                   Captures the device screen and saves it as a png file in the current directory.
                                (Example: > screencap -o 'screen1.png')
    
    search                      Searches for a given string in the extracted components and strings.
                                (Example: search foobar)
    
    show                        Prints information about components of the loaded application or session. The currently availlable info includes: applications, activities, services, activityAlias, receivers, deeplinks, providers and intentFilters. Adding the '-e' flag will print only exported components. Additionaly 'database' prints the database structure of the session database, 'manifest' prints the manifest and 'info' prints general information about the loaded application  
    
    start                       Forces to start an activity of the loaded application. Use it in combination with the tab key to see the available activities. For non exported activities, the adb must run with root privileges.
    
    startsrv, stoprsrv          Forces to start or stop a service of the loaded application. Use it in combination with the tab key to see the available services. For non exported services, the adb must run with root privileges.
    
    trace                       trace the applicaton's calls using Frida-trace
    uninstall, kill, spawn      Uninstalls, kills or starts an app in the device. Use it in combination with the tab key to see available packages.

# **Using medusa.py**

The main idea behind this script is to be able to combine frida scripts on the fly in order to hook specific API subsets. Medusa has **more than** **80** modules which can be combined, each one of them dedicated on a simple task. Some of these tasks include:

-  SSL pinning bypass
-  UI restriction bypass (e.g. Flag secure, button enable)
-  Class enumeration
-  Monitoring of:
   -  Encryption process (keys, IVs, data to be encrypted)
   -  Intents
   -  Http communications
   -  Websockets
   -  Webview events
   -  File operations
   -  Database interactions
   -  Bluetooth operations
   -  Clipboard
-  Monitoring of API calls used by malware applications, such as:
   -  Spyware
   -  Click Fraud
   -  Toll Fraud
   -  Sms Fraud

## **Quick start**

Have the frida server running on the mobile device and run the medusa script using **$python3 medusa.py** , then simply follow the directions to connect to the device. 

- **To find scripts:**

  **medusa**> search http 		//*will print all the modules related to HTTP communications, alternative you can use the **show all** command to see all availlable scripts.* 

- **You can combine as many scripts as you want by simply running:**

  **medusa**> use <module_name> 

  **medusa>** show mods //*will print the currently loaded scripts*

  **medusa>** compile      //will combine the currently loaded scripts to a single one (called agent.js). To add latency  (e.g. to wait for something to load first in order to hook) use the -t parameter  

<img src="https://user-images.githubusercontent.com/4659186/151659174-f642bd72-a455-442a-9e51-462c91a68b18.png" width="7650" height="350">

- To hook a class, a java function or a native function, you can simply run:

  **medusa>** hook -a com.foo.bar.class 	//*hook all the functions of the com.foo.bar.class class*

  **medusa>** hook -f 	//*to hook a single function* *(following screen instructions)*

  **medusa>** hook -n	//*to hook a native function* *(following screen instructions)*

To start a session you can simply run: 

**medusa>** run -f com.foo.bar 			// to spawn the package, or ommit the '-f' in order to attach

## **Native code**

Medusa can do the following:

- Display loaded libraries:

  **medusa>** libs <-a, -s, -j> com.foo.bar 					*//list the loaded libraries of com.foo.bar*

- Find exported functions:

​				**medusa>** enumerate com.foo.bar libfoo.so			//*list the exported functions of the libfoo.so*

- Patch/READ/DUMP a library on the fly:

​				**medusa>** memops com.foo.bar libfoo.so				//this will start the following interactive shell:

![Screenshot 2020-09-22 at 16 41 10](https://user-images.githubusercontent.com/4659186/151658659-b4f83296-60ec-4818-a303-5645284b0a67.png)

**Here is the full list:**

    MODULE OPERATIONS:
    
    - search [keyword]          : Search for a module containing a specific keyword
    - help [module name]        : Display help for a module
    - add [fullpath]            : Adds the module specified by fullpath to the list of available modules
    - snippet [tab]             : Show / display available frida script snippets
    - use [module name]         : Select a module to add to the final script
    - show mods                 : Show selected modules
    - show categories           : Display the available module categories (start here)
    - show mods [category]      : Display the available modules for the selected category
    - show snippets             : Display available snippets of frida scripts
    - show all                  : Show all available modules
    - import [snippet]          : Import a snippet to the scratchpad
    - rem [module name]         : Remove a module from the list that will be loaded
    - swap old_index new_index  : Change the order of modules in the compiled script
    - reset                     : Remove all modules from the list that will be loaded
    - reload                    : Reload all the existing modules
    ===============================================================================
    
    SCRIPT OPERATIONS:
    
    - export  'filename'        : Save session modules and scripts to 'filename'
    - import [tab]              : Import frida script from available snippet
    - pad                       : Edit the scratchpad using vi
    - compile [-t X millisec]   : Compile the modules to a frida script, use '-t' to add a load delay
    - hook [option]
    		-a [class name]         : Set hooks for all the functions of the given class
    		-f                      : Initiate a dialog for hooking a Java function
    		-n                      : Initiate a dialog for hooking a native function
    		-r                      : Reset the hooks setted so far
    ==================================================================================
    NATIVE OPERATIONS:
    
    - memops package_name lib.so    : READ/WRITE/SEARCH process memory
    - strace package_name           : logs system calls, signal deliveries, and changes of process state
    - load package_name full_library_path : Manually load a library in order to explore using memops. Tip: run "list package_name path" to get the application's directories
    
    - libs (-a, -s, -j) package_name [--attach]
          -a                          : List ALL loaded libraries
          -s                          : List System loaded libraries
          -j                          : List Application's Libraries
          --attach                    : Attach to the process (Default is spawn)
    - enumerate pkg_name libname [--attach] Enumerate a library's exported functions (e.g. - enumerate com.foo.gr libfoo)
                ==============================================================================================
    FRIDA SESSION:
    
    - run        [package name] : Initiate a Frida session and attach to the selected package
    - run -f     [package name] : Initiate a Frida session and spawn the selected package
    - dump       [package_name] : Dump the requested package name (works for most unpackers)
    - loaddevice                : Load or reload a device
                ==============================================================================================
    HELPERS:
    - type 'text'               : Send a text to the device
    - list 'package_name' path  : List data/app paths of 3rd party packages
    - status                    : Print Current Package/Libs/Native-Functions
    - shell                     : Open an interactive shell
    - clear                     : Clear the screen
    - c [command]               : Run a shell command
    - cc [command]              : Run a shell command on the mobile device
              ==============================================================================================
    
    Tip: Use the /modules/scratchpad.med to insert your own hooks and include them to the agent.js
                        using the 'compile script' command

# **Contribute**:

- By making a pull request
- By creating medusa modules (see bellow how to)
- By buying a beer 

**Bitcoin (BTC) Address**: bc1qhun6a7chkav6mn8fqz3924mr8m3v0wq4r7jchz

**Ethereum (ETH) Address**: 0x0951D1DD2C9F57a9401BfE7D972D0D5A65e71dA4

# **Other usefull stuff**

**Overview of the MEDUSA workflows (Presentation): [MEDUSA-Usage-workflows.pdf](https://github.com/Ch0pin/medusa/blob/master/MEDUSA-Usage-workflows.pdf)**

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

2. **Insert the modified code in the "code" segment of the following json object:** Do not forget to escape all 
quotes (`\"`).

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

##### About me:

[![Ch0pins's github stats](https://github-readme-stats.vercel.app/api?username=Ch0pin)](https://github.com/anuraghazra/github-readme-stats)


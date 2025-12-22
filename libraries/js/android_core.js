
//----------------------begin of android_core.js-------------------------------------

var containRegExps = new Array()
var notContainRegExps = new Array(RegExp(/\.jpg/), RegExp(/\.png/))

function check(str) {
  str = str.toString();
  if (! (str && str.match)) {
      return false;
  }
  for (var i = 0; i < containRegExps.length; i++) {
      if (!str.match(containRegExps[i])) {
          return false;
      }
  }
  for (var i = 0; i < notContainRegExps.length; i++) {
      if (str.match(notContainRegExps[i])) {
          return false;
      }
  }
  return true;
}

function classExists(className) {
    var exists = false;
    try {
        var clz = Java.use(className);
        exists = true;
    } catch(err) {
        //console.log(err);
    }
    return exists;
}

function describeJavaClass(className){
    var jClass = Java.use(className);
    console.log(JSON.stringify({
      _name: className,
      _methods: Object.getOwnPropertyNames(jClass.__proto__).filter(function(m) { 
        return !m.startsWith('$') // filter out Frida related special properties
          || m == 'class' || m == 'constructor' // optional
      }), 
      _fields: jClass.class.getFields().map(function(f) {
        return f.toString()
      })  
    }, null, 2));
}

//------------------------https://github.com/CreditTone/hooker EOF----------------------------
function displayAppInfo(){
    var context = null
    var ActivityThread = Java.use('android.app.ActivityThread');
    var app = ActivityThread.currentApplication();
  
      if (app != null) {
          context = app.getApplicationContext();
          var app_classname = app.getClass().toString().split(' ')[1];
  
          
              var filesDirectory= context.getFilesDir().getAbsolutePath().toString();
              var cacheDirectory= context.getCacheDir().getAbsolutePath().toString();
              var externalCacheDirectory= context.getExternalCacheDir().getAbsolutePath().toString();
              var codeCacheDirectory= 'getCodeCacheDir' in context ? context.getCodeCacheDir().getAbsolutePath().toString() : 'N/A';
              var obbDir= context.getObbDir().getAbsolutePath().toString();
              var packageCodePath= context.getPackageCodePath().toString();
              var applicationName= app_classname;
             
          colorLog("\n-------------------Application Info--------------------\n",{c: Color.Green});
          colorLog("- Frida version: "+Frida.version,{c: Color.Gray});
          colorLog("- Script runtime: "+Script.runtime,{c: Color.Gray});
          colorLog("- Application Name: "+applicationName,{c: Color.Gray});
          colorLog("- Files Directory: "+filesDirectory,{c: Color.Gray});
          colorLog("- Cache Directory: "+cacheDirectory,{c: Color.Gray});
          colorLog("- External Cache Directory: "+externalCacheDirectory,{c: Color.Gray});
          colorLog("- Code Cache Directory: "+codeCacheDirectory,{c: Color.Gray});
          colorLog("- Obb Directory: "+obbDir,{c: Color.Gray});
          colorLog("- Package Code Path: "+packageCodePath,{c: Color.Gray});
          colorLog("\n-------------------EOF Application Info-----------------\n",{c: Color.Green});
          
              var info = {};
              info.applicationName = applicationName;
              info.filesDirectory = filesDirectory;
              info.cacheDirectory = cacheDirectory;
              info.externalCacheDirectory = externalCacheDirectory;
              info.codeCacheDirectory = codeCacheDirectory;
              info.obbDir = obbDir;
              info.packageCodePath = packageCodePath;
   
              send(JSON.stringify(info));
  
      } else {
          console.log("No context yet!")
      }
}

function dumpIntent(intent, redump=true){

    if(intent.getStringExtra("marked_as_dumped") && redump === false)
        return;
    let bundle_clz = intent.getExtras();
    let data = intent.getData();
    let action = intent.getAction();
    let flags = intent.getFlags();
    colorLog(`${intent}`, {c:Color.Cyan});

    let exported = isActivityExported(intent);
    let str = "(The intent is targeting";
    if(exported)
        colorLog(str+ " an EXPORTED component)", {c:Color.Red});
    else
        colorLog(str+ " a NON EXPORTED component)", {c:Color.Green});

        let type = null;
    if(data != null){
        colorLog('\t\\_data: ', {c:Color.Cyan})
        colorLog('\t\t'+data, {c:Color.Yellow})
    }
    if(action != null){
        colorLog('\t\\_action: ', {c:Color.Cyan})
        colorLog('\t\t'+action, {c:Color.Yellow})
    }

    if(bundle_clz != null){
        colorLog('\t\\_Extras: ', {c:Color.Cyan})
        let keySet = bundle_clz.keySet();
        let iter = keySet.iterator();
        while(iter.hasNext()) {
        let currentKey = iter.next();
        let currentValue = bundle_clz.get(currentKey);
        if (currentValue!=null)
            type =  currentValue.getClass().toString();
        else type = 'undefined'
        
        let t = type.substring(type.lastIndexOf('.')+1,type.length)
        if(currentKey!='marked_as_dumped'){
            if(filterKeyWords.some(word => currentKey.toString().toLowerCase().includes(word)))
            colorLog('\t\t('+t+ ') '+ currentKey + ' = ' + currentValue, {c: Color.Red});
            else
            console.log('\t\t('+t+ ') '+ currentKey + ' = ' + currentValue);
        }
            //console.log( '\t\t('+t+ ') '+ currentKey + ' = ' + currentValue);
        }
    }
    if(flags != null){
      colorLog('\t\\_Flags: 0x' + flags.toString(16), {c: Color.Cyan});
    }
    sendIntentToMonitor(intent);
    intent.putExtra("marked_as_dumped","marked");
}

function sendIntentToMonitor(intent){
    
    try{
        let bundle_clz = intent.getExtras();
        let data = intent.getData();
        let action = intent.getAction();
        let flags = intent.getFlags();
        let exported = isActivityExported(intent);
        let component  = intent.getComponent();
        let itype = intent.getType();

        let targetPackage = "";
        let targetClassName = "";    
        let dataToString ="";
        let extras = "";
        let type = "";
    
        if(data != null){
            dataToString = data.toString();
        }
        
        if(component != null){
            targetPackage = component.getPackageName();
            targetClassName = component.getClassName();
        }

        if(itype != null){
            type = itype.toString();
        }

        if(bundle_clz != null){
            let keySet = bundle_clz.keySet();
            let iter = keySet.iterator();
            while(iter.hasNext()) {
                let currentKey = iter.next();
                let currentValue = bundle_clz.get(currentKey);
                if (currentValue!=null)
                    type =  currentValue.getClass().toString();
                else type = 'undefined'
                let t = type.substring(type.lastIndexOf('.')+1,type.length)
                if(currentKey!='marked_as_dumped'){
                    extras += '\t('+t+ ') '+ currentKey + ' = ' + currentValue+'\n'
                }
            }
            extras+='\n\n'
        }
      
        let sentData = JSON.stringify({"description":intent.toString(), "targetPackageName":targetPackage, 
            "targetClassName":targetClassName, "action":action, "data":dataToString, "type":type, "flags":flags, 
            "extras":extras, "targetIsExported":exported});

          send('IntentMsg|'+sentData);

    } catch(error){
        console.log(error);
    }
}

function enumerateModules(){
    var modules = Process.enumerateModules();
    colorLog('[+] Enumerating loaded modules:',{c: Color.Blue});
    for (var i = 0; i < modules.length; i++)
      console.log(modules[i].path + modules[i].name);
  }
  
function getApplicationContext(){
      return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
}

/*
Calculate the given funcName address from the JNIEnv pointer
*/
function getJNIFunctionAdress(jnienv_addr,func_name){
    var offset = jni_struct_array.indexOf(func_name) * Process.pointerSize
    // console.log("offset : 0x" + offset.toString(16))
    return Memory.readPointer(jnienv_addr.add(offset))
}

// Hook all function to have an overview of the function called
function hook_all(jnienv_addr){
    jni_struct_array.forEach(function(func_name){
        // Calculating the address of the function
        if(!func_name.includes("reserved"))
       {
            var func_addr = getJNIFunctionAdress(jnienv_addr,func_name)
            Interceptor.attach(func_addr,{
                onEnter: function(args){
                    console.log("[+] Entered : " + func_name)
                }
            })
        }
    })
}

function inspectObject(obj) {
    const Class_X = Java.use("java.lang.Class");
    const obj_class = Java.cast(obj.getClass(), Class_X);
    const fields = obj_class.getDeclaredFields();
    const methods = obj_class.getMethods();
    console.log("Inspecting " + obj.getClass().toString());
    console.log("[+]------------------------------Fields------------------------------:");
    for (var i in fields)
        console.log("\t\t" + fields[i].toString());
    console.log("[+]------------------------------Methods-----------------------------:");
    for (var i in methods)
        console.log("\t\t" + methods[i].toString());
}

function isActivityExported(intent){
    try{
      const context = getApplicationContext();
      const packageManager = context.getPackageManager();  
      let resolveInfo = packageManager.resolveActivity(intent, 0);
      return resolveInfo.activityInfo.value.exported.value;
    }
      catch(error){
      //console.log(error)
    }
}

function methodInBeat(invokeId, timestamp, methodName, executor) {
    var startTime = timestamp;
    var androidLogClz = Java.use("android.util.Log");
    var exceptionClz = Java.use("java.lang.Exception");
    var threadClz = Java.use("java.lang.Thread");
    var currentThread = threadClz.currentThread();
    var stackInfo = androidLogClz.getStackTraceString(exceptionClz.$new());
    var str = ("------------startFlag:" + invokeId + ",objectHash:"+executor+",thread(id:" + currentThread.getId() +",name:" + currentThread.getName() + "),timestamp:" + startTime+"---------------\n");
    str += methodName + "\n";
    str += stackInfo.substring(20);
    str += ("------------endFlag:" + invokeId + ",usedtime:" + (new Date().getTime() - startTime) +"---------------\n");
    console.log(str);
}

function newMethodBeat(text, executor) {
    var threadClz = Java.use("java.lang.Thread");
    // var androidLogClz = Java.use("android.util.Log");
    // var exceptionClz = Java.use("java.lang.Exception");
    var currentThread = threadClz.currentThread();
    var beat = new Object();
    beat.invokeId = Math.random().toString(36).slice( - 8);
    beat.executor = executor;
    beat.threadId = currentThread.getId();
    beat.threadName = currentThread.getName();
    beat.text = text;
    beat.startTime = new Date().getTime();
    //beat.stackInfo = androidLogClz.getStackTraceString(exceptionClz.$new()).substring(20);
    return beat;
}

function printBeat(beat) {
    colorLog(beat.text,{c:Color.Gray});
}

let callStackDepth_for_trace_method = 0;

function traceClass(targetClass, color = 'green') {
   
    styleLog(`\nHooking methods of:${targetClass}`, ["Hooking methods of", targetClass],  StyleLogColorset.white, StyleLogColorset.maroon);
    let hook = Java.use(targetClass);
    let methods = hook.class.getDeclaredMethods();
    let parsedMethods = ['$init'];
    let excludeMethods = [];
    methods.forEach(function (method) {
    try {
        parsedMethods.push(
          method.toString().replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]
            );
        } catch (err) {}
    });

    let targets = uniqBy(parsedMethods, JSON.stringify);
    let result = '';

    for (let key in parsedMethods) {
        result += parsedMethods[key] + " (" + key + ") ";
    }
    console.log('Hooks ' + parsedMethods.length + ', (method name, number of overloads) => ' + result);
    targets.forEach(function (targetMethod) {
    try {
        if(!excludeMethods.includes(targetMethod))
            traceMethod(targetClass + "." + targetMethod, color);
    } catch (err) {}
    });
    hook.$dispose();
    console.log();
}

function traceMethod(targetClassMethod, color) {
    let delim = targetClassMethod.lastIndexOf(".");
    if (delim === -1) return;
    let targetClass = targetClassMethod.slice(0, delim);
    let targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length);
    let hook = Java.use(targetClass);
    let overloadCount12 = hook[targetMethod].overloads.length;

    for (let i = 0; i < overloadCount12; i++) {
        hook[targetMethod].overloads[i].implementation = function () {
          let prefix = '│ '.repeat(callStackDepth_for_trace_method);
            styleLog(prefix + "┌ " + targetClassMethod, [targetClassMethod], StyleLogColorset[color], StyleLogColorset['black']);

            callStackDepth_for_trace_method++;

            for (let j = 0; j < arguments.length; j++) {
                console.log(
                    prefix + "│ + arg[" + j + "]: " + arguments[j]
                );
            }
            let retval;
            try {
                retval = this[targetMethod].apply(this, arguments);
            } finally {
              callStackDepth_for_trace_method--;
            }
            let retOutput = '';
            if (retval === undefined) {
                retOutput = "-> Returns: (undefined)";
            } else if (retval === null) {
                retOutput = "-> Returns: null";
            } else {
              let type = typeof retval;
                if (retval.$className) {
                  retOutput = "-> Returns:" + JSON.stringify(retval);
                } else if (type === "object") {
                  retOutput = "-> Returns:" + JSON.stringify(retval);
                } else {
                  retOutput = "-> Returns:" + type + ": " + retval;
                }
            }
            styleLog(prefix + "└ " + retOutput, ["Returns:"], StyleLogColorset[color], StyleLogColorset['black'])
            return retval;
        };
    }
}

function tryGetClass(className){
    var clz = undefined;
    try {
        clz = Java.use(className);
    } catch(e) {}
    return clz;
}

function waitForModule(moduleName) {
    return new Promise(resolve => {
        const interval = setInterval(() => {
            const module = Process.findModuleByName(moduleName);
            if (module != null) {
                clearInterval(interval);
                resolve(module);
            }
        }, 300);
    });
}
  
//----------------------end of android_core.js-------------------------------------


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

    var bundle_clz = intent.getExtras();
    var data = intent.getData();
    var action = intent.getAction();
    colorLog(intent, {c:Color.Cyan});

    var exported = isActivityExported(intent);
    var str = "(The intent is targeting";
    if(exported)
        colorLog(str+ " an EXPORTED component)", {c:Color.Red});
    else
        colorLog(str+ " a NON EXPORTED component)", {c:Color.Green});

    var type = null;
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
        var keySet = bundle_clz.keySet();
        var iter = keySet.iterator();
        while(iter.hasNext()) {
        var currentKey = iter.next();
        var currentValue = bundle_clz.get(currentKey);
        if (currentValue!=null)
            type =  currentValue.getClass().toString();
        else type = 'undefined'
        
        var t = type.substring(type.lastIndexOf('.')+1,type.length)
        if(currentKey!='marked_as_dumped'){
            if(filterKeyWords.some(word => currentKey.toString().toLowerCase().includes(word)))
            colorLog('\t\t('+t+ ') '+ currentKey + ' = ' + currentValue, {c: Color.Red});
            else
            console.log('\t\t('+t+ ') '+ currentKey + ' = ' + currentValue);
        }
            //console.log( '\t\t('+t+ ') '+ currentKey + ' = ' + currentValue);
        }
    }
    intent.putExtra("marked_as_dumped","marked");
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

function notifyNewSharedPreference(key, value) {
    var k = key;
    var v = value;
    Java.use('android.app.SharedPreferencesImpl$EditorImpl').putString.overload('java.lang.String', 'java.lang.String').implementation = function(k, v) {
      console.log('[SharedPreferencesImpl]', k, '=', v);
      return this.putString(k, v);
    }
}

function printBeat(beat) {
    colorLog(beat.text,{c:Color.Gray});
}
  
function traceClass(targetClass,color='Purple'){
    console.log('\x1b[43m\x1b[31m[?] Hooking methods of '+ targetClass +'\x1b[0m\n');
	var hook = Java.use(targetClass);
	var methods = hook.class.getDeclaredMethods();
	hook.$dispose();
	var parsedMethods = ['$init']; 
	methods.forEach(function(method) {
        try{
            parsedMethods.push(method.toString().replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
        }
        catch(err){}
    });
	var targets = uniqBy(parsedMethods, JSON.stringify);
    var result = '';

    for (var key in parsedMethods){
        result += parsedMethods[key] + " (" + key + ") ";
    }

    console.log('Hooks '+parsedMethods.length+', (method name, number of overloads) => '+result)
	targets.forEach(function(targetMethod) {
		try{
			traceMethod(targetClass + "." + targetMethod,color);
		}
		catch(err){}
	});
    console.log();
}

function traceMethod(targetClassMethod,color){
	var delim = targetClassMethod.lastIndexOf(".");
	if (delim === -1) return;
	var targetClass = targetClassMethod.slice(0, delim)
	var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)
	var hook = Java.use(targetClass);
	var overloadCount12 = hook[targetMethod].overloads.length;

	for (var i = 0; i < overloadCount12; i++) {
		hook[targetMethod].overloads[i].implementation = function() {
		  colorLog("\n[ ▶︎▶︎▶︎] Entering: " + targetClassMethod,{c: Color[color]});
			for (var j = 0; j < arguments.length; j++) {
				console.log("|\t\\_arg[" + j + "]: " + arguments[j]);
			}
			var retval = this[targetMethod].apply(this, arguments); 
			colorLog("[ ◀︎◀︎◀︎ ] Exiting " + targetClassMethod ,{c: Color[color]});
      
            console.log('\t\\_Returns: '+retval+'\n');
			return retval;
		}
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

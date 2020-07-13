'use strict';

var FLAG_SECURE_VALUE = "";
var mode = "";
var methodURL = "";
var requestHeaders = "";
var requestBody = "";
var responseHeaders = "";
var responseBody = "";

var Color = {
  RESET: "\x1b[39;49;00m", Black: "0;01", Blue: "4;01", Cyan: "6;01", Gray: "7;11", Green: "2;01", Purple: "5;01", Red: "1;01", Yellow: "3;01",
  Light: {
      Black: "0;11", Blue: "4;11", Cyan: "6;11", Gray: "7;01", Green: "2;11", Purple: "5;11", Red: "1;11", Yellow: "3;11"
  }
};

var colorLog = function (input, kwargs) {
  kwargs = kwargs || {};
  var logLevel = kwargs['l'] || 'log', colorPrefix = '\x1b[3', colorSuffix = 'm';
  if (typeof input === 'object')
      input = JSON.stringify(input, null, kwargs['i'] ? 2 : null);
  if (kwargs['c'])
      input = colorPrefix + kwargs['c'] + colorSuffix + input + Color.RESET;
  console[logLevel](input);
};

var printBacktrace=function () {
  Java.perform(function() {
      var android_util_Log = Java.use('android.util.Log'), java_lang_Exception = Java.use('java.lang.Exception');
      // getting stacktrace by throwing an exception
      colorLog(android_util_Log.getStackTraceString(java_lang_Exception.$new()), { c: Color.Gray });
  });
};

var processArgs = function(command, envp, dir) {
    var output = {};
    if (command) {
      console.log("Command: " + command);
    //   output.command = command;
    }
    if (envp) {
      console.log("Environment: " + envp);
    //   output.envp = envp;
    }
    if (dir) {
      console.log("Working Directory: " + dir);
    //   output.dir = dir;
    }
    // return output;
  }
  

var _byteArraytoHexString = function(byteArray) {
    if (!byteArray) { return 'null'; }
    if (byteArray.map) {
      return byteArray.map(function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
      }).join('');
    } else {
      return byteArray + "";
    }
  }
  
  var updateInput = function(input) {
    if (input.length && input.length > 0) {
      var normalized = byteArraytoHexString(input);
    } else if (input.array) {
      var normalized = byteArraytoHexString(input.array());
    } else {
      var normalized = input.toString();
    }
    return normalized;
  }
  

var byteArraytoHexString = function(byteArray) {
  if (byteArray && byteArray.map) {
    return byteArray.map(function(byte) {
      return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
  } else {
    return JSON.stringify(byteArray);
  }
}

var hexToAscii = function(input) {
  var hex = input.toString();
  var str = '';
  for (var i = 0; i < hex.length; i += 2)
    str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  return str;
}

var displayString = function(input){
	var str = input.replace('[','');
	var str1 = str.replace(']','');
	var res = str1.split(',');
	var ret = '';
	for(var i = 0; i<res.length; i++){
		if(res[i] > 31 && res[i]<127)
			ret += String.fromCharCode(res[i]);
		else ret += ' ';

	}

	console.log("[+] PARSING TO STRING: " + ret);
}
var normalize = function(input) {
    if (input.length && input.length > 0) {
      var normalized = byteArraytoHexString(input);
    } else if (input.array) {
      var normalized = byteArraytoHexString(input.array());
    } else {
      var normalized = input.toString();
    }
    return normalized;
  }

var normalizeInput = function(input) {
  if (input.array) {
    var normalized = byteArraytoHexString(input.array());
  } else if (input.length && input.length > 0) {
    var normalized = byteArraytoHexString(input);
  } else {
    var normalized = JSON.stringify(input);
  }
  return normalized;
}

var getMode = function(Cipher, mode) {
  if (mode === 2) {
    mode = "DECRYPT";
  } else if (mode === 1) {
    mode = "ENCRYPT";
  }
  return mode;
}

var getRandomValue = function(arg) {
  if (!arg) { return 'null'; }
  var type = arg.toString().split('@')[0].split('.');
  type = type[type.length - 1];
  if (type === "SecureRandom") {
    if (arg.getSeed) {
      return byteArraytoHexString(arg.getSeed(10));
    }
  }
}

var normalizeKey = function(cert_or_key) {
  var type = cert_or_key.toString().split('@')[0].split('.');
  type = type[type.length - 1];
  if (type === "SecretKeySpec") {
    return byteArraytoHexString(cert_or_key.getEncoded());
  } else {
    return "non-SecretKeySpec: " + cert_or_key.toString() + ", encoded: " + byteArraytoHexString(cert_or_key.getEncoded()) + ", object: " + JSON.stringify(cert_or_key);
  }

}
var byteArrayToString = function(input){
  var buffer = Java.array('byte', input);
  console.log(buffer.length);
  var result = "";
  for(var i = 0; i < buffer.length; ++i){
      result+= (String.fromCharCode(buffer[i]));
  }
  return result;

}

function getContext() {
	return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  }

  function readStreamToHex (stream) {
    var data = [];
    var byteRead = stream.read();
    while (byteRead != -1)
    {
        data.push( ('0' + (byteRead & 0xFF).toString(16)).slice(-2) );
                /* <---------------- binary to hex ---------------> */
        byteRead = stream.read();
    }
    stream.close();
    return data.join('');
}

  //---------------CREDITS TO: https://github.com/brompwnie/uitkyk
  
  // var objectsToLookFor = ["java.net.Socket", "dalvik.system.DexClassLoader", "java.net.URLConnection", "java.net.URL", "java.security.cert.X509Certificate"];
  // for (var i in objectsToLookFor) {
  //   Java.perform(function () {
  //     Java.choose(objectsToLookFor[i], {
  //       "onMatch": function (instance) {
  //         if (objectsToLookFor[i] == "java.net.URL" && instance.getProtocol() != "file") {
  //           console.log("\n[+] Process has Instantiated instance of: " + objectsToLookFor[i]);
  //           console.log("[*] Process is communicating via " + instance.getProtocol());
  //           console.log("[+] Communication Details: " + instance.toString());
  //         }
  //         if (objectsToLookFor[i] == "dalvik.system.DexClassLoader") {
  //           console.log("\n[+] Process has Instantiated instance of: " + objectsToLookFor[i]);
  //           console.log("[*] Process is making use of DexClassLoader");
  //           console.log("[+] Loader Details: " + instance.toString());
  //         }
  //         if (objectsToLookFor[i] == "java.net.Socket") {
  //           console.log("\n[+] Process has Instantiated instance of: " + objectsToLookFor[i]);
  //           console.log("[*] Process is making use of a Socket Connection");
  //           console.log("[+] Socket Details: " + instance.toString());
  //         }
  //         if (objectsToLookFor[i] == "java.net.URLConnection") {
  //           console.log("\n[+] Process has Instantiated instance of: " + objectsToLookFor[i]);
  //           console.log("[*] Process is making use of a URL Connection");
  //           console.log("[+] Details: " + instance.toString());
  //         }
  //         if (objectsToLookFor[i] == "java.security.cert.X509Certificate") {
  //           console.log("\n[+] Process has Instantiated instance of: " + objectsToLookFor[i]);
  //           console.log("[*] Process is making use of a X509Certificate");
  //           console.log("[+] X509Certificate Details: " + instance.toString());
  //         }
  //       },
  //       "onComplete": function () {
  //       }
  //     });
  //   });
  // }


// --------------------------------------------------------------------------------------
// colorLog(input, kwargs)               change the color of the output
// usage: colorLog('text', { c: Color.Blue });
// getContext()                          returns the application context
// printBacktrace()                      trace the calling class by raising an exception
// _byteArraytoHexString(byteArray)     
// hexToAscii = function(input) 
// byteArrayToString = function(input)
  

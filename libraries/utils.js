'use strict';

var FLAG_SECURE_VALUE = "";
var mode = "";
var methodURL = "";
var requestHeaders = "";
var requestBody = "";
var responseHeaders = "";
var responseBody = "";

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


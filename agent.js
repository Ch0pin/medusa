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

function getContext() {
	return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  }



Java.perform(function() {
 try { 
		
		console.log('\n---Universal ssl pinning bypass V2----');
		
		
		console.log('')
		console.log('===')
		console.log('* Injecting hooks into common certificate pinning methods *')
		console.log('===')
		
		var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
		var SSLContext = Java.use('javax.net.ssl.SSLContext');
		
		// build fake trust manager
		var TrustManager = Java.registerClass({
		    name: 'com.sensepost.test.TrustManager',
		    implements: [X509TrustManager],
		    methods: {
		        checkClientTrusted: function (chain, authType) {
		        },
		        checkServerTrusted: function (chain, authType) {
		        },
		        getAcceptedIssuers: function () {
		            return [];
		        }
		    }
		});
		
		// pass our own custom trust manager through when requested
		var TrustManagers = [TrustManager.$new()];
		var SSLContext_init = SSLContext.init.overload(
		    '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
		);
		SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {
		    
		
		    console.log('! Intercepted trustmanager request');
		    SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
		};
		
		console.log('* Setup custom trust manager');
		
		// okhttp3
		try {
		    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
		    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (str) {
		        console.log('! Intercepted okhttp3: ' + str);
		        return;
		    };
		
		    console.log('* Setup okhttp3 pinning')
		} catch(err) {
		    console.log('* Unable to hook into okhttp3 pinner')
		}
		
		// trustkit
		try {
		    var Activity = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
		    Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (str) {
		        console.log('! Intercepted trustkit{1}: ' + str);
		        return true;
		    };
		
		    Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (str) {
		        console.log('! Intercepted trustkit{2}: ' + str);
		        return true;
		    };
		
		    console.log('* Setup trustkit pinning')
		} catch(err) {
		    console.log('* Unable to hook into trustkit pinner')
		}
		
		// TrustManagerImpl
		try {
		    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
		    TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
		        console.log('! Intercepted TrustManagerImp: ' + host);
		        return untrustedChain;
		    }
		
		    console.log('* Setup TrustManagerImpl pinning')
		} catch (err) {
		    console.log('* Unable to hook into TrustManagerImpl')
		}
		
		// Appcelerator
		try {
		    var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
		    PinningTrustManager.checkServerTrusted.implementation = function () {
		        console.log('! Intercepted Appcelerator');
		    }
		
		    console.log('* Setup Appcelerator pinning')
		} catch (err) {
		    console.log('* Unable to hook into Appcelerator pinning')
		}
    } catch (err) {
                    console.log('Error loading module modules/http_comnunications/universal_SSL_pinning_bypass.med');
            }
 try { 
		
		console.log('\n---WebView Hook------------');
		
		var webView = Java.use('android.webkit.WebView');
		
		webView.setVisibility.implementation = function(a){
		    if(a == 2){
		        console.log('Webview visibility set to Gone');
		        console.log('Cancelling ...' );
		    }
		    else if (a == 1){
		        console.log('Webview visibility set to Hidden');
		        console.log('Cancelling....');
		    }
		        
		    return this.setVisibility(0);
		    
		}
		webView.addJavascriptInterface.implementation = function(object, name){
		    console.log('[i] Javascript interface detected:' + object.$className + ' instatiated as' + name);
		    this.addJavascriptInterface(object,name);
		}
		
		
		webView.evaluateJavascript.implementation = function(script, resultCallback){
		    console.log('[i] evaluateJavascript called with the following script: '+script);
		    this.evaluateJavascript(script,resultCallback);
		}
		
		webView.getOriginalUrl.implementation = function(){
		    console.log('[i] Original URL: ' + this.getOriginalUrl());
		    return this.getOriginalUrl();
		}
		
		webView.getUrl.implementation = function(){
		    console.log('[i] Current Loaded url:' + this.getUrl());
		    return this.getUrl();
		}
		
		webView.loadData.implementation = function(data,mimeType, encoding){
		    console.log('[i] Load data called with the following parameters:\n' + 'Data:' + data + '\nMime type: '+mimeType+'\nEncoding: '+ encoding);
		    this.loadData(data,mimeType,encoding);
		}
		
		webView.loadDataWithBaseURL.implementation = function(baseUrl,  data,  mimeType,  encoding,  historyUrl){
		    console.log('[i] loadDataWithBaseURL call detected, having the following parameters:'+
		    '\nBaseUrl: ' + baseUrl +
		    '\nData: ' + data+
		    '\nmimeType: ' + mimeType+
		    '\nhistory URL' + historyUrl);
		
		    this.loadDataWithBaseURL(baseUrl,data,mimeType,encoding,historyUrl);
		}
		
		webView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url,additionalHttpHeaders){
		    console.log('[i] Loading URL: ' + url);
		    this.loadUrl(url,additionalHttpHeaders);
		}
		
		
		webView.loadUrl.overload('java.lang.String').implementation = function(url){
		    console.log('[i] Loading URL:' + url);
		    this.loadUrl(url);
		}
		
		webView.postUrl.implementation = function (url,postData){
		            
		    var buffer = Java.array('byte', postData);
		    var result = "";
		
		    for(var i = 0; i < buffer.length; ++i){
		        result+= (String.fromCharCode(buffer[i]));
		    }
		
		    console.log('[i] Post request using the webview detected ' + '\nURL: '+url+'Post data:'+result);
		    this.postUrl(url,postData);
		}
		
		webView.removeJavascriptInterface.implementation = function(name){
		    console.log('The ' + name + ' Javascript interface removed');
		    this.removeJavascriptInterface(name);
		}
		
		webView.setWebViewClient.implementation = function(client){
		    console.log('Webview client: ' + client.$className);
		    this.setWebViewClient(client);
		}
    } catch (err) {
                    console.log('Error loading module modules/webviews/hook_webviews.med');
            }
});

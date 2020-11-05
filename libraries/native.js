
'use strict';

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

function enumerateExportsJs(libname) {

  var modulesArray = Process.enumerateModules();
  var found = false;
  colorLog('[+] Script loaded , enumerating library:'+libname+ ' exports...',{c: Color.Blue});
  colorLog('[+] Please wait for the enumeration to finish, do not press any key',{c: Color.Blue});
  for(var i = 0; i < modulesArray.length; i++)
  {
    if(modulesArray[i].path.indexOf(libname) != -1)
    {
      colorLog('Found module: '+modulesArray[i].name,{c: Color.Green})
      found = true

      var exports = modulesArray[i].enumerateExports();
        for(var j = 0; j < exports.length; j++)
          send(exports[j].name);        
          var op = recv('input', function(value) {});
          op.wait();
          
    }
    
        if (found) break;
    }
}

function enumerateModules(){
  
    var modules = Process.enumerateModules();
    colorLog('[+] Script loaded , enumerating modules...',{c: Color.Blue});
    colorLog('[+] Please wait for the enumeration to finish, do not press any key',{c: Color.Blue});

    for (var i = 0; i < modules.length; i++)
      send(modules[i].path);
      var op = recv('input', function(value) {});
      op.wait();
  }

Java.perform(function() {
enumerateModules(); 
});

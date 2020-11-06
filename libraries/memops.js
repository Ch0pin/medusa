rpc.exports = {

    memorydump: function (address, size) {
        Memory.protect(ptr(address), size, "rwx");
        var a = Memory.readByteArray(ptr(address),size-1000);
        return a;
    },
    
    moduleaddress: function (lib){
      try{
        var ret = [];
        var module = Process.findModuleByName(lib);
        var address = Module.findBaseAddress(lib);
        var sz = module.size;
      
      ret.push({
        "addr": address,
        "size": sz
      });
      return ret;
    }
    catch(err){
      console.log('[!] Error: '+err);
    }
  
  
  
    },

  };
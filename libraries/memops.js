rpc.exports = {

    memorydump: function (address, size) {
        Memory.protect(ptr(address), size, "rwx");
        var a = Memory.readByteArray(ptr(address),size-1000);
        // var baseAddress = parseInt(address,16);
        // var endAddress = baseAddress + size;

        // Process.enumerateRanges('r--').forEach(function (range) {
        //    try {
        //        Memory.scanSync(address, range.size, "??").forEach(function (match) {
        //          var curent = parceInt(match.address);

        //         if(curent >= baseAddress && curent <= endAddress)

        //            if (range.file && range.file.path
        //               && (// range.file.path.startsWith("/data/app/") ||
        //                   range.file.path.startsWith("/data/dalvik-cache/") ||
        //                   range.file.path.startsWith("/system/"))) {
        //               return;
        //           }

        //           if (verify(match.address, range, false)) {
        //               var dex_size = match.address.add(0x20).readUInt();
        //               result.push({
        //                   "addr": match.address,
        //                   "size": dex_size
        //               });
        //           }
        //       });





        // console.log('pointer: Address: '+address + ' Size:'+size)
        return a;
    },
    
    moduleaddress: function (lib){
      try{

        var ret = [];
        var module = Process.findModuleByName(lib);
        var address = Module.findBaseAddress(lib);
        var sz = module.size;
      

     // console.log('Address: '+address + ' Size:'+sz)
      
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
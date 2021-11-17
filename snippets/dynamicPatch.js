Java.perform(function () {

    let base;
    let do_dlopen = null;
    let call_ctor = null;
    const target_lib_name = 'libcleanplayer.so';
    
    Process.findModuleByName('linker64').enumerateSymbols().forEach(sym => {
        if (sym.name.indexOf('do_dlopen') >= 0) {
            do_dlopen = sym.address;
        } else if (sym.name.indexOf('call_constructor') >= 0) {
            call_ctor = sym.address;
        }
    })
    
    Interceptor.attach(do_dlopen, function (args) {
        if (args[0].readUtf8String().indexOf(target_lib_name) >= 0) {
            Interceptor.attach(call_ctor, function () {
                const module = Process.findModuleByName(target_lib_name);
                base = module.base;
                console.log('loading', target_lib_name, '- base @', base);
            
            // DoStuff
            })
        }
    })
    var module = Process.findModuleByName("libcleanplayer.so");
    var p_foo = Module.findBaseAddress("libcleanplayer.so");
    if (!p_foo) {
        console.log("Could not find module....");
        return 0;
    }
    
    var address = p_foo.add(3518);
    console.log('Write op started');
    Memory.protect(address, 0x5, "rwx");
    Memory.writeByteArray(ptr(address), [0x20,0x00,0x00])
    console.log('Write op finished');
    

});
var strncmp = undefined;
var imports = Module.enumerateImportsSync("libfoo.so");

for (var i = 0; i < imports.length; i++) {
    if (imports[i].name == "strncmp") {
        strncmp = imports[i].address;
        break;
    }
}
Interceptor.attach(strncmp, {
    
    onEnter: function(args) {
        if (args[2].toInt32() == 23 && Memory.readUtf8String(args[0], 23) == "01234567890123456789012") {
            console.log("[*] Secret string at " + args[1] + ": " + Memory.readUtf8String(args[1], 23));
        }
    },
});
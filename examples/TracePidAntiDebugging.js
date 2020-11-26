    var anti_fgets = function () {
        show_log("anti_fgets");
        var fgetsPtr = Module.findExportByName("libc.so", "fgets");
        var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
        Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
            var retval = fgets(buffer, size, fp);
            var bufstr = Memory.readUtf8String(buffer);
            if (bufstr.indexOf("TracerPid:") > -1) {
                Memory.writeUtf8String(buffer, "TracerPid:\t0");
                // dmLogout("tracerpid replaced: " + Memory.readUtf8String(buffer));
            }
            return retval;
        }, 'pointer', ['pointer', 'int', 'pointer']));
    };
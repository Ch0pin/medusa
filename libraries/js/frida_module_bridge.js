
//----------------------start of frida_Module_bridge-------------------------------------

Module.ensureInitialized = function(libname) {
    Process.getModuleByName(libname).ensureInitialized();
};

Module.findBaseAddress = function(libname) {
    if (libname === null) {
        var modules = Process.enumerateModules();
        return modules.length > 0 ? modules[0].base : null;
    }
    var mod = Process.findModuleByName(libname);
    return mod ? mod.base : null;
};

Module.getBaseAddress = function(libname) {
    if (libname === null) {
        var modules = Process.enumerateModules();
        if (modules.length > 0) return modules[0].base;
        throw new Error('No modules found');
    }
    return Process.getModuleByName(libname).base;
};

Module.getExportByName = function(libname, exportName) {
    if (libname === null) {
        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {
            var addr = modules[i].findExportByName(exportName);
            if (addr !== null) return addr;
        }
        throw new Error('Export not found: ' + exportName);
    }
    return Process.getModuleByName(libname).getExportByName(exportName);
};

Module.findExportByName = function(libname, exportName) {
    if (libname === null) {
        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {
            var addr = modules[i].findExportByName(exportName);
            if (addr !== null) return addr;
        }
        return null;
    }
    var mod = Process.findModuleByName(libname);
    return mod ? mod.findExportByName(exportName) : null;
};

Module.findSymbolByName = function(libname, symbolName) {
    if (libname === null) {
        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {
            var addr = modules[i].findSymbolByName(symbolName);
            if (addr !== null) return addr;
        }
        return null;
    }
    var mod = Process.findModuleByName(libname);
    return mod ? mod.findSymbolByName(symbolName) : null;
};

Module.getSymbolByName = function(libname, symbolName) {
    if (libname === null) {
        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {
            var addr = modules[i].findSymbolByName(symbolName);
            if (addr !== null) return addr;
        }
        throw new Error('Symbol not found: ' + symbolName);
    }
    return Process.getModuleByName(libname).getSymbolByName(symbolName);
};

Module.enumerateExports = function(libname) {
    if (libname === null) {
        var allExports = [];
        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {
            allExports = allExports.concat(modules[i].enumerateExports());
        }
        return allExports;
    }
    return Process.getModuleByName(libname).enumerateExports();
};


//----------------------End of frida_Module_bridge-------------------------------------

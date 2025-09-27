
//----------------------start of frida_Module_bridge-------------------------------------

Module.ensureInitialized = function(libname) {
    Process.getModuleByName(libname).ensureInitialized();
};

Module.findBaseAddress = function(libname) {
    return Process.getModuleByName(libname).findBaseAddress();
};

Module.getBaseAddress = function(libname) {
    return Process.getModuleByName(libname).base;
};

Module.getExportByName = function(libname, exportName) {
    return Process.getModuleByName(libname).getExportByName(exportName);
};

Module.findExportByName = function(libname, exportName) {
    return Process.getModuleByName(libname).findExportByName(exportName);
};

Module.findSymbolByName = function(libname, symbolName) {
    return Process.getModuleByName(libname).findSymbolByName(symbolName);
};

Module.getSymbolByName = function(libname, symbolName) {
    return Process.getModuleByName(libname).getSymbolByName(symbolName);
};

Module.enumerateExports = function(libname) {
    return Process.getModuleByName(libname).enumerateExports();
};


//----------------------End of frida_Module_bridge-------------------------------------

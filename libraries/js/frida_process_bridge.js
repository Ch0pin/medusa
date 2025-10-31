//----------------------start of frida_Process_bridge-------------------------------------

Process.enumerateRangesSync = function(protectionOrSpecifier) {
    return Process.enumerateRanges(protectionOrSpecifier);
};

Process.enumerateModulesSync = function() {
    return Process.enumerateModules();
};

//----------------------start of frida_Process_bridge-------------------------------------

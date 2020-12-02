
//https://www.jianshu.com/p/4291ee42c412

var func = Module.findBaseAddress("libil2cpp.so").add(0x56FCA8);
Interceptor.attach(func, {
    onEnter: function(args){
        console.log("called from:\n"+
            Thread.backtrace(this.context,Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join("\n"));
    },
    onLeave: function(retval){
        
    }
});
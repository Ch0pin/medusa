//主动调用native函数
var soAddr = Module.findBaseAddress("libil2cpp.so");
new NativeFunction(soAddr.add(0x4c33b0),"void",['pointer'])(Java.vm.tryGetEnv())

//替换native函数
//支持的类型：void,pointer,int,uint,long,ulong,char,uchar,float,double,int8,uint8,int16,uint16,int32,uint32,int64,uint64,bool
Interceptor.replace(new NativeFunction(soAddr.add(0x58F0F4),'void', ['pointer']), new NativeCallback(function (arg) {
    console.log("called from:\n"+
            Thread.backtrace(this.context,Backtracer.FUZZY)
            .map(DebugSymbol.fromAddress).join("\n"));
}, 'void', ['pointer']));

//拦截native函数
Interceptor.attach(soAddr.add(0xb7a93c),{
    onEnter:function(arg){
        console.log("called 0xb7a93c")
    },
    onLeave:function(retval){
        console.warn(retval)
    }
})
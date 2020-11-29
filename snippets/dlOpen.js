// https://www.jianshu.com/p/4291ee42c412

var dlopen = Module.findExportByName(null, "dlopen");
console.log(dlopen);
if(dlopen != null){
    Interceptor.attach(dlopen,{
        onEnter: function(args){
            var soName = args[0].readCString();
            console.log(soName);
            if(soName.indexOf("libc.so") != -1){
                this.hook = true;
            }
        },
        onLeave: function(retval){
            if(this.hook) { 
                dlopentodo();
            };
        }
    });
}


var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
console.log(android_dlopen_ext);
if(android_dlopen_ext != null){
    Interceptor.attach(android_dlopen_ext,{
        onEnter: function(args){
            var soName = args[0].readCString();
            console.log(soName);
            if(soName.indexOf("libc.so") != -1){
                this.hook = true;
            }
        },
        onLeave: function(retval){
            if(this.hook) {
                dlopentodo();
            };
        }
    });
}
function dlopentodo(){
    //todo ...
}
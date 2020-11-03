Interceptor.attach(Module.findBaseAddress('libfoo.so').add(0x1234), {
    onEnter: function(args) {

    },
    onLeave: function(retval) {

    }
  });
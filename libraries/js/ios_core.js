
//----------------------begin of ios_core.js-------------------------------------


//Credits https://codeshare.frida.re/@mrmacete/objc-method-observer/

var ISA_MASK = ptr('0x0000000ffffffff8');
var ISA_MAGIC_MASK = ptr('0x000003f000000001');
var ISA_MAGIC_VALUE = ptr('0x000001a000000001');


function ios_isObjC(p) {
    var klass = ios_getObjCClassPtr(p);
    return !klass.isNull();
}

function ios_getObjCClassPtr(p) {
    /*
     * Loosely based on:
     * https://blog.timac.org/2016/1124-testing-if-an-arbitrary-pointer-is-a-valid-objective-c-object/
     */

    if (!ios_isReadable(p)) {
        return NULL;
    }
    var isa = p.readPointer();
    var classP = isa;
    if (classP.and(ISA_MAGIC_MASK).equals(ISA_MAGIC_VALUE)) {
        classP = isa.and(ISA_MASK);
    }
    if (ios_isReadable(classP)) {
        return classP;
    }
    return NULL;
}

function ios_isReadable(p) {
    try {
        p.readU8();
        return true;
    } catch (e) {
        return false;
    }
}

function ios_observeMethod(impl, name, m,color='Purple') {
  console.log('Observing ' + name + ' ' + m);
  Interceptor.attach(impl, {
      onEnter: function(a) {
          this.log = [];
          //this.log.push('(' + a[0] + ') ' + name + ' ' + m);
          colorLog('\n[ ▶︎▶︎▶︎] Entering:'+'(' + a[0] + ') ' + name + ' ' + m,{c: Color[color]});
          if (m.indexOf(':') !== -1) {
              var params = m.split(':');
              params[0] = params[0].split(' ')[1];
              var j = 0;
              for (var i = 0; i < params.length - 1; i++) {
                  if (ios_isObjC(a[2 + i])) {
                      const theObj = new ObjC.Object(a[2 + i]);
                      console.log("|\t\\_arg[" + j + "]: " + theObj.toString() + ' (' + theObj.$className + ')');
                      j+=1;
                  }
              }
          }
      },

      onLeave: function(r) {
          if (ios_isObjC(r)) {
              this.log.push(new ObjC.Object(r).toString());
          } else {
              this.log.push(r.toString());
          }
          colorLog("\n[ ▶︎▶︎▶︎] Exiting: " + name+' [- '+m+' ]',{c: Color[color]});
          console.log("\t\\_RET: " + this.log.join('\n'));
          
        
      }
  });
}

function ios_run_hook_all_methods_of_specific_ios_class(className_arg,color='Purple')
{
  console.log("[+] Start set hooks for all methods of class: "+className_arg);
  var k = ObjC.classes[className_arg];
  if (!k) {
      return;
  }
  console.log("[+] Abbout to hook: "+k.$ownMethods.length+" methods.");
  k.$ownMethods.forEach(function(m) {
    ios_observeMethod(k[m].implementation, className_arg, m,color);
  });
  console.log("[*] Completed setting hooks for: "+className_arg);
}

//----------------------end of ios_core.js-------------------------------------



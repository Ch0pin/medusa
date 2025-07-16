//"frida-objc-bridge", version="8.0.5"

var cachedApi = null;
var defaultInvocationOptions = {
  exceptions: "propagate"
};
function getApi() {
  if (cachedApi !== null) {
    return cachedApi;
  }
  const temporaryApi = {};
  const pending = [
    {
      module: "libsystem_malloc.dylib",
      functions: {
        "free": ["void", ["pointer"]]
      }
    },
    {
      module: "libobjc.A.dylib",
      functions: {
        "objc_msgSend": function(address) {
          this.objc_msgSend = address;
        },
        "objc_msgSend_stret": function(address) {
          this.objc_msgSend_stret = address;
        },
        "objc_msgSend_fpret": function(address) {
          this.objc_msgSend_fpret = address;
        },
        "objc_msgSendSuper": function(address) {
          this.objc_msgSendSuper = address;
        },
        "objc_msgSendSuper_stret": function(address) {
          this.objc_msgSendSuper_stret = address;
        },
        "objc_msgSendSuper_fpret": function(address) {
          this.objc_msgSendSuper_fpret = address;
        },
        "objc_getClassList": ["int", ["pointer", "int"]],
        "objc_lookUpClass": ["pointer", ["pointer"]],
        "objc_allocateClassPair": ["pointer", ["pointer", "pointer", "pointer"]],
        "objc_disposeClassPair": ["void", ["pointer"]],
        "objc_registerClassPair": ["void", ["pointer"]],
        "class_isMetaClass": ["bool", ["pointer"]],
        "class_getName": ["pointer", ["pointer"]],
        "class_getImageName": ["pointer", ["pointer"]],
        "class_copyProtocolList": ["pointer", ["pointer", "pointer"]],
        "class_copyMethodList": ["pointer", ["pointer", "pointer"]],
        "class_getClassMethod": ["pointer", ["pointer", "pointer"]],
        "class_getInstanceMethod": ["pointer", ["pointer", "pointer"]],
        "class_getSuperclass": ["pointer", ["pointer"]],
        "class_addProtocol": ["bool", ["pointer", "pointer"]],
        "class_addMethod": ["bool", ["pointer", "pointer", "pointer", "pointer"]],
        "class_copyIvarList": ["pointer", ["pointer", "pointer"]],
        "objc_getProtocol": ["pointer", ["pointer"]],
        "objc_copyProtocolList": ["pointer", ["pointer"]],
        "objc_allocateProtocol": ["pointer", ["pointer"]],
        "objc_registerProtocol": ["void", ["pointer"]],
        "protocol_getName": ["pointer", ["pointer"]],
        "protocol_copyMethodDescriptionList": ["pointer", ["pointer", "bool", "bool", "pointer"]],
        "protocol_copyPropertyList": ["pointer", ["pointer", "pointer"]],
        "protocol_copyProtocolList": ["pointer", ["pointer", "pointer"]],
        "protocol_addProtocol": ["void", ["pointer", "pointer"]],
        "protocol_addMethodDescription": ["void", ["pointer", "pointer", "pointer", "bool", "bool"]],
        "ivar_getName": ["pointer", ["pointer"]],
        "ivar_getTypeEncoding": ["pointer", ["pointer"]],
        "ivar_getOffset": ["pointer", ["pointer"]],
        "object_isClass": ["bool", ["pointer"]],
        "object_getClass": ["pointer", ["pointer"]],
        "object_getClassName": ["pointer", ["pointer"]],
        "method_getName": ["pointer", ["pointer"]],
        "method_getTypeEncoding": ["pointer", ["pointer"]],
        "method_getImplementation": ["pointer", ["pointer"]],
        "method_setImplementation": ["pointer", ["pointer", "pointer"]],
        "property_getName": ["pointer", ["pointer"]],
        "property_copyAttributeList": ["pointer", ["pointer", "pointer"]],
        "sel_getName": ["pointer", ["pointer"]],
        "sel_registerName": ["pointer", ["pointer"]],
        "class_getInstanceSize": ["pointer", ["pointer"]]
      },
      optionals: {
        "objc_msgSend_stret": "ABI",
        "objc_msgSend_fpret": "ABI",
        "objc_msgSendSuper_stret": "ABI",
        "objc_msgSendSuper_fpret": "ABI",
        "object_isClass": "iOS8"
      }
    },
    {
      module: "libdispatch.dylib",
      functions: {
        "dispatch_async_f": ["void", ["pointer", "pointer", "pointer"]]
      },
      variables: {
        "_dispatch_main_q": function(address) {
          this._dispatch_main_q = address;
        }
      }
    }
  ];
  let remaining = 0;
  pending.forEach(function(api2) {
    const isObjCApi = api2.module === "libobjc.A.dylib";
    const functions = api2.functions || {};
    const variables = api2.variables || {};
    const optionals = api2.optionals || {};
    remaining += Object.keys(functions).length + Object.keys(variables).length;
    const exportByName = (Process.findModuleByName(api2.module)?.enumerateExports() ?? []).reduce(function(result, exp) {
      result[exp.name] = exp;
      return result;
    }, {});
    Object.keys(functions).forEach(function(name) {
      const exp = exportByName[name];
      if (exp !== void 0 && exp.type === "function") {
        const signature2 = functions[name];
        if (typeof signature2 === "function") {
          signature2.call(temporaryApi, exp.address);
          if (isObjCApi)
            signature2.call(temporaryApi, exp.address);
        } else {
          temporaryApi[name] = new NativeFunction(exp.address, signature2[0], signature2[1], defaultInvocationOptions);
          if (isObjCApi)
            temporaryApi[name] = temporaryApi[name];
        }
        remaining--;
      } else {
        const optional = optionals[name];
        if (optional)
          remaining--;
      }
    });
    Object.keys(variables).forEach(function(name) {
      const exp = exportByName[name];
      if (exp !== void 0 && exp.type === "variable") {
        const handler = variables[name];
        handler.call(temporaryApi, exp.address);
        remaining--;
      }
    });
  });
  if (remaining === 0) {
    if (!temporaryApi.objc_msgSend_stret)
      temporaryApi.objc_msgSend_stret = temporaryApi.objc_msgSend;
    if (!temporaryApi.objc_msgSend_fpret)
      temporaryApi.objc_msgSend_fpret = temporaryApi.objc_msgSend;
    if (!temporaryApi.objc_msgSendSuper_stret)
      temporaryApi.objc_msgSendSuper_stret = temporaryApi.objc_msgSendSuper;
    if (!temporaryApi.objc_msgSendSuper_fpret)
      temporaryApi.objc_msgSendSuper_fpret = temporaryApi.objc_msgSendSuper;
    cachedApi = temporaryApi;
  }
  return cachedApi;
}

// node_modules/frida-objc-bridge/lib/fastpaths.js
var code = `#include <glib.h>
#include <ptrauth.h>

#define KERN_SUCCESS 0
#define MALLOC_PTR_IN_USE_RANGE_TYPE 1
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
# define OBJC_ISA_MASK 0x7ffffffffff8ULL
#elif defined (HAVE_ARM64)
# define OBJC_ISA_MASK 0xffffffff8ULL
#endif

typedef struct _ChooseContext ChooseContext;

typedef struct _malloc_zone_t malloc_zone_t;
typedef struct _malloc_introspection_t malloc_introspection_t;
typedef struct _vm_range_t vm_range_t;

typedef gpointer Class;
typedef int kern_return_t;
typedef guint mach_port_t;
typedef mach_port_t task_t;
typedef guintptr vm_offset_t;
typedef guintptr vm_size_t;
typedef vm_offset_t vm_address_t;

struct _ChooseContext
{
  GHashTable * classes;
  GArray * matches;
};

struct _malloc_zone_t
{
  void * reserved1;
  void * reserved2;
  size_t (* size) (struct _malloc_zone_t * zone, const void * ptr);
  void * (* malloc) (struct _malloc_zone_t * zone, size_t size);
  void * (* calloc) (struct _malloc_zone_t * zone, size_t num_items, size_t size);
  void * (* valloc) (struct _malloc_zone_t * zone, size_t size);
  void (* free) (struct _malloc_zone_t * zone, void * ptr);
  void * (* realloc) (struct _malloc_zone_t * zone, void * ptr, size_t size);
  void (* destroy) (struct _malloc_zone_t * zone);
  const char * zone_name;

  unsigned (* batch_malloc) (struct _malloc_zone_t * zone, size_t size, void ** results, unsigned num_requested);
  void (* batch_free) (struct _malloc_zone_t * zone, void ** to_be_freed, unsigned num_to_be_freed);

  malloc_introspection_t * introspect;
};

typedef kern_return_t (* memory_reader_t) (task_t remote_task, vm_address_t remote_address, vm_size_t size, void ** local_memory);
typedef void (* vm_range_recorder_t) (task_t task, void * user_data, unsigned type, vm_range_t * ranges, unsigned count);
typedef kern_return_t (* enumerator_func) (task_t task, void * user_data, unsigned type_mask, vm_address_t zone_address, memory_reader_t reader,
      vm_range_recorder_t recorder);

struct _malloc_introspection_t
{
  enumerator_func enumerator;
};

struct _vm_range_t
{
  vm_address_t address;
  vm_size_t size;
};

extern int objc_getClassList (Class * buffer, int buffer_count);
extern Class class_getSuperclass (Class cls);
extern size_t class_getInstanceSize (Class cls);
extern kern_return_t malloc_get_all_zones (task_t task, memory_reader_t reader, vm_address_t ** addresses, unsigned * count);

static void collect_subclasses (Class klass, GHashTable * result);
static void collect_matches_in_ranges (task_t task, void * user_data, unsigned type, vm_range_t * ranges, unsigned count);
static kern_return_t read_local_memory (task_t remote_task, vm_address_t remote_address, vm_size_t size, void ** local_memory);

extern mach_port_t selfTask;

gpointer *
choose (Class * klass,
        gboolean consider_subclasses,
        guint * count)
{
  ChooseContext ctx;
  GHashTable * classes;
  vm_address_t * malloc_zone_addresses;
  unsigned malloc_zone_count, i;

  classes = g_hash_table_new_full (NULL, NULL, NULL, NULL);
  ctx.classes = classes;
  ctx.matches = g_array_new (FALSE, FALSE, sizeof (gpointer));
  if (consider_subclasses)
    collect_subclasses (klass, classes);
  else
    g_hash_table_insert (classes, klass, GSIZE_TO_POINTER (class_getInstanceSize (klass)));

  malloc_zone_count = 0;
  malloc_get_all_zones (selfTask, read_local_memory, &malloc_zone_addresses, &malloc_zone_count);

  for (i = 0; i != malloc_zone_count; i++)
  {
    vm_address_t zone_address = malloc_zone_addresses[i];
    malloc_zone_t * zone = (malloc_zone_t *) zone_address;
    enumerator_func enumerator;

    if (zone != NULL && zone->introspect != NULL &&
        (enumerator = (ptrauth_strip (zone->introspect, ptrauth_key_asda))->enumerator) != NULL)
    {
      enumerator = ptrauth_sign_unauthenticated (
          ptrauth_strip (enumerator, ptrauth_key_asia),
          ptrauth_key_asia, 0);

      enumerator (selfTask, &ctx, MALLOC_PTR_IN_USE_RANGE_TYPE, zone_address, read_local_memory,
          collect_matches_in_ranges);
    }
  }

  g_hash_table_unref (classes);

  *count = ctx.matches->len;

  return (gpointer *) g_array_free (ctx.matches, FALSE);
}

void
destroy (gpointer mem)
{
  g_free (mem);
}

static void
collect_subclasses (Class klass,
                    GHashTable * result)
{
  Class * classes;
  int count, i;

  count = objc_getClassList (NULL, 0);
  classes = g_malloc (count * sizeof (gpointer));
  count = objc_getClassList (classes, count);

  for (i = 0; i != count; i++)
  {
    Class candidate = classes[i];
    Class c;

    c = candidate;
    do
    {
      if (c == klass)
      {
        g_hash_table_insert (result, candidate, GSIZE_TO_POINTER (class_getInstanceSize (candidate)));
        break;
      }

      c = class_getSuperclass (c);
    }
    while (c != NULL);
  }

  g_free (classes);
}

static void
collect_matches_in_ranges (task_t task,
                           void * user_data,
                           unsigned type,
                           vm_range_t * ranges,
                           unsigned count)
{
  ChooseContext * ctx = user_data;
  GHashTable * classes = ctx->classes;
  unsigned i;

  for (i = 0; i != count; i++)
  {
    const vm_range_t * range = &ranges[i];
    gconstpointer candidate = GSIZE_TO_POINTER (range->address);
    gconstpointer isa;
    guint instance_size;

    isa = *(gconstpointer *) candidate;
#ifdef OBJC_ISA_MASK
    isa = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (isa) & OBJC_ISA_MASK);
#endif

    instance_size = GPOINTER_TO_UINT (g_hash_table_lookup (classes, isa));
    if (instance_size != 0 && range->size >= instance_size)
    {
      g_array_append_val (ctx->matches, candidate);
    }
  }
}

static kern_return_t
read_local_memory (task_t remote_task,
                   vm_address_t remote_address,
                   vm_size_t size,
                   void ** local_memory)
{
  *local_memory = (void *) remote_address;

  return KERN_SUCCESS;
}
`;
var { pointerSize: pointerSize2 } = Process;
var cachedModule = null;
function get() {
  if (cachedModule === null)
    cachedModule = compileModule();
  return cachedModule;
}
function compileModule() {
  const {
    objc_getClassList,
    class_getSuperclass,
    class_getInstanceSize
  } = getApi();
  const selfTask = Memory.alloc(4);
  selfTask.writeU32(Module.getGlobalExportByName("mach_task_self_").readU32());
  const cm = new CModule(code, {
    objc_getClassList,
    class_getSuperclass,
    class_getInstanceSize,
    malloc_get_all_zones: Process.getModuleByName("/usr/lib/system/libsystem_malloc.dylib").getExportByName("malloc_get_all_zones"),
    selfTask
  });
  const _choose = new NativeFunction(cm.choose, "pointer", ["pointer", "bool", "pointer"]);
  const _destroy = new NativeFunction(cm.destroy, "void", ["pointer"]);
  return {
    handle: cm,
    choose(klass, considerSubclasses) {
      const result = [];
      const countPtr = Memory.alloc(4);
      const matches = _choose(klass, considerSubclasses ? 1 : 0, countPtr);
      try {
        const count = countPtr.readU32();
        for (let i = 0; i !== count; i++)
          result.push(matches.add(i * pointerSize2).readPointer());
      } finally {
        _destroy(matches);
      }
      return result;
    }
  };
}

// node_modules/frida-objc-bridge/index.js
function Runtime() {
  const pointerSize = Process.pointerSize;
  let api = null;
  let apiError = null;
  const realizedClasses = /* @__PURE__ */ new Set();
  const classRegistry = new ClassRegistry();
  const protocolRegistry = new ProtocolRegistry();
  const replacedMethods = /* @__PURE__ */ new Map();
  const scheduledWork = /* @__PURE__ */ new Map();
  let nextId = 1;
  let workCallback = null;
  let NSAutoreleasePool = null;
  const bindings = /* @__PURE__ */ new Map();
  let readObjectIsa = null;
  const msgSendBySignatureId = /* @__PURE__ */ new Map();
  const msgSendSuperBySignatureId = /* @__PURE__ */ new Map();
  let cachedNSString = null;
  let cachedNSStringCtor = null;
  let cachedNSNumber = null;
  let cachedNSNumberCtor = null;
  let singularTypeById = null;
  let modifiers = null;
  try {
    tryInitialize();
  } catch (e) {
  }
  function tryInitialize() {
    if (api !== null)
      return true;
    if (apiError !== null)
      throw apiError;
    try {
      api = getApi();
    } catch (e) {
      apiError = e;
      throw e;
    }
    return api !== null;
  }
  function dispose() {
    for (const [rawMethodHandle, impls] of replacedMethods.entries()) {
      const methodHandle = ptr(rawMethodHandle);
      const [oldImp, newImp] = impls;
      if (api.method_getImplementation(methodHandle).equals(newImp))
        api.method_setImplementation(methodHandle, oldImp);
    }
    replacedMethods.clear();
  }
  Script.bindWeak(this, dispose);
  Object.defineProperty(this, "available", {
    enumerable: true,
    get() {
      return tryInitialize();
    }
  });
  Object.defineProperty(this, "api", {
    enumerable: true,
    get() {
      return getApi();
    }
  });
  Object.defineProperty(this, "classes", {
    enumerable: true,
    value: classRegistry
  });
  Object.defineProperty(this, "protocols", {
    enumerable: true,
    value: protocolRegistry
  });
  Object.defineProperty(this, "Object", {
    enumerable: true,
    value: ObjCObject
  });
  Object.defineProperty(this, "Protocol", {
    enumerable: true,
    value: ObjCProtocol
  });
  Object.defineProperty(this, "Block", {
    enumerable: true,
    value: Block
  });
  Object.defineProperty(this, "mainQueue", {
    enumerable: true,
    get() {
      return api?._dispatch_main_q ?? null;
    }
  });
  Object.defineProperty(this, "registerProxy", {
    enumerable: true,
    value: registerProxy
  });
  Object.defineProperty(this, "registerClass", {
    enumerable: true,
    value: registerClass
  });
  Object.defineProperty(this, "registerProtocol", {
    enumerable: true,
    value: registerProtocol
  });
  Object.defineProperty(this, "bind", {
    enumerable: true,
    value: bind
  });
  Object.defineProperty(this, "unbind", {
    enumerable: true,
    value: unbind
  });
  Object.defineProperty(this, "getBoundData", {
    enumerable: true,
    value: getBoundData
  });
  Object.defineProperty(this, "enumerateLoadedClasses", {
    enumerable: true,
    value: enumerateLoadedClasses
  });
  Object.defineProperty(this, "enumerateLoadedClassesSync", {
    enumerable: true,
    value: enumerateLoadedClassesSync
  });
  Object.defineProperty(this, "choose", {
    enumerable: true,
    value: choose
  });
  Object.defineProperty(this, "chooseSync", {
    enumerable: true,
    value(specifier) {
      const instances = [];
      choose(specifier, {
        onMatch(i) {
          instances.push(i);
        },
        onComplete() {
        }
      });
      return instances;
    }
  });
  this.schedule = function(queue, work) {
    const id = ptr(nextId++);
    scheduledWork.set(id.toString(), work);
    if (workCallback === null) {
      workCallback = new NativeCallback(performScheduledWorkItem, "void", ["pointer"]);
    }
    Script.pin();
    api.dispatch_async_f(queue, id, workCallback);
  };
  function performScheduledWorkItem(rawId) {
    const id = rawId.toString();
    const work = scheduledWork.get(id);
    scheduledWork.delete(id);
    if (NSAutoreleasePool === null)
      NSAutoreleasePool = classRegistry.NSAutoreleasePool;
    const pool = NSAutoreleasePool.alloc().init();
    let pendingException = null;
    try {
      work();
    } catch (e) {
      pendingException = e;
    }
    pool.release();
    setImmediate(performScheduledWorkCleanup, pendingException);
  }
  function performScheduledWorkCleanup(pendingException) {
    Script.unpin();
    if (pendingException !== null) {
      throw pendingException;
    }
  }
  this.implement = function(method2, fn) {
    return new NativeCallback(fn, method2.returnType, method2.argumentTypes);
  };
  this.selector = selector;
  this.selectorAsString = selectorAsString;
  function selector(name) {
    return api.sel_registerName(Memory.allocUtf8String(name));
  }
  function selectorAsString(sel2) {
    return api.sel_getName(sel2).readUtf8String();
  }
  const registryBuiltins = /* @__PURE__ */ new Set([
    "prototype",
    "constructor",
    "hasOwnProperty",
    "toJSON",
    "toString",
    "valueOf"
  ]);
  function ClassRegistry() {
    const cachedClasses = {};
    let numCachedClasses = 0;
    const registry = new Proxy(this, {
      has(target, property) {
        return hasProperty(property);
      },
      get(target, property, receiver) {
        switch (property) {
          case "prototype":
            return target.prototype;
          case "constructor":
            return target.constructor;
          case "hasOwnProperty":
            return hasProperty;
          case "toJSON":
            return toJSON;
          case "toString":
            return toString;
          case "valueOf":
            return valueOf;
          default:
            const klass = findClass(property);
            return klass !== null ? klass : void 0;
        }
      },
      set(target, property, value, receiver) {
        return false;
      },
      ownKeys(target) {
        if (api === null)
          return [];
        let numClasses = api.objc_getClassList(NULL, 0);
        if (numClasses !== numCachedClasses) {
          const classHandles = Memory.alloc(numClasses * pointerSize);
          numClasses = api.objc_getClassList(classHandles, numClasses);
          for (let i = 0; i !== numClasses; i++) {
            const handle2 = classHandles.add(i * pointerSize).readPointer();
            const name = api.class_getName(handle2).readUtf8String();
            cachedClasses[name] = handle2;
          }
          numCachedClasses = numClasses;
        }
        return Object.keys(cachedClasses);
      },
      getOwnPropertyDescriptor(target, property) {
        return {
          writable: false,
          configurable: true,
          enumerable: true
        };
      }
    });
    function hasProperty(name) {
      if (registryBuiltins.has(name))
        return true;
      return findClass(name) !== null;
    }
    function getClass(name) {
      const cls = findClass(name);
      if (cls === null)
        throw new Error("Unable to find class '" + name + "'");
      return cls;
    }
    function findClass(name) {
      let handle2 = cachedClasses[name];
      if (handle2 === void 0) {
        handle2 = api.objc_lookUpClass(Memory.allocUtf8String(name));
        if (handle2.isNull())
          return null;
        cachedClasses[name] = handle2;
        numCachedClasses++;
      }
      return new ObjCObject(handle2, void 0, true);
    }
    function toJSON() {
      return Object.keys(registry).reduce(function(r, name) {
        r[name] = getClass(name).toJSON();
        return r;
      }, {});
    }
    function toString() {
      return "ClassRegistry";
    }
    function valueOf() {
      return "ClassRegistry";
    }
    return registry;
  }
  function ProtocolRegistry() {
    let cachedProtocols = {};
    let numCachedProtocols = 0;
    const registry = new Proxy(this, {
      has(target, property) {
        return hasProperty(property);
      },
      get(target, property, receiver) {
        switch (property) {
          case "prototype":
            return target.prototype;
          case "constructor":
            return target.constructor;
          case "hasOwnProperty":
            return hasProperty;
          case "toJSON":
            return toJSON;
          case "toString":
            return toString;
          case "valueOf":
            return valueOf;
          default:
            const proto = findProtocol(property);
            return proto !== null ? proto : void 0;
        }
      },
      set(target, property, value, receiver) {
        return false;
      },
      ownKeys(target) {
        if (api === null)
          return [];
        const numProtocolsBuf = Memory.alloc(pointerSize);
        const protocolHandles = api.objc_copyProtocolList(numProtocolsBuf);
        try {
          const numProtocols = numProtocolsBuf.readUInt();
          if (numProtocols !== numCachedProtocols) {
            cachedProtocols = {};
            for (let i = 0; i !== numProtocols; i++) {
              const handle2 = protocolHandles.add(i * pointerSize).readPointer();
              const name = api.protocol_getName(handle2).readUtf8String();
              cachedProtocols[name] = handle2;
            }
            numCachedProtocols = numProtocols;
          }
        } finally {
          api.free(protocolHandles);
        }
        return Object.keys(cachedProtocols);
      },
      getOwnPropertyDescriptor(target, property) {
        return {
          writable: false,
          configurable: true,
          enumerable: true
        };
      }
    });
    function hasProperty(name) {
      if (registryBuiltins.has(name))
        return true;
      return findProtocol(name) !== null;
    }
    function findProtocol(name) {
      let handle2 = cachedProtocols[name];
      if (handle2 === void 0) {
        handle2 = api.objc_getProtocol(Memory.allocUtf8String(name));
        if (handle2.isNull())
          return null;
        cachedProtocols[name] = handle2;
        numCachedProtocols++;
      }
      return new ObjCProtocol(handle2);
    }
    function toJSON() {
      return Object.keys(registry).reduce(function(r, name) {
        r[name] = { handle: cachedProtocols[name] };
        return r;
      }, {});
    }
    function toString() {
      return "ProtocolRegistry";
    }
    function valueOf() {
      return "ProtocolRegistry";
    }
    return registry;
  }
  const objCObjectBuiltins = /* @__PURE__ */ new Set([
    "prototype",
    "constructor",
    "handle",
    "hasOwnProperty",
    "toJSON",
    "toString",
    "valueOf",
    "equals",
    "$kind",
    "$super",
    "$superClass",
    "$class",
    "$className",
    "$moduleName",
    "$protocols",
    "$methods",
    "$ownMethods",
    "$ivars"
  ]);
  function ObjCObject(handle2, protocol, cachedIsClass, superSpecifier2) {
    let cachedClassHandle = null;
    let cachedKind = null;
    let cachedSuper = null;
    let cachedSuperClass = null;
    let cachedClass = null;
    let cachedClassName = null;
    let cachedModuleName = null;
    let cachedProtocols = null;
    let cachedMethodNames = null;
    let cachedProtocolMethods = null;
    let respondsToSelector = null;
    const cachedMethods = {};
    let cachedNativeMethodNames = null;
    let cachedOwnMethodNames = null;
    let cachedIvars = null;
    handle2 = getHandle(handle2);
    if (cachedIsClass === void 0) {
      const klass = api.object_getClass(handle2);
      const key = klass.toString();
      if (!realizedClasses.has(key)) {
        api.objc_lookUpClass(api.class_getName(klass));
        realizedClasses.add(key);
      }
    }
    const self = new Proxy(this, {
      has(target, property) {
        return hasProperty(property);
      },
      get(target, property, receiver) {
        switch (property) {
          case "handle":
            return handle2;
          case "prototype":
            return target.prototype;
          case "constructor":
            return target.constructor;
          case "hasOwnProperty":
            return hasProperty;
          case "toJSON":
            return toJSON;
          case "toString":
          case "valueOf":
            const descriptionImpl = receiver.description;
            if (descriptionImpl !== void 0) {
              const description = descriptionImpl.call(receiver);
              if (description !== null)
                return description.UTF8String.bind(description);
            }
            return function() {
              return receiver.$className;
            };
          case "equals":
            return equals;
          case "$kind":
            if (cachedKind === null) {
              if (isClass())
                cachedKind = api.class_isMetaClass(handle2) ? "meta-class" : "class";
              else
                cachedKind = "instance";
            }
            return cachedKind;
          case "$super":
            if (cachedSuper === null) {
              const superHandle = api.class_getSuperclass(classHandle());
              if (!superHandle.isNull()) {
                const specifier = Memory.alloc(2 * pointerSize);
                specifier.writePointer(handle2);
                specifier.add(pointerSize).writePointer(superHandle);
                cachedSuper = [new ObjCObject(handle2, void 0, cachedIsClass, specifier)];
              } else {
                cachedSuper = [null];
              }
            }
            return cachedSuper[0];
          case "$superClass":
            if (cachedSuperClass === null) {
              const superClassHandle = api.class_getSuperclass(classHandle());
              if (!superClassHandle.isNull()) {
                cachedSuperClass = [new ObjCObject(superClassHandle)];
              } else {
                cachedSuperClass = [null];
              }
            }
            return cachedSuperClass[0];
          case "$class":
            if (cachedClass === null)
              cachedClass = new ObjCObject(api.object_getClass(handle2), void 0, true);
            return cachedClass;
          case "$className":
            if (cachedClassName === null) {
              if (superSpecifier2)
                cachedClassName = api.class_getName(superSpecifier2.add(pointerSize).readPointer()).readUtf8String();
              else if (isClass())
                cachedClassName = api.class_getName(handle2).readUtf8String();
              else
                cachedClassName = api.object_getClassName(handle2).readUtf8String();
            }
            return cachedClassName;
          case "$moduleName":
            if (cachedModuleName === null) {
              cachedModuleName = api.class_getImageName(classHandle()).readUtf8String();
            }
            return cachedModuleName;
          case "$protocols":
            if (cachedProtocols === null) {
              cachedProtocols = {};
              const numProtocolsBuf = Memory.alloc(pointerSize);
              const protocolHandles = api.class_copyProtocolList(classHandle(), numProtocolsBuf);
              if (!protocolHandles.isNull()) {
                try {
                  const numProtocols = numProtocolsBuf.readUInt();
                  for (let i = 0; i !== numProtocols; i++) {
                    const protocolHandle = protocolHandles.add(i * pointerSize).readPointer();
                    const p = new ObjCProtocol(protocolHandle);
                    cachedProtocols[p.name] = p;
                  }
                } finally {
                  api.free(protocolHandles);
                }
              }
            }
            return cachedProtocols;
          case "$methods":
            if (cachedNativeMethodNames === null) {
              const klass = superSpecifier2 ? superSpecifier2.add(pointerSize).readPointer() : classHandle();
              const meta = api.object_getClass(klass);
              const names = /* @__PURE__ */ new Set();
              let cur = meta;
              do {
                for (let methodName of collectMethodNames(cur, "+ "))
                  names.add(methodName);
                cur = api.class_getSuperclass(cur);
              } while (!cur.isNull());
              cur = klass;
              do {
                for (let methodName of collectMethodNames(cur, "- "))
                  names.add(methodName);
                cur = api.class_getSuperclass(cur);
              } while (!cur.isNull());
              cachedNativeMethodNames = Array.from(names);
            }
            return cachedNativeMethodNames;
          case "$ownMethods":
            if (cachedOwnMethodNames === null) {
              const klass = superSpecifier2 ? superSpecifier2.add(pointerSize).readPointer() : classHandle();
              const meta = api.object_getClass(klass);
              const classMethods = collectMethodNames(meta, "+ ");
              const instanceMethods = collectMethodNames(klass, "- ");
              cachedOwnMethodNames = classMethods.concat(instanceMethods);
            }
            return cachedOwnMethodNames;
          case "$ivars":
            if (cachedIvars === null) {
              if (isClass())
                cachedIvars = {};
              else
                cachedIvars = new ObjCIvars(self, classHandle());
            }
            return cachedIvars;
          default:
            if (typeof property === "symbol") {
              return target[property];
            }
            if (protocol) {
              const details = findProtocolMethod(property);
              if (details === null || !details.implemented)
                return void 0;
            }
            const wrapper = findMethodWrapper(property);
            if (wrapper === null)
              return void 0;
            return wrapper;
        }
      },
      set(target, property, value, receiver) {
        return false;
      },
      ownKeys(target) {
        if (cachedMethodNames === null) {
          if (!protocol) {
            const jsNames = {};
            const nativeNames = {};
            let cur = api.object_getClass(handle2);
            do {
              const numMethodsBuf = Memory.alloc(pointerSize);
              const methodHandles = api.class_copyMethodList(cur, numMethodsBuf);
              const fullNamePrefix = isClass() ? "+ " : "- ";
              try {
                const numMethods = numMethodsBuf.readUInt();
                for (let i = 0; i !== numMethods; i++) {
                  const methodHandle = methodHandles.add(i * pointerSize).readPointer();
                  const sel2 = api.method_getName(methodHandle);
                  const nativeName = api.sel_getName(sel2).readUtf8String();
                  if (nativeNames[nativeName] !== void 0)
                    continue;
                  nativeNames[nativeName] = nativeName;
                  const jsName = jsMethodName(nativeName);
                  let serial = 2;
                  let name = jsName;
                  while (jsNames[name] !== void 0) {
                    serial++;
                    name = jsName + serial;
                  }
                  jsNames[name] = true;
                  const fullName = fullNamePrefix + nativeName;
                  if (cachedMethods[fullName] === void 0) {
                    const details = {
                      sel: sel2,
                      handle: methodHandle,
                      wrapper: null
                    };
                    cachedMethods[fullName] = details;
                    cachedMethods[name] = details;
                  }
                }
              } finally {
                api.free(methodHandles);
              }
              cur = api.class_getSuperclass(cur);
            } while (!cur.isNull());
            cachedMethodNames = Object.keys(jsNames);
          } else {
            const methodNames = [];
            const protocolMethods = allProtocolMethods();
            Object.keys(protocolMethods).forEach(function(methodName) {
              if (methodName[0] !== "+" && methodName[0] !== "-") {
                const details = protocolMethods[methodName];
                if (details.implemented) {
                  methodNames.push(methodName);
                }
              }
            });
            cachedMethodNames = methodNames;
          }
        }
        return ["handle"].concat(cachedMethodNames);
      },
      getOwnPropertyDescriptor(target, property) {
        return {
          writable: false,
          configurable: true,
          enumerable: true
        };
      }
    });
    if (protocol) {
      respondsToSelector = !isClass() ? findMethodWrapper("- respondsToSelector:") : null;
    }
    return self;
    function hasProperty(name) {
      if (objCObjectBuiltins.has(name))
        return true;
      if (protocol) {
        const details = findProtocolMethod(name);
        return !!(details !== null && details.implemented);
      }
      return findMethod(name) !== null;
    }
    function classHandle() {
      if (cachedClassHandle === null)
        cachedClassHandle = isClass() ? handle2 : api.object_getClass(handle2);
      return cachedClassHandle;
    }
    function isClass() {
      if (cachedIsClass === void 0) {
        if (api.object_isClass)
          cachedIsClass = !!api.object_isClass(handle2);
        else
          cachedIsClass = !!api.class_isMetaClass(api.object_getClass(handle2));
      }
      return cachedIsClass;
    }
    function findMethod(rawName) {
      let method2 = cachedMethods[rawName];
      if (method2 !== void 0)
        return method2;
      const tokens = parseMethodName(rawName);
      const fullName = tokens[2];
      method2 = cachedMethods[fullName];
      if (method2 !== void 0) {
        cachedMethods[rawName] = method2;
        return method2;
      }
      const kind = tokens[0];
      const name = tokens[1];
      const sel2 = selector(name);
      const defaultKind = isClass() ? "+" : "-";
      if (protocol) {
        const details = findProtocolMethod(fullName);
        if (details !== null) {
          method2 = {
            sel: sel2,
            types: details.types,
            wrapper: null,
            kind
          };
        }
      }
      if (method2 === void 0) {
        const methodHandle = kind === "+" ? api.class_getClassMethod(classHandle(), sel2) : api.class_getInstanceMethod(classHandle(), sel2);
        if (!methodHandle.isNull()) {
          method2 = {
            sel: sel2,
            handle: methodHandle,
            wrapper: null,
            kind
          };
        } else {
          if (isClass() || kind !== "-" || name === "forwardingTargetForSelector:" || name === "methodSignatureForSelector:") {
            return null;
          }
          let target = self;
          if ("- forwardingTargetForSelector:" in self) {
            const forwardingTarget = self.forwardingTargetForSelector_(sel2);
            if (forwardingTarget !== null && forwardingTarget.$kind === "instance") {
              target = forwardingTarget;
            } else {
              return null;
            }
          } else {
            return null;
          }
          const methodHandle2 = api.class_getInstanceMethod(api.object_getClass(target.handle), sel2);
          if (methodHandle2.isNull()) {
            return null;
          }
          let types2 = api.method_getTypeEncoding(methodHandle2).readUtf8String();
          if (types2 === null || types2 === "") {
            types2 = stealTypesFromProtocols(target, fullName);
            if (types2 === null)
              types2 = stealTypesFromProtocols(self, fullName);
            if (types2 === null)
              return null;
          }
          method2 = {
            sel: sel2,
            types: types2,
            wrapper: null,
            kind
          };
        }
      }
      cachedMethods[fullName] = method2;
      cachedMethods[rawName] = method2;
      if (kind === defaultKind)
        cachedMethods[jsMethodName(name)] = method2;
      return method2;
    }
    function stealTypesFromProtocols(klass, fullName) {
      const candidates = Object.keys(klass.$protocols).map((protocolName) => flatProtocolMethods({}, klass.$protocols[protocolName])).reduce((allMethods, methods) => {
        Object.assign(allMethods, methods);
        return allMethods;
      }, {});
      const method2 = candidates[fullName];
      if (method2 === void 0) {
        return null;
      }
      return method2.types;
    }
    function flatProtocolMethods(result, protocol2) {
      if (protocol2.methods !== void 0) {
        Object.assign(result, protocol2.methods);
      }
      if (protocol2.protocol !== void 0) {
        flatProtocolMethods(result, protocol2.protocol);
      }
      return result;
    }
    function findProtocolMethod(rawName) {
      const protocolMethods = allProtocolMethods();
      const details = protocolMethods[rawName];
      return details !== void 0 ? details : null;
    }
    function allProtocolMethods() {
      if (cachedProtocolMethods === null) {
        const methods = {};
        const protocols = collectProtocols(protocol);
        const defaultKind = isClass() ? "+" : "-";
        Object.keys(protocols).forEach(function(name) {
          const p = protocols[name];
          const m2 = p.methods;
          Object.keys(m2).forEach(function(fullMethodName) {
            const method2 = m2[fullMethodName];
            const methodName = fullMethodName.substr(2);
            const kind = fullMethodName[0];
            let didCheckImplemented = false;
            let implemented = false;
            const details = {
              types: method2.types
            };
            Object.defineProperty(details, "implemented", {
              get() {
                if (!didCheckImplemented) {
                  if (method2.required) {
                    implemented = true;
                  } else {
                    implemented = respondsToSelector !== null && respondsToSelector.call(self, selector(methodName));
                  }
                  didCheckImplemented = true;
                }
                return implemented;
              }
            });
            methods[fullMethodName] = details;
            if (kind === defaultKind)
              methods[jsMethodName(methodName)] = details;
          });
        });
        cachedProtocolMethods = methods;
      }
      return cachedProtocolMethods;
    }
    function findMethodWrapper(name) {
      const method2 = findMethod(name);
      if (method2 === null)
        return null;
      let wrapper = method2.wrapper;
      if (wrapper === null) {
        wrapper = makeMethodInvocationWrapper(method2, self, superSpecifier2, defaultInvocationOptions);
        method2.wrapper = wrapper;
      }
      return wrapper;
    }
    function parseMethodName(rawName) {
      const match = /([+\-])\s(\S+)/.exec(rawName);
      let name, kind;
      if (match === null) {
        kind = isClass() ? "+" : "-";
        name = objcMethodName(rawName);
      } else {
        kind = match[1];
        name = match[2];
      }
      const fullName = [kind, name].join(" ");
      return [kind, name, fullName];
    }
    function toJSON() {
      return {
        handle: handle2.toString()
      };
    }
    function equals(ptr2) {
      return handle2.equals(getHandle(ptr2));
    }
  }
  function getReplacementMethodImplementation(methodHandle) {
    const existingEntry = replacedMethods.get(methodHandle.toString());
    if (existingEntry === void 0)
      return null;
    const [, newImp] = existingEntry;
    return newImp;
  }
  function replaceMethodImplementation(methodHandle, imp) {
    const key = methodHandle.toString();
    let oldImp;
    const existingEntry = replacedMethods.get(key);
    if (existingEntry !== void 0)
      [oldImp] = existingEntry;
    else
      oldImp = api.method_getImplementation(methodHandle);
    if (!imp.equals(oldImp))
      replacedMethods.set(key, [oldImp, imp]);
    else
      replacedMethods.delete(key);
    api.method_setImplementation(methodHandle, imp);
  }
  function collectMethodNames(klass, prefix) {
    const names = [];
    const numMethodsBuf = Memory.alloc(pointerSize);
    const methodHandles = api.class_copyMethodList(klass, numMethodsBuf);
    try {
      const numMethods = numMethodsBuf.readUInt();
      for (let i = 0; i !== numMethods; i++) {
        const methodHandle = methodHandles.add(i * pointerSize).readPointer();
        const sel2 = api.method_getName(methodHandle);
        const nativeName = api.sel_getName(sel2).readUtf8String();
        names.push(prefix + nativeName);
      }
    } finally {
      api.free(methodHandles);
    }
    return names;
  }
  function ObjCProtocol(handle2) {
    let cachedName = null;
    let cachedProtocols = null;
    let cachedProperties = null;
    let cachedMethods = null;
    Object.defineProperty(this, "handle", {
      value: handle2,
      enumerable: true
    });
    Object.defineProperty(this, "name", {
      get() {
        if (cachedName === null)
          cachedName = api.protocol_getName(handle2).readUtf8String();
        return cachedName;
      },
      enumerable: true
    });
    Object.defineProperty(this, "protocols", {
      get() {
        if (cachedProtocols === null) {
          cachedProtocols = {};
          const numProtocolsBuf = Memory.alloc(pointerSize);
          const protocolHandles = api.protocol_copyProtocolList(handle2, numProtocolsBuf);
          if (!protocolHandles.isNull()) {
            try {
              const numProtocols = numProtocolsBuf.readUInt();
              for (let i = 0; i !== numProtocols; i++) {
                const protocolHandle = protocolHandles.add(i * pointerSize).readPointer();
                const protocol = new ObjCProtocol(protocolHandle);
                cachedProtocols[protocol.name] = protocol;
              }
            } finally {
              api.free(protocolHandles);
            }
          }
        }
        return cachedProtocols;
      },
      enumerable: true
    });
    Object.defineProperty(this, "properties", {
      get() {
        if (cachedProperties === null) {
          cachedProperties = {};
          const numBuf = Memory.alloc(pointerSize);
          const propertyHandles = api.protocol_copyPropertyList(handle2, numBuf);
          if (!propertyHandles.isNull()) {
            try {
              const numProperties = numBuf.readUInt();
              for (let i = 0; i !== numProperties; i++) {
                const propertyHandle = propertyHandles.add(i * pointerSize).readPointer();
                const propName = api.property_getName(propertyHandle).readUtf8String();
                const attributes = {};
                const attributeEntries = api.property_copyAttributeList(propertyHandle, numBuf);
                if (!attributeEntries.isNull()) {
                  try {
                    const numAttributeValues = numBuf.readUInt();
                    for (let j = 0; j !== numAttributeValues; j++) {
                      const attributeEntry = attributeEntries.add(j * (2 * pointerSize));
                      const name = attributeEntry.readPointer().readUtf8String();
                      const value = attributeEntry.add(pointerSize).readPointer().readUtf8String();
                      attributes[name] = value;
                    }
                  } finally {
                    api.free(attributeEntries);
                  }
                }
                cachedProperties[propName] = attributes;
              }
            } finally {
              api.free(propertyHandles);
            }
          }
        }
        return cachedProperties;
      },
      enumerable: true
    });
    Object.defineProperty(this, "methods", {
      get() {
        if (cachedMethods === null) {
          cachedMethods = {};
          const numBuf = Memory.alloc(pointerSize);
          collectMethods(cachedMethods, numBuf, { required: true, instance: false });
          collectMethods(cachedMethods, numBuf, { required: false, instance: false });
          collectMethods(cachedMethods, numBuf, { required: true, instance: true });
          collectMethods(cachedMethods, numBuf, { required: false, instance: true });
        }
        return cachedMethods;
      },
      enumerable: true
    });
    function collectMethods(methods, numBuf, spec) {
      const methodDescValues = api.protocol_copyMethodDescriptionList(handle2, spec.required ? 1 : 0, spec.instance ? 1 : 0, numBuf);
      if (methodDescValues.isNull())
        return;
      try {
        const numMethodDescValues = numBuf.readUInt();
        for (let i = 0; i !== numMethodDescValues; i++) {
          const methodDesc = methodDescValues.add(i * (2 * pointerSize));
          const name = (spec.instance ? "- " : "+ ") + selectorAsString(methodDesc.readPointer());
          const types2 = methodDesc.add(pointerSize).readPointer().readUtf8String();
          methods[name] = {
            required: spec.required,
            types: types2
          };
        }
      } finally {
        api.free(methodDescValues);
      }
    }
  }
  const objCIvarsBuiltins = /* @__PURE__ */ new Set([
    "prototype",
    "constructor",
    "hasOwnProperty",
    "toJSON",
    "toString",
    "valueOf"
  ]);
  function ObjCIvars(instance, classHandle) {
    const ivars = {};
    let cachedIvarNames = null;
    let classHandles = [];
    let currentClassHandle = classHandle;
    do {
      classHandles.unshift(currentClassHandle);
      currentClassHandle = api.class_getSuperclass(currentClassHandle);
    } while (!currentClassHandle.isNull());
    const numIvarsBuf = Memory.alloc(pointerSize);
    classHandles.forEach((c) => {
      const ivarHandles = api.class_copyIvarList(c, numIvarsBuf);
      try {
        const numIvars = numIvarsBuf.readUInt();
        for (let i = 0; i !== numIvars; i++) {
          const handle2 = ivarHandles.add(i * pointerSize).readPointer();
          const name = api.ivar_getName(handle2).readUtf8String();
          ivars[name] = [handle2, null];
        }
      } finally {
        api.free(ivarHandles);
      }
    });
    const self = new Proxy(this, {
      has(target, property) {
        return hasProperty(property);
      },
      get(target, property, receiver) {
        switch (property) {
          case "prototype":
            return target.prototype;
          case "constructor":
            return target.constructor;
          case "hasOwnProperty":
            return hasProperty;
          case "toJSON":
            return toJSON;
          case "toString":
            return toString;
          case "valueOf":
            return valueOf;
          default:
            const ivar = findIvar(property);
            if (ivar === null)
              return void 0;
            return ivar.get();
        }
      },
      set(target, property, value, receiver) {
        const ivar = findIvar(property);
        if (ivar === null)
          throw new Error("Unknown ivar");
        ivar.set(value);
        return true;
      },
      ownKeys(target) {
        if (cachedIvarNames === null)
          cachedIvarNames = Object.keys(ivars);
        return cachedIvarNames;
      },
      getOwnPropertyDescriptor(target, property) {
        return {
          writable: true,
          configurable: true,
          enumerable: true
        };
      }
    });
    return self;
    function findIvar(name) {
      const entry = ivars[name];
      if (entry === void 0)
        return null;
      let impl = entry[1];
      if (impl === null) {
        const ivar = entry[0];
        const offset = api.ivar_getOffset(ivar).toInt32();
        const address = instance.handle.add(offset);
        const type = parseType(api.ivar_getTypeEncoding(ivar).readUtf8String());
        const fromNative = type.fromNative || identityTransform;
        const toNative = type.toNative || identityTransform;
        let read, write;
        if (name === "isa") {
          read = readObjectIsa;
          write = function() {
            throw new Error("Unable to set the isa instance variable");
          };
        } else {
          read = type.read;
          write = type.write;
        }
        impl = {
          get() {
            return fromNative.call(instance, read(address));
          },
          set(value) {
            write(address, toNative.call(instance, value));
          }
        };
        entry[1] = impl;
      }
      return impl;
    }
    function hasProperty(name) {
      if (objCIvarsBuiltins.has(name))
        return true;
      return ivars.hasOwnProperty(name);
    }
    function toJSON() {
      return Object.keys(self).reduce(function(result, name) {
        result[name] = self[name];
        return result;
      }, {});
    }
    function toString() {
      return "ObjCIvars";
    }
    function valueOf() {
      return "ObjCIvars";
    }
  }
  let blockDescriptorAllocSize, blockDescriptorDeclaredSize, blockDescriptorOffsets;
  let blockSize, blockOffsets;
  if (pointerSize === 4) {
    blockDescriptorAllocSize = 16;
    blockDescriptorDeclaredSize = 20;
    blockDescriptorOffsets = {
      reserved: 0,
      size: 4,
      rest: 8
    };
    blockSize = 20;
    blockOffsets = {
      isa: 0,
      flags: 4,
      reserved: 8,
      invoke: 12,
      descriptor: 16
    };
  } else {
    blockDescriptorAllocSize = 32;
    blockDescriptorDeclaredSize = 32;
    blockDescriptorOffsets = {
      reserved: 0,
      size: 8,
      rest: 16
    };
    blockSize = 32;
    blockOffsets = {
      isa: 0,
      flags: 8,
      reserved: 12,
      invoke: 16,
      descriptor: 24
    };
  }
  const BLOCK_HAS_COPY_DISPOSE = 1 << 25;
  const BLOCK_HAS_CTOR = 1 << 26;
  const BLOCK_IS_GLOBAL = 1 << 28;
  const BLOCK_HAS_STRET = 1 << 29;
  const BLOCK_HAS_SIGNATURE = 1 << 30;
  function Block(target, options = defaultInvocationOptions) {
    this._options = options;
    if (target instanceof NativePointer) {
      const descriptor = target.add(blockOffsets.descriptor).readPointer();
      this.handle = target;
      const flags = target.add(blockOffsets.flags).readU32();
      if ((flags & BLOCK_HAS_SIGNATURE) !== 0) {
        const signatureOffset = (flags & BLOCK_HAS_COPY_DISPOSE) !== 0 ? 2 : 0;
        this.types = descriptor.add(blockDescriptorOffsets.rest + signatureOffset * pointerSize).readPointer().readCString();
        this._signature = parseSignature(this.types);
      } else {
        this._signature = null;
      }
    } else {
      this.declare(target);
      const descriptor = Memory.alloc(blockDescriptorAllocSize + blockSize);
      const block2 = descriptor.add(blockDescriptorAllocSize);
      const typesStr = Memory.allocUtf8String(this.types);
      descriptor.add(blockDescriptorOffsets.reserved).writeULong(0);
      descriptor.add(blockDescriptorOffsets.size).writeULong(blockDescriptorDeclaredSize);
      descriptor.add(blockDescriptorOffsets.rest).writePointer(typesStr);
      block2.add(blockOffsets.isa).writePointer(classRegistry.__NSGlobalBlock__);
      block2.add(blockOffsets.flags).writeU32(BLOCK_HAS_SIGNATURE | BLOCK_IS_GLOBAL);
      block2.add(blockOffsets.reserved).writeU32(0);
      block2.add(blockOffsets.descriptor).writePointer(descriptor);
      this.handle = block2;
      this._storage = [descriptor, typesStr];
      this.implementation = target.implementation;
    }
  }
  Object.defineProperties(Block.prototype, {
    implementation: {
      enumerable: true,
      get() {
        const address = this.handle.add(blockOffsets.invoke).readPointer().strip();
        const signature2 = this._getSignature();
        return makeBlockInvocationWrapper(this, signature2, new NativeFunction(
          address.sign(),
          signature2.retType.type,
          signature2.argTypes.map(function(arg) {
            return arg.type;
          }),
          this._options
        ));
      },
      set(func) {
        const signature2 = this._getSignature();
        const callback = new NativeCallback(
          makeBlockImplementationWrapper(this, signature2, func),
          signature2.retType.type,
          signature2.argTypes.map(function(arg) {
            return arg.type;
          })
        );
        this._callback = callback;
        const location = this.handle.add(blockOffsets.invoke);
        const prot = Memory.queryProtection(location);
        const writable = prot.includes("w");
        if (!writable)
          Memory.protect(location, Process.pointerSize, "rw-");
        location.writePointer(callback.strip().sign("ia", location));
        if (!writable)
          Memory.protect(location, Process.pointerSize, prot);
      }
    },
    declare: {
      value(signature2) {
        let types2 = signature2.types;
        if (types2 === void 0) {
          types2 = unparseSignature(signature2.retType, ["block"].concat(signature2.argTypes));
        }
        this.types = types2;
        this._signature = parseSignature(types2);
      }
    },
    _getSignature: {
      value() {
        const signature2 = this._signature;
        if (signature2 === null)
          throw new Error("block is missing signature; call declare()");
        return signature2;
      }
    }
  });
  function collectProtocols(p, acc) {
    acc = acc || {};
    acc[p.name] = p;
    const parentProtocols = p.protocols;
    Object.keys(parentProtocols).forEach(function(name) {
      collectProtocols(parentProtocols[name], acc);
    });
    return acc;
  }
  function registerProxy(properties) {
    const protocols = properties.protocols || [];
    const methods = properties.methods || {};
    const events = properties.events || {};
    const supportedSelectors = new Set(
      Object.keys(methods).filter((m2) => /([+\-])\s(\S+)/.exec(m2) !== null).map((m2) => m2.split(" ")[1])
    );
    const proxyMethods = {
      "- dealloc": function() {
        const target = this.data.target;
        if ("- release" in target)
          target.release();
        unbind(this.self);
        this.super.dealloc();
        const callback = this.data.events.dealloc;
        if (callback !== void 0)
          callback.call(this);
      },
      "- respondsToSelector:": function(sel2) {
        const selector2 = selectorAsString(sel2);
        if (supportedSelectors.has(selector2))
          return true;
        return this.data.target.respondsToSelector_(sel2);
      },
      "- forwardingTargetForSelector:": function(sel2) {
        const callback = this.data.events.forward;
        if (callback !== void 0)
          callback.call(this, selectorAsString(sel2));
        return this.data.target;
      },
      "- methodSignatureForSelector:": function(sel2) {
        return this.data.target.methodSignatureForSelector_(sel2);
      },
      "- forwardInvocation:": function(invocation) {
        invocation.invokeWithTarget_(this.data.target);
      }
    };
    for (var key in methods) {
      if (methods.hasOwnProperty(key)) {
        if (proxyMethods.hasOwnProperty(key))
          throw new Error("The '" + key + "' method is reserved");
        proxyMethods[key] = methods[key];
      }
    }
    const ProxyClass = registerClass({
      name: properties.name,
      super: classRegistry.NSProxy,
      protocols,
      methods: proxyMethods
    });
    return function(target, data) {
      target = target instanceof NativePointer ? new ObjCObject(target) : target;
      data = data || {};
      const instance = ProxyClass.alloc().autorelease();
      const boundData = getBoundData(instance);
      boundData.target = "- retain" in target ? target.retain() : target;
      boundData.events = events;
      for (var key2 in data) {
        if (data.hasOwnProperty(key2)) {
          if (boundData.hasOwnProperty(key2))
            throw new Error("The '" + key2 + "' property is reserved");
          boundData[key2] = data[key2];
        }
      }
      this.handle = instance.handle;
    };
  }
  function registerClass(properties) {
    let name = properties.name;
    if (name === void 0)
      name = makeClassName();
    const superClass = properties.super !== void 0 ? properties.super : classRegistry.NSObject;
    const protocols = properties.protocols || [];
    const methods = properties.methods || {};
    const methodCallbacks = [];
    const classHandle = api.objc_allocateClassPair(superClass !== null ? superClass.handle : NULL, Memory.allocUtf8String(name), ptr("0"));
    if (classHandle.isNull())
      throw new Error("Unable to register already registered class '" + name + "'");
    const metaClassHandle = api.object_getClass(classHandle);
    try {
      protocols.forEach(function(protocol) {
        api.class_addProtocol(classHandle, protocol.handle);
      });
      Object.keys(methods).forEach(function(rawMethodName) {
        const match = /([+\-])\s(\S+)/.exec(rawMethodName);
        if (match === null)
          throw new Error("Invalid method name");
        const kind = match[1];
        const name2 = match[2];
        let method2;
        const value = methods[rawMethodName];
        if (typeof value === "function") {
          let types3 = null;
          if (rawMethodName in superClass) {
            types3 = superClass[rawMethodName].types;
          } else {
            for (let protocol of protocols) {
              const method3 = protocol.methods[rawMethodName];
              if (method3 !== void 0) {
                types3 = method3.types;
                break;
              }
            }
          }
          if (types3 === null)
            throw new Error("Unable to find '" + rawMethodName + "' in super-class or any of its protocols");
          method2 = {
            types: types3,
            implementation: value
          };
        } else {
          method2 = value;
        }
        const target = kind === "+" ? metaClassHandle : classHandle;
        let types2 = method2.types;
        if (types2 === void 0) {
          types2 = unparseSignature(method2.retType, [kind === "+" ? "class" : "object", "selector"].concat(method2.argTypes));
        }
        const signature2 = parseSignature(types2);
        const implementation2 = new NativeCallback(
          makeMethodImplementationWrapper(signature2, method2.implementation),
          signature2.retType.type,
          signature2.argTypes.map(function(arg) {
            return arg.type;
          })
        );
        methodCallbacks.push(implementation2);
        api.class_addMethod(target, selector(name2), implementation2, Memory.allocUtf8String(types2));
      });
    } catch (e) {
      api.objc_disposeClassPair(classHandle);
      throw e;
    }
    api.objc_registerClassPair(classHandle);
    classHandle._methodCallbacks = methodCallbacks;
    Script.bindWeak(classHandle, makeClassDestructor(ptr(classHandle)));
    return new ObjCObject(classHandle);
  }
  function makeClassDestructor(classHandle) {
    return function() {
      api.objc_disposeClassPair(classHandle);
    };
  }
  function registerProtocol(properties) {
    let name = properties.name;
    if (name === void 0)
      name = makeProtocolName();
    const protocols = properties.protocols || [];
    const methods = properties.methods || {};
    protocols.forEach(function(protocol) {
      if (!(protocol instanceof ObjCProtocol))
        throw new Error("Expected protocol");
    });
    const methodSpecs = Object.keys(methods).map(function(rawMethodName) {
      const method2 = methods[rawMethodName];
      const match = /([+\-])\s(\S+)/.exec(rawMethodName);
      if (match === null)
        throw new Error("Invalid method name");
      const kind = match[1];
      const name2 = match[2];
      let types2 = method2.types;
      if (types2 === void 0) {
        types2 = unparseSignature(method2.retType, [kind === "+" ? "class" : "object", "selector"].concat(method2.argTypes));
      }
      return {
        kind,
        name: name2,
        types: types2,
        optional: method2.optional
      };
    });
    const handle2 = api.objc_allocateProtocol(Memory.allocUtf8String(name));
    if (handle2.isNull())
      throw new Error("Unable to register already registered protocol '" + name + "'");
    protocols.forEach(function(protocol) {
      api.protocol_addProtocol(handle2, protocol.handle);
    });
    methodSpecs.forEach(function(spec) {
      const isRequiredMethod = spec.optional ? 0 : 1;
      const isInstanceMethod = spec.kind === "-" ? 1 : 0;
      api.protocol_addMethodDescription(handle2, selector(spec.name), Memory.allocUtf8String(spec.types), isRequiredMethod, isInstanceMethod);
    });
    api.objc_registerProtocol(handle2);
    return new ObjCProtocol(handle2);
  }
  function getHandle(obj) {
    if (obj instanceof NativePointer)
      return obj;
    else if (typeof obj === "object" && obj.hasOwnProperty("handle"))
      return obj.handle;
    else
      throw new Error("Expected NativePointer or ObjC.Object instance");
  }
  function bind(obj, data) {
    const handle2 = getHandle(obj);
    const self = obj instanceof ObjCObject ? obj : new ObjCObject(handle2);
    bindings.set(handle2.toString(), {
      self,
      super: self.$super,
      data
    });
  }
  function unbind(obj) {
    const handle2 = getHandle(obj);
    bindings.delete(handle2.toString());
  }
  function getBoundData(obj) {
    return getBinding(obj).data;
  }
  function getBinding(obj) {
    const handle2 = getHandle(obj);
    const key = handle2.toString();
    let binding = bindings.get(key);
    if (binding === void 0) {
      const self = obj instanceof ObjCObject ? obj : new ObjCObject(handle2);
      binding = {
        self,
        super: self.$super,
        data: {}
      };
      bindings.set(key, binding);
    }
    return binding;
  }
  function enumerateLoadedClasses(...args) {
    const allModules = new ModuleMap();
    let unfiltered = false;
    let callbacks;
    let modules;
    if (args.length === 1) {
      callbacks = args[0];
    } else {
      callbacks = args[1];
      const options = args[0];
      modules = options.ownedBy;
    }
    if (modules === void 0) {
      modules = allModules;
      unfiltered = true;
    }
    const classGetName = api.class_getName;
    const onMatch = callbacks.onMatch.bind(callbacks);
    const swiftNominalTypeDescriptorOffset = (pointerSize === 8 ? 8 : 11) * pointerSize;
    const numClasses = api.objc_getClassList(NULL, 0);
    const classHandles = Memory.alloc(numClasses * pointerSize);
    api.objc_getClassList(classHandles, numClasses);
    for (let i = 0; i !== numClasses; i++) {
      const classHandle = classHandles.add(i * pointerSize).readPointer();
      const rawName = classGetName(classHandle);
      let name = null;
      let modulePath = modules.findPath(rawName);
      const possiblySwift = modulePath === null && (unfiltered || allModules.findPath(rawName) === null);
      if (possiblySwift) {
        name = rawName.readCString();
        const probablySwift = name.indexOf(".") !== -1;
        if (probablySwift) {
          const nominalTypeDescriptor = classHandle.add(swiftNominalTypeDescriptorOffset).readPointer();
          modulePath = modules.findPath(nominalTypeDescriptor);
        }
      }
      if (modulePath !== null) {
        if (name === null)
          name = rawName.readUtf8String();
        onMatch(name, modulePath);
      }
    }
    callbacks.onComplete();
  }
  function enumerateLoadedClassesSync(options = {}) {
    const result = {};
    enumerateLoadedClasses(options, {
      onMatch(name, owner2) {
        let group = result[owner2];
        if (group === void 0) {
          group = [];
          result[owner2] = group;
        }
        group.push(name);
      },
      onComplete() {
      }
    });
    return result;
  }
  function choose(specifier, callbacks) {
    let cls = specifier;
    let subclasses = true;
    if (!(specifier instanceof ObjCObject) && typeof specifier === "object") {
      cls = specifier.class;
      if (specifier.hasOwnProperty("subclasses"))
        subclasses = specifier.subclasses;
    }
    if (!(cls instanceof ObjCObject && (cls.$kind === "class" || cls.$kind === "meta-class")))
      throw new Error("Expected an ObjC.Object for a class or meta-class");
    const matches = get().choose(cls, subclasses).map((handle2) => new ObjCObject(handle2));
    for (const match of matches) {
      const result = callbacks.onMatch(match);
      if (result === "stop")
        break;
    }
    callbacks.onComplete();
  }
  function makeMethodInvocationWrapper(method, owner, superSpecifier, invocationOptions) {
    const sel = method.sel;
    let handle = method.handle;
    let types;
    if (handle === void 0) {
      handle = null;
      types = method.types;
    } else {
      types = api.method_getTypeEncoding(handle).readUtf8String();
    }
    const signature = parseSignature(types);
    const retType = signature.retType;
    const argTypes = signature.argTypes.slice(2);
    const objc_msgSend = superSpecifier ? getMsgSendSuperImpl(signature, invocationOptions) : getMsgSendImpl(signature, invocationOptions);
    const argVariableNames = argTypes.map(function(t, i) {
      return "a" + (i + 1);
    });
    const callArgs = [
      superSpecifier ? "superSpecifier" : "this",
      "sel"
    ].concat(argTypes.map(function(t, i) {
      if (t.toNative) {
        return "argTypes[" + i + "].toNative.call(this, " + argVariableNames[i] + ")";
      }
      return argVariableNames[i];
    }));
    let returnCaptureLeft;
    let returnCaptureRight;
    if (retType.type === "void") {
      returnCaptureLeft = "";
      returnCaptureRight = "";
    } else if (retType.fromNative) {
      returnCaptureLeft = "return retType.fromNative.call(this, ";
      returnCaptureRight = ")";
    } else {
      returnCaptureLeft = "return ";
      returnCaptureRight = "";
    }
    const m = eval("var m = function (" + argVariableNames.join(", ") + ") { " + returnCaptureLeft + "objc_msgSend(" + callArgs.join(", ") + ")" + returnCaptureRight + "; }; m;");
    Object.defineProperty(m, "handle", {
      enumerable: true,
      get: getMethodHandle
    });
    m.selector = sel;
    Object.defineProperty(m, "implementation", {
      enumerable: true,
      get() {
        const h = getMethodHandle();
        const impl = new NativeFunction(api.method_getImplementation(h), m.returnType, m.argumentTypes, invocationOptions);
        const newImp = getReplacementMethodImplementation(h);
        if (newImp !== null)
          impl._callback = newImp;
        return impl;
      },
      set(imp) {
        replaceMethodImplementation(getMethodHandle(), imp);
      }
    });
    m.returnType = retType.type;
    m.argumentTypes = signature.argTypes.map((t) => t.type);
    m.types = types;
    Object.defineProperty(m, "symbol", {
      enumerable: true,
      get() {
        return `${method.kind}[${owner.$className} ${selectorAsString(sel)}]`;
      }
    });
    m.clone = function(options) {
      return makeMethodInvocationWrapper(method, owner, superSpecifier, options);
    };
    function getMethodHandle() {
      if (handle === null) {
        if (owner.$kind === "instance") {
          let cur = owner;
          do {
            if ("- forwardingTargetForSelector:" in cur) {
              const target = cur.forwardingTargetForSelector_(sel);
              if (target === null)
                break;
              if (target.$kind !== "instance")
                break;
              const h = api.class_getInstanceMethod(target.$class.handle, sel);
              if (!h.isNull())
                handle = h;
              else
                cur = target;
            } else {
              break;
            }
          } while (handle === null);
        }
        if (handle === null)
          throw new Error("Unable to find method handle of proxied function");
      }
      return handle;
    }
    return m;
  }
  function makeMethodImplementationWrapper(signature, implementation) {
    const retType = signature.retType;
    const argTypes = signature.argTypes;
    const argVariableNames = argTypes.map(function(t, i) {
      if (i === 0)
        return "handle";
      else if (i === 1)
        return "sel";
      else
        return "a" + (i - 1);
    });
    const callArgs = argTypes.slice(2).map(function(t, i) {
      const argVariableName = argVariableNames[2 + i];
      if (t.fromNative) {
        return "argTypes[" + (2 + i) + "].fromNative.call(self, " + argVariableName + ")";
      }
      return argVariableName;
    });
    let returnCaptureLeft;
    let returnCaptureRight;
    if (retType.type === "void") {
      returnCaptureLeft = "";
      returnCaptureRight = "";
    } else if (retType.toNative) {
      returnCaptureLeft = "return retType.toNative.call(self, ";
      returnCaptureRight = ")";
    } else {
      returnCaptureLeft = "return ";
      returnCaptureRight = "";
    }
    const m = eval("var m = function (" + argVariableNames.join(", ") + ") { var binding = getBinding(handle);var self = binding.self;" + returnCaptureLeft + "implementation.call(binding" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + "; }; m;");
    return m;
  }
  function makeBlockInvocationWrapper(block, signature, implementation) {
    const retType = signature.retType;
    const argTypes = signature.argTypes.slice(1);
    const argVariableNames = argTypes.map(function(t, i) {
      return "a" + (i + 1);
    });
    const callArgs = argTypes.map(function(t, i) {
      if (t.toNative) {
        return "argTypes[" + i + "].toNative.call(this, " + argVariableNames[i] + ")";
      }
      return argVariableNames[i];
    });
    let returnCaptureLeft;
    let returnCaptureRight;
    if (retType.type === "void") {
      returnCaptureLeft = "";
      returnCaptureRight = "";
    } else if (retType.fromNative) {
      returnCaptureLeft = "return retType.fromNative.call(this, ";
      returnCaptureRight = ")";
    } else {
      returnCaptureLeft = "return ";
      returnCaptureRight = "";
    }
    const f = eval("var f = function (" + argVariableNames.join(", ") + ") { " + returnCaptureLeft + "implementation(this" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + "; }; f;");
    return f.bind(block);
  }
  function makeBlockImplementationWrapper(block, signature, implementation) {
    const retType = signature.retType;
    const argTypes = signature.argTypes;
    const argVariableNames = argTypes.map(function(t, i) {
      if (i === 0)
        return "handle";
      else
        return "a" + i;
    });
    const callArgs = argTypes.slice(1).map(function(t, i) {
      const argVariableName = argVariableNames[1 + i];
      if (t.fromNative) {
        return "argTypes[" + (1 + i) + "].fromNative.call(this, " + argVariableName + ")";
      }
      return argVariableName;
    });
    let returnCaptureLeft;
    let returnCaptureRight;
    if (retType.type === "void") {
      returnCaptureLeft = "";
      returnCaptureRight = "";
    } else if (retType.toNative) {
      returnCaptureLeft = "return retType.toNative.call(this, ";
      returnCaptureRight = ")";
    } else {
      returnCaptureLeft = "return ";
      returnCaptureRight = "";
    }
    const f = eval("var f = function (" + argVariableNames.join(", ") + ") { if (!this.handle.equals(handle))this.handle = handle;" + returnCaptureLeft + "implementation.call(block" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + "; }; f;");
    return f.bind(block);
  }
  function rawFridaType(t) {
    return t === "object" ? "pointer" : t;
  }
  function makeClassName() {
    for (let i = 1; true; i++) {
      const name = "FridaAnonymousClass" + i;
      if (!(name in classRegistry)) {
        return name;
      }
    }
  }
  function makeProtocolName() {
    for (let i = 1; true; i++) {
      const name = "FridaAnonymousProtocol" + i;
      if (!(name in protocolRegistry)) {
        return name;
      }
    }
  }
  function objcMethodName(name) {
    return name.replace(/_/g, ":");
  }
  function jsMethodName(name) {
    let result = name.replace(/:/g, "_");
    if (objCObjectBuiltins.has(result))
      result += "2";
    return result;
  }
  const isaMasks = {
    x64: "0x7ffffffffff8",
    arm64: "0xffffffff8"
  };
  const rawMask = isaMasks[Process.arch];
  if (rawMask !== void 0) {
    const mask = ptr(rawMask);
    readObjectIsa = function(p) {
      return p.readPointer().and(mask);
    };
  } else {
    readObjectIsa = function(p) {
      return p.readPointer();
    };
  }
  function getMsgSendImpl(signature2, invocationOptions2) {
    return resolveMsgSendImpl(msgSendBySignatureId, signature2, invocationOptions2, false);
  }
  function getMsgSendSuperImpl(signature2, invocationOptions2) {
    return resolveMsgSendImpl(msgSendSuperBySignatureId, signature2, invocationOptions2, true);
  }
  function resolveMsgSendImpl(cache, signature2, invocationOptions2, isSuper) {
    if (invocationOptions2 !== defaultInvocationOptions)
      return makeMsgSendImpl(signature2, invocationOptions2, isSuper);
    const { id } = signature2;
    let impl = cache.get(id);
    if (impl === void 0) {
      impl = makeMsgSendImpl(signature2, invocationOptions2, isSuper);
      cache.set(id, impl);
    }
    return impl;
  }
  function makeMsgSendImpl(signature2, invocationOptions2, isSuper) {
    const retType2 = signature2.retType.type;
    const argTypes2 = signature2.argTypes.map(function(t) {
      return t.type;
    });
    const components = ["objc_msgSend"];
    if (isSuper)
      components.push("Super");
    const returnsStruct = retType2 instanceof Array;
    if (returnsStruct && !typeFitsInRegisters(retType2))
      components.push("_stret");
    else if (retType2 === "float" || retType2 === "double")
      components.push("_fpret");
    const name = components.join("");
    return new NativeFunction(api[name], retType2, argTypes2, invocationOptions2);
  }
  function typeFitsInRegisters(type) {
    if (Process.arch !== "x64")
      return false;
    const size = sizeOfTypeOnX64(type);
    return size <= 16;
  }
  function sizeOfTypeOnX64(type) {
    if (type instanceof Array)
      return type.reduce((total, field) => total + sizeOfTypeOnX64(field), 0);
    switch (type) {
      case "bool":
      case "char":
      case "uchar":
        return 1;
      case "int16":
      case "uint16":
        return 2;
      case "int":
      case "int32":
      case "uint":
      case "uint32":
      case "float":
        return 4;
      default:
        return 8;
    }
  }
  function unparseSignature(retType2, argTypes2) {
    const retTypeId = typeIdFromAlias(retType2);
    const argTypeIds = argTypes2.map(typeIdFromAlias);
    const argSizes = argTypeIds.map((id) => singularTypeById[id].size);
    const frameSize = argSizes.reduce((total, size) => total + size, 0);
    let frameOffset = 0;
    return retTypeId + frameSize + argTypeIds.map((id, i) => {
      const result = id + frameOffset;
      frameOffset += argSizes[i];
      return result;
    }).join("");
  }
  function parseSignature(sig) {
    const cursor = [sig, 0];
    parseQualifiers(cursor);
    const retType2 = readType(cursor);
    readNumber(cursor);
    const argTypes2 = [];
    let id = JSON.stringify(retType2.type);
    while (dataAvailable(cursor)) {
      parseQualifiers(cursor);
      const argType = readType(cursor);
      readNumber(cursor);
      argTypes2.push(argType);
      id += JSON.stringify(argType.type);
    }
    return {
      id,
      retType: retType2,
      argTypes: argTypes2
    };
  }
  function parseType(type) {
    const cursor = [type, 0];
    return readType(cursor);
  }
  function readType(cursor) {
    let id = readChar(cursor);
    if (id === "@") {
      let next = peekChar(cursor);
      if (next === "?") {
        id += next;
        skipChar(cursor);
        if (peekChar(cursor) === "<")
          skipExtendedBlock(cursor);
      } else if (next === '"') {
        skipChar(cursor);
        readUntil('"', cursor);
      }
    } else if (id === "^") {
      let next = peekChar(cursor);
      if (next === "@") {
        id += next;
        skipChar(cursor);
      }
    }
    const type = singularTypeById[id];
    if (type !== void 0) {
      return type;
    } else if (id === "[") {
      const length = readNumber(cursor);
      const elementType = readType(cursor);
      skipChar(cursor);
      return arrayType(length, elementType);
    } else if (id === "{") {
      if (!tokenExistsAhead("=", "}", cursor)) {
        readUntil("}", cursor);
        return structType([]);
      }
      readUntil("=", cursor);
      const structFields = [];
      let ch;
      while ((ch = peekChar(cursor)) !== "}") {
        if (ch === '"') {
          skipChar(cursor);
          readUntil('"', cursor);
        }
        structFields.push(readType(cursor));
      }
      skipChar(cursor);
      return structType(structFields);
    } else if (id === "(") {
      readUntil("=", cursor);
      const unionFields = [];
      while (peekChar(cursor) !== ")")
        unionFields.push(readType(cursor));
      skipChar(cursor);
      return unionType(unionFields);
    } else if (id === "b") {
      readNumber(cursor);
      return singularTypeById.i;
    } else if (id === "^") {
      readType(cursor);
      return singularTypeById["?"];
    } else if (modifiers.has(id)) {
      return readType(cursor);
    } else {
      throw new Error("Unable to handle type " + id);
    }
  }
  function skipExtendedBlock(cursor) {
    let ch;
    skipChar(cursor);
    while ((ch = peekChar(cursor)) !== ">") {
      if (peekChar(cursor) === "<") {
        skipExtendedBlock(cursor);
      } else {
        skipChar(cursor);
        if (ch === '"')
          readUntil('"', cursor);
      }
    }
    skipChar(cursor);
  }
  function readNumber(cursor) {
    let result = "";
    while (dataAvailable(cursor)) {
      const c = peekChar(cursor);
      const v = c.charCodeAt(0);
      const isDigit = v >= 48 && v <= 57;
      if (isDigit) {
        result += c;
        skipChar(cursor);
      } else {
        break;
      }
    }
    return parseInt(result);
  }
  function readUntil(token, cursor) {
    const buffer = cursor[0];
    const offset = cursor[1];
    const index = buffer.indexOf(token, offset);
    if (index === -1)
      throw new Error("Expected token '" + token + "' not found");
    const result = buffer.substring(offset, index);
    cursor[1] = index + 1;
    return result;
  }
  function readChar(cursor) {
    return cursor[0][cursor[1]++];
  }
  function peekChar(cursor) {
    return cursor[0][cursor[1]];
  }
  function tokenExistsAhead(token, terminator, cursor) {
    const [buffer, offset] = cursor;
    const tokenIndex = buffer.indexOf(token, offset);
    if (tokenIndex === -1)
      return false;
    const terminatorIndex = buffer.indexOf(terminator, offset);
    if (terminatorIndex === -1)
      throw new Error("Expected to find terminator: " + terminator);
    return tokenIndex < terminatorIndex;
  }
  function skipChar(cursor) {
    cursor[1]++;
  }
  function dataAvailable(cursor) {
    return cursor[1] !== cursor[0].length;
  }
  const qualifierById = {
    "r": "const",
    "n": "in",
    "N": "inout",
    "o": "out",
    "O": "bycopy",
    "R": "byref",
    "V": "oneway"
  };
  function parseQualifiers(cursor) {
    const qualifiers = [];
    while (true) {
      const q = qualifierById[peekChar(cursor)];
      if (q === void 0)
        break;
      qualifiers.push(q);
      skipChar(cursor);
    }
    return qualifiers;
  }
  const idByAlias = {
    "char": "c",
    "int": "i",
    "int16": "s",
    "int32": "i",
    "int64": "q",
    "uchar": "C",
    "uint": "I",
    "uint16": "S",
    "uint32": "I",
    "uint64": "Q",
    "float": "f",
    "double": "d",
    "bool": "B",
    "void": "v",
    "string": "*",
    "object": "@",
    "block": "@?",
    "class": "#",
    "selector": ":",
    "pointer": "^v"
  };
  function typeIdFromAlias(alias) {
    if (typeof alias === "object" && alias !== null)
      return `@"${alias.type}"`;
    const id = idByAlias[alias];
    if (id === void 0)
      throw new Error("No known encoding for type " + alias);
    return id;
  }
  const fromNativeId = function(h) {
    if (h.isNull()) {
      return null;
    } else if (h.toString(16) === this.handle.toString(16)) {
      return this;
    } else {
      return new ObjCObject(h);
    }
  };
  const toNativeId = function(v) {
    if (v === null)
      return NULL;
    const type = typeof v;
    if (type === "string") {
      if (cachedNSStringCtor === null) {
        cachedNSString = classRegistry.NSString;
        cachedNSStringCtor = cachedNSString.stringWithUTF8String_;
      }
      return cachedNSStringCtor.call(cachedNSString, Memory.allocUtf8String(v));
    } else if (type === "number") {
      if (cachedNSNumberCtor === null) {
        cachedNSNumber = classRegistry.NSNumber;
        cachedNSNumberCtor = cachedNSNumber.numberWithDouble_;
      }
      return cachedNSNumberCtor.call(cachedNSNumber, v);
    }
    return v;
  };
  const fromNativeBlock = function(h) {
    if (h.isNull()) {
      return null;
    } else if (h.toString(16) === this.handle.toString(16)) {
      return this;
    } else {
      return new Block(h);
    }
  };
  const toNativeBlock = function(v) {
    return v !== null ? v : NULL;
  };
  const toNativeObjectArray = function(v) {
    if (v instanceof Array) {
      const length = v.length;
      const array = Memory.alloc(length * pointerSize);
      for (let i = 0; i !== length; i++)
        array.add(i * pointerSize).writePointer(toNativeId(v[i]));
      return array;
    }
    return v;
  };
  function arrayType(length, elementType) {
    return {
      type: "pointer",
      read(address) {
        const result = [];
        const elementSize = elementType.size;
        for (let index = 0; index !== length; index++) {
          result.push(elementType.read(address.add(index * elementSize)));
        }
        return result;
      },
      write(address, values) {
        const elementSize = elementType.size;
        values.forEach((value, index) => {
          elementType.write(address.add(index * elementSize), value);
        });
      }
    };
  }
  function structType(fieldTypes) {
    let fromNative, toNative;
    if (fieldTypes.some(function(t) {
      return !!t.fromNative;
    })) {
      const fromTransforms = fieldTypes.map(function(t) {
        if (t.fromNative)
          return t.fromNative;
        else
          return identityTransform;
      });
      fromNative = function(v) {
        return v.map(function(e, i) {
          return fromTransforms[i].call(this, e);
        });
      };
    } else {
      fromNative = identityTransform;
    }
    if (fieldTypes.some(function(t) {
      return !!t.toNative;
    })) {
      const toTransforms = fieldTypes.map(function(t) {
        if (t.toNative)
          return t.toNative;
        else
          return identityTransform;
      });
      toNative = function(v) {
        return v.map(function(e, i) {
          return toTransforms[i].call(this, e);
        });
      };
    } else {
      toNative = identityTransform;
    }
    const [totalSize, fieldOffsets] = fieldTypes.reduce(function(result, t) {
      const [previousOffset, offsets] = result;
      const { size } = t;
      const offset = align(previousOffset, size);
      offsets.push(offset);
      return [offset + size, offsets];
    }, [0, []]);
    return {
      type: fieldTypes.map((t) => t.type),
      size: totalSize,
      read(address) {
        return fieldTypes.map((type, index) => type.read(address.add(fieldOffsets[index])));
      },
      write(address, values) {
        values.forEach((value, index) => {
          fieldTypes[index].write(address.add(fieldOffsets[index]), value);
        });
      },
      fromNative,
      toNative
    };
  }
  function unionType(fieldTypes) {
    const largestType = fieldTypes.reduce(function(largest, t) {
      if (t.size > largest.size)
        return t;
      else
        return largest;
    }, fieldTypes[0]);
    let fromNative, toNative;
    if (largestType.fromNative) {
      const fromTransform = largestType.fromNative;
      fromNative = function(v) {
        return fromTransform.call(this, v[0]);
      };
    } else {
      fromNative = function(v) {
        return v[0];
      };
    }
    if (largestType.toNative) {
      const toTransform = largestType.toNative;
      toNative = function(v) {
        return [toTransform.call(this, v)];
      };
    } else {
      toNative = function(v) {
        return [v];
      };
    }
    return {
      type: [largestType.type],
      size: largestType.size,
      read: largestType.read,
      write: largestType.write,
      fromNative,
      toNative
    };
  }
  const longBits = pointerSize == 8 && Process.platform !== "windows" ? 64 : 32;
  modifiers = /* @__PURE__ */ new Set([
    "j",
    // complex
    "A",
    // atomic
    "r",
    // const
    "n",
    // in
    "N",
    // inout
    "o",
    // out
    "O",
    // by copy
    "R",
    // by ref
    "V",
    // one way
    "+"
    // GNU register
  ]);
  singularTypeById = {
    "c": {
      type: "char",
      size: 1,
      read: (address) => address.readS8(),
      write: (address, value) => {
        address.writeS8(value);
      },
      toNative(v) {
        if (typeof v === "boolean") {
          return v ? 1 : 0;
        }
        return v;
      }
    },
    "i": {
      type: "int",
      size: 4,
      read: (address) => address.readInt(),
      write: (address, value) => {
        address.writeInt(value);
      }
    },
    "s": {
      type: "int16",
      size: 2,
      read: (address) => address.readS16(),
      write: (address, value) => {
        address.writeS16(value);
      }
    },
    "l": {
      type: "int32",
      size: 4,
      read: (address) => address.readS32(),
      write: (address, value) => {
        address.writeS32(value);
      }
    },
    "q": {
      type: "int64",
      size: 8,
      read: (address) => address.readS64(),
      write: (address, value) => {
        address.writeS64(value);
      }
    },
    "C": {
      type: "uchar",
      size: 1,
      read: (address) => address.readU8(),
      write: (address, value) => {
        address.writeU8(value);
      }
    },
    "I": {
      type: "uint",
      size: 4,
      read: (address) => address.readUInt(),
      write: (address, value) => {
        address.writeUInt(value);
      }
    },
    "S": {
      type: "uint16",
      size: 2,
      read: (address) => address.readU16(),
      write: (address, value) => {
        address.writeU16(value);
      }
    },
    "L": {
      type: "uint" + longBits,
      size: longBits / 8,
      read: (address) => address.readULong(),
      write: (address, value) => {
        address.writeULong(value);
      }
    },
    "Q": {
      type: "uint64",
      size: 8,
      read: (address) => address.readU64(),
      write: (address, value) => {
        address.writeU64(value);
      }
    },
    "f": {
      type: "float",
      size: 4,
      read: (address) => address.readFloat(),
      write: (address, value) => {
        address.writeFloat(value);
      }
    },
    "d": {
      type: "double",
      size: 8,
      read: (address) => address.readDouble(),
      write: (address, value) => {
        address.writeDouble(value);
      }
    },
    "B": {
      type: "bool",
      size: 1,
      read: (address) => address.readU8(),
      write: (address, value) => {
        address.writeU8(value);
      },
      fromNative(v) {
        return v ? true : false;
      },
      toNative(v) {
        return v ? 1 : 0;
      }
    },
    "v": {
      type: "void",
      size: 0
    },
    "*": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      },
      fromNative(h) {
        return h.readUtf8String();
      }
    },
    "@": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      },
      fromNative: fromNativeId,
      toNative: toNativeId
    },
    "@?": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      },
      fromNative: fromNativeBlock,
      toNative: toNativeBlock
    },
    "^@": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      },
      toNative: toNativeObjectArray
    },
    "^v": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      }
    },
    "#": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      },
      fromNative: fromNativeId,
      toNative: toNativeId
    },
    ":": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      }
    },
    "?": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      }
    }
  };
  function identityTransform(v) {
    return v;
  }
  function align(value, boundary) {
    const remainder = value % boundary;
    return remainder === 0 ? value : value + (boundary - remainder);
  }
}
var runtime = new Runtime();
let ObjC = runtime;

var fridamp =
{
  "version": 3,
  "sources": ["node_modules/frida-objc-bridge/lib/api.js", "node_modules/frida-objc-bridge/lib/fastpaths.js", "node_modules/frida-objc-bridge/index.js", "aaa.ts"],
  "mappings": "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",
  "names": ["api", "signature", "pointerSize", "method", "sel", "handle", "superSpecifier", "methodHandle", "types", "protocol", "m", "ptr", "block", "signature", "selector", "key", "name", "implementation", "owner", "invocationOptions", "retType", "argTypes", "NSAutoreleasePool"]
}

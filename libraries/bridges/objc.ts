import ObjC from 'frida-objc-bridge';
(globalThis as unknown as { ObjC: typeof ObjC }).ObjC = ObjC;

//----------------------start of frida_Memory_bridge-------------------------------------
// Read functions
Memory.readByteArray = function(nativePtr, size) {
    return nativePtr.readByteArray(size);
};

Memory.readPointer = function(nativePtr) {
    return nativePtr.readPointer();
};

Memory.readCString = function(nativePtr) {
    return nativePtr.readCString();
};

Memory.readUtf8String = function(nativePtr) {
    return nativePtr.readUtf8String();
};

Memory.readInt = function(nativePtr) {
    return nativePtr.readInt();
};

Memory.readUInt = function(nativePtr) {
    return nativePtr.readUInt();
};

Memory.readU8 = function(nativePtr) {
    return nativePtr.readU8();
};

Memory.readU16 = function(nativePtr) {
    return nativePtr.readU16();
};

Memory.readU32 = function(nativePtr) {
    return nativePtr.readU32();
};

Memory.readU64 = function(nativePtr) {
    return nativePtr.readU64();
};

// Write functions
Memory.writeByteArray = function(nativePtr, bytes) {
    return nativePtr.writeByteArray(bytes);
};

Memory.writePointer = function(nativePtr, ptr) {
    return nativePtr.writePointer(ptr);
};

Memory.writeCString = function(nativePtr, str) {
    return nativePtr.writeCString(str);
};

Memory.writeUtf8String = function(nativePtr, str) {
    return nativePtr.writeUtf8String(str);
};

Memory.writeInt = function(nativePtr, value) {
    return nativePtr.writeInt(value);
};

Memory.writeUInt = function(nativePtr, value) {
    return nativePtr.writeUInt(value);
};

Memory.writeU8 = function(nativePtr, value) {
    return nativePtr.writeU8(value);
};

Memory.writeU16 = function(nativePtr, value) {
    return nativePtr.writeU16(value);
};

Memory.writeU32 = function(nativePtr, value) {
    return nativePtr.writeU32(value);
};

Memory.writeU64 = function(nativePtr, value) {
    return nativePtr.writeU64(value);
};

//----------------------end of frida_Memory_bridge-------------------------------------

//"frida-java-bridge", version="7.0.8"

var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// frida-shim:node_modules/@frida/base64-js/index.js
var lookup = [];
var revLookup = [];
var code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
for (let i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i];
  revLookup[code.charCodeAt(i)] = i;
}
revLookup["-".charCodeAt(0)] = 62;
revLookup["_".charCodeAt(0)] = 63;
function getLens(b64) {
  const len = b64.length;
  if (len % 4 > 0) {
    throw new Error("Invalid string. Length must be a multiple of 4");
  }
  let validLen = b64.indexOf("=");
  if (validLen === -1) validLen = len;
  const placeHoldersLen = validLen === len ? 0 : 4 - validLen % 4;
  return [validLen, placeHoldersLen];
}
function _byteLength(b64, validLen, placeHoldersLen) {
  return (validLen + placeHoldersLen) * 3 / 4 - placeHoldersLen;
}
function toByteArray(b64) {
  const lens = getLens(b64);
  const validLen = lens[0];
  const placeHoldersLen = lens[1];
  const arr = new Uint8Array(_byteLength(b64, validLen, placeHoldersLen));
  let curByte = 0;
  const len = placeHoldersLen > 0 ? validLen - 4 : validLen;
  let i;
  for (i = 0; i < len; i += 4) {
    const tmp = revLookup[b64.charCodeAt(i)] << 18 | revLookup[b64.charCodeAt(i + 1)] << 12 | revLookup[b64.charCodeAt(i + 2)] << 6 | revLookup[b64.charCodeAt(i + 3)];
    arr[curByte++] = tmp >> 16 & 255;
    arr[curByte++] = tmp >> 8 & 255;
    arr[curByte++] = tmp & 255;
  }
  if (placeHoldersLen === 2) {
    const tmp = revLookup[b64.charCodeAt(i)] << 2 | revLookup[b64.charCodeAt(i + 1)] >> 4;
    arr[curByte++] = tmp & 255;
  }
  if (placeHoldersLen === 1) {
    const tmp = revLookup[b64.charCodeAt(i)] << 10 | revLookup[b64.charCodeAt(i + 1)] << 4 | revLookup[b64.charCodeAt(i + 2)] >> 2;
    arr[curByte++] = tmp >> 8 & 255;
    arr[curByte++] = tmp & 255;
  }
  return arr;
}
function tripletToBase64(num) {
  return lookup[num >> 18 & 63] + lookup[num >> 12 & 63] + lookup[num >> 6 & 63] + lookup[num & 63];
}
function encodeChunk(uint8, start, end) {
  const output = [];
  for (let i = start; i < end; i += 3) {
    const tmp = (uint8[i] << 16 & 16711680) + (uint8[i + 1] << 8 & 65280) + (uint8[i + 2] & 255);
    output.push(tripletToBase64(tmp));
  }
  return output.join("");
}
function fromByteArray(uint8) {
  const len = uint8.length;
  const extraBytes = len % 3;
  const parts = [];
  const maxChunkLength = 16383;
  for (let i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(uint8, i, i + maxChunkLength > len2 ? len2 : i + maxChunkLength));
  }
  if (extraBytes === 1) {
    const tmp = uint8[len - 1];
    parts.push(
      lookup[tmp >> 2] + lookup[tmp << 4 & 63] + "=="
    );
  } else if (extraBytes === 2) {
    const tmp = (uint8[len - 2] << 8) + uint8[len - 1];
    parts.push(
      lookup[tmp >> 10] + lookup[tmp >> 4 & 63] + lookup[tmp << 2 & 63] + "="
    );
  }
  return parts.join("");
}

// frida-shim:node_modules/@frida/ieee754/index.js
function read(buffer, offset, isLE, mLen, nBytes) {
  let e, m;
  const eLen = nBytes * 8 - mLen - 1;
  const eMax = (1 << eLen) - 1;
  const eBias = eMax >> 1;
  let nBits = -7;
  let i = isLE ? nBytes - 1 : 0;
  const d = isLE ? -1 : 1;
  let s = buffer[offset + i];
  i += d;
  e = s & (1 << -nBits) - 1;
  s >>= -nBits;
  nBits += eLen;
  while (nBits > 0) {
    e = e * 256 + buffer[offset + i];
    i += d;
    nBits -= 8;
  }
  m = e & (1 << -nBits) - 1;
  e >>= -nBits;
  nBits += mLen;
  while (nBits > 0) {
    m = m * 256 + buffer[offset + i];
    i += d;
    nBits -= 8;
  }
  if (e === 0) {
    e = 1 - eBias;
  } else if (e === eMax) {
    return m ? NaN : (s ? -1 : 1) * Infinity;
  } else {
    m = m + Math.pow(2, mLen);
    e = e - eBias;
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen);
}
function write(buffer, value, offset, isLE, mLen, nBytes) {
  let e, m, c;
  let eLen = nBytes * 8 - mLen - 1;
  const eMax = (1 << eLen) - 1;
  const eBias = eMax >> 1;
  const rt = mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0;
  let i = isLE ? 0 : nBytes - 1;
  const d = isLE ? 1 : -1;
  const s = value < 0 || value === 0 && 1 / value < 0 ? 1 : 0;
  value = Math.abs(value);
  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0;
    e = eMax;
  } else {
    e = Math.floor(Math.log(value) / Math.LN2);
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--;
      c *= 2;
    }
    if (e + eBias >= 1) {
      value += rt / c;
    } else {
      value += rt * Math.pow(2, 1 - eBias);
    }
    if (value * c >= 2) {
      e++;
      c /= 2;
    }
    if (e + eBias >= eMax) {
      m = 0;
      e = eMax;
    } else if (e + eBias >= 1) {
      m = (value * c - 1) * Math.pow(2, mLen);
      e = e + eBias;
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen);
      e = 0;
    }
  }
  while (mLen >= 8) {
    buffer[offset + i] = m & 255;
    i += d;
    m /= 256;
    mLen -= 8;
  }
  e = e << mLen | m;
  eLen += mLen;
  while (eLen > 0) {
    buffer[offset + i] = e & 255;
    i += d;
    e /= 256;
    eLen -= 8;
  }
  buffer[offset + i - d] |= s * 128;
}

// frida-shim:node_modules/@frida/buffer/index.js
var config = {
  INSPECT_MAX_BYTES: 50
};
var K_MAX_LENGTH = 2147483647;
Buffer2.TYPED_ARRAY_SUPPORT = true;
Object.defineProperty(Buffer2.prototype, "parent", {
  enumerable: true,
  get: function() {
    if (!Buffer2.isBuffer(this)) return void 0;
    return this.buffer;
  }
});
Object.defineProperty(Buffer2.prototype, "offset", {
  enumerable: true,
  get: function() {
    if (!Buffer2.isBuffer(this)) return void 0;
    return this.byteOffset;
  }
});
function createBuffer(length) {
  if (length > K_MAX_LENGTH) {
    throw new RangeError('The value "' + length + '" is invalid for option "size"');
  }
  const buf = new Uint8Array(length);
  Object.setPrototypeOf(buf, Buffer2.prototype);
  return buf;
}
function Buffer2(arg, encodingOrOffset, length) {
  if (typeof arg === "number") {
    if (typeof encodingOrOffset === "string") {
      throw new TypeError(
        'The "string" argument must be of type string. Received type number'
      );
    }
    return allocUnsafe(arg);
  }
  return from(arg, encodingOrOffset, length);
}
Buffer2.poolSize = 8192;
function from(value, encodingOrOffset, length) {
  if (typeof value === "string") {
    return fromString(value, encodingOrOffset);
  }
  if (ArrayBuffer.isView(value)) {
    return fromArrayView(value);
  }
  if (value == null) {
    throw new TypeError(
      "The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type " + typeof value
    );
  }
  if (value instanceof ArrayBuffer || value && value.buffer instanceof ArrayBuffer) {
    return fromArrayBuffer(value, encodingOrOffset, length);
  }
  if (value instanceof SharedArrayBuffer || value && value.buffer instanceof SharedArrayBuffer) {
    return fromArrayBuffer(value, encodingOrOffset, length);
  }
  if (typeof value === "number") {
    throw new TypeError(
      'The "value" argument must not be of type number. Received type number'
    );
  }
  const valueOf = value.valueOf && value.valueOf();
  if (valueOf != null && valueOf !== value) {
    return Buffer2.from(valueOf, encodingOrOffset, length);
  }
  const b = fromObject(value);
  if (b) return b;
  if (typeof Symbol !== "undefined" && Symbol.toPrimitive != null && typeof value[Symbol.toPrimitive] === "function") {
    return Buffer2.from(value[Symbol.toPrimitive]("string"), encodingOrOffset, length);
  }
  throw new TypeError(
    "The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type " + typeof value
  );
}
Buffer2.from = function(value, encodingOrOffset, length) {
  return from(value, encodingOrOffset, length);
};
Object.setPrototypeOf(Buffer2.prototype, Uint8Array.prototype);
Object.setPrototypeOf(Buffer2, Uint8Array);
function assertSize(size) {
  if (typeof size !== "number") {
    throw new TypeError('"size" argument must be of type number');
  } else if (size < 0) {
    throw new RangeError('The value "' + size + '" is invalid for option "size"');
  }
}
function alloc(size, fill2, encoding) {
  assertSize(size);
  if (size <= 0) {
    return createBuffer(size);
  }
  if (fill2 !== void 0) {
    return typeof encoding === "string" ? createBuffer(size).fill(fill2, encoding) : createBuffer(size).fill(fill2);
  }
  return createBuffer(size);
}
Buffer2.alloc = function(size, fill2, encoding) {
  return alloc(size, fill2, encoding);
};
function allocUnsafe(size) {
  assertSize(size);
  return createBuffer(size < 0 ? 0 : checked(size) | 0);
}
Buffer2.allocUnsafe = function(size) {
  return allocUnsafe(size);
};
Buffer2.allocUnsafeSlow = function(size) {
  return allocUnsafe(size);
};
function fromString(string, encoding) {
  if (typeof encoding !== "string" || encoding === "") {
    encoding = "utf8";
  }
  if (!Buffer2.isEncoding(encoding)) {
    throw new TypeError("Unknown encoding: " + encoding);
  }
  const length = byteLength(string, encoding) | 0;
  let buf = createBuffer(length);
  const actual = buf.write(string, encoding);
  if (actual !== length) {
    buf = buf.slice(0, actual);
  }
  return buf;
}
function fromArrayLike(array) {
  const length = array.length < 0 ? 0 : checked(array.length) | 0;
  const buf = createBuffer(length);
  for (let i = 0; i < length; i += 1) {
    buf[i] = array[i] & 255;
  }
  return buf;
}
function fromArrayView(arrayView) {
  if (arrayView instanceof Uint8Array) {
    const copy2 = new Uint8Array(arrayView);
    return fromArrayBuffer(copy2.buffer, copy2.byteOffset, copy2.byteLength);
  }
  return fromArrayLike(arrayView);
}
function fromArrayBuffer(array, byteOffset, length) {
  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('"offset" is outside of buffer bounds');
  }
  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('"length" is outside of buffer bounds');
  }
  let buf;
  if (byteOffset === void 0 && length === void 0) {
    buf = new Uint8Array(array);
  } else if (length === void 0) {
    buf = new Uint8Array(array, byteOffset);
  } else {
    buf = new Uint8Array(array, byteOffset, length);
  }
  Object.setPrototypeOf(buf, Buffer2.prototype);
  return buf;
}
function fromObject(obj) {
  if (Buffer2.isBuffer(obj)) {
    const len = checked(obj.length) | 0;
    const buf = createBuffer(len);
    if (buf.length === 0) {
      return buf;
    }
    obj.copy(buf, 0, 0, len);
    return buf;
  }
  if (obj.length !== void 0) {
    if (typeof obj.length !== "number" || Number.isNaN(obj.length)) {
      return createBuffer(0);
    }
    return fromArrayLike(obj);
  }
  if (obj.type === "Buffer" && Array.isArray(obj.data)) {
    return fromArrayLike(obj.data);
  }
}
function checked(length) {
  if (length >= K_MAX_LENGTH) {
    throw new RangeError("Attempt to allocate Buffer larger than maximum size: 0x" + K_MAX_LENGTH.toString(16) + " bytes");
  }
  return length | 0;
}
Buffer2.isBuffer = function isBuffer(b) {
  return b != null && b._isBuffer === true && b !== Buffer2.prototype;
};
Buffer2.compare = function compare(a, b) {
  if (a instanceof Uint8Array) a = Buffer2.from(a, a.offset, a.byteLength);
  if (b instanceof Uint8Array) b = Buffer2.from(b, b.offset, b.byteLength);
  if (!Buffer2.isBuffer(a) || !Buffer2.isBuffer(b)) {
    throw new TypeError(
      'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
    );
  }
  if (a === b) return 0;
  let x = a.length;
  let y = b.length;
  for (let i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i];
      y = b[i];
      break;
    }
  }
  if (x < y) return -1;
  if (y < x) return 1;
  return 0;
};
Buffer2.isEncoding = function isEncoding(encoding) {
  switch (String(encoding).toLowerCase()) {
    case "hex":
    case "utf8":
    case "utf-8":
    case "ascii":
    case "latin1":
    case "binary":
    case "base64":
    case "ucs2":
    case "ucs-2":
    case "utf16le":
    case "utf-16le":
      return true;
    default:
      return false;
  }
};
Buffer2.concat = function concat(list, length) {
  if (!Array.isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers');
  }
  if (list.length === 0) {
    return Buffer2.alloc(0);
  }
  let i;
  if (length === void 0) {
    length = 0;
    for (i = 0; i < list.length; ++i) {
      length += list[i].length;
    }
  }
  const buffer = Buffer2.allocUnsafe(length);
  let pos = 0;
  for (i = 0; i < list.length; ++i) {
    let buf = list[i];
    if (buf instanceof Uint8Array) {
      if (pos + buf.length > buffer.length) {
        if (!Buffer2.isBuffer(buf)) {
          buf = Buffer2.from(buf.buffer, buf.byteOffset, buf.byteLength);
        }
        buf.copy(buffer, pos);
      } else {
        Uint8Array.prototype.set.call(
          buffer,
          buf,
          pos
        );
      }
    } else if (!Buffer2.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers');
    } else {
      buf.copy(buffer, pos);
    }
    pos += buf.length;
  }
  return buffer;
};
function byteLength(string, encoding) {
  if (Buffer2.isBuffer(string)) {
    return string.length;
  }
  if (ArrayBuffer.isView(string) || string instanceof ArrayBuffer) {
    return string.byteLength;
  }
  if (typeof string !== "string") {
    throw new TypeError(
      'The "string" argument must be one of type string, Buffer, or ArrayBuffer. Received type ' + typeof string
    );
  }
  const len = string.length;
  const mustMatch = arguments.length > 2 && arguments[2] === true;
  if (!mustMatch && len === 0) return 0;
  let loweredCase = false;
  for (; ; ) {
    switch (encoding) {
      case "ascii":
      case "latin1":
      case "binary":
        return len;
      case "utf8":
      case "utf-8":
        return utf8ToBytes(string).length;
      case "ucs2":
      case "ucs-2":
      case "utf16le":
      case "utf-16le":
        return len * 2;
      case "hex":
        return len >>> 1;
      case "base64":
        return base64ToBytes(string).length;
      default:
        if (loweredCase) {
          return mustMatch ? -1 : utf8ToBytes(string).length;
        }
        encoding = ("" + encoding).toLowerCase();
        loweredCase = true;
    }
  }
}
Buffer2.byteLength = byteLength;
function slowToString(encoding, start, end) {
  let loweredCase = false;
  if (start === void 0 || start < 0) {
    start = 0;
  }
  if (start > this.length) {
    return "";
  }
  if (end === void 0 || end > this.length) {
    end = this.length;
  }
  if (end <= 0) {
    return "";
  }
  end >>>= 0;
  start >>>= 0;
  if (end <= start) {
    return "";
  }
  if (!encoding) encoding = "utf8";
  while (true) {
    switch (encoding) {
      case "hex":
        return hexSlice(this, start, end);
      case "utf8":
      case "utf-8":
        return utf8Slice(this, start, end);
      case "ascii":
        return asciiSlice(this, start, end);
      case "latin1":
      case "binary":
        return latin1Slice(this, start, end);
      case "base64":
        return base64Slice(this, start, end);
      case "ucs2":
      case "ucs-2":
      case "utf16le":
      case "utf-16le":
        return utf16leSlice(this, start, end);
      default:
        if (loweredCase) throw new TypeError("Unknown encoding: " + encoding);
        encoding = (encoding + "").toLowerCase();
        loweredCase = true;
    }
  }
}
Buffer2.prototype._isBuffer = true;
function swap(b, n, m) {
  const i = b[n];
  b[n] = b[m];
  b[m] = i;
}
Buffer2.prototype.swap16 = function swap16() {
  const len = this.length;
  if (len % 2 !== 0) {
    throw new RangeError("Buffer size must be a multiple of 16-bits");
  }
  for (let i = 0; i < len; i += 2) {
    swap(this, i, i + 1);
  }
  return this;
};
Buffer2.prototype.swap32 = function swap32() {
  const len = this.length;
  if (len % 4 !== 0) {
    throw new RangeError("Buffer size must be a multiple of 32-bits");
  }
  for (let i = 0; i < len; i += 4) {
    swap(this, i, i + 3);
    swap(this, i + 1, i + 2);
  }
  return this;
};
Buffer2.prototype.swap64 = function swap64() {
  const len = this.length;
  if (len % 8 !== 0) {
    throw new RangeError("Buffer size must be a multiple of 64-bits");
  }
  for (let i = 0; i < len; i += 8) {
    swap(this, i, i + 7);
    swap(this, i + 1, i + 6);
    swap(this, i + 2, i + 5);
    swap(this, i + 3, i + 4);
  }
  return this;
};
Buffer2.prototype.toString = function toString() {
  const length = this.length;
  if (length === 0) return "";
  if (arguments.length === 0) return utf8Slice(this, 0, length);
  return slowToString.apply(this, arguments);
};
Buffer2.prototype.toLocaleString = Buffer2.prototype.toString;
Buffer2.prototype.equals = function equals(b) {
  if (!Buffer2.isBuffer(b)) throw new TypeError("Argument must be a Buffer");
  if (this === b) return true;
  return Buffer2.compare(this, b) === 0;
};
Buffer2.prototype.inspect = function inspect() {
  let str = "";
  const max = config.INSPECT_MAX_BYTES;
  str = this.toString("hex", 0, max).replace(/(.{2})/g, "$1 ").trim();
  if (this.length > max) str += " ... ";
  return "<Buffer " + str + ">";
};
Buffer2.prototype[Symbol.for("nodejs.util.inspect.custom")] = Buffer2.prototype.inspect;
Buffer2.prototype.compare = function compare2(target, start, end, thisStart, thisEnd) {
  if (target instanceof Uint8Array) {
    target = Buffer2.from(target, target.offset, target.byteLength);
  }
  if (!Buffer2.isBuffer(target)) {
    throw new TypeError(
      'The "target" argument must be one of type Buffer or Uint8Array. Received type ' + typeof target
    );
  }
  if (start === void 0) {
    start = 0;
  }
  if (end === void 0) {
    end = target ? target.length : 0;
  }
  if (thisStart === void 0) {
    thisStart = 0;
  }
  if (thisEnd === void 0) {
    thisEnd = this.length;
  }
  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError("out of range index");
  }
  if (thisStart >= thisEnd && start >= end) {
    return 0;
  }
  if (thisStart >= thisEnd) {
    return -1;
  }
  if (start >= end) {
    return 1;
  }
  start >>>= 0;
  end >>>= 0;
  thisStart >>>= 0;
  thisEnd >>>= 0;
  if (this === target) return 0;
  let x = thisEnd - thisStart;
  let y = end - start;
  const len = Math.min(x, y);
  const thisCopy = this.slice(thisStart, thisEnd);
  const targetCopy = target.slice(start, end);
  for (let i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i];
      y = targetCopy[i];
      break;
    }
  }
  if (x < y) return -1;
  if (y < x) return 1;
  return 0;
};
function bidirectionalIndexOf(buffer, val, byteOffset, encoding, dir) {
  if (buffer.length === 0) return -1;
  if (typeof byteOffset === "string") {
    encoding = byteOffset;
    byteOffset = 0;
  } else if (byteOffset > 2147483647) {
    byteOffset = 2147483647;
  } else if (byteOffset < -2147483648) {
    byteOffset = -2147483648;
  }
  byteOffset = +byteOffset;
  if (Number.isNaN(byteOffset)) {
    byteOffset = dir ? 0 : buffer.length - 1;
  }
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset;
  if (byteOffset >= buffer.length) {
    if (dir) return -1;
    else byteOffset = buffer.length - 1;
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0;
    else return -1;
  }
  if (typeof val === "string") {
    val = Buffer2.from(val, encoding);
  }
  if (Buffer2.isBuffer(val)) {
    if (val.length === 0) {
      return -1;
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir);
  } else if (typeof val === "number") {
    val = val & 255;
    if (typeof Uint8Array.prototype.indexOf === "function") {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset);
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset);
      }
    }
    return arrayIndexOf(buffer, [val], byteOffset, encoding, dir);
  }
  throw new TypeError("val must be string, number or Buffer");
}
function arrayIndexOf(arr, val, byteOffset, encoding, dir) {
  let indexSize = 1;
  let arrLength = arr.length;
  let valLength = val.length;
  if (encoding !== void 0) {
    encoding = String(encoding).toLowerCase();
    if (encoding === "ucs2" || encoding === "ucs-2" || encoding === "utf16le" || encoding === "utf-16le") {
      if (arr.length < 2 || val.length < 2) {
        return -1;
      }
      indexSize = 2;
      arrLength /= 2;
      valLength /= 2;
      byteOffset /= 2;
    }
  }
  function read2(buf, i2) {
    if (indexSize === 1) {
      return buf[i2];
    } else {
      return buf.readUInt16BE(i2 * indexSize);
    }
  }
  let i;
  if (dir) {
    let foundIndex = -1;
    for (i = byteOffset; i < arrLength; i++) {
      if (read2(arr, i) === read2(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i;
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize;
      } else {
        if (foundIndex !== -1) i -= i - foundIndex;
        foundIndex = -1;
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength;
    for (i = byteOffset; i >= 0; i--) {
      let found = true;
      for (let j = 0; j < valLength; j++) {
        if (read2(arr, i + j) !== read2(val, j)) {
          found = false;
          break;
        }
      }
      if (found) return i;
    }
  }
  return -1;
}
Buffer2.prototype.includes = function includes(val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1;
};
Buffer2.prototype.indexOf = function indexOf(val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true);
};
Buffer2.prototype.lastIndexOf = function lastIndexOf(val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false);
};
function hexWrite(buf, string, offset, length) {
  offset = Number(offset) || 0;
  const remaining = buf.length - offset;
  if (!length) {
    length = remaining;
  } else {
    length = Number(length);
    if (length > remaining) {
      length = remaining;
    }
  }
  const strLen = string.length;
  if (length > strLen / 2) {
    length = strLen / 2;
  }
  let i;
  for (i = 0; i < length; ++i) {
    const parsed = parseInt(string.substr(i * 2, 2), 16);
    if (Number.isNaN(parsed)) return i;
    buf[offset + i] = parsed;
  }
  return i;
}
function utf8Write(buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length);
}
function asciiWrite(buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length);
}
function base64Write(buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length);
}
function ucs2Write(buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length);
}
Buffer2.prototype.write = function write2(string, offset, length, encoding) {
  if (offset === void 0) {
    encoding = "utf8";
    length = this.length;
    offset = 0;
  } else if (length === void 0 && typeof offset === "string") {
    encoding = offset;
    length = this.length;
    offset = 0;
  } else if (isFinite(offset)) {
    offset = offset >>> 0;
    if (isFinite(length)) {
      length = length >>> 0;
      if (encoding === void 0) encoding = "utf8";
    } else {
      encoding = length;
      length = void 0;
    }
  } else {
    throw new Error(
      "Buffer.write(string, encoding, offset[, length]) is no longer supported"
    );
  }
  const remaining = this.length - offset;
  if (length === void 0 || length > remaining) length = remaining;
  if (string.length > 0 && (length < 0 || offset < 0) || offset > this.length) {
    throw new RangeError("Attempt to write outside buffer bounds");
  }
  if (!encoding) encoding = "utf8";
  let loweredCase = false;
  for (; ; ) {
    switch (encoding) {
      case "hex":
        return hexWrite(this, string, offset, length);
      case "utf8":
      case "utf-8":
        return utf8Write(this, string, offset, length);
      case "ascii":
      case "latin1":
      case "binary":
        return asciiWrite(this, string, offset, length);
      case "base64":
        return base64Write(this, string, offset, length);
      case "ucs2":
      case "ucs-2":
      case "utf16le":
      case "utf-16le":
        return ucs2Write(this, string, offset, length);
      default:
        if (loweredCase) throw new TypeError("Unknown encoding: " + encoding);
        encoding = ("" + encoding).toLowerCase();
        loweredCase = true;
    }
  }
};
Buffer2.prototype.toJSON = function toJSON() {
  return {
    type: "Buffer",
    data: Array.prototype.slice.call(this._arr || this, 0)
  };
};
function base64Slice(buf, start, end) {
  if (start === 0 && end === buf.length) {
    return fromByteArray(buf);
  } else {
    return fromByteArray(buf.slice(start, end));
  }
}
function utf8Slice(buf, start, end) {
  end = Math.min(buf.length, end);
  const res = [];
  let i = start;
  while (i < end) {
    const firstByte = buf[i];
    let codePoint = null;
    let bytesPerSequence = firstByte > 239 ? 4 : firstByte > 223 ? 3 : firstByte > 191 ? 2 : 1;
    if (i + bytesPerSequence <= end) {
      let secondByte, thirdByte, fourthByte, tempCodePoint;
      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 128) {
            codePoint = firstByte;
          }
          break;
        case 2:
          secondByte = buf[i + 1];
          if ((secondByte & 192) === 128) {
            tempCodePoint = (firstByte & 31) << 6 | secondByte & 63;
            if (tempCodePoint > 127) {
              codePoint = tempCodePoint;
            }
          }
          break;
        case 3:
          secondByte = buf[i + 1];
          thirdByte = buf[i + 2];
          if ((secondByte & 192) === 128 && (thirdByte & 192) === 128) {
            tempCodePoint = (firstByte & 15) << 12 | (secondByte & 63) << 6 | thirdByte & 63;
            if (tempCodePoint > 2047 && (tempCodePoint < 55296 || tempCodePoint > 57343)) {
              codePoint = tempCodePoint;
            }
          }
          break;
        case 4:
          secondByte = buf[i + 1];
          thirdByte = buf[i + 2];
          fourthByte = buf[i + 3];
          if ((secondByte & 192) === 128 && (thirdByte & 192) === 128 && (fourthByte & 192) === 128) {
            tempCodePoint = (firstByte & 15) << 18 | (secondByte & 63) << 12 | (thirdByte & 63) << 6 | fourthByte & 63;
            if (tempCodePoint > 65535 && tempCodePoint < 1114112) {
              codePoint = tempCodePoint;
            }
          }
      }
    }
    if (codePoint === null) {
      codePoint = 65533;
      bytesPerSequence = 1;
    } else if (codePoint > 65535) {
      codePoint -= 65536;
      res.push(codePoint >>> 10 & 1023 | 55296);
      codePoint = 56320 | codePoint & 1023;
    }
    res.push(codePoint);
    i += bytesPerSequence;
  }
  return decodeCodePointsArray(res);
}
var MAX_ARGUMENTS_LENGTH = 4096;
function decodeCodePointsArray(codePoints) {
  const len = codePoints.length;
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints);
  }
  let res = "";
  let i = 0;
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    );
  }
  return res;
}
function asciiSlice(buf, start, end) {
  let ret = "";
  end = Math.min(buf.length, end);
  for (let i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 127);
  }
  return ret;
}
function latin1Slice(buf, start, end) {
  let ret = "";
  end = Math.min(buf.length, end);
  for (let i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i]);
  }
  return ret;
}
function hexSlice(buf, start, end) {
  const len = buf.length;
  if (!start || start < 0) start = 0;
  if (!end || end < 0 || end > len) end = len;
  let out = "";
  for (let i = start; i < end; ++i) {
    out += hexSliceLookupTable[buf[i]];
  }
  return out;
}
function utf16leSlice(buf, start, end) {
  const bytes = buf.slice(start, end);
  let res = "";
  for (let i = 0; i < bytes.length - 1; i += 2) {
    res += String.fromCharCode(bytes[i] + bytes[i + 1] * 256);
  }
  return res;
}
Buffer2.prototype.slice = function slice(start, end) {
  const len = this.length;
  start = ~~start;
  end = end === void 0 ? len : ~~end;
  if (start < 0) {
    start += len;
    if (start < 0) start = 0;
  } else if (start > len) {
    start = len;
  }
  if (end < 0) {
    end += len;
    if (end < 0) end = 0;
  } else if (end > len) {
    end = len;
  }
  if (end < start) end = start;
  const newBuf = this.subarray(start, end);
  Object.setPrototypeOf(newBuf, Buffer2.prototype);
  return newBuf;
};
function checkOffset(offset, ext, length) {
  if (offset % 1 !== 0 || offset < 0) throw new RangeError("offset is not uint");
  if (offset + ext > length) throw new RangeError("Trying to access beyond buffer length");
}
Buffer2.prototype.readUintLE = Buffer2.prototype.readUIntLE = function readUIntLE(offset, byteLength2, noAssert) {
  offset = offset >>> 0;
  byteLength2 = byteLength2 >>> 0;
  if (!noAssert) checkOffset(offset, byteLength2, this.length);
  let val = this[offset];
  let mul = 1;
  let i = 0;
  while (++i < byteLength2 && (mul *= 256)) {
    val += this[offset + i] * mul;
  }
  return val;
};
Buffer2.prototype.readUintBE = Buffer2.prototype.readUIntBE = function readUIntBE(offset, byteLength2, noAssert) {
  offset = offset >>> 0;
  byteLength2 = byteLength2 >>> 0;
  if (!noAssert) {
    checkOffset(offset, byteLength2, this.length);
  }
  let val = this[offset + --byteLength2];
  let mul = 1;
  while (byteLength2 > 0 && (mul *= 256)) {
    val += this[offset + --byteLength2] * mul;
  }
  return val;
};
Buffer2.prototype.readUint8 = Buffer2.prototype.readUInt8 = function readUInt8(offset, noAssert) {
  offset = offset >>> 0;
  if (!noAssert) checkOffset(offset, 1, this.length);
  return this[offset];
};
Buffer2.prototype.readUint16LE = Buffer2.prototype.readUInt16LE = function readUInt16LE(offset, noAssert) {
  offset = offset >>> 0;
  if (!noAssert) checkOffset(offset, 2, this.length);
  return this[offset] | this[offset + 1] << 8;
};
Buffer2.prototype.readUint16BE = Buffer2.prototype.readUInt16BE = function readUInt16BE(offset, noAssert) {
  offset = offset >>> 0;
  if (!noAssert) checkOffset(offset, 2, this.length);
  return this[offset] << 8 | this[offset + 1];
};
Buffer2.prototype.readUint32LE = Buffer2.prototype.readUInt32LE = function readUInt32LE(offset, noAssert) {
  offset = offset >>> 0;
  if (!noAssert) checkOffset(offset, 4, this.length);
  return (this[offset] | this[offset + 1] << 8 | this[offset + 2] << 16) + this[offset + 3] * 16777216;
};
Buffer2.prototype.readUint32BE = Buffer2.prototype.readUInt32BE = function readUInt32BE(offset, noAssert) {
  offset = offset >>> 0;
  if (!noAssert) checkOffset(offset, 4, this.length);
  return this[offset] * 16777216 + (this[offset + 1] << 16 | this[offset + 2] << 8 | this[offset + 3]);
};
Buffer2.prototype.readBigUInt64LE = function readBigUInt64LE(offset) {
  offset = offset >>> 0;
  validateNumber(offset, "offset");
  const first = this[offset];
  const last = this[offset + 7];
  if (first === void 0 || last === void 0) {
    boundsError(offset, this.length - 8);
  }
  const lo = first + this[++offset] * 2 ** 8 + this[++offset] * 2 ** 16 + this[++offset] * 2 ** 24;
  const hi = this[++offset] + this[++offset] * 2 ** 8 + this[++offset] * 2 ** 16 + last * 2 ** 24;
  return BigInt(lo) + (BigInt(hi) << BigInt(32));
};
Buffer2.prototype.readBigUInt64BE = function readBigUInt64BE(offset) {
  offset = offset >>> 0;
  validateNumber(offset, "offset");
  const first = this[offset];
  const last = this[offset + 7];
  if (first === void 0 || last === void 0) {
    boundsError(offset, this.length - 8);
  }
  const hi = first * 2 ** 24 + this[++offset] * 2 ** 16 + this[++offset] * 2 ** 8 + this[++offset];
  const lo = this[++offset] * 2 ** 24 + this[++offset] * 2 ** 16 + this[++offset] * 2 ** 8 + last;
  return (BigInt(hi) << BigInt(32)) + BigInt(lo);
};
Buffer2.prototype.readIntLE = function readIntLE(offset, byteLength2, noAssert) {
  offset = offset >>> 0;
  byteLength2 = byteLength2 >>> 0;
  if (!noAssert) checkOffset(offset, byteLength2, this.length);
  let val = this[offset];
  let mul = 1;
  let i = 0;
  while (++i < byteLength2 && (mul *= 256)) {
    val += this[offset + i] * mul;
  }
  mul *= 128;
  if (val >= mul) val -= Math.pow(2, 8 * byteLength2);
  return val;
};
Buffer2.prototype.readIntBE = function readIntBE(offset, byteLength2, noAssert) {
  offset = offset >>> 0;
  byteLength2 = byteLength2 >>> 0;
  if (!noAssert) checkOffset(offset, byteLength2, this.length);
  let i = byteLength2;
  let mul = 1;
  let val = this[offset + --i];
  while (i > 0 && (mul *= 256)) {
    val += this[offset + --i] * mul;
  }
  mul *= 128;
  if (val >= mul) val -= Math.pow(2, 8 * byteLength2);
  return val;
};
Buffer2.prototype.readInt8 = function readInt8(offset, noAssert) {
  offset = offset >>> 0;
  if (!noAssert) checkOffset(offset, 1, this.length);
  if (!(this[offset] & 128)) return this[offset];
  return (255 - this[offset] + 1) * -1;
};
Buffer2.prototype.readInt16LE = function readInt16LE(offset, noAssert) {
  offset = offset >>> 0;
  if (!noAssert) checkOffset(offset, 2, this.length);
  const val = this[offset] | this[offset + 1] << 8;
  return val & 32768 ? val | 4294901760 : val;
};
Buffer2.prototype.readInt16BE = function readInt16BE(offset, noAssert) {
  offset = offset >>> 0;
  if (!noAssert) checkOffset(offset, 2, this.length);
  const val = this[offset + 1] | this[offset] << 8;
  return val & 32768 ? val | 4294901760 : val;
};
Buffer2.prototype.readInt32LE = function readInt32LE(offset, noAssert) {
  offset = offset >>> 0;
  if (!noAssert) checkOffset(offset, 4, this.length);
  return this[offset] | this[offset + 1] << 8 | this[offset + 2] << 16 | this[offset + 3] << 24;
};
Buffer2.prototype.readInt32BE = function readInt32BE(offset, noAssert) {
  offset = offset >>> 0;
  if (!noAssert) checkOffset(offset, 4, this.length);
  return this[offset] << 24 | this[offset + 1] << 16 | this[offset + 2] << 8 | this[offset + 3];
};
Buffer2.prototype.readBigInt64LE = function readBigInt64LE(offset) {
  offset = offset >>> 0;
  validateNumber(offset, "offset");
  const first = this[offset];
  const last = this[offset + 7];
  if (first === void 0 || last === void 0) {
    boundsError(offset, this.length - 8);
  }
  const val = this[offset + 4] + this[offset + 5] * 2 ** 8 + this[offset + 6] * 2 ** 16 + (last << 24);
  return (BigInt(val) << BigInt(32)) + BigInt(first + this[++offset] * 2 ** 8 + this[++offset] * 2 ** 16 + this[++offset] * 2 ** 24);
};
Buffer2.prototype.readBigInt64BE = function readBigInt64BE(offset) {
  offset = offset >>> 0;
  validateNumber(offset, "offset");
  const first = this[offset];
  const last = this[offset + 7];
  if (first === void 0 || last === void 0) {
    boundsError(offset, this.length - 8);
  }
  const val = (first << 24) + // Overflow
  this[++offset] * 2 ** 16 + this[++offset] * 2 ** 8 + this[++offset];
  return (BigInt(val) << BigInt(32)) + BigInt(this[++offset] * 2 ** 24 + this[++offset] * 2 ** 16 + this[++offset] * 2 ** 8 + last);
};
Buffer2.prototype.readFloatLE = function readFloatLE(offset, noAssert) {
  offset = offset >>> 0;
  if (!noAssert) checkOffset(offset, 4, this.length);
  return read(this, offset, true, 23, 4);
};
Buffer2.prototype.readFloatBE = function readFloatBE(offset, noAssert) {
  offset = offset >>> 0;
  if (!noAssert) checkOffset(offset, 4, this.length);
  return read(this, offset, false, 23, 4);
};
Buffer2.prototype.readDoubleLE = function readDoubleLE(offset, noAssert) {
  offset = offset >>> 0;
  if (!noAssert) checkOffset(offset, 8, this.length);
  return read(this, offset, true, 52, 8);
};
Buffer2.prototype.readDoubleBE = function readDoubleBE(offset, noAssert) {
  offset = offset >>> 0;
  if (!noAssert) checkOffset(offset, 8, this.length);
  return read(this, offset, false, 52, 8);
};
function checkInt(buf, value, offset, ext, max, min) {
  if (!Buffer2.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance');
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds');
  if (offset + ext > buf.length) throw new RangeError("Index out of range");
}
Buffer2.prototype.writeUintLE = Buffer2.prototype.writeUIntLE = function writeUIntLE(value, offset, byteLength2, noAssert) {
  value = +value;
  offset = offset >>> 0;
  byteLength2 = byteLength2 >>> 0;
  if (!noAssert) {
    const maxBytes = Math.pow(2, 8 * byteLength2) - 1;
    checkInt(this, value, offset, byteLength2, maxBytes, 0);
  }
  let mul = 1;
  let i = 0;
  this[offset] = value & 255;
  while (++i < byteLength2 && (mul *= 256)) {
    this[offset + i] = value / mul & 255;
  }
  return offset + byteLength2;
};
Buffer2.prototype.writeUintBE = Buffer2.prototype.writeUIntBE = function writeUIntBE(value, offset, byteLength2, noAssert) {
  value = +value;
  offset = offset >>> 0;
  byteLength2 = byteLength2 >>> 0;
  if (!noAssert) {
    const maxBytes = Math.pow(2, 8 * byteLength2) - 1;
    checkInt(this, value, offset, byteLength2, maxBytes, 0);
  }
  let i = byteLength2 - 1;
  let mul = 1;
  this[offset + i] = value & 255;
  while (--i >= 0 && (mul *= 256)) {
    this[offset + i] = value / mul & 255;
  }
  return offset + byteLength2;
};
Buffer2.prototype.writeUint8 = Buffer2.prototype.writeUInt8 = function writeUInt8(value, offset, noAssert) {
  value = +value;
  offset = offset >>> 0;
  if (!noAssert) checkInt(this, value, offset, 1, 255, 0);
  this[offset] = value & 255;
  return offset + 1;
};
Buffer2.prototype.writeUint16LE = Buffer2.prototype.writeUInt16LE = function writeUInt16LE(value, offset, noAssert) {
  value = +value;
  offset = offset >>> 0;
  if (!noAssert) checkInt(this, value, offset, 2, 65535, 0);
  this[offset] = value & 255;
  this[offset + 1] = value >>> 8;
  return offset + 2;
};
Buffer2.prototype.writeUint16BE = Buffer2.prototype.writeUInt16BE = function writeUInt16BE(value, offset, noAssert) {
  value = +value;
  offset = offset >>> 0;
  if (!noAssert) checkInt(this, value, offset, 2, 65535, 0);
  this[offset] = value >>> 8;
  this[offset + 1] = value & 255;
  return offset + 2;
};
Buffer2.prototype.writeUint32LE = Buffer2.prototype.writeUInt32LE = function writeUInt32LE(value, offset, noAssert) {
  value = +value;
  offset = offset >>> 0;
  if (!noAssert) checkInt(this, value, offset, 4, 4294967295, 0);
  this[offset + 3] = value >>> 24;
  this[offset + 2] = value >>> 16;
  this[offset + 1] = value >>> 8;
  this[offset] = value & 255;
  return offset + 4;
};
Buffer2.prototype.writeUint32BE = Buffer2.prototype.writeUInt32BE = function writeUInt32BE(value, offset, noAssert) {
  value = +value;
  offset = offset >>> 0;
  if (!noAssert) checkInt(this, value, offset, 4, 4294967295, 0);
  this[offset] = value >>> 24;
  this[offset + 1] = value >>> 16;
  this[offset + 2] = value >>> 8;
  this[offset + 3] = value & 255;
  return offset + 4;
};
function wrtBigUInt64LE(buf, value, offset, min, max) {
  checkIntBI(value, min, max, buf, offset, 7);
  let lo = Number(value & BigInt(4294967295));
  buf[offset++] = lo;
  lo = lo >> 8;
  buf[offset++] = lo;
  lo = lo >> 8;
  buf[offset++] = lo;
  lo = lo >> 8;
  buf[offset++] = lo;
  let hi = Number(value >> BigInt(32) & BigInt(4294967295));
  buf[offset++] = hi;
  hi = hi >> 8;
  buf[offset++] = hi;
  hi = hi >> 8;
  buf[offset++] = hi;
  hi = hi >> 8;
  buf[offset++] = hi;
  return offset;
}
function wrtBigUInt64BE(buf, value, offset, min, max) {
  checkIntBI(value, min, max, buf, offset, 7);
  let lo = Number(value & BigInt(4294967295));
  buf[offset + 7] = lo;
  lo = lo >> 8;
  buf[offset + 6] = lo;
  lo = lo >> 8;
  buf[offset + 5] = lo;
  lo = lo >> 8;
  buf[offset + 4] = lo;
  let hi = Number(value >> BigInt(32) & BigInt(4294967295));
  buf[offset + 3] = hi;
  hi = hi >> 8;
  buf[offset + 2] = hi;
  hi = hi >> 8;
  buf[offset + 1] = hi;
  hi = hi >> 8;
  buf[offset] = hi;
  return offset + 8;
}
Buffer2.prototype.writeBigUInt64LE = function writeBigUInt64LE(value, offset = 0) {
  return wrtBigUInt64LE(this, value, offset, BigInt(0), BigInt("0xffffffffffffffff"));
};
Buffer2.prototype.writeBigUInt64BE = function writeBigUInt64BE(value, offset = 0) {
  return wrtBigUInt64BE(this, value, offset, BigInt(0), BigInt("0xffffffffffffffff"));
};
Buffer2.prototype.writeIntLE = function writeIntLE(value, offset, byteLength2, noAssert) {
  value = +value;
  offset = offset >>> 0;
  if (!noAssert) {
    const limit = Math.pow(2, 8 * byteLength2 - 1);
    checkInt(this, value, offset, byteLength2, limit - 1, -limit);
  }
  let i = 0;
  let mul = 1;
  let sub = 0;
  this[offset] = value & 255;
  while (++i < byteLength2 && (mul *= 256)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1;
    }
    this[offset + i] = (value / mul >> 0) - sub & 255;
  }
  return offset + byteLength2;
};
Buffer2.prototype.writeIntBE = function writeIntBE(value, offset, byteLength2, noAssert) {
  value = +value;
  offset = offset >>> 0;
  if (!noAssert) {
    const limit = Math.pow(2, 8 * byteLength2 - 1);
    checkInt(this, value, offset, byteLength2, limit - 1, -limit);
  }
  let i = byteLength2 - 1;
  let mul = 1;
  let sub = 0;
  this[offset + i] = value & 255;
  while (--i >= 0 && (mul *= 256)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1;
    }
    this[offset + i] = (value / mul >> 0) - sub & 255;
  }
  return offset + byteLength2;
};
Buffer2.prototype.writeInt8 = function writeInt8(value, offset, noAssert) {
  value = +value;
  offset = offset >>> 0;
  if (!noAssert) checkInt(this, value, offset, 1, 127, -128);
  if (value < 0) value = 255 + value + 1;
  this[offset] = value & 255;
  return offset + 1;
};
Buffer2.prototype.writeInt16LE = function writeInt16LE(value, offset, noAssert) {
  value = +value;
  offset = offset >>> 0;
  if (!noAssert) checkInt(this, value, offset, 2, 32767, -32768);
  this[offset] = value & 255;
  this[offset + 1] = value >>> 8;
  return offset + 2;
};
Buffer2.prototype.writeInt16BE = function writeInt16BE(value, offset, noAssert) {
  value = +value;
  offset = offset >>> 0;
  if (!noAssert) checkInt(this, value, offset, 2, 32767, -32768);
  this[offset] = value >>> 8;
  this[offset + 1] = value & 255;
  return offset + 2;
};
Buffer2.prototype.writeInt32LE = function writeInt32LE(value, offset, noAssert) {
  value = +value;
  offset = offset >>> 0;
  if (!noAssert) checkInt(this, value, offset, 4, 2147483647, -2147483648);
  this[offset] = value & 255;
  this[offset + 1] = value >>> 8;
  this[offset + 2] = value >>> 16;
  this[offset + 3] = value >>> 24;
  return offset + 4;
};
Buffer2.prototype.writeInt32BE = function writeInt32BE(value, offset, noAssert) {
  value = +value;
  offset = offset >>> 0;
  if (!noAssert) checkInt(this, value, offset, 4, 2147483647, -2147483648);
  if (value < 0) value = 4294967295 + value + 1;
  this[offset] = value >>> 24;
  this[offset + 1] = value >>> 16;
  this[offset + 2] = value >>> 8;
  this[offset + 3] = value & 255;
  return offset + 4;
};
Buffer2.prototype.writeBigInt64LE = function writeBigInt64LE(value, offset = 0) {
  return wrtBigUInt64LE(this, value, offset, -BigInt("0x8000000000000000"), BigInt("0x7fffffffffffffff"));
};
Buffer2.prototype.writeBigInt64BE = function writeBigInt64BE(value, offset = 0) {
  return wrtBigUInt64BE(this, value, offset, -BigInt("0x8000000000000000"), BigInt("0x7fffffffffffffff"));
};
function checkIEEE754(buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError("Index out of range");
  if (offset < 0) throw new RangeError("Index out of range");
}
function writeFloat(buf, value, offset, littleEndian, noAssert) {
  value = +value;
  offset = offset >>> 0;
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 34028234663852886e22, -34028234663852886e22);
  }
  write(buf, value, offset, littleEndian, 23, 4);
  return offset + 4;
}
Buffer2.prototype.writeFloatLE = function writeFloatLE(value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert);
};
Buffer2.prototype.writeFloatBE = function writeFloatBE(value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert);
};
function writeDouble(buf, value, offset, littleEndian, noAssert) {
  value = +value;
  offset = offset >>> 0;
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 17976931348623157e292, -17976931348623157e292);
  }
  write(buf, value, offset, littleEndian, 52, 8);
  return offset + 8;
}
Buffer2.prototype.writeDoubleLE = function writeDoubleLE(value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert);
};
Buffer2.prototype.writeDoubleBE = function writeDoubleBE(value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert);
};
Buffer2.prototype.copy = function copy(target, targetStart, start, end) {
  if (!Buffer2.isBuffer(target)) throw new TypeError("argument should be a Buffer");
  if (!start) start = 0;
  if (!end && end !== 0) end = this.length;
  if (targetStart >= target.length) targetStart = target.length;
  if (!targetStart) targetStart = 0;
  if (end > 0 && end < start) end = start;
  if (end === start) return 0;
  if (target.length === 0 || this.length === 0) return 0;
  if (targetStart < 0) {
    throw new RangeError("targetStart out of bounds");
  }
  if (start < 0 || start >= this.length) throw new RangeError("Index out of range");
  if (end < 0) throw new RangeError("sourceEnd out of bounds");
  if (end > this.length) end = this.length;
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start;
  }
  const len = end - start;
  if (this === target) {
    this.copyWithin(targetStart, start, end);
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, end),
      targetStart
    );
  }
  return len;
};
Buffer2.prototype.fill = function fill(val, start, end, encoding) {
  if (typeof val === "string") {
    if (typeof start === "string") {
      encoding = start;
      start = 0;
      end = this.length;
    } else if (typeof end === "string") {
      encoding = end;
      end = this.length;
    }
    if (encoding !== void 0 && typeof encoding !== "string") {
      throw new TypeError("encoding must be a string");
    }
    if (typeof encoding === "string" && !Buffer2.isEncoding(encoding)) {
      throw new TypeError("Unknown encoding: " + encoding);
    }
    if (val.length === 1) {
      const code3 = val.charCodeAt(0);
      if (encoding === "utf8" && code3 < 128 || encoding === "latin1") {
        val = code3;
      }
    }
  } else if (typeof val === "number") {
    val = val & 255;
  } else if (typeof val === "boolean") {
    val = Number(val);
  }
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError("Out of range index");
  }
  if (end <= start) {
    return this;
  }
  start = start >>> 0;
  end = end === void 0 ? this.length : end >>> 0;
  if (!val) val = 0;
  let i;
  if (typeof val === "number") {
    for (i = start; i < end; ++i) {
      this[i] = val;
    }
  } else {
    const bytes = Buffer2.isBuffer(val) ? val : Buffer2.from(val, encoding);
    const len = bytes.length;
    if (len === 0) {
      throw new TypeError('The value "' + val + '" is invalid for argument "value"');
    }
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len];
    }
  }
  return this;
};
var errors = {};
function E(sym, getMessage, Base) {
  errors[sym] = class NodeError extends Base {
    constructor() {
      super();
      Object.defineProperty(this, "message", {
        value: getMessage.apply(this, arguments),
        writable: true,
        configurable: true
      });
      this.name = `${this.name} [${sym}]`;
      this.stack;
      delete this.name;
    }
    get code() {
      return sym;
    }
    set code(value) {
      Object.defineProperty(this, "code", {
        configurable: true,
        enumerable: true,
        value,
        writable: true
      });
    }
    toString() {
      return `${this.name} [${sym}]: ${this.message}`;
    }
  };
}
E(
  "ERR_BUFFER_OUT_OF_BOUNDS",
  function(name) {
    if (name) {
      return `${name} is outside of buffer bounds`;
    }
    return "Attempt to access memory outside buffer bounds";
  },
  RangeError
);
E(
  "ERR_INVALID_ARG_TYPE",
  function(name, actual) {
    return `The "${name}" argument must be of type number. Received type ${typeof actual}`;
  },
  TypeError
);
E(
  "ERR_OUT_OF_RANGE",
  function(str, range, input) {
    let msg = `The value of "${str}" is out of range.`;
    let received = input;
    if (Number.isInteger(input) && Math.abs(input) > 2 ** 32) {
      received = addNumericalSeparator(String(input));
    } else if (typeof input === "bigint") {
      received = String(input);
      if (input > BigInt(2) ** BigInt(32) || input < -(BigInt(2) ** BigInt(32))) {
        received = addNumericalSeparator(received);
      }
      received += "n";
    }
    msg += ` It must be ${range}. Received ${received}`;
    return msg;
  },
  RangeError
);
function addNumericalSeparator(val) {
  let res = "";
  let i = val.length;
  const start = val[0] === "-" ? 1 : 0;
  for (; i >= start + 4; i -= 3) {
    res = `_${val.slice(i - 3, i)}${res}`;
  }
  return `${val.slice(0, i)}${res}`;
}
function checkBounds(buf, offset, byteLength2) {
  validateNumber(offset, "offset");
  if (buf[offset] === void 0 || buf[offset + byteLength2] === void 0) {
    boundsError(offset, buf.length - (byteLength2 + 1));
  }
}
function checkIntBI(value, min, max, buf, offset, byteLength2) {
  if (value > max || value < min) {
    const n = typeof min === "bigint" ? "n" : "";
    let range;
    if (byteLength2 > 3) {
      if (min === 0 || min === BigInt(0)) {
        range = `>= 0${n} and < 2${n} ** ${(byteLength2 + 1) * 8}${n}`;
      } else {
        range = `>= -(2${n} ** ${(byteLength2 + 1) * 8 - 1}${n}) and < 2 ** ${(byteLength2 + 1) * 8 - 1}${n}`;
      }
    } else {
      range = `>= ${min}${n} and <= ${max}${n}`;
    }
    throw new errors.ERR_OUT_OF_RANGE("value", range, value);
  }
  checkBounds(buf, offset, byteLength2);
}
function validateNumber(value, name) {
  if (typeof value !== "number") {
    throw new errors.ERR_INVALID_ARG_TYPE(name, "number", value);
  }
}
function boundsError(value, length, type) {
  if (Math.floor(value) !== value) {
    validateNumber(value, type);
    throw new errors.ERR_OUT_OF_RANGE(type || "offset", "an integer", value);
  }
  if (length < 0) {
    throw new errors.ERR_BUFFER_OUT_OF_BOUNDS();
  }
  throw new errors.ERR_OUT_OF_RANGE(
    type || "offset",
    `>= ${type ? 1 : 0} and <= ${length}`,
    value
  );
}
var INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g;
function base64clean(str) {
  str = str.split("=")[0];
  str = str.trim().replace(INVALID_BASE64_RE, "");
  if (str.length < 2) return "";
  while (str.length % 4 !== 0) {
    str = str + "=";
  }
  return str;
}
function utf8ToBytes(string, units) {
  units = units || Infinity;
  let codePoint;
  const length = string.length;
  let leadSurrogate = null;
  const bytes = [];
  for (let i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i);
    if (codePoint > 55295 && codePoint < 57344) {
      if (!leadSurrogate) {
        if (codePoint > 56319) {
          if ((units -= 3) > -1) bytes.push(239, 191, 189);
          continue;
        } else if (i + 1 === length) {
          if ((units -= 3) > -1) bytes.push(239, 191, 189);
          continue;
        }
        leadSurrogate = codePoint;
        continue;
      }
      if (codePoint < 56320) {
        if ((units -= 3) > -1) bytes.push(239, 191, 189);
        leadSurrogate = codePoint;
        continue;
      }
      codePoint = (leadSurrogate - 55296 << 10 | codePoint - 56320) + 65536;
    } else if (leadSurrogate) {
      if ((units -= 3) > -1) bytes.push(239, 191, 189);
    }
    leadSurrogate = null;
    if (codePoint < 128) {
      if ((units -= 1) < 0) break;
      bytes.push(codePoint);
    } else if (codePoint < 2048) {
      if ((units -= 2) < 0) break;
      bytes.push(
        codePoint >> 6 | 192,
        codePoint & 63 | 128
      );
    } else if (codePoint < 65536) {
      if ((units -= 3) < 0) break;
      bytes.push(
        codePoint >> 12 | 224,
        codePoint >> 6 & 63 | 128,
        codePoint & 63 | 128
      );
    } else if (codePoint < 1114112) {
      if ((units -= 4) < 0) break;
      bytes.push(
        codePoint >> 18 | 240,
        codePoint >> 12 & 63 | 128,
        codePoint >> 6 & 63 | 128,
        codePoint & 63 | 128
      );
    } else {
      throw new Error("Invalid code point");
    }
  }
  return bytes;
}
function asciiToBytes(str) {
  const byteArray = [];
  for (let i = 0; i < str.length; ++i) {
    byteArray.push(str.charCodeAt(i) & 255);
  }
  return byteArray;
}
function utf16leToBytes(str, units) {
  let c, hi, lo;
  const byteArray = [];
  for (let i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break;
    c = str.charCodeAt(i);
    hi = c >> 8;
    lo = c % 256;
    byteArray.push(lo);
    byteArray.push(hi);
  }
  return byteArray;
}
function base64ToBytes(str) {
  return toByteArray(base64clean(str));
}
function blitBuffer(src, dst, offset, length) {
  let i;
  for (i = 0; i < length; ++i) {
    if (i + offset >= dst.length || i >= src.length) break;
    dst[i + offset] = src[i];
  }
  return i;
}
var hexSliceLookupTable = function() {
  const alphabet = "0123456789abcdef";
  const table = new Array(256);
  for (let i = 0; i < 16; ++i) {
    const i16 = i * 16;
    for (let j = 0; j < 16; ++j) {
      table[i16 + j] = alphabet[i] + alphabet[j];
    }
  }
  return table;
}();

// node_modules/frida-java-bridge/lib/android.js
var android_exports = {};
__export(android_exports, {
  ArtMethod: () => ArtMethod,
  ArtStackVisitor: () => ArtStackVisitor,
  DVM_JNI_ENV_OFFSET_SELF: () => DVM_JNI_ENV_OFFSET_SELF,
  HandleVector: () => HandleVector,
  VariableSizedHandleScope: () => VariableSizedHandleScope,
  backtrace: () => backtrace,
  deoptimizeBootImage: () => deoptimizeBootImage,
  deoptimizeEverything: () => deoptimizeEverything,
  deoptimizeMethod: () => deoptimizeMethod,
  ensureClassInitialized: () => ensureClassInitialized,
  getAndroidApiLevel: () => getAndroidApiLevel,
  getAndroidVersion: () => getAndroidVersion,
  getApi: () => getApi,
  getArtClassSpec: () => getArtClassSpec,
  getArtFieldSpec: () => getArtFieldSpec,
  getArtMethodSpec: () => getArtMethodSpec,
  getArtThreadFromEnv: () => getArtThreadFromEnv,
  getArtThreadSpec: () => getArtThreadSpec,
  makeArtClassLoaderVisitor: () => makeArtClassLoaderVisitor,
  makeArtClassVisitor: () => makeArtClassVisitor,
  makeMethodMangler: () => makeMethodMangler,
  makeObjectVisitorPredicate: () => makeObjectVisitorPredicate,
  revertGlobalPatches: () => revertGlobalPatches,
  translateMethod: () => translateMethod,
  withAllArtThreadsSuspended: () => withAllArtThreadsSuspended,
  withRunnableArtThread: () => withRunnableArtThread
});

// node_modules/frida-java-bridge/lib/alloc.js
var {
  pageSize,
  pointerSize
} = Process;
var CodeAllocator = class {
  constructor(sliceSize) {
    this.sliceSize = sliceSize;
    this.slicesPerPage = pageSize / sliceSize;
    this.pages = [];
    this.free = [];
  }
  allocateSlice(spec, alignment) {
    const anyLocation = spec.near === void 0;
    const anyAlignment = alignment === 1;
    if (anyLocation && anyAlignment) {
      const slice2 = this.free.pop();
      if (slice2 !== void 0) {
        return slice2;
      }
    } else if (alignment < pageSize) {
      const { free } = this;
      const n = free.length;
      const alignMask = anyAlignment ? null : ptr(alignment - 1);
      for (let i = 0; i !== n; i++) {
        const slice2 = free[i];
        const satisfiesLocation = anyLocation || this._isSliceNear(slice2, spec);
        const satisfiesAlignment = anyAlignment || slice2.and(alignMask).isNull();
        if (satisfiesLocation && satisfiesAlignment) {
          return free.splice(i, 1)[0];
        }
      }
    }
    return this._allocatePage(spec);
  }
  _allocatePage(spec) {
    const page = Memory.alloc(pageSize, spec);
    const { sliceSize, slicesPerPage } = this;
    for (let i = 1; i !== slicesPerPage; i++) {
      const slice2 = page.add(i * sliceSize);
      this.free.push(slice2);
    }
    this.pages.push(page);
    return page;
  }
  _isSliceNear(slice2, spec) {
    const sliceEnd = slice2.add(this.sliceSize);
    const { near, maxDistance } = spec;
    const startDistance = abs(near.sub(slice2));
    const endDistance = abs(near.sub(sliceEnd));
    return startDistance.compare(maxDistance) <= 0 && endDistance.compare(maxDistance) <= 0;
  }
  freeSlice(slice2) {
    this.free.push(slice2);
  }
};
function abs(nptr) {
  const shmt = pointerSize === 4 ? 31 : 63;
  const mask = ptr(1).shl(shmt).not();
  return nptr.and(mask);
}
function makeAllocator(sliceSize) {
  return new CodeAllocator(sliceSize);
}

// node_modules/frida-java-bridge/lib/result.js
var JNI_OK = 0;
function checkJniResult(name, result) {
  if (result !== JNI_OK) {
    throw new Error(name + " failed: " + result);
  }
}

// node_modules/frida-java-bridge/lib/jvmti.js
var jvmtiVersion = {
  v1_0: 805371904,
  v1_2: 805372416
};
var jvmtiCapabilities = {
  canTagObjects: 1
};
var { pointerSize: pointerSize2 } = Process;
var nativeFunctionOptions = {
  exceptions: "propagate"
};
function EnvJvmti(handle, vm3) {
  this.handle = handle;
  this.vm = vm3;
  this.vtable = handle.readPointer();
}
EnvJvmti.prototype.deallocate = proxy(47, "int32", ["pointer", "pointer"], function(impl, mem) {
  return impl(this.handle, mem);
});
EnvJvmti.prototype.getLoadedClasses = proxy(78, "int32", ["pointer", "pointer", "pointer"], function(impl, classCountPtr, classesPtr) {
  const result = impl(this.handle, classCountPtr, classesPtr);
  checkJniResult("EnvJvmti::getLoadedClasses", result);
});
EnvJvmti.prototype.iterateOverInstancesOfClass = proxy(112, "int32", ["pointer", "pointer", "int", "pointer", "pointer"], function(impl, klass, objectFilter, heapObjectCallback, userData) {
  const result = impl(this.handle, klass, objectFilter, heapObjectCallback, userData);
  checkJniResult("EnvJvmti::iterateOverInstancesOfClass", result);
});
EnvJvmti.prototype.getObjectsWithTags = proxy(114, "int32", ["pointer", "int", "pointer", "pointer", "pointer", "pointer"], function(impl, tagCount, tags, countPtr, objectResultPtr, tagResultPtr) {
  const result = impl(this.handle, tagCount, tags, countPtr, objectResultPtr, tagResultPtr);
  checkJniResult("EnvJvmti::getObjectsWithTags", result);
});
EnvJvmti.prototype.addCapabilities = proxy(142, "int32", ["pointer", "pointer"], function(impl, capabilitiesPtr) {
  return impl(this.handle, capabilitiesPtr);
});
function proxy(offset, retType, argTypes, wrapper) {
  let impl = null;
  return function() {
    if (impl === null) {
      impl = new NativeFunction(this.vtable.add((offset - 1) * pointerSize2).readPointer(), retType, argTypes, nativeFunctionOptions);
    }
    let args = [impl];
    args = args.concat.apply(args, arguments);
    return wrapper.apply(this, args);
  };
}

// node_modules/frida-java-bridge/lib/machine-code.js
function parseInstructionsAt(address, tryParse, { limit }) {
  let cursor = address;
  let prevInsn = null;
  for (let i = 0; i !== limit; i++) {
    const insn = Instruction.parse(cursor);
    const value = tryParse(insn, prevInsn);
    if (value !== null) {
      return value;
    }
    cursor = insn.next;
    prevInsn = insn;
  }
  return null;
}

// node_modules/frida-java-bridge/lib/memoize.js
function memoize(compute) {
  let value = null;
  let computed = false;
  return function(...args) {
    if (!computed) {
      value = compute(...args);
      computed = true;
    }
    return value;
  };
}

// node_modules/frida-java-bridge/lib/env.js
function Env(handle, vm3) {
  this.handle = handle;
  this.vm = vm3;
}
var pointerSize3 = Process.pointerSize;
var JNI_ABORT = 2;
var CALL_CONSTRUCTOR_METHOD_OFFSET = 28;
var CALL_OBJECT_METHOD_OFFSET = 34;
var CALL_BOOLEAN_METHOD_OFFSET = 37;
var CALL_BYTE_METHOD_OFFSET = 40;
var CALL_CHAR_METHOD_OFFSET = 43;
var CALL_SHORT_METHOD_OFFSET = 46;
var CALL_INT_METHOD_OFFSET = 49;
var CALL_LONG_METHOD_OFFSET = 52;
var CALL_FLOAT_METHOD_OFFSET = 55;
var CALL_DOUBLE_METHOD_OFFSET = 58;
var CALL_VOID_METHOD_OFFSET = 61;
var CALL_NONVIRTUAL_OBJECT_METHOD_OFFSET = 64;
var CALL_NONVIRTUAL_BOOLEAN_METHOD_OFFSET = 67;
var CALL_NONVIRTUAL_BYTE_METHOD_OFFSET = 70;
var CALL_NONVIRTUAL_CHAR_METHOD_OFFSET = 73;
var CALL_NONVIRTUAL_SHORT_METHOD_OFFSET = 76;
var CALL_NONVIRTUAL_INT_METHOD_OFFSET = 79;
var CALL_NONVIRTUAL_LONG_METHOD_OFFSET = 82;
var CALL_NONVIRTUAL_FLOAT_METHOD_OFFSET = 85;
var CALL_NONVIRTUAL_DOUBLE_METHOD_OFFSET = 88;
var CALL_NONVIRTUAL_VOID_METHOD_OFFSET = 91;
var CALL_STATIC_OBJECT_METHOD_OFFSET = 114;
var CALL_STATIC_BOOLEAN_METHOD_OFFSET = 117;
var CALL_STATIC_BYTE_METHOD_OFFSET = 120;
var CALL_STATIC_CHAR_METHOD_OFFSET = 123;
var CALL_STATIC_SHORT_METHOD_OFFSET = 126;
var CALL_STATIC_INT_METHOD_OFFSET = 129;
var CALL_STATIC_LONG_METHOD_OFFSET = 132;
var CALL_STATIC_FLOAT_METHOD_OFFSET = 135;
var CALL_STATIC_DOUBLE_METHOD_OFFSET = 138;
var CALL_STATIC_VOID_METHOD_OFFSET = 141;
var GET_OBJECT_FIELD_OFFSET = 95;
var GET_BOOLEAN_FIELD_OFFSET = 96;
var GET_BYTE_FIELD_OFFSET = 97;
var GET_CHAR_FIELD_OFFSET = 98;
var GET_SHORT_FIELD_OFFSET = 99;
var GET_INT_FIELD_OFFSET = 100;
var GET_LONG_FIELD_OFFSET = 101;
var GET_FLOAT_FIELD_OFFSET = 102;
var GET_DOUBLE_FIELD_OFFSET = 103;
var SET_OBJECT_FIELD_OFFSET = 104;
var SET_BOOLEAN_FIELD_OFFSET = 105;
var SET_BYTE_FIELD_OFFSET = 106;
var SET_CHAR_FIELD_OFFSET = 107;
var SET_SHORT_FIELD_OFFSET = 108;
var SET_INT_FIELD_OFFSET = 109;
var SET_LONG_FIELD_OFFSET = 110;
var SET_FLOAT_FIELD_OFFSET = 111;
var SET_DOUBLE_FIELD_OFFSET = 112;
var GET_STATIC_OBJECT_FIELD_OFFSET = 145;
var GET_STATIC_BOOLEAN_FIELD_OFFSET = 146;
var GET_STATIC_BYTE_FIELD_OFFSET = 147;
var GET_STATIC_CHAR_FIELD_OFFSET = 148;
var GET_STATIC_SHORT_FIELD_OFFSET = 149;
var GET_STATIC_INT_FIELD_OFFSET = 150;
var GET_STATIC_LONG_FIELD_OFFSET = 151;
var GET_STATIC_FLOAT_FIELD_OFFSET = 152;
var GET_STATIC_DOUBLE_FIELD_OFFSET = 153;
var SET_STATIC_OBJECT_FIELD_OFFSET = 154;
var SET_STATIC_BOOLEAN_FIELD_OFFSET = 155;
var SET_STATIC_BYTE_FIELD_OFFSET = 156;
var SET_STATIC_CHAR_FIELD_OFFSET = 157;
var SET_STATIC_SHORT_FIELD_OFFSET = 158;
var SET_STATIC_INT_FIELD_OFFSET = 159;
var SET_STATIC_LONG_FIELD_OFFSET = 160;
var SET_STATIC_FLOAT_FIELD_OFFSET = 161;
var SET_STATIC_DOUBLE_FIELD_OFFSET = 162;
var callMethodOffset = {
  pointer: CALL_OBJECT_METHOD_OFFSET,
  uint8: CALL_BOOLEAN_METHOD_OFFSET,
  int8: CALL_BYTE_METHOD_OFFSET,
  uint16: CALL_CHAR_METHOD_OFFSET,
  int16: CALL_SHORT_METHOD_OFFSET,
  int32: CALL_INT_METHOD_OFFSET,
  int64: CALL_LONG_METHOD_OFFSET,
  float: CALL_FLOAT_METHOD_OFFSET,
  double: CALL_DOUBLE_METHOD_OFFSET,
  void: CALL_VOID_METHOD_OFFSET
};
var callNonvirtualMethodOffset = {
  pointer: CALL_NONVIRTUAL_OBJECT_METHOD_OFFSET,
  uint8: CALL_NONVIRTUAL_BOOLEAN_METHOD_OFFSET,
  int8: CALL_NONVIRTUAL_BYTE_METHOD_OFFSET,
  uint16: CALL_NONVIRTUAL_CHAR_METHOD_OFFSET,
  int16: CALL_NONVIRTUAL_SHORT_METHOD_OFFSET,
  int32: CALL_NONVIRTUAL_INT_METHOD_OFFSET,
  int64: CALL_NONVIRTUAL_LONG_METHOD_OFFSET,
  float: CALL_NONVIRTUAL_FLOAT_METHOD_OFFSET,
  double: CALL_NONVIRTUAL_DOUBLE_METHOD_OFFSET,
  void: CALL_NONVIRTUAL_VOID_METHOD_OFFSET
};
var callStaticMethodOffset = {
  pointer: CALL_STATIC_OBJECT_METHOD_OFFSET,
  uint8: CALL_STATIC_BOOLEAN_METHOD_OFFSET,
  int8: CALL_STATIC_BYTE_METHOD_OFFSET,
  uint16: CALL_STATIC_CHAR_METHOD_OFFSET,
  int16: CALL_STATIC_SHORT_METHOD_OFFSET,
  int32: CALL_STATIC_INT_METHOD_OFFSET,
  int64: CALL_STATIC_LONG_METHOD_OFFSET,
  float: CALL_STATIC_FLOAT_METHOD_OFFSET,
  double: CALL_STATIC_DOUBLE_METHOD_OFFSET,
  void: CALL_STATIC_VOID_METHOD_OFFSET
};
var getFieldOffset = {
  pointer: GET_OBJECT_FIELD_OFFSET,
  uint8: GET_BOOLEAN_FIELD_OFFSET,
  int8: GET_BYTE_FIELD_OFFSET,
  uint16: GET_CHAR_FIELD_OFFSET,
  int16: GET_SHORT_FIELD_OFFSET,
  int32: GET_INT_FIELD_OFFSET,
  int64: GET_LONG_FIELD_OFFSET,
  float: GET_FLOAT_FIELD_OFFSET,
  double: GET_DOUBLE_FIELD_OFFSET
};
var setFieldOffset = {
  pointer: SET_OBJECT_FIELD_OFFSET,
  uint8: SET_BOOLEAN_FIELD_OFFSET,
  int8: SET_BYTE_FIELD_OFFSET,
  uint16: SET_CHAR_FIELD_OFFSET,
  int16: SET_SHORT_FIELD_OFFSET,
  int32: SET_INT_FIELD_OFFSET,
  int64: SET_LONG_FIELD_OFFSET,
  float: SET_FLOAT_FIELD_OFFSET,
  double: SET_DOUBLE_FIELD_OFFSET
};
var getStaticFieldOffset = {
  pointer: GET_STATIC_OBJECT_FIELD_OFFSET,
  uint8: GET_STATIC_BOOLEAN_FIELD_OFFSET,
  int8: GET_STATIC_BYTE_FIELD_OFFSET,
  uint16: GET_STATIC_CHAR_FIELD_OFFSET,
  int16: GET_STATIC_SHORT_FIELD_OFFSET,
  int32: GET_STATIC_INT_FIELD_OFFSET,
  int64: GET_STATIC_LONG_FIELD_OFFSET,
  float: GET_STATIC_FLOAT_FIELD_OFFSET,
  double: GET_STATIC_DOUBLE_FIELD_OFFSET
};
var setStaticFieldOffset = {
  pointer: SET_STATIC_OBJECT_FIELD_OFFSET,
  uint8: SET_STATIC_BOOLEAN_FIELD_OFFSET,
  int8: SET_STATIC_BYTE_FIELD_OFFSET,
  uint16: SET_STATIC_CHAR_FIELD_OFFSET,
  int16: SET_STATIC_SHORT_FIELD_OFFSET,
  int32: SET_STATIC_INT_FIELD_OFFSET,
  int64: SET_STATIC_LONG_FIELD_OFFSET,
  float: SET_STATIC_FLOAT_FIELD_OFFSET,
  double: SET_STATIC_DOUBLE_FIELD_OFFSET
};
var nativeFunctionOptions2 = {
  exceptions: "propagate"
};
var cachedVtable = null;
var globalRefs = [];
Env.dispose = function(env) {
  globalRefs.forEach(env.deleteGlobalRef, env);
  globalRefs = [];
};
function register(globalRef) {
  globalRefs.push(globalRef);
  return globalRef;
}
function vtable(instance) {
  if (cachedVtable === null) {
    cachedVtable = instance.handle.readPointer();
  }
  return cachedVtable;
}
function proxy2(offset, retType, argTypes, wrapper) {
  let impl = null;
  return function() {
    if (impl === null) {
      impl = new NativeFunction(vtable(this).add(offset * pointerSize3).readPointer(), retType, argTypes, nativeFunctionOptions2);
    }
    let args = [impl];
    args = args.concat.apply(args, arguments);
    return wrapper.apply(this, args);
  };
}
Env.prototype.getVersion = proxy2(4, "int32", ["pointer"], function(impl) {
  return impl(this.handle);
});
Env.prototype.findClass = proxy2(6, "pointer", ["pointer", "pointer"], function(impl, name) {
  const result = impl(this.handle, Memory.allocUtf8String(name));
  this.throwIfExceptionPending();
  return result;
});
Env.prototype.throwIfExceptionPending = function() {
  const throwable = this.exceptionOccurred();
  if (throwable.isNull()) {
    return;
  }
  this.exceptionClear();
  const handle = this.newGlobalRef(throwable);
  this.deleteLocalRef(throwable);
  const description = this.vaMethod("pointer", [])(this.handle, handle, this.javaLangObject().toString);
  const descriptionStr = this.stringFromJni(description);
  this.deleteLocalRef(description);
  const error = new Error(descriptionStr);
  error.$h = handle;
  Script.bindWeak(error, makeErrorHandleDestructor(this.vm, handle));
  throw error;
};
function makeErrorHandleDestructor(vm3, handle) {
  return function() {
    vm3.perform((env) => {
      env.deleteGlobalRef(handle);
    });
  };
}
Env.prototype.fromReflectedMethod = proxy2(7, "pointer", ["pointer", "pointer"], function(impl, method) {
  return impl(this.handle, method);
});
Env.prototype.fromReflectedField = proxy2(8, "pointer", ["pointer", "pointer"], function(impl, method) {
  return impl(this.handle, method);
});
Env.prototype.toReflectedMethod = proxy2(9, "pointer", ["pointer", "pointer", "pointer", "uint8"], function(impl, klass, methodId, isStatic) {
  return impl(this.handle, klass, methodId, isStatic);
});
Env.prototype.getSuperclass = proxy2(10, "pointer", ["pointer", "pointer"], function(impl, klass) {
  return impl(this.handle, klass);
});
Env.prototype.isAssignableFrom = proxy2(11, "uint8", ["pointer", "pointer", "pointer"], function(impl, klass1, klass2) {
  return !!impl(this.handle, klass1, klass2);
});
Env.prototype.toReflectedField = proxy2(12, "pointer", ["pointer", "pointer", "pointer", "uint8"], function(impl, klass, fieldId, isStatic) {
  return impl(this.handle, klass, fieldId, isStatic);
});
Env.prototype.throw = proxy2(13, "int32", ["pointer", "pointer"], function(impl, obj) {
  return impl(this.handle, obj);
});
Env.prototype.exceptionOccurred = proxy2(15, "pointer", ["pointer"], function(impl) {
  return impl(this.handle);
});
Env.prototype.exceptionDescribe = proxy2(16, "void", ["pointer"], function(impl) {
  impl(this.handle);
});
Env.prototype.exceptionClear = proxy2(17, "void", ["pointer"], function(impl) {
  impl(this.handle);
});
Env.prototype.pushLocalFrame = proxy2(19, "int32", ["pointer", "int32"], function(impl, capacity) {
  return impl(this.handle, capacity);
});
Env.prototype.popLocalFrame = proxy2(20, "pointer", ["pointer", "pointer"], function(impl, result) {
  return impl(this.handle, result);
});
Env.prototype.newGlobalRef = proxy2(21, "pointer", ["pointer", "pointer"], function(impl, obj) {
  return impl(this.handle, obj);
});
Env.prototype.deleteGlobalRef = proxy2(22, "void", ["pointer", "pointer"], function(impl, globalRef) {
  impl(this.handle, globalRef);
});
Env.prototype.deleteLocalRef = proxy2(23, "void", ["pointer", "pointer"], function(impl, localRef) {
  impl(this.handle, localRef);
});
Env.prototype.isSameObject = proxy2(24, "uint8", ["pointer", "pointer", "pointer"], function(impl, ref1, ref2) {
  return !!impl(this.handle, ref1, ref2);
});
Env.prototype.newLocalRef = proxy2(25, "pointer", ["pointer", "pointer"], function(impl, obj) {
  return impl(this.handle, obj);
});
Env.prototype.allocObject = proxy2(27, "pointer", ["pointer", "pointer"], function(impl, clazz) {
  return impl(this.handle, clazz);
});
Env.prototype.getObjectClass = proxy2(31, "pointer", ["pointer", "pointer"], function(impl, obj) {
  return impl(this.handle, obj);
});
Env.prototype.isInstanceOf = proxy2(32, "uint8", ["pointer", "pointer", "pointer"], function(impl, obj, klass) {
  return !!impl(this.handle, obj, klass);
});
Env.prototype.getMethodId = proxy2(33, "pointer", ["pointer", "pointer", "pointer", "pointer"], function(impl, klass, name, sig) {
  return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
});
Env.prototype.getFieldId = proxy2(94, "pointer", ["pointer", "pointer", "pointer", "pointer"], function(impl, klass, name, sig) {
  return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
});
Env.prototype.getIntField = proxy2(100, "int32", ["pointer", "pointer", "pointer"], function(impl, obj, fieldId) {
  return impl(this.handle, obj, fieldId);
});
Env.prototype.getStaticMethodId = proxy2(113, "pointer", ["pointer", "pointer", "pointer", "pointer"], function(impl, klass, name, sig) {
  return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
});
Env.prototype.getStaticFieldId = proxy2(144, "pointer", ["pointer", "pointer", "pointer", "pointer"], function(impl, klass, name, sig) {
  return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
});
Env.prototype.getStaticIntField = proxy2(150, "int32", ["pointer", "pointer", "pointer"], function(impl, obj, fieldId) {
  return impl(this.handle, obj, fieldId);
});
Env.prototype.getStringLength = proxy2(164, "int32", ["pointer", "pointer"], function(impl, str) {
  return impl(this.handle, str);
});
Env.prototype.getStringChars = proxy2(165, "pointer", ["pointer", "pointer", "pointer"], function(impl, str) {
  return impl(this.handle, str, NULL);
});
Env.prototype.releaseStringChars = proxy2(166, "void", ["pointer", "pointer", "pointer"], function(impl, str, utf) {
  impl(this.handle, str, utf);
});
Env.prototype.newStringUtf = proxy2(167, "pointer", ["pointer", "pointer"], function(impl, str) {
  const utf = Memory.allocUtf8String(str);
  return impl(this.handle, utf);
});
Env.prototype.getStringUtfChars = proxy2(169, "pointer", ["pointer", "pointer", "pointer"], function(impl, str) {
  return impl(this.handle, str, NULL);
});
Env.prototype.releaseStringUtfChars = proxy2(170, "void", ["pointer", "pointer", "pointer"], function(impl, str, utf) {
  impl(this.handle, str, utf);
});
Env.prototype.getArrayLength = proxy2(171, "int32", ["pointer", "pointer"], function(impl, array) {
  return impl(this.handle, array);
});
Env.prototype.newObjectArray = proxy2(172, "pointer", ["pointer", "int32", "pointer", "pointer"], function(impl, length, elementClass, initialElement) {
  return impl(this.handle, length, elementClass, initialElement);
});
Env.prototype.getObjectArrayElement = proxy2(173, "pointer", ["pointer", "pointer", "int32"], function(impl, array, index) {
  return impl(this.handle, array, index);
});
Env.prototype.setObjectArrayElement = proxy2(174, "void", ["pointer", "pointer", "int32", "pointer"], function(impl, array, index, value) {
  impl(this.handle, array, index, value);
});
Env.prototype.newBooleanArray = proxy2(175, "pointer", ["pointer", "int32"], function(impl, length) {
  return impl(this.handle, length);
});
Env.prototype.newByteArray = proxy2(176, "pointer", ["pointer", "int32"], function(impl, length) {
  return impl(this.handle, length);
});
Env.prototype.newCharArray = proxy2(177, "pointer", ["pointer", "int32"], function(impl, length) {
  return impl(this.handle, length);
});
Env.prototype.newShortArray = proxy2(178, "pointer", ["pointer", "int32"], function(impl, length) {
  return impl(this.handle, length);
});
Env.prototype.newIntArray = proxy2(179, "pointer", ["pointer", "int32"], function(impl, length) {
  return impl(this.handle, length);
});
Env.prototype.newLongArray = proxy2(180, "pointer", ["pointer", "int32"], function(impl, length) {
  return impl(this.handle, length);
});
Env.prototype.newFloatArray = proxy2(181, "pointer", ["pointer", "int32"], function(impl, length) {
  return impl(this.handle, length);
});
Env.prototype.newDoubleArray = proxy2(182, "pointer", ["pointer", "int32"], function(impl, length) {
  return impl(this.handle, length);
});
Env.prototype.getBooleanArrayElements = proxy2(183, "pointer", ["pointer", "pointer", "pointer"], function(impl, array) {
  return impl(this.handle, array, NULL);
});
Env.prototype.getByteArrayElements = proxy2(184, "pointer", ["pointer", "pointer", "pointer"], function(impl, array) {
  return impl(this.handle, array, NULL);
});
Env.prototype.getCharArrayElements = proxy2(185, "pointer", ["pointer", "pointer", "pointer"], function(impl, array) {
  return impl(this.handle, array, NULL);
});
Env.prototype.getShortArrayElements = proxy2(186, "pointer", ["pointer", "pointer", "pointer"], function(impl, array) {
  return impl(this.handle, array, NULL);
});
Env.prototype.getIntArrayElements = proxy2(187, "pointer", ["pointer", "pointer", "pointer"], function(impl, array) {
  return impl(this.handle, array, NULL);
});
Env.prototype.getLongArrayElements = proxy2(188, "pointer", ["pointer", "pointer", "pointer"], function(impl, array) {
  return impl(this.handle, array, NULL);
});
Env.prototype.getFloatArrayElements = proxy2(189, "pointer", ["pointer", "pointer", "pointer"], function(impl, array) {
  return impl(this.handle, array, NULL);
});
Env.prototype.getDoubleArrayElements = proxy2(190, "pointer", ["pointer", "pointer", "pointer"], function(impl, array) {
  return impl(this.handle, array, NULL);
});
Env.prototype.releaseBooleanArrayElements = proxy2(191, "pointer", ["pointer", "pointer", "pointer", "int32"], function(impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});
Env.prototype.releaseByteArrayElements = proxy2(192, "pointer", ["pointer", "pointer", "pointer", "int32"], function(impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});
Env.prototype.releaseCharArrayElements = proxy2(193, "pointer", ["pointer", "pointer", "pointer", "int32"], function(impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});
Env.prototype.releaseShortArrayElements = proxy2(194, "pointer", ["pointer", "pointer", "pointer", "int32"], function(impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});
Env.prototype.releaseIntArrayElements = proxy2(195, "pointer", ["pointer", "pointer", "pointer", "int32"], function(impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});
Env.prototype.releaseLongArrayElements = proxy2(196, "pointer", ["pointer", "pointer", "pointer", "int32"], function(impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});
Env.prototype.releaseFloatArrayElements = proxy2(197, "pointer", ["pointer", "pointer", "pointer", "int32"], function(impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});
Env.prototype.releaseDoubleArrayElements = proxy2(198, "pointer", ["pointer", "pointer", "pointer", "int32"], function(impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});
Env.prototype.getByteArrayRegion = proxy2(200, "void", ["pointer", "pointer", "int", "int", "pointer"], function(impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});
Env.prototype.setBooleanArrayRegion = proxy2(207, "void", ["pointer", "pointer", "int32", "int32", "pointer"], function(impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});
Env.prototype.setByteArrayRegion = proxy2(208, "void", ["pointer", "pointer", "int32", "int32", "pointer"], function(impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});
Env.prototype.setCharArrayRegion = proxy2(209, "void", ["pointer", "pointer", "int32", "int32", "pointer"], function(impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});
Env.prototype.setShortArrayRegion = proxy2(210, "void", ["pointer", "pointer", "int32", "int32", "pointer"], function(impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});
Env.prototype.setIntArrayRegion = proxy2(211, "void", ["pointer", "pointer", "int32", "int32", "pointer"], function(impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});
Env.prototype.setLongArrayRegion = proxy2(212, "void", ["pointer", "pointer", "int32", "int32", "pointer"], function(impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});
Env.prototype.setFloatArrayRegion = proxy2(213, "void", ["pointer", "pointer", "int32", "int32", "pointer"], function(impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});
Env.prototype.setDoubleArrayRegion = proxy2(214, "void", ["pointer", "pointer", "int32", "int32", "pointer"], function(impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});
Env.prototype.registerNatives = proxy2(215, "int32", ["pointer", "pointer", "pointer", "int32"], function(impl, klass, methods, numMethods) {
  return impl(this.handle, klass, methods, numMethods);
});
Env.prototype.monitorEnter = proxy2(217, "int32", ["pointer", "pointer"], function(impl, obj) {
  return impl(this.handle, obj);
});
Env.prototype.monitorExit = proxy2(218, "int32", ["pointer", "pointer"], function(impl, obj) {
  return impl(this.handle, obj);
});
Env.prototype.getDirectBufferAddress = proxy2(230, "pointer", ["pointer", "pointer"], function(impl, obj) {
  return impl(this.handle, obj);
});
Env.prototype.getObjectRefType = proxy2(232, "int32", ["pointer", "pointer"], function(impl, ref) {
  return impl(this.handle, ref);
});
var cachedMethods = /* @__PURE__ */ new Map();
function plainMethod(offset, retType, argTypes, options) {
  return getOrMakeMethod(this, "p", makePlainMethod, offset, retType, argTypes, options);
}
function vaMethod(offset, retType, argTypes, options) {
  return getOrMakeMethod(this, "v", makeVaMethod, offset, retType, argTypes, options);
}
function nonvirtualVaMethod(offset, retType, argTypes, options) {
  return getOrMakeMethod(this, "n", makeNonvirtualVaMethod, offset, retType, argTypes, options);
}
function getOrMakeMethod(env, flavor, construct, offset, retType, argTypes, options) {
  if (options !== void 0) {
    return construct(env, offset, retType, argTypes, options);
  }
  const key = [offset, flavor, retType].concat(argTypes).join("|");
  let m = cachedMethods.get(key);
  if (m === void 0) {
    m = construct(env, offset, retType, argTypes, nativeFunctionOptions2);
    cachedMethods.set(key, m);
  }
  return m;
}
function makePlainMethod(env, offset, retType, argTypes, options) {
  return new NativeFunction(
    vtable(env).add(offset * pointerSize3).readPointer(),
    retType,
    ["pointer", "pointer", "pointer"].concat(argTypes),
    options
  );
}
function makeVaMethod(env, offset, retType, argTypes, options) {
  return new NativeFunction(
    vtable(env).add(offset * pointerSize3).readPointer(),
    retType,
    ["pointer", "pointer", "pointer", "..."].concat(argTypes),
    options
  );
}
function makeNonvirtualVaMethod(env, offset, retType, argTypes, options) {
  return new NativeFunction(
    vtable(env).add(offset * pointerSize3).readPointer(),
    retType,
    ["pointer", "pointer", "pointer", "pointer", "..."].concat(argTypes),
    options
  );
}
Env.prototype.constructor = function(argTypes, options) {
  return vaMethod.call(this, CALL_CONSTRUCTOR_METHOD_OFFSET, "pointer", argTypes, options);
};
Env.prototype.vaMethod = function(retType, argTypes, options) {
  const offset = callMethodOffset[retType];
  if (offset === void 0) {
    throw new Error("Unsupported type: " + retType);
  }
  return vaMethod.call(this, offset, retType, argTypes, options);
};
Env.prototype.nonvirtualVaMethod = function(retType, argTypes, options) {
  const offset = callNonvirtualMethodOffset[retType];
  if (offset === void 0) {
    throw new Error("Unsupported type: " + retType);
  }
  return nonvirtualVaMethod.call(this, offset, retType, argTypes, options);
};
Env.prototype.staticVaMethod = function(retType, argTypes, options) {
  const offset = callStaticMethodOffset[retType];
  if (offset === void 0) {
    throw new Error("Unsupported type: " + retType);
  }
  return vaMethod.call(this, offset, retType, argTypes, options);
};
Env.prototype.getField = function(fieldType) {
  const offset = getFieldOffset[fieldType];
  if (offset === void 0) {
    throw new Error("Unsupported type: " + fieldType);
  }
  return plainMethod.call(this, offset, fieldType, []);
};
Env.prototype.getStaticField = function(fieldType) {
  const offset = getStaticFieldOffset[fieldType];
  if (offset === void 0) {
    throw new Error("Unsupported type: " + fieldType);
  }
  return plainMethod.call(this, offset, fieldType, []);
};
Env.prototype.setField = function(fieldType) {
  const offset = setFieldOffset[fieldType];
  if (offset === void 0) {
    throw new Error("Unsupported type: " + fieldType);
  }
  return plainMethod.call(this, offset, "void", [fieldType]);
};
Env.prototype.setStaticField = function(fieldType) {
  const offset = setStaticFieldOffset[fieldType];
  if (offset === void 0) {
    throw new Error("Unsupported type: " + fieldType);
  }
  return plainMethod.call(this, offset, "void", [fieldType]);
};
var javaLangClass = null;
Env.prototype.javaLangClass = function() {
  if (javaLangClass === null) {
    const handle = this.findClass("java/lang/Class");
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangClass = {
        handle: register(this.newGlobalRef(handle)),
        getName: get("getName", "()Ljava/lang/String;"),
        getSimpleName: get("getSimpleName", "()Ljava/lang/String;"),
        getGenericSuperclass: get("getGenericSuperclass", "()Ljava/lang/reflect/Type;"),
        getDeclaredConstructors: get("getDeclaredConstructors", "()[Ljava/lang/reflect/Constructor;"),
        getDeclaredMethods: get("getDeclaredMethods", "()[Ljava/lang/reflect/Method;"),
        getDeclaredFields: get("getDeclaredFields", "()[Ljava/lang/reflect/Field;"),
        isArray: get("isArray", "()Z"),
        isPrimitive: get("isPrimitive", "()Z"),
        isInterface: get("isInterface", "()Z"),
        getComponentType: get("getComponentType", "()Ljava/lang/Class;")
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangClass;
};
var javaLangObject = null;
Env.prototype.javaLangObject = function() {
  if (javaLangObject === null) {
    const handle = this.findClass("java/lang/Object");
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangObject = {
        handle: register(this.newGlobalRef(handle)),
        toString: get("toString", "()Ljava/lang/String;"),
        getClass: get("getClass", "()Ljava/lang/Class;")
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangObject;
};
var javaLangReflectConstructor = null;
Env.prototype.javaLangReflectConstructor = function() {
  if (javaLangReflectConstructor === null) {
    const handle = this.findClass("java/lang/reflect/Constructor");
    try {
      javaLangReflectConstructor = {
        getGenericParameterTypes: this.getMethodId(handle, "getGenericParameterTypes", "()[Ljava/lang/reflect/Type;")
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectConstructor;
};
var javaLangReflectMethod = null;
Env.prototype.javaLangReflectMethod = function() {
  if (javaLangReflectMethod === null) {
    const handle = this.findClass("java/lang/reflect/Method");
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangReflectMethod = {
        getName: get("getName", "()Ljava/lang/String;"),
        getGenericParameterTypes: get("getGenericParameterTypes", "()[Ljava/lang/reflect/Type;"),
        getParameterTypes: get("getParameterTypes", "()[Ljava/lang/Class;"),
        getGenericReturnType: get("getGenericReturnType", "()Ljava/lang/reflect/Type;"),
        getGenericExceptionTypes: get("getGenericExceptionTypes", "()[Ljava/lang/reflect/Type;"),
        getModifiers: get("getModifiers", "()I"),
        isVarArgs: get("isVarArgs", "()Z")
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectMethod;
};
var javaLangReflectField = null;
Env.prototype.javaLangReflectField = function() {
  if (javaLangReflectField === null) {
    const handle = this.findClass("java/lang/reflect/Field");
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangReflectField = {
        getName: get("getName", "()Ljava/lang/String;"),
        getType: get("getType", "()Ljava/lang/Class;"),
        getGenericType: get("getGenericType", "()Ljava/lang/reflect/Type;"),
        getModifiers: get("getModifiers", "()I"),
        toString: get("toString", "()Ljava/lang/String;")
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectField;
};
var javaLangReflectTypeVariable = null;
Env.prototype.javaLangReflectTypeVariable = function() {
  if (javaLangReflectTypeVariable === null) {
    const handle = this.findClass("java/lang/reflect/TypeVariable");
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangReflectTypeVariable = {
        handle: register(this.newGlobalRef(handle)),
        getName: get("getName", "()Ljava/lang/String;"),
        getBounds: get("getBounds", "()[Ljava/lang/reflect/Type;"),
        getGenericDeclaration: get("getGenericDeclaration", "()Ljava/lang/reflect/GenericDeclaration;")
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectTypeVariable;
};
var javaLangReflectWildcardType = null;
Env.prototype.javaLangReflectWildcardType = function() {
  if (javaLangReflectWildcardType === null) {
    const handle = this.findClass("java/lang/reflect/WildcardType");
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangReflectWildcardType = {
        handle: register(this.newGlobalRef(handle)),
        getLowerBounds: get("getLowerBounds", "()[Ljava/lang/reflect/Type;"),
        getUpperBounds: get("getUpperBounds", "()[Ljava/lang/reflect/Type;")
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectWildcardType;
};
var javaLangReflectGenericArrayType = null;
Env.prototype.javaLangReflectGenericArrayType = function() {
  if (javaLangReflectGenericArrayType === null) {
    const handle = this.findClass("java/lang/reflect/GenericArrayType");
    try {
      javaLangReflectGenericArrayType = {
        handle: register(this.newGlobalRef(handle)),
        getGenericComponentType: this.getMethodId(handle, "getGenericComponentType", "()Ljava/lang/reflect/Type;")
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectGenericArrayType;
};
var javaLangReflectParameterizedType = null;
Env.prototype.javaLangReflectParameterizedType = function() {
  if (javaLangReflectParameterizedType === null) {
    const handle = this.findClass("java/lang/reflect/ParameterizedType");
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangReflectParameterizedType = {
        handle: register(this.newGlobalRef(handle)),
        getActualTypeArguments: get("getActualTypeArguments", "()[Ljava/lang/reflect/Type;"),
        getRawType: get("getRawType", "()Ljava/lang/reflect/Type;"),
        getOwnerType: get("getOwnerType", "()Ljava/lang/reflect/Type;")
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectParameterizedType;
};
var javaLangString = null;
Env.prototype.javaLangString = function() {
  if (javaLangString === null) {
    const handle = this.findClass("java/lang/String");
    try {
      javaLangString = {
        handle: register(this.newGlobalRef(handle))
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangString;
};
Env.prototype.getClassName = function(classHandle) {
  const name = this.vaMethod("pointer", [])(this.handle, classHandle, this.javaLangClass().getName);
  try {
    return this.stringFromJni(name);
  } finally {
    this.deleteLocalRef(name);
  }
};
Env.prototype.getObjectClassName = function(objHandle) {
  const jklass = this.getObjectClass(objHandle);
  try {
    return this.getClassName(jklass);
  } finally {
    this.deleteLocalRef(jklass);
  }
};
Env.prototype.getActualTypeArgument = function(type) {
  const actualTypeArguments = this.vaMethod("pointer", [])(this.handle, type, this.javaLangReflectParameterizedType().getActualTypeArguments);
  this.throwIfExceptionPending();
  if (!actualTypeArguments.isNull()) {
    try {
      return this.getTypeNameFromFirstTypeElement(actualTypeArguments);
    } finally {
      this.deleteLocalRef(actualTypeArguments);
    }
  }
};
Env.prototype.getTypeNameFromFirstTypeElement = function(typeArray) {
  const length = this.getArrayLength(typeArray);
  if (length > 0) {
    const typeArgument0 = this.getObjectArrayElement(typeArray, 0);
    try {
      return this.getTypeName(typeArgument0);
    } finally {
      this.deleteLocalRef(typeArgument0);
    }
  } else {
    return "java.lang.Object";
  }
};
Env.prototype.getTypeName = function(type, getGenericsInformation) {
  const invokeObjectMethodNoArgs = this.vaMethod("pointer", []);
  if (this.isInstanceOf(type, this.javaLangClass().handle)) {
    return this.getClassName(type);
  } else if (this.isInstanceOf(type, this.javaLangReflectGenericArrayType().handle)) {
    return this.getArrayTypeName(type);
  } else if (this.isInstanceOf(type, this.javaLangReflectParameterizedType().handle)) {
    const rawType = invokeObjectMethodNoArgs(this.handle, type, this.javaLangReflectParameterizedType().getRawType);
    this.throwIfExceptionPending();
    let result;
    try {
      result = this.getTypeName(rawType);
    } finally {
      this.deleteLocalRef(rawType);
    }
    if (getGenericsInformation) {
      result += "<" + this.getActualTypeArgument(type) + ">";
    }
    return result;
  } else if (this.isInstanceOf(type, this.javaLangReflectTypeVariable().handle)) {
    return "java.lang.Object";
  } else if (this.isInstanceOf(type, this.javaLangReflectWildcardType().handle)) {
    return "java.lang.Object";
  } else {
    return "java.lang.Object";
  }
};
Env.prototype.getArrayTypeName = function(type) {
  const invokeObjectMethodNoArgs = this.vaMethod("pointer", []);
  if (this.isInstanceOf(type, this.javaLangClass().handle)) {
    return this.getClassName(type);
  } else if (this.isInstanceOf(type, this.javaLangReflectGenericArrayType().handle)) {
    const componentType = invokeObjectMethodNoArgs(this.handle, type, this.javaLangReflectGenericArrayType().getGenericComponentType);
    this.throwIfExceptionPending();
    try {
      return "[L" + this.getTypeName(componentType) + ";";
    } finally {
      this.deleteLocalRef(componentType);
    }
  } else {
    return "[Ljava.lang.Object;";
  }
};
Env.prototype.stringFromJni = function(str) {
  const utf = this.getStringChars(str);
  if (utf.isNull()) {
    throw new Error("Unable to access string");
  }
  try {
    const length = this.getStringLength(str);
    return utf.readUtf16String(length);
  } finally {
    this.releaseStringChars(str, utf);
  }
};

// node_modules/frida-java-bridge/lib/vm.js
var JNI_VERSION_1_6 = 65542;
var pointerSize4 = Process.pointerSize;
var jsThreadID = Process.getCurrentThreadId();
var attachedThreads = /* @__PURE__ */ new Map();
var activeEnvs = /* @__PURE__ */ new Map();
function VM(api2) {
  const handle = api2.vm;
  let attachCurrentThread = null;
  let detachCurrentThread = null;
  let getEnv = null;
  function initialize2() {
    const vtable2 = handle.readPointer();
    const options = {
      exceptions: "propagate"
    };
    attachCurrentThread = new NativeFunction(vtable2.add(4 * pointerSize4).readPointer(), "int32", ["pointer", "pointer", "pointer"], options);
    detachCurrentThread = new NativeFunction(vtable2.add(5 * pointerSize4).readPointer(), "int32", ["pointer"], options);
    getEnv = new NativeFunction(vtable2.add(6 * pointerSize4).readPointer(), "int32", ["pointer", "pointer", "int32"], options);
  }
  this.handle = handle;
  this.perform = function(fn) {
    const threadId = Process.getCurrentThreadId();
    const cachedEnv = tryGetCachedEnv(threadId);
    if (cachedEnv !== null) {
      return fn(cachedEnv);
    }
    let env = this._tryGetEnv();
    const alreadyAttached = env !== null;
    if (!alreadyAttached) {
      env = this.attachCurrentThread();
      attachedThreads.set(threadId, true);
    }
    this.link(threadId, env);
    try {
      return fn(env);
    } finally {
      const isJsThread = threadId === jsThreadID;
      if (!isJsThread) {
        this.unlink(threadId);
      }
      if (!alreadyAttached && !isJsThread) {
        const allowedToDetach = attachedThreads.get(threadId);
        attachedThreads.delete(threadId);
        if (allowedToDetach) {
          this.detachCurrentThread();
        }
      }
    }
  };
  this.attachCurrentThread = function() {
    const envBuf = Memory.alloc(pointerSize4);
    checkJniResult("VM::AttachCurrentThread", attachCurrentThread(handle, envBuf, NULL));
    return new Env(envBuf.readPointer(), this);
  };
  this.detachCurrentThread = function() {
    checkJniResult("VM::DetachCurrentThread", detachCurrentThread(handle));
  };
  this.preventDetachDueToClassLoader = function() {
    const threadId = Process.getCurrentThreadId();
    if (attachedThreads.has(threadId)) {
      attachedThreads.set(threadId, false);
    }
  };
  this.getEnv = function() {
    const cachedEnv = tryGetCachedEnv(Process.getCurrentThreadId());
    if (cachedEnv !== null) {
      return cachedEnv;
    }
    const envBuf = Memory.alloc(pointerSize4);
    const result = getEnv(handle, envBuf, JNI_VERSION_1_6);
    if (result === -2) {
      throw new Error("Current thread is not attached to the Java VM; please move this code inside a Java.perform() callback");
    }
    checkJniResult("VM::GetEnv", result);
    return new Env(envBuf.readPointer(), this);
  };
  this.tryGetEnv = function() {
    const cachedEnv = tryGetCachedEnv(Process.getCurrentThreadId());
    if (cachedEnv !== null) {
      return cachedEnv;
    }
    return this._tryGetEnv();
  };
  this._tryGetEnv = function() {
    const h = this.tryGetEnvHandle(JNI_VERSION_1_6);
    if (h === null) {
      return null;
    }
    return new Env(h, this);
  };
  this.tryGetEnvHandle = function(version) {
    const envBuf = Memory.alloc(pointerSize4);
    const result = getEnv(handle, envBuf, version);
    if (result !== JNI_OK) {
      return null;
    }
    return envBuf.readPointer();
  };
  this.makeHandleDestructor = function(handle2) {
    return () => {
      this.perform((env) => {
        env.deleteGlobalRef(handle2);
      });
    };
  };
  this.link = function(tid, env) {
    const entry = activeEnvs.get(tid);
    if (entry === void 0) {
      activeEnvs.set(tid, [env, 1]);
    } else {
      entry[1]++;
    }
  };
  this.unlink = function(tid) {
    const entry = activeEnvs.get(tid);
    if (entry[1] === 1) {
      activeEnvs.delete(tid);
    } else {
      entry[1]--;
    }
  };
  function tryGetCachedEnv(threadId) {
    const entry = activeEnvs.get(threadId);
    if (entry === void 0) {
      return null;
    }
    return entry[0];
  }
  initialize2.call(this);
}
VM.dispose = function(vm3) {
  if (attachedThreads.get(jsThreadID) === true) {
    attachedThreads.delete(jsThreadID);
    vm3.detachCurrentThread();
  }
};

// node_modules/frida-java-bridge/lib/android.js
var jsizeSize = 4;
var pointerSize5 = Process.pointerSize;
var {
  readU32,
  readPointer,
  writeU32,
  writePointer
} = NativePointer.prototype;
var kAccPublic = 1;
var kAccStatic = 8;
var kAccFinal = 16;
var kAccNative = 256;
var kAccFastNative = 524288;
var kAccCriticalNative = 2097152;
var kAccFastInterpreterToInterpreterInvoke = 1073741824;
var kAccSkipAccessChecks = 524288;
var kAccSingleImplementation = 134217728;
var kAccNterpEntryPointFastPathFlag = 1048576;
var kAccNterpInvokeFastPathFlag = 2097152;
var kAccPublicApi = 268435456;
var kAccXposedHookedMethod = 268435456;
var kPointer = 0;
var kFullDeoptimization = 3;
var kSelectiveDeoptimization = 5;
var THUMB_BIT_REMOVAL_MASK = ptr(1).not();
var X86_JMP_MAX_DISTANCE = 2147467263;
var ARM64_ADRP_MAX_DISTANCE = 4294963200;
var ENV_VTABLE_OFFSET_EXCEPTION_CLEAR = 17 * pointerSize5;
var ENV_VTABLE_OFFSET_FATAL_ERROR = 18 * pointerSize5;
var DVM_JNI_ENV_OFFSET_SELF = 12;
var DVM_CLASS_OBJECT_OFFSET_VTABLE_COUNT = 112;
var DVM_CLASS_OBJECT_OFFSET_VTABLE = 116;
var DVM_OBJECT_OFFSET_CLAZZ = 0;
var DVM_METHOD_SIZE = 56;
var DVM_METHOD_OFFSET_ACCESS_FLAGS = 4;
var DVM_METHOD_OFFSET_METHOD_INDEX = 8;
var DVM_METHOD_OFFSET_REGISTERS_SIZE = 10;
var DVM_METHOD_OFFSET_OUTS_SIZE = 12;
var DVM_METHOD_OFFSET_INS_SIZE = 14;
var DVM_METHOD_OFFSET_SHORTY = 28;
var DVM_METHOD_OFFSET_JNI_ARG_INFO = 36;
var DALVIK_JNI_RETURN_VOID = 0;
var DALVIK_JNI_RETURN_FLOAT = 1;
var DALVIK_JNI_RETURN_DOUBLE = 2;
var DALVIK_JNI_RETURN_S8 = 3;
var DALVIK_JNI_RETURN_S4 = 4;
var DALVIK_JNI_RETURN_S2 = 5;
var DALVIK_JNI_RETURN_U2 = 6;
var DALVIK_JNI_RETURN_S1 = 7;
var DALVIK_JNI_NO_ARG_INFO = 2147483648;
var DALVIK_JNI_RETURN_SHIFT = 28;
var STD_STRING_SIZE = 3 * pointerSize5;
var STD_VECTOR_SIZE = 3 * pointerSize5;
var AF_UNIX = 1;
var SOCK_STREAM = 1;
var getArtRuntimeSpec = memoize(_getArtRuntimeSpec);
var getArtInstrumentationSpec = memoize(_getArtInstrumentationSpec);
var getArtMethodSpec = memoize(_getArtMethodSpec);
var getArtThreadSpec = memoize(_getArtThreadSpec);
var getArtManagedStackSpec = memoize(_getArtManagedStackSpec);
var getArtThreadStateTransitionImpl = memoize(_getArtThreadStateTransitionImpl);
var getAndroidVersion = memoize(_getAndroidVersion);
var getAndroidCodename = memoize(_getAndroidCodename);
var getAndroidApiLevel = memoize(_getAndroidApiLevel);
var getArtQuickFrameInfoGetterThunk = memoize(_getArtQuickFrameInfoGetterThunk);
var makeCxxMethodWrapperReturningPointerByValue = Process.arch === "ia32" ? makeCxxMethodWrapperReturningPointerByValueInFirstArg : makeCxxMethodWrapperReturningPointerByValueGeneric;
var nativeFunctionOptions3 = {
  exceptions: "propagate"
};
var artThreadStateTransitions = {};
var cachedApi = null;
var cachedArtClassLinkerSpec = null;
var MethodMangler = null;
var artController = null;
var inlineHooks = [];
var patchedClasses = /* @__PURE__ */ new Map();
var artQuickInterceptors = [];
var thunkPage = null;
var thunkOffset = 0;
var taughtArtAboutReplacementMethods = false;
var taughtArtAboutMethodInstrumentation = false;
var backtraceModule = null;
var jdwpSessions = [];
var socketpair = null;
var trampolineAllocator = null;
function getApi() {
  if (cachedApi === null) {
    cachedApi = _getApi();
  }
  return cachedApi;
}
function _getApi() {
  const vmModules = Process.enumerateModules().filter((m) => /^lib(art|dvm).so$/.test(m.name)).filter((m) => !/\/system\/fake-libs/.test(m.path));
  if (vmModules.length === 0) {
    return null;
  }
  const vmModule = vmModules[0];
  const flavor = vmModule.name.indexOf("art") !== -1 ? "art" : "dalvik";
  const isArt = flavor === "art";
  const temporaryApi = {
    module: vmModule,
    find(name) {
      const { module } = this;
      let address = module.findExportByName(name);
      if (address === null) {
        address = module.findSymbolByName(name);
      }
      return address;
    },
    flavor,
    addLocalReference: null
  };
  temporaryApi.isApiLevel34OrApexEquivalent = isArt && (temporaryApi.find("_ZN3art7AppInfo29GetPrimaryApkReferenceProfileEv") !== null || temporaryApi.find("_ZN3art6Thread15RunFlipFunctionEPS0_") !== null);
  const pending = isArt ? {
    functions: {
      JNI_GetCreatedJavaVMs: ["JNI_GetCreatedJavaVMs", "int", ["pointer", "int", "pointer"]],
      // Android < 7
      artInterpreterToCompiledCodeBridge: function(address) {
        this.artInterpreterToCompiledCodeBridge = address;
      },
      // Android >= 8
      _ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadENS_6ObjPtrINS_6mirror6ObjectEEE: ["art::JavaVMExt::AddGlobalRef", "pointer", ["pointer", "pointer", "pointer"]],
      // Android >= 6
      _ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadEPNS_6mirror6ObjectE: ["art::JavaVMExt::AddGlobalRef", "pointer", ["pointer", "pointer", "pointer"]],
      // Android < 6: makeAddGlobalRefFallbackForAndroid5() needs these:
      _ZN3art17ReaderWriterMutex13ExclusiveLockEPNS_6ThreadE: ["art::ReaderWriterMutex::ExclusiveLock", "void", ["pointer", "pointer"]],
      _ZN3art17ReaderWriterMutex15ExclusiveUnlockEPNS_6ThreadE: ["art::ReaderWriterMutex::ExclusiveUnlock", "void", ["pointer", "pointer"]],
      // Android <= 7
      _ZN3art22IndirectReferenceTable3AddEjPNS_6mirror6ObjectE: function(address) {
        this["art::IndirectReferenceTable::Add"] = new NativeFunction(address, "pointer", ["pointer", "uint", "pointer"], nativeFunctionOptions3);
      },
      // Android > 7
      _ZN3art22IndirectReferenceTable3AddENS_15IRTSegmentStateENS_6ObjPtrINS_6mirror6ObjectEEE: function(address) {
        this["art::IndirectReferenceTable::Add"] = new NativeFunction(address, "pointer", ["pointer", "uint", "pointer"], nativeFunctionOptions3);
      },
      // Android >= 7
      _ZN3art9JavaVMExt12DecodeGlobalEPv: function(address) {
        let decodeGlobal;
        if (getAndroidApiLevel() >= 26) {
          decodeGlobal = makeCxxMethodWrapperReturningPointerByValue(address, ["pointer", "pointer"]);
        } else {
          decodeGlobal = new NativeFunction(address, "pointer", ["pointer", "pointer"], nativeFunctionOptions3);
        }
        this["art::JavaVMExt::DecodeGlobal"] = function(vm3, thread, ref) {
          return decodeGlobal(vm3, ref);
        };
      },
      // Android >= 6
      _ZN3art9JavaVMExt12DecodeGlobalEPNS_6ThreadEPv: ["art::JavaVMExt::DecodeGlobal", "pointer", ["pointer", "pointer", "pointer"]],
      // makeDecodeGlobalFallback() uses:
      // Android >= 15
      _ZNK3art6Thread19DecodeGlobalJObjectEP8_jobject: ["art::Thread::DecodeJObject", "pointer", ["pointer", "pointer"]],
      // Android < 6
      _ZNK3art6Thread13DecodeJObjectEP8_jobject: ["art::Thread::DecodeJObject", "pointer", ["pointer", "pointer"]],
      // Android >= 6
      _ZN3art10ThreadList10SuspendAllEPKcb: ["art::ThreadList::SuspendAll", "void", ["pointer", "pointer", "bool"]],
      // or fallback:
      _ZN3art10ThreadList10SuspendAllEv: function(address) {
        const suspendAll = new NativeFunction(address, "void", ["pointer"], nativeFunctionOptions3);
        this["art::ThreadList::SuspendAll"] = function(threadList, cause, longSuspend) {
          return suspendAll(threadList);
        };
      },
      _ZN3art10ThreadList9ResumeAllEv: ["art::ThreadList::ResumeAll", "void", ["pointer"]],
      // Android >= 7
      _ZN3art11ClassLinker12VisitClassesEPNS_12ClassVisitorE: ["art::ClassLinker::VisitClasses", "void", ["pointer", "pointer"]],
      // Android < 7
      _ZN3art11ClassLinker12VisitClassesEPFbPNS_6mirror5ClassEPvES4_: function(address) {
        const visitClasses = new NativeFunction(address, "void", ["pointer", "pointer", "pointer"], nativeFunctionOptions3);
        this["art::ClassLinker::VisitClasses"] = function(classLinker, visitor) {
          visitClasses(classLinker, visitor, NULL);
        };
      },
      _ZNK3art11ClassLinker17VisitClassLoadersEPNS_18ClassLoaderVisitorE: ["art::ClassLinker::VisitClassLoaders", "void", ["pointer", "pointer"]],
      _ZN3art2gc4Heap12VisitObjectsEPFvPNS_6mirror6ObjectEPvES5_: ["art::gc::Heap::VisitObjects", "void", ["pointer", "pointer", "pointer"]],
      _ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE: ["art::gc::Heap::GetInstances", "void", ["pointer", "pointer", "pointer", "int", "pointer"]],
      // Android >= 9
      _ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEbiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE: function(address) {
        const getInstances = new NativeFunction(address, "void", ["pointer", "pointer", "pointer", "bool", "int", "pointer"], nativeFunctionOptions3);
        this["art::gc::Heap::GetInstances"] = function(instance, scope, hClass, maxCount, instances) {
          const useIsAssignableFrom = 0;
          getInstances(instance, scope, hClass, useIsAssignableFrom, maxCount, instances);
        };
      },
      _ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEjb: ["art::StackVisitor::StackVisitor", "void", ["pointer", "pointer", "pointer", "uint", "uint", "bool"]],
      _ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEmb: ["art::StackVisitor::StackVisitor", "void", ["pointer", "pointer", "pointer", "uint", "size_t", "bool"]],
      _ZN3art12StackVisitor9WalkStackILNS0_16CountTransitionsE0EEEvb: ["art::StackVisitor::WalkStack", "void", ["pointer", "bool"]],
      _ZNK3art12StackVisitor9GetMethodEv: ["art::StackVisitor::GetMethod", "pointer", ["pointer"]],
      _ZNK3art12StackVisitor16DescribeLocationEv: function(address) {
        this["art::StackVisitor::DescribeLocation"] = makeCxxMethodWrapperReturningStdStringByValue(address, ["pointer"]);
      },
      _ZNK3art12StackVisitor24GetCurrentQuickFrameInfoEv: function(address) {
        this["art::StackVisitor::GetCurrentQuickFrameInfo"] = makeArtQuickFrameInfoGetter(address);
      },
      _ZN3art6Thread18GetLongJumpContextEv: ["art::Thread::GetLongJumpContext", "pointer", ["pointer"]],
      _ZN3art6mirror5Class13GetDescriptorEPNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE: function(address) {
        this["art::mirror::Class::GetDescriptor"] = address;
      },
      _ZN3art6mirror5Class11GetLocationEv: function(address) {
        this["art::mirror::Class::GetLocation"] = makeCxxMethodWrapperReturningStdStringByValue(address, ["pointer"]);
      },
      _ZN3art9ArtMethod12PrettyMethodEb: function(address) {
        this["art::ArtMethod::PrettyMethod"] = makeCxxMethodWrapperReturningStdStringByValue(address, ["pointer", "bool"]);
      },
      _ZN3art12PrettyMethodEPNS_9ArtMethodEb: function(address) {
        this["art::ArtMethod::PrettyMethodNullSafe"] = makeCxxMethodWrapperReturningStdStringByValue(address, ["pointer", "bool"]);
      },
      // Android < 6 for cloneArtMethod()
      _ZN3art6Thread14CurrentFromGdbEv: ["art::Thread::CurrentFromGdb", "pointer", []],
      _ZN3art6mirror6Object5CloneEPNS_6ThreadE: function(address) {
        this["art::mirror::Object::Clone"] = new NativeFunction(address, "pointer", ["pointer", "pointer"], nativeFunctionOptions3);
      },
      _ZN3art6mirror6Object5CloneEPNS_6ThreadEm: function(address) {
        const clone = new NativeFunction(address, "pointer", ["pointer", "pointer", "pointer"], nativeFunctionOptions3);
        this["art::mirror::Object::Clone"] = function(thisPtr, threadPtr) {
          const numTargetBytes = NULL;
          return clone(thisPtr, threadPtr, numTargetBytes);
        };
      },
      _ZN3art6mirror6Object5CloneEPNS_6ThreadEj: function(address) {
        const clone = new NativeFunction(address, "pointer", ["pointer", "pointer", "uint"], nativeFunctionOptions3);
        this["art::mirror::Object::Clone"] = function(thisPtr, threadPtr) {
          const numTargetBytes = 0;
          return clone(thisPtr, threadPtr, numTargetBytes);
        };
      },
      _ZN3art3Dbg14SetJdwpAllowedEb: ["art::Dbg::SetJdwpAllowed", "void", ["bool"]],
      _ZN3art3Dbg13ConfigureJdwpERKNS_4JDWP11JdwpOptionsE: ["art::Dbg::ConfigureJdwp", "void", ["pointer"]],
      _ZN3art31InternalDebuggerControlCallback13StartDebuggerEv: ["art::InternalDebuggerControlCallback::StartDebugger", "void", ["pointer"]],
      _ZN3art3Dbg9StartJdwpEv: ["art::Dbg::StartJdwp", "void", []],
      _ZN3art3Dbg8GoActiveEv: ["art::Dbg::GoActive", "void", []],
      _ZN3art3Dbg21RequestDeoptimizationERKNS_21DeoptimizationRequestE: ["art::Dbg::RequestDeoptimization", "void", ["pointer"]],
      _ZN3art3Dbg20ManageDeoptimizationEv: ["art::Dbg::ManageDeoptimization", "void", []],
      _ZN3art15instrumentation15Instrumentation20EnableDeoptimizationEv: ["art::Instrumentation::EnableDeoptimization", "void", ["pointer"]],
      // Android >= 6
      _ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEPKc: ["art::Instrumentation::DeoptimizeEverything", "void", ["pointer", "pointer"]],
      // Android < 6
      _ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEv: function(address) {
        const deoptimize = new NativeFunction(address, "void", ["pointer"], nativeFunctionOptions3);
        this["art::Instrumentation::DeoptimizeEverything"] = function(instrumentation, key) {
          deoptimize(instrumentation);
        };
      },
      _ZN3art7Runtime19DeoptimizeBootImageEv: ["art::Runtime::DeoptimizeBootImage", "void", ["pointer"]],
      _ZN3art15instrumentation15Instrumentation10DeoptimizeEPNS_9ArtMethodE: ["art::Instrumentation::Deoptimize", "void", ["pointer", "pointer"]],
      // Android >= 11
      _ZN3art3jni12JniIdManager14DecodeMethodIdEP10_jmethodID: ["art::jni::JniIdManager::DecodeMethodId", "pointer", ["pointer", "pointer"]],
      _ZN3art3jni12JniIdManager13DecodeFieldIdEP9_jfieldID: ["art::jni::JniIdManager::DecodeFieldId", "pointer", ["pointer", "pointer"]],
      _ZN3art11interpreter18GetNterpEntryPointEv: ["art::interpreter::GetNterpEntryPoint", "pointer", []],
      _ZN3art7Monitor17TranslateLocationEPNS_9ArtMethodEjPPKcPi: ["art::Monitor::TranslateLocation", "void", ["pointer", "uint32", "pointer", "pointer"]]
    },
    variables: {
      _ZN3art3Dbg9gRegistryE: function(address) {
        this.isJdwpStarted = () => !address.readPointer().isNull();
      },
      _ZN3art3Dbg15gDebuggerActiveE: function(address) {
        this.isDebuggerActive = () => !!address.readU8();
      }
    },
    optionals: /* @__PURE__ */ new Set([
      "artInterpreterToCompiledCodeBridge",
      "_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadENS_6ObjPtrINS_6mirror6ObjectEEE",
      "_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadEPNS_6mirror6ObjectE",
      "_ZN3art9JavaVMExt12DecodeGlobalEPv",
      "_ZN3art9JavaVMExt12DecodeGlobalEPNS_6ThreadEPv",
      "_ZNK3art6Thread19DecodeGlobalJObjectEP8_jobject",
      "_ZNK3art6Thread13DecodeJObjectEP8_jobject",
      "_ZN3art10ThreadList10SuspendAllEPKcb",
      "_ZN3art10ThreadList10SuspendAllEv",
      "_ZN3art11ClassLinker12VisitClassesEPNS_12ClassVisitorE",
      "_ZN3art11ClassLinker12VisitClassesEPFbPNS_6mirror5ClassEPvES4_",
      "_ZNK3art11ClassLinker17VisitClassLoadersEPNS_18ClassLoaderVisitorE",
      "_ZN3art6mirror6Object5CloneEPNS_6ThreadE",
      "_ZN3art6mirror6Object5CloneEPNS_6ThreadEm",
      "_ZN3art6mirror6Object5CloneEPNS_6ThreadEj",
      "_ZN3art22IndirectReferenceTable3AddEjPNS_6mirror6ObjectE",
      "_ZN3art22IndirectReferenceTable3AddENS_15IRTSegmentStateENS_6ObjPtrINS_6mirror6ObjectEEE",
      "_ZN3art2gc4Heap12VisitObjectsEPFvPNS_6mirror6ObjectEPvES5_",
      "_ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE",
      "_ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEbiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE",
      "_ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEjb",
      "_ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEmb",
      "_ZN3art12StackVisitor9WalkStackILNS0_16CountTransitionsE0EEEvb",
      "_ZNK3art12StackVisitor9GetMethodEv",
      "_ZNK3art12StackVisitor16DescribeLocationEv",
      "_ZNK3art12StackVisitor24GetCurrentQuickFrameInfoEv",
      "_ZN3art6Thread18GetLongJumpContextEv",
      "_ZN3art6mirror5Class13GetDescriptorEPNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE",
      "_ZN3art6mirror5Class11GetLocationEv",
      "_ZN3art9ArtMethod12PrettyMethodEb",
      "_ZN3art12PrettyMethodEPNS_9ArtMethodEb",
      "_ZN3art3Dbg13ConfigureJdwpERKNS_4JDWP11JdwpOptionsE",
      "_ZN3art31InternalDebuggerControlCallback13StartDebuggerEv",
      "_ZN3art3Dbg15gDebuggerActiveE",
      "_ZN3art15instrumentation15Instrumentation20EnableDeoptimizationEv",
      "_ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEPKc",
      "_ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEv",
      "_ZN3art7Runtime19DeoptimizeBootImageEv",
      "_ZN3art15instrumentation15Instrumentation10DeoptimizeEPNS_9ArtMethodE",
      "_ZN3art3Dbg9StartJdwpEv",
      "_ZN3art3Dbg8GoActiveEv",
      "_ZN3art3Dbg21RequestDeoptimizationERKNS_21DeoptimizationRequestE",
      "_ZN3art3Dbg20ManageDeoptimizationEv",
      "_ZN3art3Dbg9gRegistryE",
      "_ZN3art3jni12JniIdManager14DecodeMethodIdEP10_jmethodID",
      "_ZN3art3jni12JniIdManager13DecodeFieldIdEP9_jfieldID",
      "_ZN3art11interpreter18GetNterpEntryPointEv",
      "_ZN3art7Monitor17TranslateLocationEPNS_9ArtMethodEjPPKcPi"
    ])
  } : {
    functions: {
      _Z20dvmDecodeIndirectRefP6ThreadP8_jobject: ["dvmDecodeIndirectRef", "pointer", ["pointer", "pointer"]],
      _Z15dvmUseJNIBridgeP6MethodPv: ["dvmUseJNIBridge", "void", ["pointer", "pointer"]],
      _Z20dvmHeapSourceGetBasev: ["dvmHeapSourceGetBase", "pointer", []],
      _Z21dvmHeapSourceGetLimitv: ["dvmHeapSourceGetLimit", "pointer", []],
      _Z16dvmIsValidObjectPK6Object: ["dvmIsValidObject", "uint8", ["pointer"]],
      JNI_GetCreatedJavaVMs: ["JNI_GetCreatedJavaVMs", "int", ["pointer", "int", "pointer"]]
    },
    variables: {
      gDvmJni: function(address) {
        this.gDvmJni = address;
      },
      gDvm: function(address) {
        this.gDvm = address;
      }
    }
  };
  const {
    functions = {},
    variables = {},
    optionals = /* @__PURE__ */ new Set()
  } = pending;
  const missing = [];
  for (const [name, signature] of Object.entries(functions)) {
    const address = temporaryApi.find(name);
    if (address !== null) {
      if (typeof signature === "function") {
        signature.call(temporaryApi, address);
      } else {
        temporaryApi[signature[0]] = new NativeFunction(address, signature[1], signature[2], nativeFunctionOptions3);
      }
    } else {
      if (!optionals.has(name)) {
        missing.push(name);
      }
    }
  }
  for (const [name, handler] of Object.entries(variables)) {
    const address = temporaryApi.find(name);
    if (address !== null) {
      handler.call(temporaryApi, address);
    } else {
      if (!optionals.has(name)) {
        missing.push(name);
      }
    }
  }
  if (missing.length > 0) {
    throw new Error("Java API only partially available; please file a bug. Missing: " + missing.join(", "));
  }
  const vms = Memory.alloc(pointerSize5);
  const vmCount = Memory.alloc(jsizeSize);
  checkJniResult("JNI_GetCreatedJavaVMs", temporaryApi.JNI_GetCreatedJavaVMs(vms, 1, vmCount));
  if (vmCount.readInt() === 0) {
    return null;
  }
  temporaryApi.vm = vms.readPointer();
  if (isArt) {
    const apiLevel = getAndroidApiLevel();
    let kAccCompileDontBother;
    if (apiLevel >= 27) {
      kAccCompileDontBother = 33554432;
    } else if (apiLevel >= 24) {
      kAccCompileDontBother = 16777216;
    } else {
      kAccCompileDontBother = 0;
    }
    temporaryApi.kAccCompileDontBother = kAccCompileDontBother;
    const artRuntime = temporaryApi.vm.add(pointerSize5).readPointer();
    temporaryApi.artRuntime = artRuntime;
    const runtimeSpec = getArtRuntimeSpec(temporaryApi);
    const runtimeOffset = runtimeSpec.offset;
    const instrumentationOffset = runtimeOffset.instrumentation;
    temporaryApi.artInstrumentation = instrumentationOffset !== null ? artRuntime.add(instrumentationOffset) : null;
    temporaryApi.artHeap = artRuntime.add(runtimeOffset.heap).readPointer();
    temporaryApi.artThreadList = artRuntime.add(runtimeOffset.threadList).readPointer();
    const classLinker = artRuntime.add(runtimeOffset.classLinker).readPointer();
    const classLinkerOffsets = getArtClassLinkerSpec(artRuntime, runtimeSpec).offset;
    const quickResolutionTrampoline = classLinker.add(classLinkerOffsets.quickResolutionTrampoline).readPointer();
    const quickImtConflictTrampoline = classLinker.add(classLinkerOffsets.quickImtConflictTrampoline).readPointer();
    const quickGenericJniTrampoline = classLinker.add(classLinkerOffsets.quickGenericJniTrampoline).readPointer();
    const quickToInterpreterBridgeTrampoline = classLinker.add(classLinkerOffsets.quickToInterpreterBridgeTrampoline).readPointer();
    temporaryApi.artClassLinker = {
      address: classLinker,
      quickResolutionTrampoline,
      quickImtConflictTrampoline,
      quickGenericJniTrampoline,
      quickToInterpreterBridgeTrampoline
    };
    const vm3 = new VM(temporaryApi);
    temporaryApi.artQuickGenericJniTrampoline = getArtQuickEntrypointFromTrampoline(quickGenericJniTrampoline, vm3);
    temporaryApi.artQuickToInterpreterBridge = getArtQuickEntrypointFromTrampoline(quickToInterpreterBridgeTrampoline, vm3);
    temporaryApi.artQuickResolutionTrampoline = getArtQuickEntrypointFromTrampoline(quickResolutionTrampoline, vm3);
    if (temporaryApi["art::JavaVMExt::AddGlobalRef"] === void 0) {
      temporaryApi["art::JavaVMExt::AddGlobalRef"] = makeAddGlobalRefFallbackForAndroid5(temporaryApi);
    }
    if (temporaryApi["art::JavaVMExt::DecodeGlobal"] === void 0) {
      temporaryApi["art::JavaVMExt::DecodeGlobal"] = makeDecodeGlobalFallback(temporaryApi);
    }
    if (temporaryApi["art::ArtMethod::PrettyMethod"] === void 0) {
      temporaryApi["art::ArtMethod::PrettyMethod"] = temporaryApi["art::ArtMethod::PrettyMethodNullSafe"];
    }
    if (temporaryApi["art::interpreter::GetNterpEntryPoint"] !== void 0) {
      temporaryApi.artNterpEntryPoint = temporaryApi["art::interpreter::GetNterpEntryPoint"]();
    } else {
      temporaryApi.artNterpEntryPoint = temporaryApi.find("ExecuteNterpImpl");
    }
    artController = makeArtController(temporaryApi, vm3);
    fixupArtQuickDeliverExceptionBug(temporaryApi);
    let cachedJvmti = null;
    Object.defineProperty(temporaryApi, "jvmti", {
      get() {
        if (cachedJvmti === null) {
          cachedJvmti = [tryGetEnvJvmti(vm3, this.artRuntime)];
        }
        return cachedJvmti[0];
      }
    });
  }
  const cxxImports = vmModule.enumerateImports().filter((imp) => imp.name.indexOf("_Z") === 0).reduce((result, imp) => {
    result[imp.name] = imp.address;
    return result;
  }, {});
  temporaryApi.$new = new NativeFunction(cxxImports._Znwm || cxxImports._Znwj, "pointer", ["ulong"], nativeFunctionOptions3);
  temporaryApi.$delete = new NativeFunction(cxxImports._ZdlPv, "void", ["pointer"], nativeFunctionOptions3);
  MethodMangler = isArt ? ArtMethodMangler : DalvikMethodMangler;
  return temporaryApi;
}
function tryGetEnvJvmti(vm3, runtime2) {
  let env = null;
  vm3.perform(() => {
    const ensurePluginLoadedAddr = getApi().find("_ZN3art7Runtime18EnsurePluginLoadedEPKcPNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE");
    if (ensurePluginLoadedAddr === null) {
      return;
    }
    const ensurePluginLoaded = new NativeFunction(
      ensurePluginLoadedAddr,
      "bool",
      ["pointer", "pointer", "pointer"]
    );
    const errorPtr = Memory.alloc(pointerSize5);
    const success = ensurePluginLoaded(runtime2, Memory.allocUtf8String("libopenjdkjvmti.so"), errorPtr);
    if (!success) {
      return;
    }
    const kArtTiVersion = jvmtiVersion.v1_2 | 1073741824;
    const handle = vm3.tryGetEnvHandle(kArtTiVersion);
    if (handle === null) {
      return;
    }
    env = new EnvJvmti(handle, vm3);
    const capaBuf = Memory.alloc(8);
    capaBuf.writeU64(jvmtiCapabilities.canTagObjects);
    const result = env.addCapabilities(capaBuf);
    if (result !== JNI_OK) {
      env = null;
    }
  });
  return env;
}
function ensureClassInitialized(env, classRef) {
  const api2 = getApi();
  if (api2.flavor !== "art") {
    return;
  }
  env.getFieldId(classRef, "x", "Z");
  env.exceptionClear();
}
function getArtVMSpec(api2) {
  return {
    offset: pointerSize5 === 4 ? {
      globalsLock: 32,
      globals: 72
    } : {
      globalsLock: 64,
      globals: 112
    }
  };
}
function _getArtRuntimeSpec(api2) {
  const vm3 = api2.vm;
  const runtime2 = api2.artRuntime;
  const startOffset = pointerSize5 === 4 ? 200 : 384;
  const endOffset = startOffset + 100 * pointerSize5;
  const apiLevel = getAndroidApiLevel();
  const codename = getAndroidCodename();
  const { isApiLevel34OrApexEquivalent } = api2;
  let spec = null;
  for (let offset = startOffset; offset !== endOffset; offset += pointerSize5) {
    const value = runtime2.add(offset).readPointer();
    if (value.equals(vm3)) {
      let classLinkerOffsets;
      let jniIdManagerOffset = null;
      if (apiLevel >= 33 || codename === "Tiramisu" || isApiLevel34OrApexEquivalent) {
        classLinkerOffsets = [offset - 4 * pointerSize5];
        jniIdManagerOffset = offset - pointerSize5;
      } else if (apiLevel >= 30 || codename === "R") {
        classLinkerOffsets = [offset - 3 * pointerSize5, offset - 4 * pointerSize5];
        jniIdManagerOffset = offset - pointerSize5;
      } else if (apiLevel >= 29) {
        classLinkerOffsets = [offset - 2 * pointerSize5];
      } else if (apiLevel >= 27) {
        classLinkerOffsets = [offset - STD_STRING_SIZE - 3 * pointerSize5];
      } else {
        classLinkerOffsets = [offset - STD_STRING_SIZE - 2 * pointerSize5];
      }
      for (const classLinkerOffset of classLinkerOffsets) {
        const internTableOffset = classLinkerOffset - pointerSize5;
        const threadListOffset = internTableOffset - pointerSize5;
        let heapOffset;
        if (isApiLevel34OrApexEquivalent) {
          heapOffset = threadListOffset - 9 * pointerSize5;
        } else if (apiLevel >= 24) {
          heapOffset = threadListOffset - 8 * pointerSize5;
        } else if (apiLevel >= 23) {
          heapOffset = threadListOffset - 7 * pointerSize5;
        } else {
          heapOffset = threadListOffset - 4 * pointerSize5;
        }
        const candidate = {
          offset: {
            heap: heapOffset,
            threadList: threadListOffset,
            internTable: internTableOffset,
            classLinker: classLinkerOffset,
            jniIdManager: jniIdManagerOffset
          }
        };
        if (tryGetArtClassLinkerSpec(runtime2, candidate) !== null) {
          spec = candidate;
          break;
        }
      }
      break;
    }
  }
  if (spec === null) {
    throw new Error("Unable to determine Runtime field offsets");
  }
  spec.offset.instrumentation = tryDetectInstrumentationOffset(api2);
  spec.offset.jniIdsIndirection = tryDetectJniIdsIndirectionOffset(api2);
  return spec;
}
var instrumentationOffsetParsers = {
  ia32: parsex86InstrumentationOffset,
  x64: parsex86InstrumentationOffset,
  arm: parseArmInstrumentationOffset,
  arm64: parseArm64InstrumentationOffset
};
function tryDetectInstrumentationOffset(api2) {
  const impl = api2["art::Runtime::DeoptimizeBootImage"];
  if (impl === void 0) {
    return null;
  }
  return parseInstructionsAt(impl, instrumentationOffsetParsers[Process.arch], { limit: 30 });
}
function parsex86InstrumentationOffset(insn) {
  if (insn.mnemonic !== "lea") {
    return null;
  }
  const offset = insn.operands[1].value.disp;
  if (offset < 256 || offset > 1024) {
    return null;
  }
  return offset;
}
function parseArmInstrumentationOffset(insn) {
  if (insn.mnemonic !== "add.w") {
    return null;
  }
  const ops = insn.operands;
  if (ops.length !== 3) {
    return null;
  }
  const op2 = ops[2];
  if (op2.type !== "imm") {
    return null;
  }
  return op2.value;
}
function parseArm64InstrumentationOffset(insn) {
  if (insn.mnemonic !== "add") {
    return null;
  }
  const ops = insn.operands;
  if (ops.length !== 3) {
    return null;
  }
  if (ops[0].value === "sp" || ops[1].value === "sp") {
    return null;
  }
  const op2 = ops[2];
  if (op2.type !== "imm") {
    return null;
  }
  const offset = op2.value.valueOf();
  if (offset < 256 || offset > 1024) {
    return null;
  }
  return offset;
}
var jniIdsIndirectionOffsetParsers = {
  ia32: parsex86JniIdsIndirectionOffset,
  x64: parsex86JniIdsIndirectionOffset,
  arm: parseArmJniIdsIndirectionOffset,
  arm64: parseArm64JniIdsIndirectionOffset
};
function tryDetectJniIdsIndirectionOffset(api2) {
  const impl = api2.find("_ZN3art7Runtime12SetJniIdTypeENS_9JniIdTypeE");
  if (impl === null) {
    return null;
  }
  const offset = parseInstructionsAt(impl, jniIdsIndirectionOffsetParsers[Process.arch], { limit: 20 });
  if (offset === null) {
    throw new Error("Unable to determine Runtime.jni_ids_indirection_ offset");
  }
  return offset;
}
function parsex86JniIdsIndirectionOffset(insn) {
  if (insn.mnemonic === "cmp") {
    return insn.operands[0].value.disp;
  }
  return null;
}
function parseArmJniIdsIndirectionOffset(insn) {
  if (insn.mnemonic === "ldr.w") {
    return insn.operands[1].value.disp;
  }
  return null;
}
function parseArm64JniIdsIndirectionOffset(insn, prevInsn) {
  if (prevInsn === null) {
    return null;
  }
  const { mnemonic } = insn;
  const { mnemonic: prevMnemonic } = prevInsn;
  if (mnemonic === "cmp" && prevMnemonic === "ldr" || mnemonic === "bl" && prevMnemonic === "str") {
    return prevInsn.operands[1].value.disp;
  }
  return null;
}
function _getArtInstrumentationSpec() {
  const deoptimizationEnabledOffsets = {
    "4-21": 136,
    "4-22": 136,
    "4-23": 172,
    "4-24": 196,
    "4-25": 196,
    "4-26": 196,
    "4-27": 196,
    "4-28": 212,
    "4-29": 172,
    "4-30": 180,
    "4-31": 180,
    "8-21": 224,
    "8-22": 224,
    "8-23": 296,
    "8-24": 344,
    "8-25": 344,
    "8-26": 352,
    "8-27": 352,
    "8-28": 392,
    "8-29": 328,
    "8-30": 336,
    "8-31": 336
  };
  const deoptEnabledOffset = deoptimizationEnabledOffsets[`${pointerSize5}-${getAndroidApiLevel()}`];
  if (deoptEnabledOffset === void 0) {
    throw new Error("Unable to determine Instrumentation field offsets");
  }
  return {
    offset: {
      forcedInterpretOnly: 4,
      deoptimizationEnabled: deoptEnabledOffset
    }
  };
}
function getArtClassLinkerSpec(runtime2, runtimeSpec) {
  const spec = tryGetArtClassLinkerSpec(runtime2, runtimeSpec);
  if (spec === null) {
    throw new Error("Unable to determine ClassLinker field offsets");
  }
  return spec;
}
function tryGetArtClassLinkerSpec(runtime2, runtimeSpec) {
  if (cachedArtClassLinkerSpec !== null) {
    return cachedArtClassLinkerSpec;
  }
  const { classLinker: classLinkerOffset, internTable: internTableOffset } = runtimeSpec.offset;
  const classLinker = runtime2.add(classLinkerOffset).readPointer();
  const internTable = runtime2.add(internTableOffset).readPointer();
  const startOffset = pointerSize5 === 4 ? 100 : 200;
  const endOffset = startOffset + 100 * pointerSize5;
  const apiLevel = getAndroidApiLevel();
  let spec = null;
  for (let offset = startOffset; offset !== endOffset; offset += pointerSize5) {
    const value = classLinker.add(offset).readPointer();
    if (value.equals(internTable)) {
      let delta;
      if (apiLevel >= 30 || getAndroidCodename() === "R") {
        delta = 6;
      } else if (apiLevel >= 29) {
        delta = 4;
      } else if (apiLevel >= 23) {
        delta = 3;
      } else {
        delta = 5;
      }
      const quickGenericJniTrampolineOffset = offset + delta * pointerSize5;
      let quickResolutionTrampolineOffset;
      if (apiLevel >= 23) {
        quickResolutionTrampolineOffset = quickGenericJniTrampolineOffset - 2 * pointerSize5;
      } else {
        quickResolutionTrampolineOffset = quickGenericJniTrampolineOffset - 3 * pointerSize5;
      }
      spec = {
        offset: {
          quickResolutionTrampoline: quickResolutionTrampolineOffset,
          quickImtConflictTrampoline: quickGenericJniTrampolineOffset - pointerSize5,
          quickGenericJniTrampoline: quickGenericJniTrampolineOffset,
          quickToInterpreterBridgeTrampoline: quickGenericJniTrampolineOffset + pointerSize5
        }
      };
      break;
    }
  }
  if (spec !== null) {
    cachedArtClassLinkerSpec = spec;
  }
  return spec;
}
function getArtClassSpec(vm3) {
  const MAX_OFFSET = 256;
  let spec = null;
  vm3.perform((env) => {
    const fieldSpec = getArtFieldSpec(vm3);
    const methodSpec = getArtMethodSpec(vm3);
    const fInfo = {
      artArrayLengthSize: 4,
      artArrayEntrySize: fieldSpec.size,
      // java/lang/Thread has 36 fields on Android 16.
      artArrayMax: 50
    };
    const mInfo = {
      artArrayLengthSize: pointerSize5,
      artArrayEntrySize: methodSpec.size,
      // java/lang/Thread has 79 methods on Android 16.
      artArrayMax: 100
    };
    const readArtArray = (objectBase, fieldOffset, lengthSize) => {
      const header = objectBase.add(fieldOffset).readPointer();
      if (header.isNull()) {
        return null;
      }
      const length = lengthSize === 4 ? header.readU32() : header.readU64().valueOf();
      if (length <= 0) {
        return null;
      }
      return {
        length,
        data: header.add(lengthSize)
      };
    };
    const hasEntry = (objectBase, offset, needle, info) => {
      try {
        const artArray = readArtArray(objectBase, offset, info.artArrayLengthSize);
        if (artArray === null) {
          return false;
        }
        const artArrayEnd = Math.min(artArray.length, info.artArrayMax);
        for (let i = 0; i !== artArrayEnd; i++) {
          const fieldPtr = artArray.data.add(i * info.artArrayEntrySize);
          if (fieldPtr.equals(needle)) {
            return true;
          }
        }
      } catch {
      }
      return false;
    };
    const clazz = env.findClass("java/lang/Thread");
    const clazzRef = env.newGlobalRef(clazz);
    try {
      let object;
      withRunnableArtThread(vm3, env, (thread) => {
        object = getApi()["art::JavaVMExt::DecodeGlobal"](vm3, thread, clazzRef);
      });
      const fieldInstance = unwrapFieldId(env.getFieldId(clazzRef, "name", "Ljava/lang/String;"));
      const fieldStatic = unwrapFieldId(env.getStaticFieldId(clazzRef, "MAX_PRIORITY", "I"));
      let offsetStatic = -1;
      let offsetInstance = -1;
      for (let offset = 0; offset !== MAX_OFFSET; offset += 4) {
        if (offsetStatic === -1 && hasEntry(object, offset, fieldStatic, fInfo)) {
          offsetStatic = offset;
        }
        if (offsetInstance === -1 && hasEntry(object, offset, fieldInstance, fInfo)) {
          offsetInstance = offset;
        }
      }
      if (offsetInstance === -1 || offsetStatic === -1) {
        throw new Error("Unable to find fields in java/lang/Thread; please file a bug");
      }
      const sfieldOffset = offsetInstance !== offsetStatic ? offsetStatic : 0;
      const ifieldOffset = offsetInstance;
      let offsetMethods = -1;
      const methodInstance = unwrapMethodId(env.getMethodId(clazzRef, "getName", "()Ljava/lang/String;"));
      for (let offset = 0; offset !== MAX_OFFSET; offset += 4) {
        if (offsetMethods === -1 && hasEntry(object, offset, methodInstance, mInfo)) {
          offsetMethods = offset;
        }
      }
      if (offsetMethods === -1) {
        throw new Error("Unable to find methods in java/lang/Thread; please file a bug");
      }
      let offsetCopiedMethods = -1;
      const methodsArray = readArtArray(object, offsetMethods, mInfo.artArrayLengthSize);
      const methodsArraySize = methodsArray.length;
      for (let offset = offsetMethods; offset !== MAX_OFFSET; offset += 4) {
        if (object.add(offset).readU16() === methodsArraySize) {
          offsetCopiedMethods = offset;
          break;
        }
      }
      if (offsetCopiedMethods === -1) {
        throw new Error("Unable to find copied methods in java/lang/Thread; please file a bug");
      }
      spec = {
        offset: {
          ifields: ifieldOffset,
          methods: offsetMethods,
          sfields: sfieldOffset,
          copiedMethodsOffset: offsetCopiedMethods
        }
      };
    } finally {
      env.deleteLocalRef(clazz);
      env.deleteGlobalRef(clazzRef);
    }
  });
  return spec;
}
function _getArtMethodSpec(vm3) {
  const api2 = getApi();
  let spec;
  vm3.perform((env) => {
    const process = env.findClass("android/os/Process");
    const getElapsedCpuTime = unwrapMethodId(env.getStaticMethodId(process, "getElapsedCpuTime", "()J"));
    env.deleteLocalRef(process);
    const runtimeModule = Process.getModuleByName("libandroid_runtime.so");
    const runtimeStart = runtimeModule.base;
    const runtimeEnd = runtimeStart.add(runtimeModule.size);
    const apiLevel = getAndroidApiLevel();
    const entrypointFieldSize = apiLevel <= 21 ? 8 : pointerSize5;
    const expectedAccessFlags = kAccPublic | kAccStatic | kAccFinal | kAccNative;
    const relevantAccessFlagsMask = ~(kAccFastInterpreterToInterpreterInvoke | kAccPublicApi | kAccNterpInvokeFastPathFlag) >>> 0;
    let jniCodeOffset = null;
    let accessFlagsOffset = null;
    let remaining = 2;
    for (let offset = 0; offset !== 64 && remaining !== 0; offset += 4) {
      const field = getElapsedCpuTime.add(offset);
      if (jniCodeOffset === null) {
        const address = field.readPointer();
        if (address.compare(runtimeStart) >= 0 && address.compare(runtimeEnd) < 0) {
          jniCodeOffset = offset;
          remaining--;
        }
      }
      if (accessFlagsOffset === null) {
        const flags = field.readU32();
        if ((flags & relevantAccessFlagsMask) === expectedAccessFlags) {
          accessFlagsOffset = offset;
          remaining--;
        }
      }
    }
    if (remaining !== 0) {
      throw new Error("Unable to determine ArtMethod field offsets");
    }
    const quickCodeOffset = jniCodeOffset + entrypointFieldSize;
    const size = apiLevel <= 21 ? quickCodeOffset + 32 : quickCodeOffset + pointerSize5;
    spec = {
      size,
      offset: {
        jniCode: jniCodeOffset,
        quickCode: quickCodeOffset,
        accessFlags: accessFlagsOffset
      }
    };
    if ("artInterpreterToCompiledCodeBridge" in api2) {
      spec.offset.interpreterCode = jniCodeOffset - entrypointFieldSize;
    }
  });
  return spec;
}
function getArtFieldSpec(vm3) {
  const apiLevel = getAndroidApiLevel();
  if (apiLevel >= 23) {
    return {
      size: 16,
      offset: {
        accessFlags: 4
      }
    };
  }
  if (apiLevel >= 21) {
    return {
      size: 24,
      offset: {
        accessFlags: 12
      }
    };
  }
  return null;
}
function _getArtThreadSpec(vm3) {
  const apiLevel = getAndroidApiLevel();
  let spec;
  vm3.perform((env) => {
    const threadHandle = getArtThreadFromEnv(env);
    const envHandle = env.handle;
    let isExceptionReportedOffset = null;
    let exceptionOffset = null;
    let throwLocationOffset = null;
    let topHandleScopeOffset = null;
    let managedStackOffset = null;
    let selfOffset = null;
    for (let offset = 144; offset !== 256; offset += pointerSize5) {
      const field = threadHandle.add(offset);
      const value = field.readPointer();
      if (value.equals(envHandle)) {
        exceptionOffset = offset - 6 * pointerSize5;
        managedStackOffset = offset - 4 * pointerSize5;
        selfOffset = offset + 2 * pointerSize5;
        if (apiLevel <= 22) {
          exceptionOffset -= pointerSize5;
          isExceptionReportedOffset = exceptionOffset - pointerSize5 - 9 * 8 - 3 * 4;
          throwLocationOffset = offset + 6 * pointerSize5;
          managedStackOffset -= pointerSize5;
          selfOffset -= pointerSize5;
        }
        topHandleScopeOffset = offset + 9 * pointerSize5;
        if (apiLevel <= 22) {
          topHandleScopeOffset += 2 * pointerSize5 + 4;
          if (pointerSize5 === 8) {
            topHandleScopeOffset += 4;
          }
        }
        if (apiLevel >= 23) {
          topHandleScopeOffset += pointerSize5;
        }
        break;
      }
    }
    if (topHandleScopeOffset === null) {
      throw new Error("Unable to determine ArtThread field offsets");
    }
    spec = {
      offset: {
        isExceptionReportedToInstrumentation: isExceptionReportedOffset,
        exception: exceptionOffset,
        throwLocation: throwLocationOffset,
        topHandleScope: topHandleScopeOffset,
        managedStack: managedStackOffset,
        self: selfOffset
      }
    };
  });
  return spec;
}
function _getArtManagedStackSpec() {
  const apiLevel = getAndroidApiLevel();
  if (apiLevel >= 23) {
    return {
      offset: {
        topQuickFrame: 0,
        link: pointerSize5
      }
    };
  } else {
    return {
      offset: {
        topQuickFrame: 2 * pointerSize5,
        link: 0
      }
    };
  }
}
var artQuickTrampolineParsers = {
  ia32: parseArtQuickTrampolineX86,
  x64: parseArtQuickTrampolineX86,
  arm: parseArtQuickTrampolineArm,
  arm64: parseArtQuickTrampolineArm64
};
function getArtQuickEntrypointFromTrampoline(trampoline, vm3) {
  let address;
  vm3.perform((env) => {
    const thread = getArtThreadFromEnv(env);
    const tryParse = artQuickTrampolineParsers[Process.arch];
    const insn = Instruction.parse(trampoline);
    const offset = tryParse(insn);
    if (offset !== null) {
      address = thread.add(offset).readPointer();
    } else {
      address = trampoline;
    }
  });
  return address;
}
function parseArtQuickTrampolineX86(insn) {
  if (insn.mnemonic === "jmp") {
    return insn.operands[0].value.disp;
  }
  return null;
}
function parseArtQuickTrampolineArm(insn) {
  if (insn.mnemonic === "ldr.w") {
    return insn.operands[1].value.disp;
  }
  return null;
}
function parseArtQuickTrampolineArm64(insn) {
  if (insn.mnemonic === "ldr") {
    return insn.operands[1].value.disp;
  }
  return null;
}
function getArtThreadFromEnv(env) {
  return env.handle.add(pointerSize5).readPointer();
}
function _getAndroidVersion() {
  return getAndroidSystemProperty("ro.build.version.release");
}
function _getAndroidCodename() {
  return getAndroidSystemProperty("ro.build.version.codename");
}
function _getAndroidApiLevel() {
  return parseInt(getAndroidSystemProperty("ro.build.version.sdk"), 10);
}
var systemPropertyGet = null;
var PROP_VALUE_MAX = 92;
function getAndroidSystemProperty(name) {
  if (systemPropertyGet === null) {
    systemPropertyGet = new NativeFunction(
      Process.getModuleByName("libc.so").getExportByName("__system_property_get"),
      "int",
      ["pointer", "pointer"],
      nativeFunctionOptions3
    );
  }
  const buf = Memory.alloc(PROP_VALUE_MAX);
  systemPropertyGet(Memory.allocUtf8String(name), buf);
  return buf.readUtf8String();
}
function withRunnableArtThread(vm3, env, fn) {
  const perform = getArtThreadStateTransitionImpl(vm3, env);
  const id = getArtThreadFromEnv(env).toString();
  artThreadStateTransitions[id] = fn;
  perform(env.handle);
  if (artThreadStateTransitions[id] !== void 0) {
    delete artThreadStateTransitions[id];
    throw new Error("Unable to perform state transition; please file a bug");
  }
}
function _getArtThreadStateTransitionImpl(vm3, env) {
  const callback = new NativeCallback(onThreadStateTransitionComplete, "void", ["pointer"]);
  return makeArtThreadStateTransitionImpl(vm3, env, callback);
}
function onThreadStateTransitionComplete(thread) {
  const id = thread.toString();
  const fn = artThreadStateTransitions[id];
  delete artThreadStateTransitions[id];
  fn(thread);
}
function withAllArtThreadsSuspended(fn) {
  const api2 = getApi();
  const threadList = api2.artThreadList;
  const longSuspend = false;
  api2["art::ThreadList::SuspendAll"](threadList, Memory.allocUtf8String("frida"), longSuspend ? 1 : 0);
  try {
    fn();
  } finally {
    api2["art::ThreadList::ResumeAll"](threadList);
  }
}
var ArtClassVisitor = class {
  constructor(visit) {
    const visitor = Memory.alloc(4 * pointerSize5);
    const vtable2 = visitor.add(pointerSize5);
    visitor.writePointer(vtable2);
    const onVisit = new NativeCallback((self, klass) => {
      return visit(klass) === true ? 1 : 0;
    }, "bool", ["pointer", "pointer"]);
    vtable2.add(2 * pointerSize5).writePointer(onVisit);
    this.handle = visitor;
    this._onVisit = onVisit;
  }
};
function makeArtClassVisitor(visit) {
  const api2 = getApi();
  if (api2["art::ClassLinker::VisitClasses"] instanceof NativeFunction) {
    return new ArtClassVisitor(visit);
  }
  return new NativeCallback((klass) => {
    return visit(klass) === true ? 1 : 0;
  }, "bool", ["pointer", "pointer"]);
}
var ArtClassLoaderVisitor = class {
  constructor(visit) {
    const visitor = Memory.alloc(4 * pointerSize5);
    const vtable2 = visitor.add(pointerSize5);
    visitor.writePointer(vtable2);
    const onVisit = new NativeCallback((self, klass) => {
      visit(klass);
    }, "void", ["pointer", "pointer"]);
    vtable2.add(2 * pointerSize5).writePointer(onVisit);
    this.handle = visitor;
    this._onVisit = onVisit;
  }
};
function makeArtClassLoaderVisitor(visit) {
  return new ArtClassLoaderVisitor(visit);
}
var WalkKind = {
  "include-inlined-frames": 0,
  "skip-inlined-frames": 1
};
var ArtStackVisitor = class {
  constructor(thread, context, walkKind, numFrames = 0, checkSuspended = true) {
    const api2 = getApi();
    const baseSize = 512;
    const vtableSize = 3 * pointerSize5;
    const visitor = Memory.alloc(baseSize + vtableSize);
    api2["art::StackVisitor::StackVisitor"](
      visitor,
      thread,
      context,
      WalkKind[walkKind],
      numFrames,
      checkSuspended ? 1 : 0
    );
    const vtable2 = visitor.add(baseSize);
    visitor.writePointer(vtable2);
    const onVisitFrame = new NativeCallback(this._visitFrame.bind(this), "bool", ["pointer"]);
    vtable2.add(2 * pointerSize5).writePointer(onVisitFrame);
    this.handle = visitor;
    this._onVisitFrame = onVisitFrame;
    const curShadowFrame = visitor.add(pointerSize5 === 4 ? 12 : 24);
    this._curShadowFrame = curShadowFrame;
    this._curQuickFrame = curShadowFrame.add(pointerSize5);
    this._curQuickFramePc = curShadowFrame.add(2 * pointerSize5);
    this._curOatQuickMethodHeader = curShadowFrame.add(3 * pointerSize5);
    this._getMethodImpl = api2["art::StackVisitor::GetMethod"];
    this._descLocImpl = api2["art::StackVisitor::DescribeLocation"];
    this._getCQFIImpl = api2["art::StackVisitor::GetCurrentQuickFrameInfo"];
  }
  walkStack(includeTransitions = false) {
    getApi()["art::StackVisitor::WalkStack"](this.handle, includeTransitions ? 1 : 0);
  }
  _visitFrame() {
    return this.visitFrame() ? 1 : 0;
  }
  visitFrame() {
    throw new Error("Subclass must implement visitFrame");
  }
  getMethod() {
    const methodHandle = this._getMethodImpl(this.handle);
    if (methodHandle.isNull()) {
      return null;
    }
    return new ArtMethod(methodHandle);
  }
  getCurrentQuickFramePc() {
    return this._curQuickFramePc.readPointer();
  }
  getCurrentQuickFrame() {
    return this._curQuickFrame.readPointer();
  }
  getCurrentShadowFrame() {
    return this._curShadowFrame.readPointer();
  }
  describeLocation() {
    const result = new StdString();
    this._descLocImpl(result, this.handle);
    return result.disposeToString();
  }
  getCurrentOatQuickMethodHeader() {
    return this._curOatQuickMethodHeader.readPointer();
  }
  getCurrentQuickFrameInfo() {
    return this._getCQFIImpl(this.handle);
  }
};
var ArtMethod = class {
  constructor(handle) {
    this.handle = handle;
  }
  prettyMethod(withSignature = true) {
    const result = new StdString();
    getApi()["art::ArtMethod::PrettyMethod"](result, this.handle, withSignature ? 1 : 0);
    return result.disposeToString();
  }
  toString() {
    return `ArtMethod(handle=${this.handle})`;
  }
};
function makeArtQuickFrameInfoGetter(impl) {
  return function(self) {
    const result = Memory.alloc(12);
    getArtQuickFrameInfoGetterThunk(impl)(result, self);
    return {
      frameSizeInBytes: result.readU32(),
      coreSpillMask: result.add(4).readU32(),
      fpSpillMask: result.add(8).readU32()
    };
  };
}
function _getArtQuickFrameInfoGetterThunk(impl) {
  let thunk = NULL;
  switch (Process.arch) {
    case "ia32":
      thunk = makeThunk(32, (writer) => {
        writer.putMovRegRegOffsetPtr("ecx", "esp", 4);
        writer.putMovRegRegOffsetPtr("edx", "esp", 8);
        writer.putCallAddressWithArguments(impl, ["ecx", "edx"]);
        writer.putMovRegReg("esp", "ebp");
        writer.putPopReg("ebp");
        writer.putRet();
      });
      break;
    case "x64":
      thunk = makeThunk(32, (writer) => {
        writer.putPushReg("rdi");
        writer.putCallAddressWithArguments(impl, ["rsi"]);
        writer.putPopReg("rdi");
        writer.putMovRegPtrReg("rdi", "rax");
        writer.putMovRegOffsetPtrReg("rdi", 8, "edx");
        writer.putRet();
      });
      break;
    case "arm":
      thunk = makeThunk(16, (writer) => {
        writer.putCallAddressWithArguments(impl, ["r0", "r1"]);
        writer.putPopRegs(["r0", "lr"]);
        writer.putMovRegReg("pc", "lr");
      });
      break;
    case "arm64":
      thunk = makeThunk(64, (writer) => {
        writer.putPushRegReg("x0", "lr");
        writer.putCallAddressWithArguments(impl, ["x1"]);
        writer.putPopRegReg("x2", "lr");
        writer.putStrRegRegOffset("x0", "x2", 0);
        writer.putStrRegRegOffset("w1", "x2", 8);
        writer.putRet();
      });
      break;
  }
  return new NativeFunction(thunk, "void", ["pointer", "pointer"], nativeFunctionOptions3);
}
var thunkRelocators = {
  ia32: globalThis.X86Relocator,
  x64: globalThis.X86Relocator,
  arm: globalThis.ThumbRelocator,
  arm64: globalThis.Arm64Relocator
};
var thunkWriters = {
  ia32: globalThis.X86Writer,
  x64: globalThis.X86Writer,
  arm: globalThis.ThumbWriter,
  arm64: globalThis.Arm64Writer
};
function makeThunk(size, write3) {
  if (thunkPage === null) {
    thunkPage = Memory.alloc(Process.pageSize);
  }
  const thunk = thunkPage.add(thunkOffset);
  const arch = Process.arch;
  const Writer = thunkWriters[arch];
  Memory.patchCode(thunk, size, (code3) => {
    const writer = new Writer(code3, { pc: thunk });
    write3(writer);
    writer.flush();
    if (writer.offset > size) {
      throw new Error(`Wrote ${writer.offset}, exceeding maximum of ${size}`);
    }
  });
  thunkOffset += size;
  return arch === "arm" ? thunk.or(1) : thunk;
}
function notifyArtMethodHooked(method, vm3) {
  ensureArtKnowsHowToHandleMethodInstrumentation(vm3);
  ensureArtKnowsHowToHandleReplacementMethods(vm3);
}
function makeArtController(api2, vm3) {
  const threadOffsets = getArtThreadSpec(vm3).offset;
  const managedStackOffsets = getArtManagedStackSpec().offset;
  const code3 = `
#include <gum/guminterceptor.h>

extern GMutex lock;
extern GHashTable * methods;
extern GHashTable * replacements;
extern gpointer last_seen_art_method;

extern gpointer get_oat_quick_method_header_impl (gpointer method, gpointer pc);

void
init (void)
{
  g_mutex_init (&lock);
  methods = g_hash_table_new_full (NULL, NULL, NULL, NULL);
  replacements = g_hash_table_new_full (NULL, NULL, NULL, NULL);
}

void
finalize (void)
{
  g_hash_table_unref (replacements);
  g_hash_table_unref (methods);
  g_mutex_clear (&lock);
}

gboolean
is_replacement_method (gpointer method)
{
  gboolean is_replacement;

  g_mutex_lock (&lock);

  is_replacement = g_hash_table_contains (replacements, method);

  g_mutex_unlock (&lock);

  return is_replacement;
}

gpointer
get_replacement_method (gpointer original_method)
{
  gpointer replacement_method;

  g_mutex_lock (&lock);

  replacement_method = g_hash_table_lookup (methods, original_method);

  g_mutex_unlock (&lock);

  return replacement_method;
}

void
set_replacement_method (gpointer original_method,
                        gpointer replacement_method)
{
  g_mutex_lock (&lock);

  g_hash_table_insert (methods, original_method, replacement_method);
  g_hash_table_insert (replacements, replacement_method, original_method);

  g_mutex_unlock (&lock);
}

void
delete_replacement_method (gpointer original_method)
{
  gpointer replacement_method;

  g_mutex_lock (&lock);

  replacement_method = g_hash_table_lookup (methods, original_method);
  if (replacement_method != NULL)
  {
    g_hash_table_remove (methods, original_method);
    g_hash_table_remove (replacements, replacement_method);
  }

  g_mutex_unlock (&lock);
}

gpointer
translate_method (gpointer method)
{
  gpointer translated_method;

  g_mutex_lock (&lock);

  translated_method = g_hash_table_lookup (replacements, method);

  g_mutex_unlock (&lock);

  return (translated_method != NULL) ? translated_method : method;
}

gpointer
find_replacement_method_from_quick_code (gpointer method,
                                         gpointer thread)
{
  gpointer replacement_method;
  gpointer managed_stack;
  gpointer top_quick_frame;
  gpointer link_managed_stack;
  gpointer * link_top_quick_frame;

  replacement_method = get_replacement_method (method);
  if (replacement_method == NULL)
    return NULL;

  /*
   * Stack check.
   *
   * Return NULL to indicate that the original method should be invoked, otherwise
   * return a pointer to the replacement ArtMethod.
   *
   * If the caller is our own JNI replacement stub, then a stack transition must
   * have been pushed onto the current thread's linked list.
   *
   * Therefore, we invoke the original method if the following conditions are met:
   *   1- The current managed stack is empty.
   *   2- The ArtMethod * inside the linked managed stack's top quick frame is the
   *      same as our replacement.
   */
  managed_stack = thread + ${threadOffsets.managedStack};
  top_quick_frame = *((gpointer *) (managed_stack + ${managedStackOffsets.topQuickFrame}));
  if (top_quick_frame != NULL)
    return replacement_method;

  link_managed_stack = *((gpointer *) (managed_stack + ${managedStackOffsets.link}));
  if (link_managed_stack == NULL)
    return replacement_method;

  link_top_quick_frame = GSIZE_TO_POINTER (*((gsize *) (link_managed_stack + ${managedStackOffsets.topQuickFrame})) & ~((gsize) 1));
  if (link_top_quick_frame == NULL || *link_top_quick_frame != replacement_method)
    return replacement_method;

  return NULL;
}

void
on_interpreter_do_call (GumInvocationContext * ic)
{
  gpointer method, replacement_method;

  method = gum_invocation_context_get_nth_argument (ic, 0);

  replacement_method = get_replacement_method (method);
  if (replacement_method != NULL)
    gum_invocation_context_replace_nth_argument (ic, 0, replacement_method);
}

gpointer
on_art_method_get_oat_quick_method_header (gpointer method,
                                           gpointer pc)
{
  if (is_replacement_method (method))
    return NULL;

  return get_oat_quick_method_header_impl (method, pc);
}

void
on_art_method_pretty_method (GumInvocationContext * ic)
{
  const guint this_arg_index = ${Process.arch === "arm64" ? 0 : 1};
  gpointer method;

  method = gum_invocation_context_get_nth_argument (ic, this_arg_index);
  if (method == NULL)
    gum_invocation_context_replace_nth_argument (ic, this_arg_index, last_seen_art_method);
  else
    last_seen_art_method = method;
}

void
on_leave_gc_concurrent_copying_copying_phase (GumInvocationContext * ic)
{
  GHashTableIter iter;
  gpointer hooked_method, replacement_method;

  g_mutex_lock (&lock);

  g_hash_table_iter_init (&iter, methods);
  while (g_hash_table_iter_next (&iter, &hooked_method, &replacement_method))
    *((uint32_t *) replacement_method) = *((uint32_t *) hooked_method);

  g_mutex_unlock (&lock);
}
`;
  const lockSize = 8;
  const methodsSize = pointerSize5;
  const replacementsSize = pointerSize5;
  const lastSeenArtMethodSize = pointerSize5;
  const data = Memory.alloc(lockSize + methodsSize + replacementsSize + lastSeenArtMethodSize);
  const lock = data;
  const methods = lock.add(lockSize);
  const replacements = methods.add(methodsSize);
  const lastSeenArtMethod = replacements.add(replacementsSize);
  const getOatQuickMethodHeaderImpl = api2.find(pointerSize5 === 4 ? "_ZN3art9ArtMethod23GetOatQuickMethodHeaderEj" : "_ZN3art9ArtMethod23GetOatQuickMethodHeaderEm");
  const cm2 = new CModule(code3, {
    lock,
    methods,
    replacements,
    last_seen_art_method: lastSeenArtMethod,
    get_oat_quick_method_header_impl: getOatQuickMethodHeaderImpl ?? ptr("0xdeadbeef")
  });
  const fastOptions = { exceptions: "propagate", scheduling: "exclusive" };
  return {
    handle: cm2,
    replacedMethods: {
      isReplacement: new NativeFunction(cm2.is_replacement_method, "bool", ["pointer"], fastOptions),
      get: new NativeFunction(cm2.get_replacement_method, "pointer", ["pointer"], fastOptions),
      set: new NativeFunction(cm2.set_replacement_method, "void", ["pointer", "pointer"], fastOptions),
      delete: new NativeFunction(cm2.delete_replacement_method, "void", ["pointer"], fastOptions),
      translate: new NativeFunction(cm2.translate_method, "pointer", ["pointer"], fastOptions),
      findReplacementFromQuickCode: cm2.find_replacement_method_from_quick_code
    },
    getOatQuickMethodHeaderImpl,
    hooks: {
      Interpreter: {
        doCall: cm2.on_interpreter_do_call
      },
      ArtMethod: {
        getOatQuickMethodHeader: cm2.on_art_method_get_oat_quick_method_header,
        prettyMethod: cm2.on_art_method_pretty_method
      },
      Gc: {
        copyingPhase: {
          onLeave: cm2.on_leave_gc_concurrent_copying_copying_phase
        },
        runFlip: {
          onEnter: cm2.on_leave_gc_concurrent_copying_copying_phase
        }
      }
    }
  };
}
function ensureArtKnowsHowToHandleMethodInstrumentation(vm3) {
  if (taughtArtAboutMethodInstrumentation) {
    return;
  }
  taughtArtAboutMethodInstrumentation = true;
  instrumentArtQuickEntrypoints(vm3);
  instrumentArtMethodInvocationFromInterpreter();
}
function instrumentArtQuickEntrypoints(vm3) {
  const api2 = getApi();
  const quickEntrypoints = [
    api2.artQuickGenericJniTrampoline,
    api2.artQuickToInterpreterBridge,
    api2.artQuickResolutionTrampoline
  ];
  quickEntrypoints.forEach((entrypoint) => {
    Memory.protect(entrypoint, 32, "rwx");
    const interceptor = new ArtQuickCodeInterceptor(entrypoint);
    interceptor.activate(vm3);
    artQuickInterceptors.push(interceptor);
  });
}
function instrumentArtMethodInvocationFromInterpreter() {
  const api2 = getApi();
  const apiLevel = getAndroidApiLevel();
  const { isApiLevel34OrApexEquivalent } = api2;
  let artInterpreterDoCallExportRegex;
  if (apiLevel <= 22) {
    artInterpreterDoCallExportRegex = /^_ZN3art11interpreter6DoCallILb[0-1]ELb[0-1]EEEbPNS_6mirror9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE$/;
  } else if (apiLevel <= 33 && !isApiLevel34OrApexEquivalent) {
    artInterpreterDoCallExportRegex = /^_ZN3art11interpreter6DoCallILb[0-1]ELb[0-1]EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE$/;
  } else if (isApiLevel34OrApexEquivalent) {
    artInterpreterDoCallExportRegex = /^_ZN3art11interpreter6DoCallILb[0-1]EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtbPNS_6JValueE$/;
  } else {
    throw new Error("Unable to find method invocation in ART; please file a bug");
  }
  const art = api2.module;
  const entries = [...art.enumerateExports(), ...art.enumerateSymbols()].filter((entry) => artInterpreterDoCallExportRegex.test(entry.name));
  if (entries.length === 0) {
    throw new Error("Unable to find method invocation in ART; please file a bug");
  }
  for (const entry of entries) {
    Interceptor.attach(entry.address, artController.hooks.Interpreter.doCall);
  }
}
function ensureArtKnowsHowToHandleReplacementMethods(vm3) {
  if (taughtArtAboutReplacementMethods) {
    return;
  }
  taughtArtAboutReplacementMethods = true;
  if (!maybeInstrumentGetOatQuickMethodHeaderInlineCopies()) {
    const { getOatQuickMethodHeaderImpl } = artController;
    if (getOatQuickMethodHeaderImpl === null) {
      return;
    }
    try {
      Interceptor.replace(getOatQuickMethodHeaderImpl, artController.hooks.ArtMethod.getOatQuickMethodHeader);
    } catch (e) {
    }
  }
  const apiLevel = getAndroidApiLevel();
  let copyingPhase = null;
  const api2 = getApi();
  if (apiLevel > 28) {
    copyingPhase = api2.find("_ZN3art2gc9collector17ConcurrentCopying12CopyingPhaseEv");
  } else if (apiLevel > 22) {
    copyingPhase = api2.find("_ZN3art2gc9collector17ConcurrentCopying12MarkingPhaseEv");
  }
  if (copyingPhase !== null) {
    Interceptor.attach(copyingPhase, artController.hooks.Gc.copyingPhase);
  }
  let runFlip = null;
  runFlip = api2.find("_ZN3art6Thread15RunFlipFunctionEPS0_");
  if (runFlip === null) {
    runFlip = api2.find("_ZN3art6Thread15RunFlipFunctionEPS0_b");
  }
  if (runFlip !== null) {
    Interceptor.attach(runFlip, artController.hooks.Gc.runFlip);
  }
}
var artGetOatQuickMethodHeaderInlinedCopyHandler = {
  arm: {
    signatures: [
      {
        pattern: [
          "b0 68",
          // ldr r0, [r6, #8]
          "01 30",
          // adds r0, #1
          "0c d0",
          // beq #0x16fcd4
          "1b 98",
          // ldr r0, [sp, #0x6c]
          ":",
          "c0 ff",
          "c0 ff",
          "00 ff",
          "00 2f"
        ],
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm
      },
      {
        pattern: [
          "d8 f8 08 00",
          // ldr r0, [r8, #8]
          "01 30",
          // adds r0, #1
          "0c d0",
          // beq #0x16fcd4
          "1b 98",
          // ldr r0, [sp, #0x6c]
          ":",
          "f0 ff ff 0f",
          "ff ff",
          "00 ff",
          "00 2f"
        ],
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm
      },
      {
        pattern: [
          "b0 68",
          // ldr r0, [r6, #8]
          "01 30",
          // adds r0, #1
          "40 f0 c3 80",
          // bne #0x203bf0
          "00 25",
          // movs r5, #0
          ":",
          "c0 ff",
          "c0 ff",
          "c0 fb 00 d0",
          "ff f8"
        ],
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm
      }
    ],
    instrument: instrumentGetOatQuickMethodHeaderInlinedCopyArm
  },
  arm64: {
    signatures: [
      {
        pattern: [
          /* e8 */
          "0a 40 b9",
          // ldr w8, [x23, #0x8]
          "1f 05 00 31",
          // cmn w8, #0x1
          "40 01 00 54",
          // b.eq 0x2e4204
          "88 39 00 f0",
          // adrp x8, 0xa17000
          ":",
          /* 00 */
          "fc ff ff",
          "1f fc ff ff",
          "1f 00 00 ff",
          "00 00 00 9f"
        ],
        offset: 1,
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm64
      },
      {
        pattern: [
          /* e8 */
          "0a 40 b9",
          // ldr w8, [x23, #0x8]
          "1f 05 00 31",
          // cmn w8, #0x1
          "01 34 00 54",
          // b.ne 0x3d8e50
          "e0 03 1f aa",
          // mov x0, xzr
          ":",
          /* 00 */
          "fc ff ff",
          "1f fc ff ff",
          "1f 00 00 ff",
          "e0 ff ff ff"
        ],
        offset: 1,
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm64
      }
    ],
    instrument: instrumentGetOatQuickMethodHeaderInlinedCopyArm64
  }
};
function validateGetOatQuickMethodHeaderInlinedMatchArm({ address, size }) {
  const ldr = Instruction.parse(address.or(1));
  const [ldrDst, ldrSrc] = ldr.operands;
  const methodReg = ldrSrc.value.base;
  const scratchReg = ldrDst.value;
  const branch = Instruction.parse(ldr.next.add(2));
  const targetWhenTrue = ptr(branch.operands[0].value);
  const targetWhenFalse = branch.address.add(branch.size);
  let targetWhenRegularMethod, targetWhenRuntimeMethod;
  if (branch.mnemonic === "beq") {
    targetWhenRegularMethod = targetWhenFalse;
    targetWhenRuntimeMethod = targetWhenTrue;
  } else {
    targetWhenRegularMethod = targetWhenTrue;
    targetWhenRuntimeMethod = targetWhenFalse;
  }
  return parseInstructionsAt(targetWhenRegularMethod.or(1), tryParse, { limit: 3 });
  function tryParse(insn) {
    const { mnemonic } = insn;
    if (!(mnemonic === "ldr" || mnemonic === "ldr.w")) {
      return null;
    }
    const { base, disp } = insn.operands[1].value;
    if (!(base === methodReg && disp === 20)) {
      return null;
    }
    return {
      methodReg,
      scratchReg,
      target: {
        whenTrue: targetWhenTrue,
        whenRegularMethod: targetWhenRegularMethod,
        whenRuntimeMethod: targetWhenRuntimeMethod
      }
    };
  }
}
function validateGetOatQuickMethodHeaderInlinedMatchArm64({ address, size }) {
  const [ldrDst, ldrSrc] = Instruction.parse(address).operands;
  const methodReg = ldrSrc.value.base;
  const scratchReg = "x" + ldrDst.value.substring(1);
  const branch = Instruction.parse(address.add(8));
  const targetWhenTrue = ptr(branch.operands[0].value);
  const targetWhenFalse = address.add(12);
  let targetWhenRegularMethod, targetWhenRuntimeMethod;
  if (branch.mnemonic === "b.eq") {
    targetWhenRegularMethod = targetWhenFalse;
    targetWhenRuntimeMethod = targetWhenTrue;
  } else {
    targetWhenRegularMethod = targetWhenTrue;
    targetWhenRuntimeMethod = targetWhenFalse;
  }
  return parseInstructionsAt(targetWhenRegularMethod, tryParse, { limit: 3 });
  function tryParse(insn) {
    if (insn.mnemonic !== "ldr") {
      return null;
    }
    const { base, disp } = insn.operands[1].value;
    if (!(base === methodReg && disp === 24)) {
      return null;
    }
    return {
      methodReg,
      scratchReg,
      target: {
        whenTrue: targetWhenTrue,
        whenRegularMethod: targetWhenRegularMethod,
        whenRuntimeMethod: targetWhenRuntimeMethod
      }
    };
  }
}
function maybeInstrumentGetOatQuickMethodHeaderInlineCopies() {
  if (getAndroidApiLevel() < 31) {
    return false;
  }
  const handler = artGetOatQuickMethodHeaderInlinedCopyHandler[Process.arch];
  if (handler === void 0) {
    return false;
  }
  const signatures = handler.signatures.map(({ pattern, offset = 0, validateMatch = returnEmptyObject }) => {
    return {
      pattern: new MatchPattern(pattern.join("")),
      offset,
      validateMatch
    };
  });
  const impls = [];
  for (const { base, size } of getApi().module.enumerateRanges("--x")) {
    for (const { pattern, offset, validateMatch } of signatures) {
      const matches = Memory.scanSync(base, size, pattern).map(({ address, size: size2 }) => {
        return { address: address.sub(offset), size: size2 + offset };
      }).filter((match) => {
        const validationResult = validateMatch(match);
        if (validationResult === null) {
          return false;
        }
        match.validationResult = validationResult;
        return true;
      });
      impls.push(...matches);
    }
  }
  if (impls.length === 0) {
    return false;
  }
  impls.forEach(handler.instrument);
  return true;
}
function returnEmptyObject() {
  return {};
}
var InlineHook = class {
  constructor(address, size, trampoline) {
    this.address = address;
    this.size = size;
    this.originalCode = address.readByteArray(size);
    this.trampoline = trampoline;
  }
  revert() {
    Memory.patchCode(this.address, this.size, (code3) => {
      code3.writeByteArray(this.originalCode);
    });
  }
};
function instrumentGetOatQuickMethodHeaderInlinedCopyArm({ address, size, validationResult }) {
  const { methodReg, target } = validationResult;
  const trampoline = Memory.alloc(Process.pageSize);
  let redirectCapacity = size;
  Memory.patchCode(trampoline, 256, (code3) => {
    const writer = new ThumbWriter(code3, { pc: trampoline });
    const relocator = new ThumbRelocator(address, writer);
    for (let i = 0; i !== 2; i++) {
      relocator.readOne();
    }
    relocator.writeAll();
    relocator.readOne();
    relocator.skipOne();
    writer.putBCondLabel("eq", "runtime_or_replacement_method");
    const vpushFpRegs = [45, 237, 16, 10];
    writer.putBytes(vpushFpRegs);
    const savedRegs = ["r0", "r1", "r2", "r3"];
    writer.putPushRegs(savedRegs);
    writer.putCallAddressWithArguments(artController.replacedMethods.isReplacement, [methodReg]);
    writer.putCmpRegImm("r0", 0);
    writer.putPopRegs(savedRegs);
    const vpopFpRegs = [189, 236, 16, 10];
    writer.putBytes(vpopFpRegs);
    writer.putBCondLabel("ne", "runtime_or_replacement_method");
    writer.putBLabel("regular_method");
    relocator.readOne();
    const tailIsRegular = relocator.input.address.equals(target.whenRegularMethod);
    writer.putLabel(tailIsRegular ? "regular_method" : "runtime_or_replacement_method");
    relocator.writeOne();
    while (redirectCapacity < 10) {
      const offset = relocator.readOne();
      if (offset === 0) {
        redirectCapacity = 10;
        break;
      }
      redirectCapacity = offset;
    }
    relocator.writeAll();
    writer.putBranchAddress(address.add(redirectCapacity + 1));
    writer.putLabel(tailIsRegular ? "runtime_or_replacement_method" : "regular_method");
    writer.putBranchAddress(target.whenTrue);
    writer.flush();
  });
  inlineHooks.push(new InlineHook(address, redirectCapacity, trampoline));
  Memory.patchCode(address, redirectCapacity, (code3) => {
    const writer = new ThumbWriter(code3, { pc: address });
    writer.putLdrRegAddress("pc", trampoline.or(1));
    writer.flush();
  });
}
function instrumentGetOatQuickMethodHeaderInlinedCopyArm64({ address, size, validationResult }) {
  const { methodReg, scratchReg, target } = validationResult;
  const trampoline = Memory.alloc(Process.pageSize);
  Memory.patchCode(trampoline, 256, (code3) => {
    const writer = new Arm64Writer(code3, { pc: trampoline });
    const relocator = new Arm64Relocator(address, writer);
    for (let i = 0; i !== 2; i++) {
      relocator.readOne();
    }
    relocator.writeAll();
    relocator.readOne();
    relocator.skipOne();
    writer.putBCondLabel("eq", "runtime_or_replacement_method");
    const savedRegs = [
      "d0",
      "d1",
      "d2",
      "d3",
      "d4",
      "d5",
      "d6",
      "d7",
      "x0",
      "x1",
      "x2",
      "x3",
      "x4",
      "x5",
      "x6",
      "x7",
      "x8",
      "x9",
      "x10",
      "x11",
      "x12",
      "x13",
      "x14",
      "x15",
      "x16",
      "x17"
    ];
    const numSavedRegs = savedRegs.length;
    for (let i = 0; i !== numSavedRegs; i += 2) {
      writer.putPushRegReg(savedRegs[i], savedRegs[i + 1]);
    }
    writer.putCallAddressWithArguments(artController.replacedMethods.isReplacement, [methodReg]);
    writer.putCmpRegReg("x0", "xzr");
    for (let i = numSavedRegs - 2; i >= 0; i -= 2) {
      writer.putPopRegReg(savedRegs[i], savedRegs[i + 1]);
    }
    writer.putBCondLabel("ne", "runtime_or_replacement_method");
    writer.putBLabel("regular_method");
    relocator.readOne();
    const tailInstruction = relocator.input;
    const tailIsRegular = tailInstruction.address.equals(target.whenRegularMethod);
    writer.putLabel(tailIsRegular ? "regular_method" : "runtime_or_replacement_method");
    relocator.writeOne();
    writer.putBranchAddress(tailInstruction.next);
    writer.putLabel(tailIsRegular ? "runtime_or_replacement_method" : "regular_method");
    writer.putBranchAddress(target.whenTrue);
    writer.flush();
  });
  inlineHooks.push(new InlineHook(address, size, trampoline));
  Memory.patchCode(address, size, (code3) => {
    const writer = new Arm64Writer(code3, { pc: address });
    writer.putLdrRegAddress(scratchReg, trampoline);
    writer.putBrReg(scratchReg);
    writer.flush();
  });
}
function makeMethodMangler(methodId) {
  return new MethodMangler(methodId);
}
function translateMethod(methodId) {
  return artController.replacedMethods.translate(methodId);
}
function backtrace(vm3, options = {}) {
  const { limit = 16 } = options;
  const env = vm3.getEnv();
  if (backtraceModule === null) {
    backtraceModule = makeBacktraceModule(vm3, env);
  }
  return backtraceModule.backtrace(env, limit);
}
function makeBacktraceModule(vm3, env) {
  const api2 = getApi();
  const performImpl = Memory.alloc(Process.pointerSize);
  const cm2 = new CModule(`
#include <glib.h>
#include <stdbool.h>
#include <string.h>
#include <gum/gumtls.h>
#include <json-glib/json-glib.h>

typedef struct _ArtBacktrace ArtBacktrace;
typedef struct _ArtStackFrame ArtStackFrame;

typedef struct _ArtStackVisitor ArtStackVisitor;
typedef struct _ArtStackVisitorVTable ArtStackVisitorVTable;

typedef struct _ArtClass ArtClass;
typedef struct _ArtMethod ArtMethod;
typedef struct _ArtThread ArtThread;
typedef struct _ArtContext ArtContext;

typedef struct _JNIEnv JNIEnv;

typedef struct _StdString StdString;
typedef struct _StdTinyString StdTinyString;
typedef struct _StdLargeString StdLargeString;

typedef enum {
  STACK_WALK_INCLUDE_INLINED_FRAMES,
  STACK_WALK_SKIP_INLINED_FRAMES,
} StackWalkKind;

struct _StdTinyString
{
  guint8 unused;
  gchar data[(3 * sizeof (gpointer)) - 1];
};

struct _StdLargeString
{
  gsize capacity;
  gsize size;
  gchar * data;
};

struct _StdString
{
  union
  {
    guint8 flags;
    StdTinyString tiny;
    StdLargeString large;
  };
};

struct _ArtBacktrace
{
  GChecksum * id;
  GArray * frames;
  gchar * frames_json;
};

struct _ArtStackFrame
{
  ArtMethod * method;
  gsize dexpc;
  StdString description;
};

struct _ArtStackVisitorVTable
{
  void (* unused1) (void);
  void (* unused2) (void);
  bool (* visit) (ArtStackVisitor * visitor);
};

struct _ArtStackVisitor
{
  ArtStackVisitorVTable * vtable;

  guint8 padding[512];

  ArtStackVisitorVTable vtable_storage;

  ArtBacktrace * backtrace;
};

struct _ArtMethod
{
  guint32 declaring_class;
  guint32 access_flags;
};

extern GumTlsKey current_backtrace;

extern void (* perform_art_thread_state_transition) (JNIEnv * env);

extern ArtContext * art_thread_get_long_jump_context (ArtThread * thread);

extern void art_stack_visitor_init (ArtStackVisitor * visitor, ArtThread * thread, void * context, StackWalkKind walk_kind,
    size_t num_frames, bool check_suspended);
extern void art_stack_visitor_walk_stack (ArtStackVisitor * visitor, bool include_transitions);
extern ArtMethod * art_stack_visitor_get_method (ArtStackVisitor * visitor);
extern void art_stack_visitor_describe_location (StdString * description, ArtStackVisitor * visitor);
extern ArtMethod * translate_method (ArtMethod * method);
extern void translate_location (ArtMethod * method, guint32 pc, const gchar ** source_file, gint32 * line_number);
extern void get_class_location (StdString * result, ArtClass * klass);
extern void cxx_delete (void * mem);
extern unsigned long strtoul (const char * str, char ** endptr, int base);

static bool visit_frame (ArtStackVisitor * visitor);
static void art_stack_frame_destroy (ArtStackFrame * frame);

static void append_jni_type_name (GString * s, const gchar * name, gsize length);

static void std_string_destroy (StdString * str);
static gchar * std_string_get_data (StdString * str);

void
init (void)
{
  current_backtrace = gum_tls_key_new ();
}

void
finalize (void)
{
  gum_tls_key_free (current_backtrace);
}

ArtBacktrace *
_create (JNIEnv * env,
         guint limit)
{
  ArtBacktrace * bt;

  bt = g_new (ArtBacktrace, 1);
  bt->id = g_checksum_new (G_CHECKSUM_SHA1);
  bt->frames = (limit != 0)
      ? g_array_sized_new (FALSE, FALSE, sizeof (ArtStackFrame), limit)
      : g_array_new (FALSE, FALSE, sizeof (ArtStackFrame));
  g_array_set_clear_func (bt->frames, (GDestroyNotify) art_stack_frame_destroy);
  bt->frames_json = NULL;

  gum_tls_key_set_value (current_backtrace, bt);

  perform_art_thread_state_transition (env);

  gum_tls_key_set_value (current_backtrace, NULL);

  return bt;
}

void
_on_thread_state_transition_complete (ArtThread * thread)
{
  ArtContext * context;
  ArtStackVisitor visitor = {
    .vtable_storage = {
      .visit = visit_frame,
    },
  };

  context = art_thread_get_long_jump_context (thread);

  art_stack_visitor_init (&visitor, thread, context, STACK_WALK_SKIP_INLINED_FRAMES, 0, true);
  visitor.vtable = &visitor.vtable_storage;
  visitor.backtrace = gum_tls_key_get_value (current_backtrace);

  art_stack_visitor_walk_stack (&visitor, false);

  cxx_delete (context);
}

static bool
visit_frame (ArtStackVisitor * visitor)
{
  ArtBacktrace * bt = visitor->backtrace;
  ArtStackFrame frame;
  const gchar * description, * dexpc_part;

  frame.method = art_stack_visitor_get_method (visitor);

  art_stack_visitor_describe_location (&frame.description, visitor);

  description = std_string_get_data (&frame.description);
  if (strstr (description, " '<") != NULL)
    goto skip;

  dexpc_part = strstr (description, " at dex PC 0x");
  if (dexpc_part == NULL)
    goto skip;
  frame.dexpc = strtoul (dexpc_part + 13, NULL, 16);

  g_array_append_val (bt->frames, frame);

  g_checksum_update (bt->id, (guchar *) &frame.method, sizeof (frame.method));
  g_checksum_update (bt->id, (guchar *) &frame.dexpc, sizeof (frame.dexpc));

  return true;

skip:
  std_string_destroy (&frame.description);
  return true;
}

static void
art_stack_frame_destroy (ArtStackFrame * frame)
{
  std_string_destroy (&frame->description);
}

void
_destroy (ArtBacktrace * backtrace)
{
  g_free (backtrace->frames_json);
  g_array_free (backtrace->frames, TRUE);
  g_checksum_free (backtrace->id);
  g_free (backtrace);
}

const gchar *
_get_id (ArtBacktrace * backtrace)
{
  return g_checksum_get_string (backtrace->id);
}

const gchar *
_get_frames (ArtBacktrace * backtrace)
{
  GArray * frames = backtrace->frames;
  JsonBuilder * b;
  guint i;
  JsonNode * root;

  if (backtrace->frames_json != NULL)
    return backtrace->frames_json;

  b = json_builder_new_immutable ();

  json_builder_begin_array (b);

  for (i = 0; i != frames->len; i++)
  {
    ArtStackFrame * frame = &g_array_index (frames, ArtStackFrame, i);
    gchar * description, * ret_type, * paren_open, * paren_close, * arg_types, * token, * method_name, * class_name;
    GString * signature;
    gchar * cursor;
    ArtMethod * translated_method;
    StdString location;
    gsize dexpc;
    const gchar * source_file;
    gint32 line_number;

    description = std_string_get_data (&frame->description);

    ret_type = strchr (description, '\\'') + 1;

    paren_open = strchr (ret_type, '(');
    paren_close = strchr (paren_open, ')');
    *paren_open = '\\0';
    *paren_close = '\\0';

    arg_types = paren_open + 1;

    token = strrchr (ret_type, '.');
    *token = '\\0';

    method_name = token + 1;

    token = strrchr (ret_type, ' ');
    *token = '\\0';

    class_name = token + 1;

    signature = g_string_sized_new (128);

    append_jni_type_name (signature, class_name, method_name - class_name - 1);
    g_string_append_c (signature, ',');
    g_string_append (signature, method_name);
    g_string_append (signature, ",(");

    if (arg_types != paren_close)
    {
      for (cursor = arg_types; cursor != NULL;)
      {
        gsize length;
        gchar * next;

        token = strstr (cursor, ", ");
        if (token != NULL)
        {
          length = token - cursor;
          next = token + 2;
        }
        else
        {
          length = paren_close - cursor;
          next = NULL;
        }

        append_jni_type_name (signature, cursor, length);

        cursor = next;
      }
    }

    g_string_append_c (signature, ')');

    append_jni_type_name (signature, ret_type, class_name - ret_type - 1);

    translated_method = translate_method (frame->method);
    dexpc = (translated_method == frame->method) ? frame->dexpc : 0;

    get_class_location (&location, GSIZE_TO_POINTER (translated_method->declaring_class));

    translate_location (translated_method, dexpc, &source_file, &line_number);

    json_builder_begin_object (b);

    json_builder_set_member_name (b, "signature");
    json_builder_add_string_value (b, signature->str);

    json_builder_set_member_name (b, "origin");
    json_builder_add_string_value (b, std_string_get_data (&location));

    json_builder_set_member_name (b, "className");
    json_builder_add_string_value (b, class_name);

    json_builder_set_member_name (b, "methodName");
    json_builder_add_string_value (b, method_name);

    json_builder_set_member_name (b, "methodFlags");
    json_builder_add_int_value (b, translated_method->access_flags);

    json_builder_set_member_name (b, "fileName");
    json_builder_add_string_value (b, source_file);

    json_builder_set_member_name (b, "lineNumber");
    json_builder_add_int_value (b, line_number);

    json_builder_end_object (b);

    std_string_destroy (&location);
    g_string_free (signature, TRUE);
  }

  json_builder_end_array (b);

  root = json_builder_get_root (b);
  backtrace->frames_json = json_to_string (root, FALSE);
  json_node_unref (root);

  return backtrace->frames_json;
}

static void
append_jni_type_name (GString * s,
                      const gchar * name,
                      gsize length)
{
  gchar shorty = '\\0';
  gsize i;

  switch (name[0])
  {
    case 'b':
      if (strncmp (name, "boolean", length) == 0)
        shorty = 'Z';
      else if (strncmp (name, "byte", length) == 0)
        shorty = 'B';
      break;
    case 'c':
      if (strncmp (name, "char", length) == 0)
        shorty = 'C';
      break;
    case 'd':
      if (strncmp (name, "double", length) == 0)
        shorty = 'D';
      break;
    case 'f':
      if (strncmp (name, "float", length) == 0)
        shorty = 'F';
      break;
    case 'i':
      if (strncmp (name, "int", length) == 0)
        shorty = 'I';
      break;
    case 'l':
      if (strncmp (name, "long", length) == 0)
        shorty = 'J';
      break;
    case 's':
      if (strncmp (name, "short", length) == 0)
        shorty = 'S';
      break;
    case 'v':
      if (strncmp (name, "void", length) == 0)
        shorty = 'V';
      break;
  }

  if (shorty != '\\0')
  {
    g_string_append_c (s, shorty);

    return;
  }

  if (length > 2 && name[length - 2] == '[' && name[length - 1] == ']')
  {
    g_string_append_c (s, '[');
    append_jni_type_name (s, name, length - 2);

    return;
  }

  g_string_append_c (s, 'L');

  for (i = 0; i != length; i++)
  {
    gchar ch = name[i];
    if (ch != '.')
      g_string_append_c (s, ch);
    else
      g_string_append_c (s, '/');
  }

  g_string_append_c (s, ';');
}

static void
std_string_destroy (StdString * str)
{
  bool is_large = (str->flags & 1) != 0;
  if (is_large)
    cxx_delete (str->large.data);
}

static gchar *
std_string_get_data (StdString * str)
{
  bool is_large = (str->flags & 1) != 0;
  return is_large ? str->large.data : str->tiny.data;
}
`, {
    current_backtrace: Memory.alloc(Process.pointerSize),
    perform_art_thread_state_transition: performImpl,
    art_thread_get_long_jump_context: api2["art::Thread::GetLongJumpContext"],
    art_stack_visitor_init: api2["art::StackVisitor::StackVisitor"],
    art_stack_visitor_walk_stack: api2["art::StackVisitor::WalkStack"],
    art_stack_visitor_get_method: api2["art::StackVisitor::GetMethod"],
    art_stack_visitor_describe_location: api2["art::StackVisitor::DescribeLocation"],
    translate_method: artController.replacedMethods.translate,
    translate_location: api2["art::Monitor::TranslateLocation"],
    get_class_location: api2["art::mirror::Class::GetLocation"],
    cxx_delete: api2.$delete,
    strtoul: Process.getModuleByName("libc.so").getExportByName("strtoul")
  });
  const _create = new NativeFunction(cm2._create, "pointer", ["pointer", "uint"], nativeFunctionOptions3);
  const _destroy = new NativeFunction(cm2._destroy, "void", ["pointer"], nativeFunctionOptions3);
  const fastOptions = { exceptions: "propagate", scheduling: "exclusive" };
  const _getId = new NativeFunction(cm2._get_id, "pointer", ["pointer"], fastOptions);
  const _getFrames = new NativeFunction(cm2._get_frames, "pointer", ["pointer"], fastOptions);
  const performThreadStateTransition = makeArtThreadStateTransitionImpl(vm3, env, cm2._on_thread_state_transition_complete);
  cm2._performData = performThreadStateTransition;
  performImpl.writePointer(performThreadStateTransition);
  cm2.backtrace = (env2, limit) => {
    const handle = _create(env2, limit);
    const bt = new Backtrace(handle);
    Script.bindWeak(bt, destroy.bind(null, handle));
    return bt;
  };
  function destroy(handle) {
    _destroy(handle);
  }
  cm2.getId = (handle) => {
    return _getId(handle).readUtf8String();
  };
  cm2.getFrames = (handle) => {
    return JSON.parse(_getFrames(handle).readUtf8String());
  };
  return cm2;
}
var Backtrace = class {
  constructor(handle) {
    this.handle = handle;
  }
  get id() {
    return backtraceModule.getId(this.handle);
  }
  get frames() {
    return backtraceModule.getFrames(this.handle);
  }
};
function revertGlobalPatches() {
  patchedClasses.forEach((entry) => {
    entry.vtablePtr.writePointer(entry.vtable);
    entry.vtableCountPtr.writeS32(entry.vtableCount);
  });
  patchedClasses.clear();
  for (const interceptor of artQuickInterceptors.splice(0)) {
    interceptor.deactivate();
  }
  for (const hook of inlineHooks.splice(0)) {
    hook.revert();
  }
}
function unwrapMethodId(methodId) {
  return unwrapGenericId(methodId, "art::jni::JniIdManager::DecodeMethodId");
}
function unwrapFieldId(fieldId) {
  return unwrapGenericId(fieldId, "art::jni::JniIdManager::DecodeFieldId");
}
function unwrapGenericId(genericId, apiMethod) {
  const api2 = getApi();
  const runtimeOffset = getArtRuntimeSpec(api2).offset;
  const jniIdManagerOffset = runtimeOffset.jniIdManager;
  const jniIdsIndirectionOffset = runtimeOffset.jniIdsIndirection;
  if (jniIdManagerOffset !== null && jniIdsIndirectionOffset !== null) {
    const runtime2 = api2.artRuntime;
    const jniIdsIndirection = runtime2.add(jniIdsIndirectionOffset).readInt();
    if (jniIdsIndirection !== kPointer) {
      const jniIdManager = runtime2.add(jniIdManagerOffset).readPointer();
      return api2[apiMethod](jniIdManager, genericId);
    }
  }
  return genericId;
}
var artQuickCodeReplacementTrampolineWriters = {
  ia32: writeArtQuickCodeReplacementTrampolineIA32,
  x64: writeArtQuickCodeReplacementTrampolineX64,
  arm: writeArtQuickCodeReplacementTrampolineArm,
  arm64: writeArtQuickCodeReplacementTrampolineArm64
};
function writeArtQuickCodeReplacementTrampolineIA32(trampoline, target, redirectSize, constraints, vm3) {
  const threadOffsets = getArtThreadSpec(vm3).offset;
  const artMethodOffsets = getArtMethodSpec(vm3).offset;
  let offset;
  Memory.patchCode(trampoline, 128, (code3) => {
    const writer = new X86Writer(code3, { pc: trampoline });
    const relocator = new X86Relocator(target, writer);
    const fxsave = [15, 174, 4, 36];
    const fxrstor = [15, 174, 12, 36];
    writer.putPushax();
    writer.putMovRegReg("ebp", "esp");
    writer.putAndRegU32("esp", 4294967280);
    writer.putSubRegImm("esp", 512);
    writer.putBytes(fxsave);
    writer.putMovRegFsU32Ptr("ebx", threadOffsets.self);
    writer.putCallAddressWithAlignedArguments(artController.replacedMethods.findReplacementFromQuickCode, ["eax", "ebx"]);
    writer.putTestRegReg("eax", "eax");
    writer.putJccShortLabel("je", "restore_registers", "no-hint");
    writer.putMovRegOffsetPtrReg("ebp", 7 * 4, "eax");
    writer.putLabel("restore_registers");
    writer.putBytes(fxrstor);
    writer.putMovRegReg("esp", "ebp");
    writer.putPopax();
    writer.putJccShortLabel("jne", "invoke_replacement", "no-hint");
    do {
      offset = relocator.readOne();
    } while (offset < redirectSize && !relocator.eoi);
    relocator.writeAll();
    if (!relocator.eoi) {
      writer.putJmpAddress(target.add(offset));
    }
    writer.putLabel("invoke_replacement");
    writer.putJmpRegOffsetPtr("eax", artMethodOffsets.quickCode);
    writer.flush();
  });
  return offset;
}
function writeArtQuickCodeReplacementTrampolineX64(trampoline, target, redirectSize, constraints, vm3) {
  const threadOffsets = getArtThreadSpec(vm3).offset;
  const artMethodOffsets = getArtMethodSpec(vm3).offset;
  let offset;
  Memory.patchCode(trampoline, 256, (code3) => {
    const writer = new X86Writer(code3, { pc: trampoline });
    const relocator = new X86Relocator(target, writer);
    const fxsave = [15, 174, 4, 36];
    const fxrstor = [15, 174, 12, 36];
    writer.putPushax();
    writer.putMovRegReg("rbp", "rsp");
    writer.putAndRegU32("rsp", 4294967280);
    writer.putSubRegImm("rsp", 512);
    writer.putBytes(fxsave);
    writer.putMovRegGsU32Ptr("rbx", threadOffsets.self);
    writer.putCallAddressWithAlignedArguments(artController.replacedMethods.findReplacementFromQuickCode, ["rdi", "rbx"]);
    writer.putTestRegReg("rax", "rax");
    writer.putJccShortLabel("je", "restore_registers", "no-hint");
    writer.putMovRegOffsetPtrReg("rbp", 8 * 8, "rax");
    writer.putLabel("restore_registers");
    writer.putBytes(fxrstor);
    writer.putMovRegReg("rsp", "rbp");
    writer.putPopax();
    writer.putJccShortLabel("jne", "invoke_replacement", "no-hint");
    do {
      offset = relocator.readOne();
    } while (offset < redirectSize && !relocator.eoi);
    relocator.writeAll();
    if (!relocator.eoi) {
      writer.putJmpAddress(target.add(offset));
    }
    writer.putLabel("invoke_replacement");
    writer.putJmpRegOffsetPtr("rdi", artMethodOffsets.quickCode);
    writer.flush();
  });
  return offset;
}
function writeArtQuickCodeReplacementTrampolineArm(trampoline, target, redirectSize, constraints, vm3) {
  const artMethodOffsets = getArtMethodSpec(vm3).offset;
  const targetAddress = target.and(THUMB_BIT_REMOVAL_MASK);
  let offset;
  Memory.patchCode(trampoline, 128, (code3) => {
    const writer = new ThumbWriter(code3, { pc: trampoline });
    const relocator = new ThumbRelocator(targetAddress, writer);
    const vpushFpRegs = [45, 237, 16, 10];
    const vpopFpRegs = [189, 236, 16, 10];
    writer.putPushRegs([
      "r1",
      "r2",
      "r3",
      "r5",
      "r6",
      "r7",
      "r8",
      "r10",
      "r11",
      "lr"
    ]);
    writer.putBytes(vpushFpRegs);
    writer.putSubRegRegImm("sp", "sp", 8);
    writer.putStrRegRegOffset("r0", "sp", 0);
    writer.putCallAddressWithArguments(artController.replacedMethods.findReplacementFromQuickCode, ["r0", "r9"]);
    writer.putCmpRegImm("r0", 0);
    writer.putBCondLabel("eq", "restore_registers");
    writer.putStrRegRegOffset("r0", "sp", 0);
    writer.putLabel("restore_registers");
    writer.putLdrRegRegOffset("r0", "sp", 0);
    writer.putAddRegRegImm("sp", "sp", 8);
    writer.putBytes(vpopFpRegs);
    writer.putPopRegs([
      "lr",
      "r11",
      "r10",
      "r8",
      "r7",
      "r6",
      "r5",
      "r3",
      "r2",
      "r1"
    ]);
    writer.putBCondLabel("ne", "invoke_replacement");
    do {
      offset = relocator.readOne();
    } while (offset < redirectSize && !relocator.eoi);
    relocator.writeAll();
    if (!relocator.eoi) {
      writer.putLdrRegAddress("pc", target.add(offset));
    }
    writer.putLabel("invoke_replacement");
    writer.putLdrRegRegOffset("pc", "r0", artMethodOffsets.quickCode);
    writer.flush();
  });
  return offset;
}
function writeArtQuickCodeReplacementTrampolineArm64(trampoline, target, redirectSize, { availableScratchRegs }, vm3) {
  const artMethodOffsets = getArtMethodSpec(vm3).offset;
  let offset;
  Memory.patchCode(trampoline, 256, (code3) => {
    const writer = new Arm64Writer(code3, { pc: trampoline });
    const relocator = new Arm64Relocator(target, writer);
    writer.putPushRegReg("d0", "d1");
    writer.putPushRegReg("d2", "d3");
    writer.putPushRegReg("d4", "d5");
    writer.putPushRegReg("d6", "d7");
    writer.putPushRegReg("x1", "x2");
    writer.putPushRegReg("x3", "x4");
    writer.putPushRegReg("x5", "x6");
    writer.putPushRegReg("x7", "x20");
    writer.putPushRegReg("x21", "x22");
    writer.putPushRegReg("x23", "x24");
    writer.putPushRegReg("x25", "x26");
    writer.putPushRegReg("x27", "x28");
    writer.putPushRegReg("x29", "lr");
    writer.putSubRegRegImm("sp", "sp", 16);
    writer.putStrRegRegOffset("x0", "sp", 0);
    writer.putCallAddressWithArguments(artController.replacedMethods.findReplacementFromQuickCode, ["x0", "x19"]);
    writer.putCmpRegReg("x0", "xzr");
    writer.putBCondLabel("eq", "restore_registers");
    writer.putStrRegRegOffset("x0", "sp", 0);
    writer.putLabel("restore_registers");
    writer.putLdrRegRegOffset("x0", "sp", 0);
    writer.putAddRegRegImm("sp", "sp", 16);
    writer.putPopRegReg("x29", "lr");
    writer.putPopRegReg("x27", "x28");
    writer.putPopRegReg("x25", "x26");
    writer.putPopRegReg("x23", "x24");
    writer.putPopRegReg("x21", "x22");
    writer.putPopRegReg("x7", "x20");
    writer.putPopRegReg("x5", "x6");
    writer.putPopRegReg("x3", "x4");
    writer.putPopRegReg("x1", "x2");
    writer.putPopRegReg("d6", "d7");
    writer.putPopRegReg("d4", "d5");
    writer.putPopRegReg("d2", "d3");
    writer.putPopRegReg("d0", "d1");
    writer.putBCondLabel("ne", "invoke_replacement");
    do {
      offset = relocator.readOne();
    } while (offset < redirectSize && !relocator.eoi);
    relocator.writeAll();
    if (!relocator.eoi) {
      const scratchReg = Array.from(availableScratchRegs)[0];
      writer.putLdrRegAddress(scratchReg, target.add(offset));
      writer.putBrReg(scratchReg);
    }
    writer.putLabel("invoke_replacement");
    writer.putLdrRegRegOffset("x16", "x0", artMethodOffsets.quickCode);
    writer.putBrReg("x16");
    writer.flush();
  });
  return offset;
}
var artQuickCodePrologueWriters = {
  ia32: writeArtQuickCodePrologueX86,
  x64: writeArtQuickCodePrologueX86,
  arm: writeArtQuickCodePrologueArm,
  arm64: writeArtQuickCodePrologueArm64
};
function writeArtQuickCodePrologueX86(target, trampoline, redirectSize) {
  Memory.patchCode(target, 16, (code3) => {
    const writer = new X86Writer(code3, { pc: target });
    writer.putJmpAddress(trampoline);
    writer.flush();
  });
}
function writeArtQuickCodePrologueArm(target, trampoline, redirectSize) {
  const targetAddress = target.and(THUMB_BIT_REMOVAL_MASK);
  Memory.patchCode(targetAddress, 16, (code3) => {
    const writer = new ThumbWriter(code3, { pc: targetAddress });
    writer.putLdrRegAddress("pc", trampoline.or(1));
    writer.flush();
  });
}
function writeArtQuickCodePrologueArm64(target, trampoline, redirectSize) {
  Memory.patchCode(target, 16, (code3) => {
    const writer = new Arm64Writer(code3, { pc: target });
    if (redirectSize === 16) {
      writer.putLdrRegAddress("x16", trampoline);
    } else {
      writer.putAdrpRegAddress("x16", trampoline);
    }
    writer.putBrReg("x16");
    writer.flush();
  });
}
var artQuickCodeHookRedirectSize = {
  ia32: 5,
  x64: 16,
  arm: 8,
  arm64: 16
};
var ArtQuickCodeInterceptor = class {
  constructor(quickCode) {
    this.quickCode = quickCode;
    this.quickCodeAddress = Process.arch === "arm" ? quickCode.and(THUMB_BIT_REMOVAL_MASK) : quickCode;
    this.redirectSize = 0;
    this.trampoline = null;
    this.overwrittenPrologue = null;
    this.overwrittenPrologueLength = 0;
  }
  _canRelocateCode(relocationSize, constraints) {
    const Writer = thunkWriters[Process.arch];
    const Relocator = thunkRelocators[Process.arch];
    const { quickCodeAddress } = this;
    const writer = new Writer(quickCodeAddress);
    const relocator = new Relocator(quickCodeAddress, writer);
    let offset;
    if (Process.arch === "arm64") {
      let availableScratchRegs = /* @__PURE__ */ new Set(["x16", "x17"]);
      do {
        const nextOffset = relocator.readOne();
        const nextScratchRegs = new Set(availableScratchRegs);
        const { read: read2, written } = relocator.input.regsAccessed;
        for (const regs of [read2, written]) {
          for (const reg of regs) {
            let name;
            if (reg.startsWith("w")) {
              name = "x" + reg.substring(1);
            } else {
              name = reg;
            }
            nextScratchRegs.delete(name);
          }
        }
        if (nextScratchRegs.size === 0) {
          break;
        }
        offset = nextOffset;
        availableScratchRegs = nextScratchRegs;
      } while (offset < relocationSize && !relocator.eoi);
      constraints.availableScratchRegs = availableScratchRegs;
    } else {
      do {
        offset = relocator.readOne();
      } while (offset < relocationSize && !relocator.eoi);
    }
    return offset >= relocationSize;
  }
  _allocateTrampoline() {
    if (trampolineAllocator === null) {
      const trampolineSize = pointerSize5 === 4 ? 128 : 256;
      trampolineAllocator = makeAllocator(trampolineSize);
    }
    const maxRedirectSize = artQuickCodeHookRedirectSize[Process.arch];
    let redirectSize, spec;
    let alignment = 1;
    const constraints = {};
    if (pointerSize5 === 4 || this._canRelocateCode(maxRedirectSize, constraints)) {
      redirectSize = maxRedirectSize;
      spec = {};
    } else {
      let maxDistance;
      if (Process.arch === "x64") {
        redirectSize = 5;
        maxDistance = X86_JMP_MAX_DISTANCE;
      } else if (Process.arch === "arm64") {
        redirectSize = 8;
        maxDistance = ARM64_ADRP_MAX_DISTANCE;
        alignment = 4096;
      }
      spec = { near: this.quickCodeAddress, maxDistance };
    }
    this.redirectSize = redirectSize;
    this.trampoline = trampolineAllocator.allocateSlice(spec, alignment);
    return constraints;
  }
  _destroyTrampoline() {
    trampolineAllocator.freeSlice(this.trampoline);
  }
  activate(vm3) {
    const constraints = this._allocateTrampoline();
    const { trampoline, quickCode, redirectSize } = this;
    const writeTrampoline = artQuickCodeReplacementTrampolineWriters[Process.arch];
    const prologueLength = writeTrampoline(trampoline, quickCode, redirectSize, constraints, vm3);
    this.overwrittenPrologueLength = prologueLength;
    this.overwrittenPrologue = Memory.dup(this.quickCodeAddress, prologueLength);
    const writePrologue = artQuickCodePrologueWriters[Process.arch];
    writePrologue(quickCode, trampoline, redirectSize);
  }
  deactivate() {
    const { quickCodeAddress, overwrittenPrologueLength: prologueLength } = this;
    const Writer = thunkWriters[Process.arch];
    Memory.patchCode(quickCodeAddress, prologueLength, (code3) => {
      const writer = new Writer(code3, { pc: quickCodeAddress });
      const { overwrittenPrologue } = this;
      writer.putBytes(overwrittenPrologue.readByteArray(prologueLength));
      writer.flush();
    });
    this._destroyTrampoline();
  }
};
function isArtQuickEntrypoint(address) {
  const api2 = getApi();
  const { module: m, artClassLinker } = api2;
  return address.equals(artClassLinker.quickGenericJniTrampoline) || address.equals(artClassLinker.quickToInterpreterBridgeTrampoline) || address.equals(artClassLinker.quickResolutionTrampoline) || address.equals(artClassLinker.quickImtConflictTrampoline) || address.compare(m.base) >= 0 && address.compare(m.base.add(m.size)) < 0;
}
var ArtMethodMangler = class {
  constructor(opaqueMethodId) {
    const methodId = unwrapMethodId(opaqueMethodId);
    this.methodId = methodId;
    this.originalMethod = null;
    this.hookedMethodId = methodId;
    this.replacementMethodId = null;
    this.interceptor = null;
  }
  replace(impl, isInstanceMethod, argTypes, vm3, api2) {
    const { kAccCompileDontBother, artNterpEntryPoint } = api2;
    this.originalMethod = fetchArtMethod(this.methodId, vm3);
    const originalFlags = this.originalMethod.accessFlags;
    if ((originalFlags & kAccXposedHookedMethod) !== 0 && xposedIsSupported()) {
      const hookInfo = this.originalMethod.jniCode;
      this.hookedMethodId = hookInfo.add(2 * pointerSize5).readPointer();
      this.originalMethod = fetchArtMethod(this.hookedMethodId, vm3);
    }
    const { hookedMethodId } = this;
    const replacementMethodId = cloneArtMethod(hookedMethodId, vm3);
    this.replacementMethodId = replacementMethodId;
    patchArtMethod(replacementMethodId, {
      jniCode: impl,
      accessFlags: (originalFlags & ~(kAccCriticalNative | kAccFastNative | kAccNterpEntryPointFastPathFlag) | kAccNative | kAccCompileDontBother) >>> 0,
      quickCode: api2.artClassLinker.quickGenericJniTrampoline,
      interpreterCode: api2.artInterpreterToCompiledCodeBridge
    }, vm3);
    let hookedMethodRemovedFlags = kAccFastInterpreterToInterpreterInvoke | kAccSingleImplementation | kAccNterpEntryPointFastPathFlag;
    if ((originalFlags & kAccNative) === 0) {
      hookedMethodRemovedFlags |= kAccSkipAccessChecks;
    }
    patchArtMethod(hookedMethodId, {
      accessFlags: (originalFlags & ~hookedMethodRemovedFlags | kAccCompileDontBother) >>> 0
    }, vm3);
    const quickCode = this.originalMethod.quickCode;
    if (artNterpEntryPoint !== null && quickCode.equals(artNterpEntryPoint)) {
      patchArtMethod(hookedMethodId, {
        quickCode: api2.artQuickToInterpreterBridge
      }, vm3);
    }
    if (!isArtQuickEntrypoint(quickCode)) {
      const interceptor = new ArtQuickCodeInterceptor(quickCode);
      interceptor.activate(vm3);
      this.interceptor = interceptor;
    }
    artController.replacedMethods.set(hookedMethodId, replacementMethodId);
    notifyArtMethodHooked(hookedMethodId, vm3);
  }
  revert(vm3) {
    const { hookedMethodId, interceptor } = this;
    patchArtMethod(hookedMethodId, this.originalMethod, vm3);
    artController.replacedMethods.delete(hookedMethodId);
    if (interceptor !== null) {
      interceptor.deactivate();
      this.interceptor = null;
    }
  }
  resolveTarget(wrapper, isInstanceMethod, env, api2) {
    return this.hookedMethodId;
  }
};
function xposedIsSupported() {
  return getAndroidApiLevel() < 28;
}
function fetchArtMethod(methodId, vm3) {
  const artMethodSpec = getArtMethodSpec(vm3);
  const artMethodOffset = artMethodSpec.offset;
  return ["jniCode", "accessFlags", "quickCode", "interpreterCode"].reduce((original, name) => {
    const offset = artMethodOffset[name];
    if (offset === void 0) {
      return original;
    }
    const address = methodId.add(offset);
    const read2 = name === "accessFlags" ? readU32 : readPointer;
    original[name] = read2.call(address);
    return original;
  }, {});
}
function patchArtMethod(methodId, patches, vm3) {
  const artMethodSpec = getArtMethodSpec(vm3);
  const artMethodOffset = artMethodSpec.offset;
  Object.keys(patches).forEach((name) => {
    const offset = artMethodOffset[name];
    if (offset === void 0) {
      return;
    }
    const address = methodId.add(offset);
    const write3 = name === "accessFlags" ? writeU32 : writePointer;
    write3.call(address, patches[name]);
  });
}
var DalvikMethodMangler = class {
  constructor(methodId) {
    this.methodId = methodId;
    this.originalMethod = null;
  }
  replace(impl, isInstanceMethod, argTypes, vm3, api2) {
    const { methodId } = this;
    this.originalMethod = Memory.dup(methodId, DVM_METHOD_SIZE);
    let argsSize = argTypes.reduce((acc, t) => acc + t.size, 0);
    if (isInstanceMethod) {
      argsSize++;
    }
    const accessFlags = (methodId.add(DVM_METHOD_OFFSET_ACCESS_FLAGS).readU32() | kAccNative) >>> 0;
    const registersSize = argsSize;
    const outsSize = 0;
    const insSize = argsSize;
    methodId.add(DVM_METHOD_OFFSET_ACCESS_FLAGS).writeU32(accessFlags);
    methodId.add(DVM_METHOD_OFFSET_REGISTERS_SIZE).writeU16(registersSize);
    methodId.add(DVM_METHOD_OFFSET_OUTS_SIZE).writeU16(outsSize);
    methodId.add(DVM_METHOD_OFFSET_INS_SIZE).writeU16(insSize);
    methodId.add(DVM_METHOD_OFFSET_JNI_ARG_INFO).writeU32(computeDalvikJniArgInfo(methodId));
    api2.dvmUseJNIBridge(methodId, impl);
  }
  revert(vm3) {
    Memory.copy(this.methodId, this.originalMethod, DVM_METHOD_SIZE);
  }
  resolveTarget(wrapper, isInstanceMethod, env, api2) {
    const thread = env.handle.add(DVM_JNI_ENV_OFFSET_SELF).readPointer();
    let objectPtr;
    if (isInstanceMethod) {
      objectPtr = api2.dvmDecodeIndirectRef(thread, wrapper.$h);
    } else {
      const h = wrapper.$borrowClassHandle(env);
      objectPtr = api2.dvmDecodeIndirectRef(thread, h.value);
      h.unref(env);
    }
    let classObject;
    if (isInstanceMethod) {
      classObject = objectPtr.add(DVM_OBJECT_OFFSET_CLAZZ).readPointer();
    } else {
      classObject = objectPtr;
    }
    const classKey = classObject.toString(16);
    let entry = patchedClasses.get(classKey);
    if (entry === void 0) {
      const vtablePtr = classObject.add(DVM_CLASS_OBJECT_OFFSET_VTABLE);
      const vtableCountPtr = classObject.add(DVM_CLASS_OBJECT_OFFSET_VTABLE_COUNT);
      const vtable2 = vtablePtr.readPointer();
      const vtableCount = vtableCountPtr.readS32();
      const vtableSize = vtableCount * pointerSize5;
      const shadowVtable = Memory.alloc(2 * vtableSize);
      Memory.copy(shadowVtable, vtable2, vtableSize);
      vtablePtr.writePointer(shadowVtable);
      entry = {
        classObject,
        vtablePtr,
        vtableCountPtr,
        vtable: vtable2,
        vtableCount,
        shadowVtable,
        shadowVtableCount: vtableCount,
        targetMethods: /* @__PURE__ */ new Map()
      };
      patchedClasses.set(classKey, entry);
    }
    const methodKey = this.methodId.toString(16);
    let targetMethod = entry.targetMethods.get(methodKey);
    if (targetMethod === void 0) {
      targetMethod = Memory.dup(this.originalMethod, DVM_METHOD_SIZE);
      const methodIndex = entry.shadowVtableCount++;
      entry.shadowVtable.add(methodIndex * pointerSize5).writePointer(targetMethod);
      targetMethod.add(DVM_METHOD_OFFSET_METHOD_INDEX).writeU16(methodIndex);
      entry.vtableCountPtr.writeS32(entry.shadowVtableCount);
      entry.targetMethods.set(methodKey, targetMethod);
    }
    return targetMethod;
  }
};
function computeDalvikJniArgInfo(methodId) {
  if (Process.arch !== "ia32") {
    return DALVIK_JNI_NO_ARG_INFO;
  }
  const shorty = methodId.add(DVM_METHOD_OFFSET_SHORTY).readPointer().readCString();
  if (shorty === null || shorty.length === 0 || shorty.length > 65535) {
    return DALVIK_JNI_NO_ARG_INFO;
  }
  let returnType;
  switch (shorty[0]) {
    case "V":
      returnType = DALVIK_JNI_RETURN_VOID;
      break;
    case "F":
      returnType = DALVIK_JNI_RETURN_FLOAT;
      break;
    case "D":
      returnType = DALVIK_JNI_RETURN_DOUBLE;
      break;
    case "J":
      returnType = DALVIK_JNI_RETURN_S8;
      break;
    case "Z":
    case "B":
      returnType = DALVIK_JNI_RETURN_S1;
      break;
    case "C":
      returnType = DALVIK_JNI_RETURN_U2;
      break;
    case "S":
      returnType = DALVIK_JNI_RETURN_S2;
      break;
    default:
      returnType = DALVIK_JNI_RETURN_S4;
      break;
  }
  let hints = 0;
  for (let i = shorty.length - 1; i > 0; i--) {
    const ch = shorty[i];
    hints += ch === "D" || ch === "J" ? 2 : 1;
  }
  return returnType << DALVIK_JNI_RETURN_SHIFT | hints;
}
function cloneArtMethod(method, vm3) {
  const api2 = getApi();
  if (getAndroidApiLevel() < 23) {
    const thread = api2["art::Thread::CurrentFromGdb"]();
    return api2["art::mirror::Object::Clone"](method, thread);
  }
  return Memory.dup(method, getArtMethodSpec(vm3).size);
}
function deoptimizeMethod(vm3, env, method) {
  requestDeoptimization(vm3, env, kSelectiveDeoptimization, method);
}
function deoptimizeEverything(vm3, env) {
  requestDeoptimization(vm3, env, kFullDeoptimization);
}
function deoptimizeBootImage(vm3, env) {
  const api2 = getApi();
  if (getAndroidApiLevel() < 26) {
    throw new Error("This API is only available on Android >= 8.0");
  }
  withRunnableArtThread(vm3, env, (thread) => {
    api2["art::Runtime::DeoptimizeBootImage"](api2.artRuntime);
  });
}
function requestDeoptimization(vm3, env, kind, method) {
  const api2 = getApi();
  if (getAndroidApiLevel() < 24) {
    throw new Error("This API is only available on Android >= 7.0");
  }
  withRunnableArtThread(vm3, env, (thread) => {
    if (getAndroidApiLevel() < 30) {
      if (!api2.isJdwpStarted()) {
        const session = startJdwp(api2);
        jdwpSessions.push(session);
      }
      if (!api2.isDebuggerActive()) {
        api2["art::Dbg::GoActive"]();
      }
      const request = Memory.alloc(8 + pointerSize5);
      request.writeU32(kind);
      switch (kind) {
        case kFullDeoptimization:
          break;
        case kSelectiveDeoptimization:
          request.add(8).writePointer(method);
          break;
        default:
          throw new Error("Unsupported deoptimization kind");
      }
      api2["art::Dbg::RequestDeoptimization"](request);
      api2["art::Dbg::ManageDeoptimization"]();
    } else {
      const instrumentation = api2.artInstrumentation;
      if (instrumentation === null) {
        throw new Error("Unable to find Instrumentation class in ART; please file a bug");
      }
      const enableDeopt = api2["art::Instrumentation::EnableDeoptimization"];
      if (enableDeopt !== void 0) {
        const deoptimizationEnabled = !!instrumentation.add(getArtInstrumentationSpec().offset.deoptimizationEnabled).readU8();
        if (!deoptimizationEnabled) {
          enableDeopt(instrumentation);
        }
      }
      switch (kind) {
        case kFullDeoptimization:
          api2["art::Instrumentation::DeoptimizeEverything"](instrumentation, Memory.allocUtf8String("frida"));
          break;
        case kSelectiveDeoptimization:
          api2["art::Instrumentation::Deoptimize"](instrumentation, method);
          break;
        default:
          throw new Error("Unsupported deoptimization kind");
      }
    }
  });
}
var JdwpSession = class {
  constructor() {
    const libart = Process.getModuleByName("libart.so");
    const acceptImpl = libart.getExportByName("_ZN3art4JDWP12JdwpAdbState6AcceptEv");
    const receiveClientFdImpl = libart.getExportByName("_ZN3art4JDWP12JdwpAdbState15ReceiveClientFdEv");
    const controlPair = makeSocketPair();
    const clientPair = makeSocketPair();
    this._controlFd = controlPair[0];
    this._clientFd = clientPair[0];
    let acceptListener = null;
    acceptListener = Interceptor.attach(acceptImpl, function(args) {
      const state = args[0];
      const controlSockPtr = Memory.scanSync(state.add(8252), 256, "00 ff ff ff ff 00")[0].address.add(1);
      controlSockPtr.writeS32(controlPair[1]);
      acceptListener.detach();
    });
    Interceptor.replace(receiveClientFdImpl, new NativeCallback(function(state) {
      Interceptor.revert(receiveClientFdImpl);
      return clientPair[1];
    }, "int", ["pointer"]));
    Interceptor.flush();
    this._handshakeRequest = this._performHandshake();
  }
  async _performHandshake() {
    const input = new UnixInputStream(this._clientFd, { autoClose: false });
    const output = new UnixOutputStream(this._clientFd, { autoClose: false });
    const handshakePacket = [74, 68, 87, 80, 45, 72, 97, 110, 100, 115, 104, 97, 107, 101];
    try {
      await output.writeAll(handshakePacket);
      await input.readAll(handshakePacket.length);
    } catch (e) {
    }
  }
};
function startJdwp(api2) {
  const session = new JdwpSession();
  api2["art::Dbg::SetJdwpAllowed"](1);
  const options = makeJdwpOptions();
  api2["art::Dbg::ConfigureJdwp"](options);
  const startDebugger = api2["art::InternalDebuggerControlCallback::StartDebugger"];
  if (startDebugger !== void 0) {
    startDebugger(NULL);
  } else {
    api2["art::Dbg::StartJdwp"]();
  }
  return session;
}
function makeJdwpOptions() {
  const kJdwpTransportAndroidAdb = getAndroidApiLevel() < 28 ? 2 : 3;
  const kJdwpPortFirstAvailable = 0;
  const transport = kJdwpTransportAndroidAdb;
  const server = true;
  const suspend = false;
  const port = kJdwpPortFirstAvailable;
  const size = 8 + STD_STRING_SIZE + 2;
  const result = Memory.alloc(size);
  result.writeU32(transport).add(4).writeU8(server ? 1 : 0).add(1).writeU8(suspend ? 1 : 0).add(1).add(STD_STRING_SIZE).writeU16(port);
  return result;
}
function makeSocketPair() {
  if (socketpair === null) {
    socketpair = new NativeFunction(
      Process.getModuleByName("libc.so").getExportByName("socketpair"),
      "int",
      ["int", "int", "int", "pointer"]
    );
  }
  const buf = Memory.alloc(8);
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, buf) === -1) {
    throw new Error("Unable to create socketpair for JDWP");
  }
  return [
    buf.readS32(),
    buf.add(4).readS32()
  ];
}
function makeAddGlobalRefFallbackForAndroid5(api2) {
  const offset = getArtVMSpec().offset;
  const lock = api2.vm.add(offset.globalsLock);
  const table = api2.vm.add(offset.globals);
  const add = api2["art::IndirectReferenceTable::Add"];
  const acquire = api2["art::ReaderWriterMutex::ExclusiveLock"];
  const release = api2["art::ReaderWriterMutex::ExclusiveUnlock"];
  const IRT_FIRST_SEGMENT = 0;
  return function(vm3, thread, obj) {
    acquire(lock, thread);
    try {
      return add(table, IRT_FIRST_SEGMENT, obj);
    } finally {
      release(lock, thread);
    }
  };
}
function makeDecodeGlobalFallback(api2) {
  const decode = api2["art::Thread::DecodeJObject"];
  if (decode === void 0) {
    throw new Error("art::Thread::DecodeJObject is not available; please file a bug");
  }
  return function(vm3, thread, ref) {
    return decode(thread, ref);
  };
}
var threadStateTransitionRecompilers = {
  ia32: recompileExceptionClearForX86,
  x64: recompileExceptionClearForX86,
  arm: recompileExceptionClearForArm,
  arm64: recompileExceptionClearForArm64
};
function makeArtThreadStateTransitionImpl(vm3, env, callback) {
  const api2 = getApi();
  const envVtable = env.handle.readPointer();
  let exceptionClearImpl;
  const innerExceptionClearImpl = api2.find("_ZN3art3JNIILb1EE14ExceptionClearEP7_JNIEnv");
  if (innerExceptionClearImpl !== null) {
    exceptionClearImpl = innerExceptionClearImpl;
  } else {
    exceptionClearImpl = envVtable.add(ENV_VTABLE_OFFSET_EXCEPTION_CLEAR).readPointer();
  }
  let nextFuncImpl;
  const innerNextFuncImpl = api2.find("_ZN3art3JNIILb1EE10FatalErrorEP7_JNIEnvPKc");
  if (innerNextFuncImpl !== null) {
    nextFuncImpl = innerNextFuncImpl;
  } else {
    nextFuncImpl = envVtable.add(ENV_VTABLE_OFFSET_FATAL_ERROR).readPointer();
  }
  const recompile = threadStateTransitionRecompilers[Process.arch];
  if (recompile === void 0) {
    throw new Error("Not yet implemented for " + Process.arch);
  }
  let perform = null;
  const threadOffsets = getArtThreadSpec(vm3).offset;
  const exceptionOffset = threadOffsets.exception;
  const neuteredOffsets = /* @__PURE__ */ new Set();
  const isReportedOffset = threadOffsets.isExceptionReportedToInstrumentation;
  if (isReportedOffset !== null) {
    neuteredOffsets.add(isReportedOffset);
  }
  const throwLocationStartOffset = threadOffsets.throwLocation;
  if (throwLocationStartOffset !== null) {
    neuteredOffsets.add(throwLocationStartOffset);
    neuteredOffsets.add(throwLocationStartOffset + pointerSize5);
    neuteredOffsets.add(throwLocationStartOffset + 2 * pointerSize5);
  }
  const codeSize = 65536;
  const code3 = Memory.alloc(codeSize);
  Memory.patchCode(code3, codeSize, (buffer) => {
    perform = recompile(buffer, code3, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback);
  });
  perform._code = code3;
  perform._callback = callback;
  return perform;
}
function recompileExceptionClearForX86(buffer, pc, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback) {
  const blocks = {};
  const branchTargets = /* @__PURE__ */ new Set();
  const pending = [exceptionClearImpl];
  while (pending.length > 0) {
    let current = pending.shift();
    const alreadyCovered = Object.values(blocks).some(({ begin, end }) => current.compare(begin) >= 0 && current.compare(end) < 0);
    if (alreadyCovered) {
      continue;
    }
    const blockAddressKey = current.toString();
    let block = {
      begin: current
    };
    let lastInsn = null;
    let reachedEndOfBlock = false;
    do {
      if (current.equals(nextFuncImpl)) {
        reachedEndOfBlock = true;
        break;
      }
      const insn = Instruction.parse(current);
      lastInsn = insn;
      const existingBlock = blocks[insn.address.toString()];
      if (existingBlock !== void 0) {
        delete blocks[existingBlock.begin.toString()];
        blocks[blockAddressKey] = existingBlock;
        existingBlock.begin = block.begin;
        block = null;
        break;
      }
      let branchTarget = null;
      switch (insn.mnemonic) {
        case "jmp":
          branchTarget = ptr(insn.operands[0].value);
          reachedEndOfBlock = true;
          break;
        case "je":
        case "jg":
        case "jle":
        case "jne":
        case "js":
          branchTarget = ptr(insn.operands[0].value);
          break;
        case "ret":
          reachedEndOfBlock = true;
          break;
      }
      if (branchTarget !== null) {
        branchTargets.add(branchTarget.toString());
        pending.push(branchTarget);
        pending.sort((a, b) => a.compare(b));
      }
      current = insn.next;
    } while (!reachedEndOfBlock);
    if (block !== null) {
      block.end = lastInsn.address.add(lastInsn.size);
      blocks[blockAddressKey] = block;
    }
  }
  const blocksOrdered = Object.keys(blocks).map((key) => blocks[key]);
  blocksOrdered.sort((a, b) => a.begin.compare(b.begin));
  const entryBlock = blocks[exceptionClearImpl.toString()];
  blocksOrdered.splice(blocksOrdered.indexOf(entryBlock), 1);
  blocksOrdered.unshift(entryBlock);
  const writer = new X86Writer(buffer, { pc });
  let foundCore = false;
  let threadReg = null;
  blocksOrdered.forEach((block) => {
    const size = block.end.sub(block.begin).toInt32();
    const relocator = new X86Relocator(block.begin, writer);
    let offset;
    while ((offset = relocator.readOne()) !== 0) {
      const insn = relocator.input;
      const { mnemonic } = insn;
      const insnAddressId = insn.address.toString();
      if (branchTargets.has(insnAddressId)) {
        writer.putLabel(insnAddressId);
      }
      let keep = true;
      switch (mnemonic) {
        case "jmp":
          writer.putJmpNearLabel(branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case "je":
        case "jg":
        case "jle":
        case "jne":
        case "js":
          writer.putJccNearLabel(mnemonic, branchLabelFromOperand(insn.operands[0]), "no-hint");
          keep = false;
          break;
        /*
         * JNI::ExceptionClear(), when checked JNI is off.
         */
        case "mov": {
          const [dst, src] = insn.operands;
          if (dst.type === "mem" && src.type === "imm") {
            const dstValue = dst.value;
            const dstOffset = dstValue.disp;
            if (dstOffset === exceptionOffset && src.value.valueOf() === 0) {
              threadReg = dstValue.base;
              writer.putPushfx();
              writer.putPushax();
              writer.putMovRegReg("xbp", "xsp");
              if (pointerSize5 === 4) {
                writer.putAndRegU32("esp", 4294967280);
              } else {
                const scratchReg = threadReg !== "rdi" ? "rdi" : "rsi";
                writer.putMovRegU64(scratchReg, uint64("0xfffffffffffffff0"));
                writer.putAndRegReg("rsp", scratchReg);
              }
              writer.putCallAddressWithAlignedArguments(callback, [threadReg]);
              writer.putMovRegReg("xsp", "xbp");
              writer.putPopax();
              writer.putPopfx();
              foundCore = true;
              keep = false;
            } else if (neuteredOffsets.has(dstOffset) && dstValue.base === threadReg) {
              keep = false;
            }
          }
          break;
        }
        /*
         * CheckJNI::ExceptionClear, when checked JNI is on. Wrapper that calls JNI::ExceptionClear().
         */
        case "call": {
          const target = insn.operands[0];
          if (target.type === "mem" && target.value.disp === ENV_VTABLE_OFFSET_EXCEPTION_CLEAR) {
            if (pointerSize5 === 4) {
              writer.putPopReg("eax");
              writer.putMovRegRegOffsetPtr("eax", "eax", 4);
              writer.putPushReg("eax");
            } else {
              writer.putMovRegRegOffsetPtr("rdi", "rdi", 8);
            }
            writer.putCallAddressWithArguments(callback, []);
            foundCore = true;
            keep = false;
          }
          break;
        }
      }
      if (keep) {
        relocator.writeAll();
      } else {
        relocator.skipOne();
      }
      if (offset === size) {
        break;
      }
    }
    relocator.dispose();
  });
  writer.dispose();
  if (!foundCore) {
    throwThreadStateTransitionParseError();
  }
  return new NativeFunction(pc, "void", ["pointer"], nativeFunctionOptions3);
}
function recompileExceptionClearForArm(buffer, pc, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback) {
  const blocks = {};
  const branchTargets = /* @__PURE__ */ new Set();
  const thumbBitRemovalMask = ptr(1).not();
  const pending = [exceptionClearImpl];
  while (pending.length > 0) {
    let current = pending.shift();
    const alreadyCovered = Object.values(blocks).some(({ begin: begin2, end }) => current.compare(begin2) >= 0 && current.compare(end) < 0);
    if (alreadyCovered) {
      continue;
    }
    const begin = current.and(thumbBitRemovalMask);
    const blockId = begin.toString();
    const thumbBit = current.and(1);
    let block = {
      begin
    };
    let lastInsn = null;
    let reachedEndOfBlock = false;
    let ifThenBlockRemaining = 0;
    do {
      if (current.equals(nextFuncImpl)) {
        reachedEndOfBlock = true;
        break;
      }
      const insn = Instruction.parse(current);
      const { mnemonic } = insn;
      lastInsn = insn;
      const currentAddress = current.and(thumbBitRemovalMask);
      const insnId = currentAddress.toString();
      const existingBlock = blocks[insnId];
      if (existingBlock !== void 0) {
        delete blocks[existingBlock.begin.toString()];
        blocks[blockId] = existingBlock;
        existingBlock.begin = block.begin;
        block = null;
        break;
      }
      const isOutsideIfThenBlock = ifThenBlockRemaining === 0;
      let branchTarget = null;
      switch (mnemonic) {
        case "b":
          branchTarget = ptr(insn.operands[0].value);
          reachedEndOfBlock = isOutsideIfThenBlock;
          break;
        case "beq.w":
        case "beq":
        case "bne":
        case "bne.w":
        case "bgt":
          branchTarget = ptr(insn.operands[0].value);
          break;
        case "cbz":
        case "cbnz":
          branchTarget = ptr(insn.operands[1].value);
          break;
        case "pop.w":
          if (isOutsideIfThenBlock) {
            reachedEndOfBlock = insn.operands.filter((op) => op.value === "pc").length === 1;
          }
          break;
      }
      switch (mnemonic) {
        case "it":
          ifThenBlockRemaining = 1;
          break;
        case "itt":
          ifThenBlockRemaining = 2;
          break;
        case "ittt":
          ifThenBlockRemaining = 3;
          break;
        case "itttt":
          ifThenBlockRemaining = 4;
          break;
        default:
          if (ifThenBlockRemaining > 0) {
            ifThenBlockRemaining--;
          }
          break;
      }
      if (branchTarget !== null) {
        branchTargets.add(branchTarget.toString());
        pending.push(branchTarget.or(thumbBit));
        pending.sort((a, b) => a.compare(b));
      }
      current = insn.next;
    } while (!reachedEndOfBlock);
    if (block !== null) {
      block.end = lastInsn.address.add(lastInsn.size);
      blocks[blockId] = block;
    }
  }
  const blocksOrdered = Object.keys(blocks).map((key) => blocks[key]);
  blocksOrdered.sort((a, b) => a.begin.compare(b.begin));
  const entryBlock = blocks[exceptionClearImpl.and(thumbBitRemovalMask).toString()];
  blocksOrdered.splice(blocksOrdered.indexOf(entryBlock), 1);
  blocksOrdered.unshift(entryBlock);
  const writer = new ThumbWriter(buffer, { pc });
  let foundCore = false;
  let threadReg = null;
  let realImplReg = null;
  blocksOrdered.forEach((block) => {
    const relocator = new ThumbRelocator(block.begin, writer);
    let address = block.begin;
    const end = block.end;
    let size = 0;
    do {
      const offset = relocator.readOne();
      if (offset === 0) {
        throw new Error("Unexpected end of block");
      }
      const insn = relocator.input;
      address = insn.address;
      size = insn.size;
      const { mnemonic } = insn;
      const insnAddressId = address.toString();
      if (branchTargets.has(insnAddressId)) {
        writer.putLabel(insnAddressId);
      }
      let keep = true;
      switch (mnemonic) {
        case "b":
          writer.putBLabel(branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case "beq.w":
          writer.putBCondLabelWide("eq", branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case "bne.w":
          writer.putBCondLabelWide("ne", branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case "beq":
        case "bne":
        case "bgt":
          writer.putBCondLabelWide(mnemonic.substr(1), branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case "cbz": {
          const ops = insn.operands;
          writer.putCbzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
          keep = false;
          break;
        }
        case "cbnz": {
          const ops = insn.operands;
          writer.putCbnzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
          keep = false;
          break;
        }
        /*
         * JNI::ExceptionClear(), when checked JNI is off.
         */
        case "str":
        case "str.w": {
          const dstValue = insn.operands[1].value;
          const dstOffset = dstValue.disp;
          if (dstOffset === exceptionOffset) {
            threadReg = dstValue.base;
            const nzcvqReg = threadReg !== "r4" ? "r4" : "r5";
            const clobberedRegs = ["r0", "r1", "r2", "r3", nzcvqReg, "r9", "r12", "lr"];
            writer.putPushRegs(clobberedRegs);
            writer.putMrsRegReg(nzcvqReg, "apsr-nzcvq");
            writer.putCallAddressWithArguments(callback, [threadReg]);
            writer.putMsrRegReg("apsr-nzcvq", nzcvqReg);
            writer.putPopRegs(clobberedRegs);
            foundCore = true;
            keep = false;
          } else if (neuteredOffsets.has(dstOffset) && dstValue.base === threadReg) {
            keep = false;
          }
          break;
        }
        /*
         * CheckJNI::ExceptionClear, when checked JNI is on. Wrapper that calls JNI::ExceptionClear().
         */
        case "ldr": {
          const [dstOp, srcOp] = insn.operands;
          if (srcOp.type === "mem") {
            const src = srcOp.value;
            if (src.base[0] === "r" && src.disp === ENV_VTABLE_OFFSET_EXCEPTION_CLEAR) {
              realImplReg = dstOp.value;
            }
          }
          break;
        }
        case "blx":
          if (insn.operands[0].value === realImplReg) {
            writer.putLdrRegRegOffset("r0", "r0", 4);
            writer.putCallAddressWithArguments(callback, ["r0"]);
            foundCore = true;
            realImplReg = null;
            keep = false;
          }
          break;
      }
      if (keep) {
        relocator.writeAll();
      } else {
        relocator.skipOne();
      }
    } while (!address.add(size).equals(end));
    relocator.dispose();
  });
  writer.dispose();
  if (!foundCore) {
    throwThreadStateTransitionParseError();
  }
  return new NativeFunction(pc.or(1), "void", ["pointer"], nativeFunctionOptions3);
}
function recompileExceptionClearForArm64(buffer, pc, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback) {
  const blocks = {};
  const branchTargets = /* @__PURE__ */ new Set();
  const pending = [exceptionClearImpl];
  while (pending.length > 0) {
    let current = pending.shift();
    const alreadyCovered = Object.values(blocks).some(({ begin, end }) => current.compare(begin) >= 0 && current.compare(end) < 0);
    if (alreadyCovered) {
      continue;
    }
    const blockAddressKey = current.toString();
    let block = {
      begin: current
    };
    let lastInsn = null;
    let reachedEndOfBlock = false;
    do {
      if (current.equals(nextFuncImpl)) {
        reachedEndOfBlock = true;
        break;
      }
      let insn;
      try {
        insn = Instruction.parse(current);
      } catch (e) {
        if (current.readU32() === 0) {
          reachedEndOfBlock = true;
          break;
        } else {
          throw e;
        }
      }
      lastInsn = insn;
      const existingBlock = blocks[insn.address.toString()];
      if (existingBlock !== void 0) {
        delete blocks[existingBlock.begin.toString()];
        blocks[blockAddressKey] = existingBlock;
        existingBlock.begin = block.begin;
        block = null;
        break;
      }
      let branchTarget = null;
      switch (insn.mnemonic) {
        case "b":
          branchTarget = ptr(insn.operands[0].value);
          reachedEndOfBlock = true;
          break;
        case "b.eq":
        case "b.ne":
        case "b.le":
        case "b.gt":
          branchTarget = ptr(insn.operands[0].value);
          break;
        case "cbz":
        case "cbnz":
          branchTarget = ptr(insn.operands[1].value);
          break;
        case "tbz":
        case "tbnz":
          branchTarget = ptr(insn.operands[2].value);
          break;
        case "ret":
          reachedEndOfBlock = true;
          break;
      }
      if (branchTarget !== null) {
        branchTargets.add(branchTarget.toString());
        pending.push(branchTarget);
        pending.sort((a, b) => a.compare(b));
      }
      current = insn.next;
    } while (!reachedEndOfBlock);
    if (block !== null) {
      block.end = lastInsn.address.add(lastInsn.size);
      blocks[blockAddressKey] = block;
    }
  }
  const blocksOrdered = Object.keys(blocks).map((key) => blocks[key]);
  blocksOrdered.sort((a, b) => a.begin.compare(b.begin));
  const entryBlock = blocks[exceptionClearImpl.toString()];
  blocksOrdered.splice(blocksOrdered.indexOf(entryBlock), 1);
  blocksOrdered.unshift(entryBlock);
  const writer = new Arm64Writer(buffer, { pc });
  writer.putBLabel("performTransition");
  const invokeCallback = pc.add(writer.offset);
  writer.putPushAllXRegisters();
  writer.putCallAddressWithArguments(callback, ["x0"]);
  writer.putPopAllXRegisters();
  writer.putRet();
  writer.putLabel("performTransition");
  let foundCore = false;
  let threadReg = null;
  let realImplReg = null;
  blocksOrdered.forEach((block) => {
    const size = block.end.sub(block.begin).toInt32();
    const relocator = new Arm64Relocator(block.begin, writer);
    let offset;
    while ((offset = relocator.readOne()) !== 0) {
      const insn = relocator.input;
      const { mnemonic } = insn;
      const insnAddressId = insn.address.toString();
      if (branchTargets.has(insnAddressId)) {
        writer.putLabel(insnAddressId);
      }
      let keep = true;
      switch (mnemonic) {
        case "b":
          writer.putBLabel(branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case "b.eq":
        case "b.ne":
        case "b.le":
        case "b.gt":
          writer.putBCondLabel(mnemonic.substr(2), branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case "cbz": {
          const ops = insn.operands;
          writer.putCbzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
          keep = false;
          break;
        }
        case "cbnz": {
          const ops = insn.operands;
          writer.putCbnzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
          keep = false;
          break;
        }
        case "tbz": {
          const ops = insn.operands;
          writer.putTbzRegImmLabel(ops[0].value, ops[1].value.valueOf(), branchLabelFromOperand(ops[2]));
          keep = false;
          break;
        }
        case "tbnz": {
          const ops = insn.operands;
          writer.putTbnzRegImmLabel(ops[0].value, ops[1].value.valueOf(), branchLabelFromOperand(ops[2]));
          keep = false;
          break;
        }
        /*
         * JNI::ExceptionClear(), when checked JNI is off.
         */
        case "str": {
          const ops = insn.operands;
          const srcReg = ops[0].value;
          const dstValue = ops[1].value;
          const dstOffset = dstValue.disp;
          if (srcReg === "xzr" && dstOffset === exceptionOffset) {
            threadReg = dstValue.base;
            writer.putPushRegReg("x0", "lr");
            writer.putMovRegReg("x0", threadReg);
            writer.putBlImm(invokeCallback);
            writer.putPopRegReg("x0", "lr");
            foundCore = true;
            keep = false;
          } else if (neuteredOffsets.has(dstOffset) && dstValue.base === threadReg) {
            keep = false;
          }
          break;
        }
        /*
         * CheckJNI::ExceptionClear, when checked JNI is on. Wrapper that calls JNI::ExceptionClear().
         */
        case "ldr": {
          const ops = insn.operands;
          const src = ops[1].value;
          if (src.base[0] === "x" && src.disp === ENV_VTABLE_OFFSET_EXCEPTION_CLEAR) {
            realImplReg = ops[0].value;
          }
          break;
        }
        case "blr":
          if (insn.operands[0].value === realImplReg) {
            writer.putLdrRegRegOffset("x0", "x0", 8);
            writer.putCallAddressWithArguments(callback, ["x0"]);
            foundCore = true;
            realImplReg = null;
            keep = false;
          }
          break;
      }
      if (keep) {
        relocator.writeAll();
      } else {
        relocator.skipOne();
      }
      if (offset === size) {
        break;
      }
    }
    relocator.dispose();
  });
  writer.dispose();
  if (!foundCore) {
    throwThreadStateTransitionParseError();
  }
  return new NativeFunction(pc, "void", ["pointer"], nativeFunctionOptions3);
}
function throwThreadStateTransitionParseError() {
  throw new Error("Unable to parse ART internals; please file a bug");
}
function fixupArtQuickDeliverExceptionBug(api2) {
  const prettyMethod = api2["art::ArtMethod::PrettyMethod"];
  if (prettyMethod === void 0) {
    return;
  }
  Interceptor.attach(prettyMethod.impl, artController.hooks.ArtMethod.prettyMethod);
  Interceptor.flush();
}
function branchLabelFromOperand(op) {
  return ptr(op.value).toString();
}
function makeCxxMethodWrapperReturningPointerByValueGeneric(address, argTypes) {
  return new NativeFunction(address, "pointer", argTypes, nativeFunctionOptions3);
}
function makeCxxMethodWrapperReturningPointerByValueInFirstArg(address, argTypes) {
  const impl = new NativeFunction(address, "void", ["pointer"].concat(argTypes), nativeFunctionOptions3);
  return function() {
    const resultPtr = Memory.alloc(pointerSize5);
    impl(resultPtr, ...arguments);
    return resultPtr.readPointer();
  };
}
function makeCxxMethodWrapperReturningStdStringByValue(impl, argTypes) {
  const { arch } = Process;
  switch (arch) {
    case "ia32":
    case "arm64": {
      let thunk;
      if (arch === "ia32") {
        thunk = makeThunk(64, (writer) => {
          const argCount = 1 + argTypes.length;
          const argvSize = argCount * 4;
          writer.putSubRegImm("esp", argvSize);
          for (let i = 0; i !== argCount; i++) {
            const offset = i * 4;
            writer.putMovRegRegOffsetPtr("eax", "esp", argvSize + 4 + offset);
            writer.putMovRegOffsetPtrReg("esp", offset, "eax");
          }
          writer.putCallAddress(impl);
          writer.putAddRegImm("esp", argvSize - 4);
          writer.putRet();
        });
      } else {
        thunk = makeThunk(32, (writer) => {
          writer.putMovRegReg("x8", "x0");
          argTypes.forEach((t, i) => {
            writer.putMovRegReg("x" + i, "x" + (i + 1));
          });
          writer.putLdrRegAddress("x7", impl);
          writer.putBrReg("x7");
        });
      }
      const invokeThunk = new NativeFunction(thunk, "void", ["pointer"].concat(argTypes), nativeFunctionOptions3);
      const wrapper = function(...args) {
        invokeThunk(...args);
      };
      wrapper.handle = thunk;
      wrapper.impl = impl;
      return wrapper;
    }
    default: {
      const result = new NativeFunction(impl, "void", ["pointer"].concat(argTypes), nativeFunctionOptions3);
      result.impl = impl;
      return result;
    }
  }
}
var StdString = class {
  constructor() {
    this.handle = Memory.alloc(STD_STRING_SIZE);
  }
  dispose() {
    const [data, isTiny] = this._getData();
    if (!isTiny) {
      getApi().$delete(data);
    }
  }
  disposeToString() {
    const result = this.toString();
    this.dispose();
    return result;
  }
  toString() {
    const [data] = this._getData();
    return data.readUtf8String();
  }
  _getData() {
    const str = this.handle;
    const isTiny = (str.readU8() & 1) === 0;
    const data = isTiny ? str.add(1) : str.add(2 * pointerSize5).readPointer();
    return [data, isTiny];
  }
};
var StdVector = class {
  $delete() {
    this.dispose();
    getApi().$delete(this);
  }
  constructor(storage, elementSize) {
    this.handle = storage;
    this._begin = storage;
    this._end = storage.add(pointerSize5);
    this._storage = storage.add(2 * pointerSize5);
    this._elementSize = elementSize;
  }
  init() {
    this.begin = NULL;
    this.end = NULL;
    this.storage = NULL;
  }
  dispose() {
    getApi().$delete(this.begin);
  }
  get begin() {
    return this._begin.readPointer();
  }
  set begin(value) {
    this._begin.writePointer(value);
  }
  get end() {
    return this._end.readPointer();
  }
  set end(value) {
    this._end.writePointer(value);
  }
  get storage() {
    return this._storage.readPointer();
  }
  set storage(value) {
    this._storage.writePointer(value);
  }
  get size() {
    return this.end.sub(this.begin).toInt32() / this._elementSize;
  }
};
var HandleVector = class _HandleVector extends StdVector {
  static $new() {
    const vector = new _HandleVector(getApi().$new(STD_VECTOR_SIZE));
    vector.init();
    return vector;
  }
  constructor(storage) {
    super(storage, pointerSize5);
  }
  get handles() {
    const result = [];
    let cur = this.begin;
    const end = this.end;
    while (!cur.equals(end)) {
      result.push(cur.readPointer());
      cur = cur.add(pointerSize5);
    }
    return result;
  }
};
var BHS_OFFSET_LINK = 0;
var BHS_OFFSET_NUM_REFS = pointerSize5;
var BHS_SIZE = BHS_OFFSET_NUM_REFS + 4;
var kNumReferencesVariableSized = -1;
var BaseHandleScope = class _BaseHandleScope {
  $delete() {
    this.dispose();
    getApi().$delete(this);
  }
  constructor(storage) {
    this.handle = storage;
    this._link = storage.add(BHS_OFFSET_LINK);
    this._numberOfReferences = storage.add(BHS_OFFSET_NUM_REFS);
  }
  init(link, numberOfReferences) {
    this.link = link;
    this.numberOfReferences = numberOfReferences;
  }
  dispose() {
  }
  get link() {
    return new _BaseHandleScope(this._link.readPointer());
  }
  set link(value) {
    this._link.writePointer(value);
  }
  get numberOfReferences() {
    return this._numberOfReferences.readS32();
  }
  set numberOfReferences(value) {
    this._numberOfReferences.writeS32(value);
  }
};
var VSHS_OFFSET_SELF = alignPointerOffset(BHS_SIZE);
var VSHS_OFFSET_CURRENT_SCOPE = VSHS_OFFSET_SELF + pointerSize5;
var VSHS_SIZE = VSHS_OFFSET_CURRENT_SCOPE + pointerSize5;
var VariableSizedHandleScope = class _VariableSizedHandleScope extends BaseHandleScope {
  static $new(thread, vm3) {
    const scope = new _VariableSizedHandleScope(getApi().$new(VSHS_SIZE));
    scope.init(thread, vm3);
    return scope;
  }
  constructor(storage) {
    super(storage);
    this._self = storage.add(VSHS_OFFSET_SELF);
    this._currentScope = storage.add(VSHS_OFFSET_CURRENT_SCOPE);
    const kLocalScopeSize = 64;
    const kSizeOfReferencesPerScope = kLocalScopeSize - pointerSize5 - 4 - 4;
    const kNumReferencesPerScope = kSizeOfReferencesPerScope / 4;
    this._scopeLayout = FixedSizeHandleScope.layoutForCapacity(kNumReferencesPerScope);
    this._topHandleScopePtr = null;
  }
  init(thread, vm3) {
    const topHandleScopePtr = thread.add(getArtThreadSpec(vm3).offset.topHandleScope);
    this._topHandleScopePtr = topHandleScopePtr;
    super.init(topHandleScopePtr.readPointer(), kNumReferencesVariableSized);
    this.self = thread;
    this.currentScope = FixedSizeHandleScope.$new(this._scopeLayout);
    topHandleScopePtr.writePointer(this);
  }
  dispose() {
    this._topHandleScopePtr.writePointer(this.link);
    let scope;
    while ((scope = this.currentScope) !== null) {
      const next = scope.link;
      scope.$delete();
      this.currentScope = next;
    }
  }
  get self() {
    return this._self.readPointer();
  }
  set self(value) {
    this._self.writePointer(value);
  }
  get currentScope() {
    const storage = this._currentScope.readPointer();
    if (storage.isNull()) {
      return null;
    }
    return new FixedSizeHandleScope(storage, this._scopeLayout);
  }
  set currentScope(value) {
    this._currentScope.writePointer(value);
  }
  newHandle(object) {
    return this.currentScope.newHandle(object);
  }
};
var FixedSizeHandleScope = class _FixedSizeHandleScope extends BaseHandleScope {
  static $new(layout) {
    const scope = new _FixedSizeHandleScope(getApi().$new(layout.size), layout);
    scope.init();
    return scope;
  }
  constructor(storage, layout) {
    super(storage);
    const { offset } = layout;
    this._refsStorage = storage.add(offset.refsStorage);
    this._pos = storage.add(offset.pos);
    this._layout = layout;
  }
  init() {
    super.init(NULL, this._layout.numberOfReferences);
    this.pos = 0;
  }
  get pos() {
    return this._pos.readU32();
  }
  set pos(value) {
    this._pos.writeU32(value);
  }
  newHandle(object) {
    const pos = this.pos;
    const handle = this._refsStorage.add(pos * 4);
    handle.writeS32(object.toInt32());
    this.pos = pos + 1;
    return handle;
  }
  static layoutForCapacity(numRefs) {
    const refsStorage = BHS_SIZE;
    const pos = refsStorage + numRefs * 4;
    return {
      size: pos + 4,
      numberOfReferences: numRefs,
      offset: {
        refsStorage,
        pos
      }
    };
  }
};
var objectVisitorPredicateFactories = {
  arm: function(needle, onMatch) {
    const size = Process.pageSize;
    const predicate = Memory.alloc(size);
    Memory.protect(predicate, size, "rwx");
    const onMatchCallback = new NativeCallback(onMatch, "void", ["pointer"]);
    predicate._onMatchCallback = onMatchCallback;
    const instructions = [
      26625,
      // ldr r1, [r0]
      18947,
      // ldr r2, =needle
      17041,
      // cmp r1, r2
      53505,
      // bne mismatch
      19202,
      // ldr r3, =onMatch
      18200,
      // bx r3
      18288,
      // bx lr
      48896
      // nop
    ];
    const needleOffset = instructions.length * 2;
    const onMatchOffset = needleOffset + 4;
    const codeSize = onMatchOffset + 4;
    Memory.patchCode(predicate, codeSize, function(address) {
      instructions.forEach((instruction, index) => {
        address.add(index * 2).writeU16(instruction);
      });
      address.add(needleOffset).writeS32(needle);
      address.add(onMatchOffset).writePointer(onMatchCallback);
    });
    return predicate.or(1);
  },
  arm64: function(needle, onMatch) {
    const size = Process.pageSize;
    const predicate = Memory.alloc(size);
    Memory.protect(predicate, size, "rwx");
    const onMatchCallback = new NativeCallback(onMatch, "void", ["pointer"]);
    predicate._onMatchCallback = onMatchCallback;
    const instructions = [
      3107979265,
      // ldr w1, [x0]
      402653378,
      // ldr w2, =needle
      1795293247,
      // cmp w1, w2
      1409286241,
      // b.ne mismatch
      1476395139,
      // ldr x3, =onMatch
      3592355936,
      // br x3
      3596551104
      // ret
    ];
    const needleOffset = instructions.length * 4;
    const onMatchOffset = needleOffset + 4;
    const codeSize = onMatchOffset + 8;
    Memory.patchCode(predicate, codeSize, function(address) {
      instructions.forEach((instruction, index) => {
        address.add(index * 4).writeU32(instruction);
      });
      address.add(needleOffset).writeS32(needle);
      address.add(onMatchOffset).writePointer(onMatchCallback);
    });
    return predicate;
  }
};
function makeObjectVisitorPredicate(needle, onMatch) {
  const factory = objectVisitorPredicateFactories[Process.arch] || makeGenericObjectVisitorPredicate;
  return factory(needle, onMatch);
}
function makeGenericObjectVisitorPredicate(needle, onMatch) {
  return new NativeCallback((object) => {
    const klass = object.readS32();
    if (klass === needle) {
      onMatch(object);
    }
  }, "void", ["pointer", "pointer"]);
}
function alignPointerOffset(offset) {
  const remainder = offset % pointerSize5;
  if (remainder !== 0) {
    return offset + pointerSize5 - remainder;
  }
  return offset;
}

// node_modules/frida-java-bridge/lib/jvm.js
var jsizeSize2 = 4;
var { pointerSize: pointerSize6 } = Process;
var JVM_ACC_NATIVE = 256;
var JVM_ACC_IS_OLD = 65536;
var JVM_ACC_IS_OBSOLETE = 131072;
var JVM_ACC_NOT_C2_COMPILABLE = 33554432;
var JVM_ACC_NOT_C1_COMPILABLE = 67108864;
var JVM_ACC_NOT_C2_OSR_COMPILABLE = 134217728;
var nativeFunctionOptions4 = {
  exceptions: "propagate"
};
var getJvmMethodSpec = memoize(_getJvmMethodSpec);
var getJvmInstanceKlassSpec = memoize(_getJvmInstanceKlassSpec);
var getJvmThreadSpec = memoize(_getJvmThreadSpec);
var cachedApi2 = null;
var manglersScheduled = false;
var replaceManglers = /* @__PURE__ */ new Map();
var revertManglers = /* @__PURE__ */ new Map();
function getApi2() {
  if (cachedApi2 === null) {
    cachedApi2 = _getApi2();
  }
  return cachedApi2;
}
function _getApi2() {
  const vmModules = Process.enumerateModules().filter((m) => /jvm.(dll|dylib|so)$/.test(m.name));
  if (vmModules.length === 0) {
    return null;
  }
  const vmModule = vmModules[0];
  const temporaryApi = {
    flavor: "jvm"
  };
  const pending = Process.platform === "windows" ? [{
    module: vmModule,
    functions: {
      JNI_GetCreatedJavaVMs: ["JNI_GetCreatedJavaVMs", "int", ["pointer", "int", "pointer"]],
      JVM_Sleep: ["JVM_Sleep", "void", ["pointer", "pointer", "long"]],
      "VMThread::execute": ["VMThread::execute", "void", ["pointer"]],
      "Method::size": ["Method::size", "int", ["int"]],
      "Method::set_native_function": ["Method::set_native_function", "void", ["pointer", "pointer", "int"]],
      "Method::clear_native_function": ["Method::clear_native_function", "void", ["pointer"]],
      "Method::jmethod_id": ["Method::jmethod_id", "pointer", ["pointer"]],
      "ClassLoaderDataGraph::classes_do": ["ClassLoaderDataGraph::classes_do", "void", ["pointer"]],
      "NMethodSweeper::sweep_code_cache": ["NMethodSweeper::sweep_code_cache", "void", []],
      "OopMapCache::flush_obsolete_entries": ["OopMapCache::flush_obsolete_entries", "void", ["pointer"]]
    },
    variables: {
      "VM_RedefineClasses::`vftable'": function(address) {
        this.vtableRedefineClasses = address;
      },
      "VM_RedefineClasses::doit": function(address) {
        this.redefineClassesDoIt = address;
      },
      "VM_RedefineClasses::doit_prologue": function(address) {
        this.redefineClassesDoItPrologue = address;
      },
      "VM_RedefineClasses::doit_epilogue": function(address) {
        this.redefineClassesDoItEpilogue = address;
      },
      "VM_RedefineClasses::allow_nested_vm_operations": function(address) {
        this.redefineClassesAllow = address;
      },
      "NMethodSweeper::_traversals": function(address) {
        this.traversals = address;
      },
      "NMethodSweeper::_should_sweep": function(address) {
        this.shouldSweep = address;
      }
    },
    optionals: []
  }] : [{
    module: vmModule,
    functions: {
      JNI_GetCreatedJavaVMs: ["JNI_GetCreatedJavaVMs", "int", ["pointer", "int", "pointer"]],
      _ZN6Method4sizeEb: ["Method::size", "int", ["int"]],
      _ZN6Method19set_native_functionEPhb: ["Method::set_native_function", "void", ["pointer", "pointer", "int"]],
      _ZN6Method21clear_native_functionEv: ["Method::clear_native_function", "void", ["pointer"]],
      // JDK >= 17
      _ZN6Method24restore_unshareable_infoEP10JavaThread: ["Method::restore_unshareable_info", "void", ["pointer", "pointer"]],
      // JDK < 17
      _ZN6Method24restore_unshareable_infoEP6Thread: ["Method::restore_unshareable_info", "void", ["pointer", "pointer"]],
      _ZN6Method11link_methodERK12methodHandleP10JavaThread: ["Method::link_method", "void", ["pointer", "pointer", "pointer"]],
      _ZN6Method10jmethod_idEv: ["Method::jmethod_id", "pointer", ["pointer"]],
      _ZN6Method10clear_codeEv: function(address) {
        const clearCode = new NativeFunction(address, "void", ["pointer"], nativeFunctionOptions4);
        this["Method::clear_code"] = function(thisPtr) {
          clearCode(thisPtr);
        };
      },
      _ZN6Method10clear_codeEb: function(address) {
        const clearCode = new NativeFunction(address, "void", ["pointer", "int"], nativeFunctionOptions4);
        const lock = 0;
        this["Method::clear_code"] = function(thisPtr) {
          clearCode(thisPtr, lock);
        };
      },
      // JDK >= 13
      _ZN18VM_RedefineClasses19mark_dependent_codeEP13InstanceKlass: ["VM_RedefineClasses::mark_dependent_code", "void", ["pointer", "pointer"]],
      _ZN18VM_RedefineClasses20flush_dependent_codeEv: ["VM_RedefineClasses::flush_dependent_code", "void", []],
      // JDK < 13
      _ZN18VM_RedefineClasses20flush_dependent_codeEP13InstanceKlassP6Thread: ["VM_RedefineClasses::flush_dependent_code", "void", ["pointer", "pointer", "pointer"]],
      // JDK < 10
      _ZN18VM_RedefineClasses20flush_dependent_codeE19instanceKlassHandleP6Thread: ["VM_RedefineClasses::flush_dependent_code", "void", ["pointer", "pointer", "pointer"]],
      _ZN19ResolvedMethodTable21adjust_method_entriesEPb: ["ResolvedMethodTable::adjust_method_entries", "void", ["pointer"]],
      // JDK < 10
      _ZN15MemberNameTable21adjust_method_entriesEP13InstanceKlassPb: ["MemberNameTable::adjust_method_entries", "void", ["pointer", "pointer", "pointer"]],
      _ZN17ConstantPoolCache21adjust_method_entriesEPb: function(address) {
        const adjustMethod = new NativeFunction(address, "void", ["pointer", "pointer"], nativeFunctionOptions4);
        this["ConstantPoolCache::adjust_method_entries"] = function(thisPtr, holderPtr, tracePtr) {
          adjustMethod(thisPtr, tracePtr);
        };
      },
      // JDK < 13
      _ZN17ConstantPoolCache21adjust_method_entriesEP13InstanceKlassPb: function(address) {
        const adjustMethod = new NativeFunction(address, "void", ["pointer", "pointer", "pointer"], nativeFunctionOptions4);
        this["ConstantPoolCache::adjust_method_entries"] = function(thisPtr, holderPtr, tracePtr) {
          adjustMethod(thisPtr, holderPtr, tracePtr);
        };
      },
      _ZN20ClassLoaderDataGraph10classes_doEP12KlassClosure: ["ClassLoaderDataGraph::classes_do", "void", ["pointer"]],
      _ZN20ClassLoaderDataGraph22clean_deallocate_listsEb: ["ClassLoaderDataGraph::clean_deallocate_lists", "void", ["int"]],
      _ZN10JavaThread27thread_from_jni_environmentEP7JNIEnv_: ["JavaThread::thread_from_jni_environment", "pointer", ["pointer"]],
      _ZN8VMThread7executeEP12VM_Operation: ["VMThread::execute", "void", ["pointer"]],
      _ZN11OopMapCache22flush_obsolete_entriesEv: ["OopMapCache::flush_obsolete_entries", "void", ["pointer"]],
      _ZN14NMethodSweeper11force_sweepEv: ["NMethodSweeper::force_sweep", "void", []],
      _ZN14NMethodSweeper16sweep_code_cacheEv: ["NMethodSweeper::sweep_code_cache", "void", []],
      _ZN14NMethodSweeper17sweep_in_progressEv: ["NMethodSweeper::sweep_in_progress", "bool", []],
      JVM_Sleep: ["JVM_Sleep", "void", ["pointer", "pointer", "long"]]
    },
    variables: {
      // JDK <= 9
      _ZN18VM_RedefineClasses14_the_class_oopE: function(address) {
        this.redefineClass = address;
      },
      // 9 < JDK < 13
      _ZN18VM_RedefineClasses10_the_classE: function(address) {
        this.redefineClass = address;
      },
      // JDK < 13
      _ZN18VM_RedefineClasses25AdjustCpoolCacheAndVtable8do_klassEP5Klass: function(address) {
        this.doKlass = address;
      },
      // JDK >= 13
      _ZN18VM_RedefineClasses22AdjustAndCleanMetadata8do_klassEP5Klass: function(address) {
        this.doKlass = address;
      },
      _ZTV18VM_RedefineClasses: function(address) {
        this.vtableRedefineClasses = address;
      },
      _ZN18VM_RedefineClasses4doitEv: function(address) {
        this.redefineClassesDoIt = address;
      },
      _ZN18VM_RedefineClasses13doit_prologueEv: function(address) {
        this.redefineClassesDoItPrologue = address;
      },
      _ZN18VM_RedefineClasses13doit_epilogueEv: function(address) {
        this.redefineClassesDoItEpilogue = address;
      },
      _ZN18VM_RedefineClassesD0Ev: function(address) {
        this.redefineClassesDispose0 = address;
      },
      _ZN18VM_RedefineClassesD1Ev: function(address) {
        this.redefineClassesDispose1 = address;
      },
      _ZNK18VM_RedefineClasses26allow_nested_vm_operationsEv: function(address) {
        this.redefineClassesAllow = address;
      },
      _ZNK18VM_RedefineClasses14print_on_errorEP12outputStream: function(address) {
        this.redefineClassesOnError = address;
      },
      // JDK >= 17
      _ZN13InstanceKlass33create_new_default_vtable_indicesEiP10JavaThread: function(address) {
        this.createNewDefaultVtableIndices = address;
      },
      // JDK < 17
      _ZN13InstanceKlass33create_new_default_vtable_indicesEiP6Thread: function(address) {
        this.createNewDefaultVtableIndices = address;
      },
      _ZN19Abstract_VM_Version19jre_release_versionEv: function(address) {
        const getVersion = new NativeFunction(address, "pointer", [], nativeFunctionOptions4);
        const versionS = getVersion().readCString();
        this.version = versionS.startsWith("1.8") ? 8 : versionS.startsWith("9.") ? 9 : parseInt(versionS.slice(0, 2), 10);
        this.versionS = versionS;
      },
      _ZN14NMethodSweeper11_traversalsE: function(address) {
        this.traversals = address;
      },
      _ZN14NMethodSweeper21_sweep_fractions_leftE: function(address) {
        this.fractions = address;
      },
      _ZN14NMethodSweeper13_should_sweepE: function(address) {
        this.shouldSweep = address;
      }
    },
    optionals: [
      "_ZN6Method24restore_unshareable_infoEP10JavaThread",
      "_ZN6Method24restore_unshareable_infoEP6Thread",
      "_ZN6Method11link_methodERK12methodHandleP10JavaThread",
      "_ZN6Method10clear_codeEv",
      "_ZN6Method10clear_codeEb",
      "_ZN18VM_RedefineClasses19mark_dependent_codeEP13InstanceKlass",
      "_ZN18VM_RedefineClasses20flush_dependent_codeEv",
      "_ZN18VM_RedefineClasses20flush_dependent_codeEP13InstanceKlassP6Thread",
      "_ZN18VM_RedefineClasses20flush_dependent_codeE19instanceKlassHandleP6Thread",
      "_ZN19ResolvedMethodTable21adjust_method_entriesEPb",
      "_ZN15MemberNameTable21adjust_method_entriesEP13InstanceKlassPb",
      "_ZN17ConstantPoolCache21adjust_method_entriesEPb",
      "_ZN17ConstantPoolCache21adjust_method_entriesEP13InstanceKlassPb",
      "_ZN20ClassLoaderDataGraph22clean_deallocate_listsEb",
      "_ZN10JavaThread27thread_from_jni_environmentEP7JNIEnv_",
      "_ZN14NMethodSweeper11force_sweepEv",
      "_ZN14NMethodSweeper17sweep_in_progressEv",
      "_ZN18VM_RedefineClasses14_the_class_oopE",
      "_ZN18VM_RedefineClasses10_the_classE",
      "_ZN18VM_RedefineClasses25AdjustCpoolCacheAndVtable8do_klassEP5Klass",
      "_ZN18VM_RedefineClasses22AdjustAndCleanMetadata8do_klassEP5Klass",
      "_ZN18VM_RedefineClassesD0Ev",
      "_ZN18VM_RedefineClassesD1Ev",
      "_ZNK18VM_RedefineClasses14print_on_errorEP12outputStream",
      "_ZN13InstanceKlass33create_new_default_vtable_indicesEiP10JavaThread",
      "_ZN13InstanceKlass33create_new_default_vtable_indicesEiP6Thread",
      "_ZN14NMethodSweeper21_sweep_fractions_leftE"
    ]
  }];
  const missing = [];
  pending.forEach(function(api2) {
    const module = api2.module;
    const functions = api2.functions || {};
    const variables = api2.variables || {};
    const optionals = new Set(api2.optionals || []);
    const tmp = module.enumerateExports().reduce(function(result, exp) {
      result[exp.name] = exp;
      return result;
    }, {});
    const exportByName = module.enumerateSymbols().reduce(function(result, exp) {
      result[exp.name] = exp;
      return result;
    }, tmp);
    Object.keys(functions).forEach(function(name) {
      const exp = exportByName[name];
      if (exp !== void 0) {
        const signature = functions[name];
        if (typeof signature === "function") {
          signature.call(temporaryApi, exp.address);
        } else {
          temporaryApi[signature[0]] = new NativeFunction(exp.address, signature[1], signature[2], nativeFunctionOptions4);
        }
      } else {
        if (!optionals.has(name)) {
          missing.push(name);
        }
      }
    });
    Object.keys(variables).forEach(function(name) {
      const exp = exportByName[name];
      if (exp !== void 0) {
        const handler = variables[name];
        handler.call(temporaryApi, exp.address);
      } else {
        if (!optionals.has(name)) {
          missing.push(name);
        }
      }
    });
  });
  if (missing.length > 0) {
    throw new Error("Java API only partially available; please file a bug. Missing: " + missing.join(", "));
  }
  const vms = Memory.alloc(pointerSize6);
  const vmCount = Memory.alloc(jsizeSize2);
  checkJniResult("JNI_GetCreatedJavaVMs", temporaryApi.JNI_GetCreatedJavaVMs(vms, 1, vmCount));
  if (vmCount.readInt() === 0) {
    return null;
  }
  temporaryApi.vm = vms.readPointer();
  const allocatorFunctions = Process.platform === "windows" ? {
    $new: ["??2@YAPEAX_K@Z", "pointer", ["ulong"]],
    $delete: ["??3@YAXPEAX@Z", "void", ["pointer"]]
  } : {
    $new: ["_Znwm", "pointer", ["ulong"]],
    $delete: ["_ZdlPv", "void", ["pointer"]]
  };
  for (const [name, [rawName, retType, argTypes]] of Object.entries(allocatorFunctions)) {
    let address = Module.findGlobalExportByName(rawName);
    if (address === null) {
      address = DebugSymbol.fromName(rawName).address;
      if (address.isNull()) {
        throw new Error(`unable to find C++ allocator API, missing: '${rawName}'`);
      }
    }
    temporaryApi[name] = new NativeFunction(address, retType, argTypes, nativeFunctionOptions4);
  }
  temporaryApi.jvmti = getEnvJvmti(temporaryApi);
  if (temporaryApi["JavaThread::thread_from_jni_environment"] === void 0) {
    temporaryApi["JavaThread::thread_from_jni_environment"] = makeThreadFromJniHelper(temporaryApi);
  }
  return temporaryApi;
}
function getEnvJvmti(api2) {
  const vm3 = new VM(api2);
  let env;
  vm3.perform(() => {
    const handle = vm3.tryGetEnvHandle(jvmtiVersion.v1_0);
    if (handle === null) {
      throw new Error("JVMTI not available");
    }
    env = new EnvJvmti(handle, vm3);
    const capaBuf = Memory.alloc(8);
    capaBuf.writeU64(jvmtiCapabilities.canTagObjects);
    const result = env.addCapabilities(capaBuf);
    checkJniResult("getEnvJvmti::AddCapabilities", result);
  });
  return env;
}
var threadOffsetParsers = {
  x64: parseX64ThreadOffset
};
function makeThreadFromJniHelper(api2) {
  let offset = null;
  const tryParse = threadOffsetParsers[Process.arch];
  if (tryParse !== void 0) {
    const vm3 = new VM(api2);
    const findClassImpl = vm3.perform((env) => env.handle.readPointer().add(6 * pointerSize6).readPointer());
    offset = parseInstructionsAt(findClassImpl, tryParse, { limit: 11 });
  }
  if (offset === null) {
    return () => {
      throw new Error("Unable to make thread_from_jni_environment() helper for the current architecture");
    };
  }
  return (env) => {
    return env.add(offset);
  };
}
function parseX64ThreadOffset(insn) {
  if (insn.mnemonic !== "lea") {
    return null;
  }
  const { base, disp } = insn.operands[1].value;
  if (!(base === "rdi" && disp < 0)) {
    return null;
  }
  return disp;
}
function ensureClassInitialized2(env, classRef) {
}
var JvmMethodMangler = class {
  constructor(methodId) {
    this.methodId = methodId;
    this.method = methodId.readPointer();
    this.originalMethod = null;
    this.newMethod = null;
    this.resolved = null;
    this.impl = null;
    this.key = methodId.toString(16);
  }
  replace(impl, isInstanceMethod, argTypes, vm3, api2) {
    const { key } = this;
    const mangler = revertManglers.get(key);
    if (mangler !== void 0) {
      revertManglers.delete(key);
      this.method = mangler.method;
      this.originalMethod = mangler.originalMethod;
      this.newMethod = mangler.newMethod;
      this.resolved = mangler.resolved;
    }
    this.impl = impl;
    replaceManglers.set(key, this);
    ensureManglersScheduled(vm3);
  }
  revert(vm3) {
    const { key } = this;
    replaceManglers.delete(key);
    revertManglers.set(key, this);
    ensureManglersScheduled(vm3);
  }
  resolveTarget(wrapper, isInstanceMethod, env, api2) {
    const { resolved, originalMethod, methodId } = this;
    if (resolved !== null) {
      return resolved;
    }
    if (originalMethod === null) {
      return methodId;
    }
    const vip = originalMethod.oldMethod.vtableIndexPtr;
    vip.writeS32(-2);
    const jmethodID = Memory.alloc(pointerSize6);
    jmethodID.writePointer(this.method);
    this.resolved = jmethodID;
    return jmethodID;
  }
};
function ensureManglersScheduled(vm3) {
  if (!manglersScheduled) {
    manglersScheduled = true;
    Script.nextTick(doManglers, vm3);
  }
}
function doManglers(vm3) {
  const localReplaceManglers = new Map(replaceManglers);
  const localRevertManglers = new Map(revertManglers);
  replaceManglers.clear();
  revertManglers.clear();
  manglersScheduled = false;
  vm3.perform((env) => {
    const api2 = getApi2();
    const thread = api2["JavaThread::thread_from_jni_environment"](env.handle);
    let force = false;
    withJvmThread(() => {
      localReplaceManglers.forEach((mangler) => {
        const { method, originalMethod, impl, methodId, newMethod } = mangler;
        if (originalMethod === null) {
          mangler.originalMethod = fetchJvmMethod(method);
          mangler.newMethod = nativeJvmMethod(method, impl, thread);
          installJvmMethod(mangler.newMethod, methodId, thread);
        } else {
          api2["Method::set_native_function"](newMethod.method, impl, 0);
        }
      });
      localRevertManglers.forEach((mangler) => {
        const { originalMethod, methodId, newMethod } = mangler;
        if (originalMethod !== null) {
          revertJvmMethod(originalMethod);
          const revert = originalMethod.oldMethod;
          revert.oldMethod = newMethod;
          installJvmMethod(revert, methodId, thread);
          force = true;
        }
      });
    });
    if (force) {
      forceSweep(env.handle);
    }
  });
}
function forceSweep(env) {
  const {
    fractions,
    shouldSweep,
    traversals,
    "NMethodSweeper::sweep_code_cache": sweep,
    "NMethodSweeper::sweep_in_progress": inProgress,
    "NMethodSweeper::force_sweep": force,
    JVM_Sleep: sleep
  } = getApi2();
  if (force !== void 0) {
    Thread.sleep(0.05);
    force();
    Thread.sleep(0.05);
    force();
  } else {
    let trav = traversals.readS64();
    const endTrav = trav + 2;
    while (endTrav > trav) {
      fractions.writeS32(1);
      sleep(env, NULL, 50);
      if (!inProgress()) {
        withJvmThread(() => {
          Thread.sleep(0.05);
        });
      }
      const sweepNotAlreadyInProgress = shouldSweep.readU8() === 0;
      if (sweepNotAlreadyInProgress) {
        fractions.writeS32(1);
        sweep();
      }
      trav = traversals.readS64();
    }
  }
}
function withJvmThread(fn, fnPrologue, fnEpilogue) {
  const {
    execute,
    vtable: vtable2,
    vtableSize,
    doItOffset,
    prologueOffset,
    epilogueOffset
  } = getJvmThreadSpec();
  const vtableDup = Memory.dup(vtable2, vtableSize);
  const vmOperation = Memory.alloc(pointerSize6 * 25);
  vmOperation.writePointer(vtableDup);
  const doIt = new NativeCallback(fn, "void", ["pointer"]);
  vtableDup.add(doItOffset).writePointer(doIt);
  let prologue = null;
  if (fnPrologue !== void 0) {
    prologue = new NativeCallback(fnPrologue, "int", ["pointer"]);
    vtableDup.add(prologueOffset).writePointer(prologue);
  }
  let epilogue = null;
  if (fnEpilogue !== void 0) {
    epilogue = new NativeCallback(fnEpilogue, "void", ["pointer"]);
    vtableDup.add(epilogueOffset).writePointer(epilogue);
  }
  execute(vmOperation);
}
function _getJvmThreadSpec() {
  const {
    vtableRedefineClasses,
    redefineClassesDoIt,
    redefineClassesDoItPrologue,
    redefineClassesDoItEpilogue,
    redefineClassesOnError,
    redefineClassesAllow,
    redefineClassesDispose0,
    redefineClassesDispose1,
    "VMThread::execute": execute
  } = getApi2();
  const vtablePtr = vtableRedefineClasses.add(2 * pointerSize6);
  const vtableSize = 15 * pointerSize6;
  const vtable2 = Memory.dup(vtablePtr, vtableSize);
  const emptyCallback = new NativeCallback(() => {
  }, "void", ["pointer"]);
  let doItOffset, prologueOffset, epilogueOffset;
  for (let offset = 0; offset !== vtableSize; offset += pointerSize6) {
    const element = vtable2.add(offset);
    const value = element.readPointer();
    if (redefineClassesOnError !== void 0 && value.equals(redefineClassesOnError) || redefineClassesDispose0 !== void 0 && value.equals(redefineClassesDispose0) || redefineClassesDispose1 !== void 0 && value.equals(redefineClassesDispose1)) {
      element.writePointer(emptyCallback);
    } else if (value.equals(redefineClassesDoIt)) {
      doItOffset = offset;
    } else if (value.equals(redefineClassesDoItPrologue)) {
      prologueOffset = offset;
      element.writePointer(redefineClassesAllow);
    } else if (value.equals(redefineClassesDoItEpilogue)) {
      epilogueOffset = offset;
      element.writePointer(emptyCallback);
    }
  }
  return {
    execute,
    emptyCallback,
    vtable: vtable2,
    vtableSize,
    doItOffset,
    prologueOffset,
    epilogueOffset
  };
}
function makeMethodMangler2(methodId) {
  return new JvmMethodMangler(methodId);
}
function installJvmMethod(method, methodId, thread) {
  const { method: handle, oldMethod: old } = method;
  const api2 = getApi2();
  method.methodsArray.add(method.methodIndex * pointerSize6).writePointer(handle);
  if (method.vtableIndex >= 0) {
    method.vtable.add(method.vtableIndex * pointerSize6).writePointer(handle);
  }
  methodId.writePointer(handle);
  old.accessFlagsPtr.writeU32((old.accessFlags | JVM_ACC_IS_OLD | JVM_ACC_IS_OBSOLETE) >>> 0);
  const flushObs = api2["OopMapCache::flush_obsolete_entries"];
  if (flushObs !== void 0) {
    const { oopMapCache } = method;
    if (!oopMapCache.isNull()) {
      flushObs(oopMapCache);
    }
  }
  const mark = api2["VM_RedefineClasses::mark_dependent_code"];
  const flush = api2["VM_RedefineClasses::flush_dependent_code"];
  if (mark !== void 0) {
    mark(NULL, method.instanceKlass);
    flush();
  } else {
    flush(NULL, method.instanceKlass, thread);
  }
  const traceNamePrinted = Memory.alloc(1);
  traceNamePrinted.writeU8(1);
  api2["ConstantPoolCache::adjust_method_entries"](method.cache, method.instanceKlass, traceNamePrinted);
  const klassClosure = Memory.alloc(3 * pointerSize6);
  const doKlassPtr = Memory.alloc(pointerSize6);
  doKlassPtr.writePointer(api2.doKlass);
  klassClosure.writePointer(doKlassPtr);
  klassClosure.add(pointerSize6).writePointer(thread);
  klassClosure.add(2 * pointerSize6).writePointer(thread);
  if (api2.redefineClass !== void 0) {
    api2.redefineClass.writePointer(method.instanceKlass);
  }
  api2["ClassLoaderDataGraph::classes_do"](klassClosure);
  const rmtAdjustMethodEntries = api2["ResolvedMethodTable::adjust_method_entries"];
  if (rmtAdjustMethodEntries !== void 0) {
    rmtAdjustMethodEntries(traceNamePrinted);
  } else {
    const { memberNames } = method;
    if (!memberNames.isNull()) {
      const mntAdjustMethodEntries = api2["MemberNameTable::adjust_method_entries"];
      if (mntAdjustMethodEntries !== void 0) {
        mntAdjustMethodEntries(memberNames, method.instanceKlass, traceNamePrinted);
      }
    }
  }
  const clean = api2["ClassLoaderDataGraph::clean_deallocate_lists"];
  if (clean !== void 0) {
    clean(0);
  }
}
function nativeJvmMethod(method, impl, thread) {
  const api2 = getApi2();
  const newMethod = fetchJvmMethod(method);
  newMethod.constPtr.writePointer(newMethod.const);
  const flags = (newMethod.accessFlags | JVM_ACC_NATIVE | JVM_ACC_NOT_C2_COMPILABLE | JVM_ACC_NOT_C1_COMPILABLE | JVM_ACC_NOT_C2_OSR_COMPILABLE) >>> 0;
  newMethod.accessFlagsPtr.writeU32(flags);
  newMethod.signatureHandler.writePointer(NULL);
  newMethod.adapter.writePointer(NULL);
  newMethod.i2iEntry.writePointer(NULL);
  api2["Method::clear_code"](newMethod.method);
  newMethod.dataPtr.writePointer(NULL);
  newMethod.countersPtr.writePointer(NULL);
  newMethod.stackmapPtr.writePointer(NULL);
  api2["Method::clear_native_function"](newMethod.method);
  api2["Method::set_native_function"](newMethod.method, impl, 0);
  api2["Method::restore_unshareable_info"](newMethod.method, thread);
  if (api2.version >= 17) {
    const methodHandle = Memory.alloc(2 * pointerSize6);
    methodHandle.writePointer(newMethod.method);
    methodHandle.add(pointerSize6).writePointer(thread);
    api2["Method::link_method"](newMethod.method, methodHandle, thread);
  }
  return newMethod;
}
function fetchJvmMethod(method) {
  const spec = getJvmMethodSpec();
  const constMethod = method.add(spec.method.constMethodOffset).readPointer();
  const constMethodSize = constMethod.add(spec.constMethod.sizeOffset).readS32() * pointerSize6;
  const newConstMethod = Memory.alloc(constMethodSize + spec.method.size);
  Memory.copy(newConstMethod, constMethod, constMethodSize);
  const newMethod = newConstMethod.add(constMethodSize);
  Memory.copy(newMethod, method, spec.method.size);
  const result = readJvmMethod(newMethod, newConstMethod, constMethodSize);
  const oldMethod = readJvmMethod(method, constMethod, constMethodSize);
  result.oldMethod = oldMethod;
  return result;
}
function readJvmMethod(method, constMethod, constMethodSize) {
  const api2 = getApi2();
  const spec = getJvmMethodSpec();
  const constPtr = method.add(spec.method.constMethodOffset);
  const dataPtr = method.add(spec.method.methodDataOffset);
  const countersPtr = method.add(spec.method.methodCountersOffset);
  const accessFlagsPtr = method.add(spec.method.accessFlagsOffset);
  const accessFlags = accessFlagsPtr.readU32();
  const adapter = spec.getAdapterPointer(method, constMethod);
  const i2iEntry = method.add(spec.method.i2iEntryOffset);
  const signatureHandler = method.add(spec.method.signatureHandlerOffset);
  const constantPool = constMethod.add(spec.constMethod.constantPoolOffset).readPointer();
  const stackmapPtr = constMethod.add(spec.constMethod.stackmapDataOffset);
  const instanceKlass = constantPool.add(spec.constantPool.instanceKlassOffset).readPointer();
  const cache = constantPool.add(spec.constantPool.cacheOffset).readPointer();
  const instanceKlassSpec = getJvmInstanceKlassSpec();
  const methods = instanceKlass.add(instanceKlassSpec.methodsOffset).readPointer();
  const methodsCount = methods.readS32();
  const methodsArray = methods.add(pointerSize6);
  const methodIndex = constMethod.add(spec.constMethod.methodIdnumOffset).readU16();
  const vtableIndexPtr = method.add(spec.method.vtableIndexOffset);
  const vtableIndex = vtableIndexPtr.readS32();
  const vtable2 = instanceKlass.add(instanceKlassSpec.vtableOffset);
  const oopMapCache = instanceKlass.add(instanceKlassSpec.oopMapCacheOffset).readPointer();
  const memberNames = api2.version >= 10 ? instanceKlass.add(instanceKlassSpec.memberNamesOffset).readPointer() : NULL;
  return {
    method,
    methodSize: spec.method.size,
    const: constMethod,
    constSize: constMethodSize,
    constPtr,
    dataPtr,
    countersPtr,
    stackmapPtr,
    instanceKlass,
    methodsArray,
    methodsCount,
    methodIndex,
    vtableIndex,
    vtableIndexPtr,
    vtable: vtable2,
    accessFlags,
    accessFlagsPtr,
    adapter,
    i2iEntry,
    signatureHandler,
    memberNames,
    cache,
    oopMapCache
  };
}
function revertJvmMethod(method) {
  const { oldMethod: old } = method;
  old.accessFlagsPtr.writeU32(old.accessFlags);
  old.vtableIndexPtr.writeS32(old.vtableIndex);
}
function _getJvmMethodSpec() {
  const api2 = getApi2();
  const { version } = api2;
  let adapterHandlerLocation;
  if (version >= 17) {
    adapterHandlerLocation = "method:early";
  } else if (version >= 9 && version <= 16) {
    adapterHandlerLocation = "const-method";
  } else {
    adapterHandlerLocation = "method:late";
  }
  const isNative = 1;
  const methodSize = api2["Method::size"](isNative) * pointerSize6;
  const constMethodOffset = pointerSize6;
  const methodDataOffset = 2 * pointerSize6;
  const methodCountersOffset = 3 * pointerSize6;
  const adapterInMethodEarlyOffset = 4 * pointerSize6;
  const adapterInMethodEarlySize = adapterHandlerLocation === "method:early" ? pointerSize6 : 0;
  const accessFlagsOffset = adapterInMethodEarlyOffset + adapterInMethodEarlySize;
  const vtableIndexOffset = accessFlagsOffset + 4;
  const i2iEntryOffset = vtableIndexOffset + 4 + 8;
  const adapterInMethodLateOffset = i2iEntryOffset + pointerSize6;
  const adapterInMethodOffset = adapterInMethodEarlySize !== 0 ? adapterInMethodEarlyOffset : adapterInMethodLateOffset;
  const nativeFunctionOffset = methodSize - 2 * pointerSize6;
  const signatureHandlerOffset = methodSize - pointerSize6;
  const constantPoolOffset = 8;
  const stackmapDataOffset = constantPoolOffset + pointerSize6;
  const adapterInConstMethodOffset = stackmapDataOffset + pointerSize6;
  const adapterInConstMethodSize = adapterHandlerLocation === "const-method" ? pointerSize6 : 0;
  const constMethodSizeOffset = adapterInConstMethodOffset + adapterInConstMethodSize;
  const methodIdnumOffset = constMethodSizeOffset + 14;
  const cacheOffset = 2 * pointerSize6;
  const instanceKlassOffset = 3 * pointerSize6;
  const getAdapterPointer = adapterInConstMethodSize !== 0 ? function(method, constMethod) {
    return constMethod.add(adapterInConstMethodOffset);
  } : function(method, constMethod) {
    return method.add(adapterInMethodOffset);
  };
  return {
    getAdapterPointer,
    method: {
      size: methodSize,
      constMethodOffset,
      methodDataOffset,
      methodCountersOffset,
      accessFlagsOffset,
      vtableIndexOffset,
      i2iEntryOffset,
      nativeFunctionOffset,
      signatureHandlerOffset
    },
    constMethod: {
      constantPoolOffset,
      stackmapDataOffset,
      sizeOffset: constMethodSizeOffset,
      methodIdnumOffset
    },
    constantPool: {
      cacheOffset,
      instanceKlassOffset
    }
  };
}
var vtableOffsetParsers = {
  x64: parseX64VTableOffset
};
function _getJvmInstanceKlassSpec() {
  const { version: jvmVersion, createNewDefaultVtableIndices } = getApi2();
  const tryParse = vtableOffsetParsers[Process.arch];
  if (tryParse === void 0) {
    throw new Error(`Missing vtable offset parser for ${Process.arch}`);
  }
  const vtableOffset = parseInstructionsAt(createNewDefaultVtableIndices, tryParse, { limit: 32 });
  if (vtableOffset === null) {
    throw new Error("Unable to deduce vtable offset");
  }
  const oopMultiplier = jvmVersion >= 10 && jvmVersion <= 11 || jvmVersion >= 15 ? 17 : 18;
  const methodsOffset = vtableOffset - 7 * pointerSize6;
  const memberNamesOffset = vtableOffset - 17 * pointerSize6;
  const oopMapCacheOffset = vtableOffset - oopMultiplier * pointerSize6;
  return {
    vtableOffset,
    methodsOffset,
    memberNamesOffset,
    oopMapCacheOffset
  };
}
function parseX64VTableOffset(insn) {
  if (insn.mnemonic !== "mov") {
    return null;
  }
  const dst = insn.operands[0];
  if (dst.type !== "mem") {
    return null;
  }
  const { value: dstValue } = dst;
  if (dstValue.scale !== 1) {
    return null;
  }
  const { disp } = dstValue;
  if (disp < 256) {
    return null;
  }
  const defaultVtableIndicesOffset = disp;
  return defaultVtableIndicesOffset + 16;
}

// node_modules/frida-java-bridge/lib/api.js
var getApi3 = getApi;
try {
  getAndroidVersion();
} catch (e) {
  getApi3 = getApi2;
}
var api_default = getApi3;

// node_modules/frida-java-bridge/lib/class-model.js
var code2 = `#include <json-glib/json-glib.h>
#include <string.h>

#define kAccStatic 0x0008
#define kAccConstructor 0x00010000

typedef struct _Model Model;
typedef struct _EnumerateMethodsContext EnumerateMethodsContext;

typedef struct _JavaApi JavaApi;
typedef struct _JavaClassApi JavaClassApi;
typedef struct _JavaMethodApi JavaMethodApi;
typedef struct _JavaFieldApi JavaFieldApi;

typedef struct _JNIEnv JNIEnv;
typedef guint8 jboolean;
typedef gint32 jint;
typedef jint jsize;
typedef gpointer jobject;
typedef jobject jclass;
typedef jobject jstring;
typedef jobject jarray;
typedef jarray jobjectArray;
typedef gpointer jfieldID;
typedef gpointer jmethodID;

typedef struct _jvmtiEnv jvmtiEnv;
typedef enum
{
  JVMTI_ERROR_NONE = 0
} jvmtiError;

typedef struct _ArtApi ArtApi;
typedef guint32 ArtHeapReference;
typedef struct _ArtObject ArtObject;
typedef struct _ArtClass ArtClass;
typedef struct _ArtClassLinker ArtClassLinker;
typedef struct _ArtClassVisitor ArtClassVisitor;
typedef struct _ArtClassVisitorVTable ArtClassVisitorVTable;
typedef struct _ArtMethod ArtMethod;
typedef struct _ArtString ArtString;

typedef union _StdString StdString;
typedef struct _StdStringShort StdStringShort;
typedef struct _StdStringLong StdStringLong;

typedef void (* ArtVisitClassesFunc) (ArtClassLinker * linker, ArtClassVisitor * visitor);
typedef const char * (* ArtGetClassDescriptorFunc) (ArtClass * klass, StdString * storage);
typedef void (* ArtPrettyMethodFunc) (StdString * result, ArtMethod * method, jboolean with_signature);

struct _Model
{
  GHashTable * members;
};

struct _EnumerateMethodsContext
{
  GPatternSpec * class_query;
  GPatternSpec * method_query;
  jboolean include_signature;
  jboolean ignore_case;
  jboolean skip_system_classes;
  GHashTable * groups;
};

struct _JavaClassApi
{
  jmethodID get_declared_methods;
  jmethodID get_declared_fields;
};

struct _JavaMethodApi
{
  jmethodID get_name;
  jmethodID get_modifiers;
};

struct _JavaFieldApi
{
  jmethodID get_name;
  jmethodID get_modifiers;
};

struct _JavaApi
{
  JavaClassApi clazz;
  JavaMethodApi method;
  JavaFieldApi field;
};

struct _JNIEnv
{
  gpointer * functions;
};

struct _jvmtiEnv
{
  gpointer * functions;
};

struct _ArtApi
{
  gboolean available;

  guint class_offset_ifields;
  guint class_offset_methods;
  guint class_offset_sfields;
  guint class_offset_copied_methods_offset;

  guint method_size;
  guint method_offset_access_flags;

  guint field_size;
  guint field_offset_access_flags;

  guint alignment_padding;

  ArtClassLinker * linker;
  ArtVisitClassesFunc visit_classes;
  ArtGetClassDescriptorFunc get_class_descriptor;
  ArtPrettyMethodFunc pretty_method;

  void (* free) (gpointer mem);
};

struct _ArtObject
{
  ArtHeapReference klass;
  ArtHeapReference monitor;
};

struct _ArtClass
{
  ArtObject parent;

  ArtHeapReference class_loader;
};

struct _ArtClassVisitor
{
  ArtClassVisitorVTable * vtable;
  gpointer user_data;
};

struct _ArtClassVisitorVTable
{
  void (* reserved1) (ArtClassVisitor * self);
  void (* reserved2) (ArtClassVisitor * self);
  jboolean (* visit) (ArtClassVisitor * self, ArtClass * klass);
};

struct _ArtString
{
  ArtObject parent;

  gint32 count;
  guint32 hash_code;

  union
  {
    guint16 value[0];
    guint8 value_compressed[0];
  };
};

struct _StdStringShort
{
  guint8 size;
  gchar data[(3 * sizeof (gpointer)) - sizeof (guint8)];
};

struct _StdStringLong
{
  gsize capacity;
  gsize size;
  gchar * data;
};

union _StdString
{
  StdStringShort s;
  StdStringLong l;
};

static void model_add_method (Model * self, const gchar * name, jmethodID id, jint modifiers);
static void model_add_field (Model * self, const gchar * name, jfieldID id, jint modifiers);
static void model_free (Model * model);

static jboolean collect_matching_class_methods (ArtClassVisitor * self, ArtClass * klass);
static gchar * finalize_method_groups_to_json (GHashTable * groups);
static GPatternSpec * make_pattern_spec (const gchar * pattern, jboolean ignore_case);
static gchar * class_name_from_signature (const gchar * signature);
static gchar * format_method_signature (const gchar * name, const gchar * signature);
static void append_type (GString * output, const gchar ** type);

static gpointer read_art_array (gpointer object_base, guint field_offset, guint length_size, guint * length);

static void std_string_destroy (StdString * str);
static gchar * std_string_c_str (StdString * self);

extern GMutex lock;
extern GArray * models;
extern JavaApi java_api;
extern ArtApi art_api;

void
init (void)
{
  g_mutex_init (&lock);
  models = g_array_new (FALSE, FALSE, sizeof (Model *));
}

void
finalize (void)
{
  guint n, i;

  n = models->len;
  for (i = 0; i != n; i++)
  {
    Model * model = g_array_index (models, Model *, i);
    model_free (model);
  }

  g_array_unref (models);
  g_mutex_clear (&lock);
}

Model *
model_new (jclass class_handle,
           gpointer class_object,
           JNIEnv * env)
{
  Model * model;
  GHashTable * members;
  gpointer * funcs = env->functions;
  jmethodID (* from_reflected_method) (JNIEnv *, jobject) = funcs[7];
  jfieldID (* from_reflected_field) (JNIEnv *, jobject) = funcs[8];
  jobject (* to_reflected_method) (JNIEnv *, jclass, jmethodID, jboolean) = funcs[9];
  jobject (* to_reflected_field) (JNIEnv *, jclass, jfieldID, jboolean) = funcs[12];
  void (* delete_local_ref) (JNIEnv *, jobject) = funcs[23];
  jobject (* call_object_method) (JNIEnv *, jobject, jmethodID, ...) = funcs[34];
  jint (* call_int_method) (JNIEnv *, jobject, jmethodID, ...) = funcs[49];
  const char * (* get_string_utf_chars) (JNIEnv *, jstring, jboolean *) = funcs[169];
  void (* release_string_utf_chars) (JNIEnv *, jstring, const char *) = funcs[170];
  jsize (* get_array_length) (JNIEnv *, jarray) = funcs[171];
  jobject (* get_object_array_element) (JNIEnv *, jobjectArray, jsize) = funcs[173];
  jsize n, i;

  model = g_new (Model, 1);

  members = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  model->members = members;

  if (art_api.available)
  {
    gpointer elements;
    guint n, i;
    const guint field_arrays[] = {
      art_api.class_offset_ifields,
      art_api.class_offset_sfields
    };
    guint field_array_cursor;
    gboolean merged_fields = art_api.class_offset_sfields == 0;

    elements = read_art_array (class_object, art_api.class_offset_methods, sizeof (gsize), NULL);
    n = *(guint16 *) (class_object + art_api.class_offset_copied_methods_offset);
    for (i = 0; i != n; i++)
    {
      jmethodID id;
      guint32 access_flags;
      jboolean is_static;
      jobject method, name;
      const char * name_str;
      jint modifiers;

      id = elements + (i * art_api.method_size);

      access_flags = *(guint32 *) (id + art_api.method_offset_access_flags);
      if ((access_flags & kAccConstructor) != 0)
        continue;
      is_static = (access_flags & kAccStatic) != 0;
      method = to_reflected_method (env, class_handle, id, is_static);
      name = call_object_method (env, method, java_api.method.get_name);
      name_str = get_string_utf_chars (env, name, NULL);
      modifiers = access_flags & 0xffff;

      model_add_method (model, name_str, id, modifiers);

      release_string_utf_chars (env, name, name_str);
      delete_local_ref (env, name);
      delete_local_ref (env, method);
    }

    for (field_array_cursor = 0; field_array_cursor != G_N_ELEMENTS (field_arrays); field_array_cursor++)
    {
      jboolean is_static;

      if (field_arrays[field_array_cursor] == 0)
        continue;

      if (!merged_fields)
        is_static = field_array_cursor == 1;

      elements = read_art_array (class_object, field_arrays[field_array_cursor], sizeof (guint32), &n);
      for (i = 0; i != n; i++)
      {
        jfieldID id;
        guint32 access_flags;
        jobject field, name;
        const char * name_str;
        jint modifiers;

        id = elements + (i * art_api.field_size);

        access_flags = *(guint32 *) (id + art_api.field_offset_access_flags);
        if (merged_fields)
          is_static = (access_flags & kAccStatic) != 0;
        field = to_reflected_field (env, class_handle, id, is_static);
        name = call_object_method (env, field, java_api.field.get_name);
        name_str = get_string_utf_chars (env, name, NULL);
        modifiers = access_flags & 0xffff;

        model_add_field (model, name_str, id, modifiers);

        release_string_utf_chars (env, name, name_str);
        delete_local_ref (env, name);
        delete_local_ref (env, field);
      }
    }
  }
  else
  {
    jobject elements;

    elements = call_object_method (env, class_handle, java_api.clazz.get_declared_methods);
    n = get_array_length (env, elements);
    for (i = 0; i != n; i++)
    {
      jobject method, name;
      const char * name_str;
      jmethodID id;
      jint modifiers;

      method = get_object_array_element (env, elements, i);
      name = call_object_method (env, method, java_api.method.get_name);
      name_str = get_string_utf_chars (env, name, NULL);
      id = from_reflected_method (env, method);
      modifiers = call_int_method (env, method, java_api.method.get_modifiers);

      model_add_method (model, name_str, id, modifiers);

      release_string_utf_chars (env, name, name_str);
      delete_local_ref (env, name);
      delete_local_ref (env, method);
    }
    delete_local_ref (env, elements);

    elements = call_object_method (env, class_handle, java_api.clazz.get_declared_fields);
    n = get_array_length (env, elements);
    for (i = 0; i != n; i++)
    {
      jobject field, name;
      const char * name_str;
      jfieldID id;
      jint modifiers;

      field = get_object_array_element (env, elements, i);
      name = call_object_method (env, field, java_api.field.get_name);
      name_str = get_string_utf_chars (env, name, NULL);
      id = from_reflected_field (env, field);
      modifiers = call_int_method (env, field, java_api.field.get_modifiers);

      model_add_field (model, name_str, id, modifiers);

      release_string_utf_chars (env, name, name_str);
      delete_local_ref (env, name);
      delete_local_ref (env, field);
    }
    delete_local_ref (env, elements);
  }

  g_mutex_lock (&lock);
  g_array_append_val (models, model);
  g_mutex_unlock (&lock);

  return model;
}

static void
model_add_method (Model * self,
                  const gchar * name,
                  jmethodID id,
                  jint modifiers)
{
  GHashTable * members = self->members;
  gchar * key, type;
  const gchar * value;

  if (name[0] == '$')
    key = g_strdup_printf ("_%s", name);
  else
    key = g_strdup (name);

  type = (modifiers & kAccStatic) != 0 ? 's' : 'i';

  value = g_hash_table_lookup (members, key);
  if (value == NULL)
    g_hash_table_insert (members, key, g_strdup_printf ("m:%c0x%zx", type, id));
  else
    g_hash_table_insert (members, key, g_strdup_printf ("%s:%c0x%zx", value, type, id));
}

static void
model_add_field (Model * self,
                 const gchar * name,
                 jfieldID id,
                 jint modifiers)
{
  GHashTable * members = self->members;
  gchar * key, type;

  if (name[0] == '$')
    key = g_strdup_printf ("_%s", name);
  else
    key = g_strdup (name);
  while (g_hash_table_contains (members, key))
  {
    gchar * new_key = g_strdup_printf ("_%s", key);
    g_free (key);
    key = new_key;
  }

  type = (modifiers & kAccStatic) != 0 ? 's' : 'i';

  g_hash_table_insert (members, key, g_strdup_printf ("f:%c0x%zx", type, id));
}

static void
model_free (Model * model)
{
  g_hash_table_unref (model->members);

  g_free (model);
}

gboolean
model_has (Model * self,
           const gchar * member)
{
  return g_hash_table_contains (self->members, member);
}

const gchar *
model_find (Model * self,
            const gchar * member)
{
  return g_hash_table_lookup (self->members, member);
}

gchar *
model_list (Model * self)
{
  GString * result;
  GHashTableIter iter;
  guint i;
  const gchar * name;

  result = g_string_sized_new (128);

  g_string_append_c (result, '[');

  g_hash_table_iter_init (&iter, self->members);
  for (i = 0; g_hash_table_iter_next (&iter, (gpointer *) &name, NULL); i++)
  {
    if (i > 0)
      g_string_append_c (result, ',');

    g_string_append_c (result, '"');
    g_string_append (result, name);
    g_string_append_c (result, '"');
  }

  g_string_append_c (result, ']');

  return g_string_free (result, FALSE);
}

gchar *
enumerate_methods_art (const gchar * class_query,
                       const gchar * method_query,
                       jboolean include_signature,
                       jboolean ignore_case,
                       jboolean skip_system_classes)
{
  gchar * result;
  EnumerateMethodsContext ctx;
  ArtClassVisitor visitor;
  ArtClassVisitorVTable visitor_vtable = { NULL, };

  ctx.class_query = make_pattern_spec (class_query, ignore_case);
  ctx.method_query = make_pattern_spec (method_query, ignore_case);
  ctx.include_signature = include_signature;
  ctx.ignore_case = ignore_case;
  ctx.skip_system_classes = skip_system_classes;
  ctx.groups = g_hash_table_new_full (NULL, NULL, NULL, NULL);

  visitor.vtable = &visitor_vtable;
  visitor.user_data = &ctx;

  visitor_vtable.visit = collect_matching_class_methods;

  art_api.visit_classes (art_api.linker, &visitor);

  result = finalize_method_groups_to_json (ctx.groups);

  g_hash_table_unref (ctx.groups);
  g_pattern_spec_free (ctx.method_query);
  g_pattern_spec_free (ctx.class_query);

  return result;
}

static jboolean
collect_matching_class_methods (ArtClassVisitor * self,
                                ArtClass * klass)
{
  EnumerateMethodsContext * ctx = self->user_data;
  const char * descriptor;
  StdString descriptor_storage = { 0, };
  gchar * class_name = NULL;
  gchar * class_name_copy = NULL;
  const gchar * normalized_class_name;
  JsonBuilder * group;
  size_t class_name_length;
  GHashTable * seen_method_names;
  gpointer elements;
  guint n, i;

  if (ctx->skip_system_classes && klass->class_loader == 0)
    goto skip_class;

  descriptor = art_api.get_class_descriptor (klass, &descriptor_storage);
  if (descriptor[0] != 'L')
    goto skip_class;

  class_name = class_name_from_signature (descriptor);

  if (ctx->ignore_case)
  {
    class_name_copy = g_utf8_strdown (class_name, -1);
    normalized_class_name = class_name_copy;
  }
  else
  {
    normalized_class_name = class_name;
  }

  if (!g_pattern_match_string (ctx->class_query, normalized_class_name))
    goto skip_class;

  group = NULL;
  class_name_length = strlen (class_name);
  seen_method_names = ctx->include_signature ? NULL : g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  elements = read_art_array (klass, art_api.class_offset_methods, sizeof (gsize), NULL);
  n = *(guint16 *) ((gpointer) klass + art_api.class_offset_copied_methods_offset);
  for (i = 0; i != n; i++)
  {
    ArtMethod * method;
    guint32 access_flags;
    jboolean is_constructor;
    StdString method_name = { 0, };
    const gchar * bare_method_name;
    gchar * bare_method_name_copy = NULL;
    const gchar * normalized_method_name;
    gchar * normalized_method_name_copy = NULL;

    method = elements + (i * art_api.method_size);

    access_flags = *(guint32 *) ((gpointer) method + art_api.method_offset_access_flags);
    is_constructor = (access_flags & kAccConstructor) != 0;

    art_api.pretty_method (&method_name, method, ctx->include_signature);
    bare_method_name = std_string_c_str (&method_name);
    if (ctx->include_signature)
    {
      const gchar * return_type_end, * name_begin;
      GString * name;

      return_type_end = strchr (bare_method_name, ' ');
      name_begin = return_type_end + 1 + class_name_length + 1;
      if (is_constructor && g_str_has_prefix (name_begin, "<clinit>"))
        goto skip_method;

      name = g_string_sized_new (64);

      if (is_constructor)
      {
        g_string_append (name, "$init");
        g_string_append (name, strchr (name_begin, '>') + 1);
      }
      else
      {
        g_string_append (name, name_begin);
      }
      g_string_append (name, ": ");
      g_string_append_len (name, bare_method_name, return_type_end - bare_method_name);

      bare_method_name_copy = g_string_free (name, FALSE);
      bare_method_name = bare_method_name_copy;
    }
    else
    {
      const gchar * name_begin;

      name_begin = bare_method_name + class_name_length + 1;
      if (is_constructor && strcmp (name_begin, "<clinit>") == 0)
        goto skip_method;

      if (is_constructor)
        bare_method_name = "$init";
      else
        bare_method_name += class_name_length + 1;
    }

    if (seen_method_names != NULL && g_hash_table_contains (seen_method_names, bare_method_name))
      goto skip_method;

    if (ctx->ignore_case)
    {
      normalized_method_name_copy = g_utf8_strdown (bare_method_name, -1);
      normalized_method_name = normalized_method_name_copy;
    }
    else
    {
      normalized_method_name = bare_method_name;
    }

    if (!g_pattern_match_string (ctx->method_query, normalized_method_name))
      goto skip_method;

    if (group == NULL)
    {
      group = g_hash_table_lookup (ctx->groups, GUINT_TO_POINTER (klass->class_loader));
      if (group == NULL)
      {
        group = json_builder_new_immutable ();
        g_hash_table_insert (ctx->groups, GUINT_TO_POINTER (klass->class_loader), group);

        json_builder_begin_object (group);

        json_builder_set_member_name (group, "loader");
        json_builder_add_int_value (group, klass->class_loader);

        json_builder_set_member_name (group, "classes");
        json_builder_begin_array (group);
      }

      json_builder_begin_object (group);

      json_builder_set_member_name (group, "name");
      json_builder_add_string_value (group, class_name);

      json_builder_set_member_name (group, "methods");
      json_builder_begin_array (group);
    }

    json_builder_add_string_value (group, bare_method_name);

    if (seen_method_names != NULL)
      g_hash_table_add (seen_method_names, g_strdup (bare_method_name));

skip_method:
    g_free (normalized_method_name_copy);
    g_free (bare_method_name_copy);
    std_string_destroy (&method_name);
  }

  if (seen_method_names != NULL)
    g_hash_table_unref (seen_method_names);

  if (group == NULL)
    goto skip_class;

  json_builder_end_array (group);
  json_builder_end_object (group);

skip_class:
  g_free (class_name_copy);
  g_free (class_name);
  std_string_destroy (&descriptor_storage);

  return TRUE;
}

gchar *
enumerate_methods_jvm (const gchar * class_query,
                       const gchar * method_query,
                       jboolean include_signature,
                       jboolean ignore_case,
                       jboolean skip_system_classes,
                       JNIEnv * env,
                       jvmtiEnv * jvmti)
{
  gchar * result;
  GPatternSpec * class_pattern, * method_pattern;
  GHashTable * groups;
  gpointer * ef = env->functions;
  jobject (* new_global_ref) (JNIEnv *, jobject) = ef[21];
  void (* delete_local_ref) (JNIEnv *, jobject) = ef[23];
  jboolean (* is_same_object) (JNIEnv *, jobject, jobject) = ef[24];
  gpointer * jf = jvmti->functions - 1;
  jvmtiError (* deallocate) (jvmtiEnv *, void * mem) = jf[47];
  jvmtiError (* get_class_signature) (jvmtiEnv *, jclass, char **, char **) = jf[48];
  jvmtiError (* get_class_methods) (jvmtiEnv *, jclass, jint *, jmethodID **) = jf[52];
  jvmtiError (* get_class_loader) (jvmtiEnv *, jclass, jobject *) = jf[57];
  jvmtiError (* get_method_name) (jvmtiEnv *, jmethodID, char **, char **, char **) = jf[64];
  jvmtiError (* get_loaded_classes) (jvmtiEnv *, jint *, jclass **) = jf[78];
  jint class_count, class_index;
  jclass * classes;

  class_pattern = make_pattern_spec (class_query, ignore_case);
  method_pattern = make_pattern_spec (method_query, ignore_case);
  groups = g_hash_table_new_full (NULL, NULL, NULL, NULL);

  if (get_loaded_classes (jvmti, &class_count, &classes) != JVMTI_ERROR_NONE)
    goto emit_results;

  for (class_index = 0; class_index != class_count; class_index++)
  {
    jclass klass = classes[class_index];
    jobject loader = NULL;
    gboolean have_loader = FALSE;
    char * signature = NULL;
    gchar * class_name = NULL;
    gchar * class_name_copy = NULL;
    const gchar * normalized_class_name;
    jint method_count, method_index;
    jmethodID * methods = NULL;
    JsonBuilder * group = NULL;
    GHashTable * seen_method_names = NULL;

    if (skip_system_classes)
    {
      if (get_class_loader (jvmti, klass, &loader) != JVMTI_ERROR_NONE)
        goto skip_class;
      have_loader = TRUE;

      if (loader == NULL)
        goto skip_class;
    }

    if (get_class_signature (jvmti, klass, &signature, NULL) != JVMTI_ERROR_NONE)
      goto skip_class;

    class_name = class_name_from_signature (signature);

    if (ignore_case)
    {
      class_name_copy = g_utf8_strdown (class_name, -1);
      normalized_class_name = class_name_copy;
    }
    else
    {
      normalized_class_name = class_name;
    }

    if (!g_pattern_match_string (class_pattern, normalized_class_name))
      goto skip_class;

    if (get_class_methods (jvmti, klass, &method_count, &methods) != JVMTI_ERROR_NONE)
      goto skip_class;

    if (!include_signature)
      seen_method_names = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

    for (method_index = 0; method_index != method_count; method_index++)
    {
      jmethodID method = methods[method_index];
      const gchar * method_name;
      char * method_name_value = NULL;
      char * method_signature_value = NULL;
      gchar * method_name_copy = NULL;
      const gchar * normalized_method_name;
      gchar * normalized_method_name_copy = NULL;

      if (get_method_name (jvmti, method, &method_name_value, include_signature ? &method_signature_value : NULL, NULL) != JVMTI_ERROR_NONE)
        goto skip_method;
      method_name = method_name_value;

      if (method_name[0] == '<')
      {
        if (strcmp (method_name, "<init>") == 0)
          method_name = "$init";
        else if (strcmp (method_name, "<clinit>") == 0)
          goto skip_method;
      }

      if (include_signature)
      {
        method_name_copy = format_method_signature (method_name, method_signature_value);
        method_name = method_name_copy;
      }

      if (seen_method_names != NULL && g_hash_table_contains (seen_method_names, method_name))
        goto skip_method;

      if (ignore_case)
      {
        normalized_method_name_copy = g_utf8_strdown (method_name, -1);
        normalized_method_name = normalized_method_name_copy;
      }
      else
      {
        normalized_method_name = method_name;
      }

      if (!g_pattern_match_string (method_pattern, normalized_method_name))
        goto skip_method;

      if (group == NULL)
      {
        if (!have_loader && get_class_loader (jvmti, klass, &loader) != JVMTI_ERROR_NONE)
          goto skip_method;

        if (loader == NULL)
        {
          group = g_hash_table_lookup (groups, NULL);
        }
        else
        {
          GHashTableIter iter;
          jobject cur_loader;
          JsonBuilder * cur_group;

          g_hash_table_iter_init (&iter, groups);
          while (g_hash_table_iter_next (&iter, (gpointer *) &cur_loader, (gpointer *) &cur_group))
          {
            if (cur_loader != NULL && is_same_object (env, cur_loader, loader))
            {
              group = cur_group;
              break;
            }
          }
        }

        if (group == NULL)
        {
          jobject l;
          gchar * str;

          l = (loader != NULL) ? new_global_ref (env, loader) : NULL;

          group = json_builder_new_immutable ();
          g_hash_table_insert (groups, l, group);

          json_builder_begin_object (group);

          json_builder_set_member_name (group, "loader");
          str = g_strdup_printf ("0x%" G_GSIZE_MODIFIER "x", GPOINTER_TO_SIZE (l));
          json_builder_add_string_value (group, str);
          g_free (str);

          json_builder_set_member_name (group, "classes");
          json_builder_begin_array (group);
        }

        json_builder_begin_object (group);

        json_builder_set_member_name (group, "name");
        json_builder_add_string_value (group, class_name);

        json_builder_set_member_name (group, "methods");
        json_builder_begin_array (group);
      }

      json_builder_add_string_value (group, method_name);

      if (seen_method_names != NULL)
        g_hash_table_add (seen_method_names, g_strdup (method_name));

skip_method:
      g_free (normalized_method_name_copy);
      g_free (method_name_copy);
      deallocate (jvmti, method_signature_value);
      deallocate (jvmti, method_name_value);
    }

skip_class:
    if (group != NULL)
    {
      json_builder_end_array (group);
      json_builder_end_object (group);
    }

    if (seen_method_names != NULL)
      g_hash_table_unref (seen_method_names);

    deallocate (jvmti, methods);

    g_free (class_name_copy);
    g_free (class_name);
    deallocate (jvmti, signature);

    if (loader != NULL)
      delete_local_ref (env, loader);

    delete_local_ref (env, klass);
  }

  deallocate (jvmti, classes);

emit_results:
  result = finalize_method_groups_to_json (groups);

  g_hash_table_unref (groups);
  g_pattern_spec_free (method_pattern);
  g_pattern_spec_free (class_pattern);

  return result;
}

static gchar *
finalize_method_groups_to_json (GHashTable * groups)
{
  GString * result;
  GHashTableIter iter;
  guint i;
  JsonBuilder * group;

  result = g_string_sized_new (1024);

  g_string_append_c (result, '[');

  g_hash_table_iter_init (&iter, groups);
  for (i = 0; g_hash_table_iter_next (&iter, NULL, (gpointer *) &group); i++)
  {
    JsonNode * root;
    gchar * json;

    if (i > 0)
      g_string_append_c (result, ',');

    json_builder_end_array (group);
    json_builder_end_object (group);

    root = json_builder_get_root (group);
    json = json_to_string (root, FALSE);
    g_string_append (result, json);
    g_free (json);
    json_node_unref (root);

    g_object_unref (group);
  }

  g_string_append_c (result, ']');

  return g_string_free (result, FALSE);
}

static GPatternSpec *
make_pattern_spec (const gchar * pattern,
                   jboolean ignore_case)
{
  GPatternSpec * spec;

  if (ignore_case)
  {
    gchar * str = g_utf8_strdown (pattern, -1);
    spec = g_pattern_spec_new (str);
    g_free (str);
  }
  else
  {
    spec = g_pattern_spec_new (pattern);
  }

  return spec;
}

static gchar *
class_name_from_signature (const gchar * descriptor)
{
  gchar * result, * c;

  result = g_strdup (descriptor + 1);

  for (c = result; *c != '\\0'; c++)
  {
    if (*c == '/')
      *c = '.';
  }

  c[-1] = '\\0';

  return result;
}

static gchar *
format_method_signature (const gchar * name,
                         const gchar * signature)
{
  GString * sig;
  const gchar * cursor;
  gint arg_index;

  sig = g_string_sized_new (128);

  g_string_append (sig, name);

  cursor = signature;
  arg_index = -1;
  while (TRUE)
  {
    const gchar c = *cursor;

    if (c == '(')
    {
      g_string_append_c (sig, c);
      cursor++;
      arg_index = 0;
    }
    else if (c == ')')
    {
      g_string_append_c (sig, c);
      cursor++;
      break;
    }
    else
    {
      if (arg_index >= 1)
        g_string_append (sig, ", ");

      append_type (sig, &cursor);

      if (arg_index != -1)
        arg_index++;
    }
  }

  g_string_append (sig, ": ");
  append_type (sig, &cursor);

  return g_string_free (sig, FALSE);
}

static void
append_type (GString * output,
             const gchar ** type)
{
  const gchar * cursor = *type;

  switch (*cursor)
  {
    case 'Z':
      g_string_append (output, "boolean");
      cursor++;
      break;
    case 'B':
      g_string_append (output, "byte");
      cursor++;
      break;
    case 'C':
      g_string_append (output, "char");
      cursor++;
      break;
    case 'S':
      g_string_append (output, "short");
      cursor++;
      break;
    case 'I':
      g_string_append (output, "int");
      cursor++;
      break;
    case 'J':
      g_string_append (output, "long");
      cursor++;
      break;
    case 'F':
      g_string_append (output, "float");
      cursor++;
      break;
    case 'D':
      g_string_append (output, "double");
      cursor++;
      break;
    case 'V':
      g_string_append (output, "void");
      cursor++;
      break;
    case 'L':
    {
      gchar ch;

      cursor++;
      for (; (ch = *cursor) != ';'; cursor++)
      {
        g_string_append_c (output, (ch != '/') ? ch : '.');
      }
      cursor++;

      break;
    }
    case '[':
      *type = cursor + 1;
      append_type (output, type);
      g_string_append (output, "[]");
      return;
    default:
      g_string_append (output, "BUG");
      cursor++;
  }

  *type = cursor;
}

void
dealloc (gpointer mem)
{
  g_free (mem);
}

static gpointer
read_art_array (gpointer object_base,
                guint field_offset,
                guint length_size,
                guint * length)
{
  gpointer result, header;
  guint n;

  header = GSIZE_TO_POINTER (*(guint64 *) (object_base + field_offset));
  if (header != NULL)
  {
    result = header + length_size;
    if (length_size == sizeof (guint32))
      n = *(guint32 *) header;
    else
      n = *(guint64 *) header;
  }
  else
  {
    result = NULL;
    n = 0;
  }

  if (length != NULL)
    *length = n;

  return result;
}

static void
std_string_destroy (StdString * str)
{
  if ((str->l.capacity & 1) != 0)
    art_api.free (str->l.data);
}

static gchar *
std_string_c_str (StdString * self)
{
  if ((self->l.capacity & 1) != 0)
    return self->l.data;

  return self->s.data;
}
`;
var methodQueryPattern = /(.+)!([^/]+)\/?([isu]+)?/;
var cm = null;
var unwrap = null;
var Model = class _Model {
  static build(handle, env) {
    ensureInitialized(env);
    return unwrap(handle, env, (object) => {
      return new _Model(cm.new(handle, object, env));
    });
  }
  static enumerateMethods(query, api2, env) {
    ensureInitialized(env);
    const params = query.match(methodQueryPattern);
    if (params === null) {
      throw new Error("Invalid query; format is: class!method -- see documentation of Java.enumerateMethods(query) for details");
    }
    const classQuery = Memory.allocUtf8String(params[1]);
    const methodQuery = Memory.allocUtf8String(params[2]);
    let includeSignature = false;
    let ignoreCase = false;
    let skipSystemClasses = false;
    const modifiers = params[3];
    if (modifiers !== void 0) {
      includeSignature = modifiers.indexOf("s") !== -1;
      ignoreCase = modifiers.indexOf("i") !== -1;
      skipSystemClasses = modifiers.indexOf("u") !== -1;
    }
    let result;
    if (api2.flavor === "jvm") {
      const json = cm.enumerateMethodsJvm(
        classQuery,
        methodQuery,
        boolToNative(includeSignature),
        boolToNative(ignoreCase),
        boolToNative(skipSystemClasses),
        env,
        api2.jvmti
      );
      try {
        result = JSON.parse(json.readUtf8String()).map((group) => {
          const loaderRef = ptr(group.loader);
          group.loader = !loaderRef.isNull() ? loaderRef : null;
          return group;
        });
      } finally {
        cm.dealloc(json);
      }
    } else {
      withRunnableArtThread(env.vm, env, (thread) => {
        const json = cm.enumerateMethodsArt(
          classQuery,
          methodQuery,
          boolToNative(includeSignature),
          boolToNative(ignoreCase),
          boolToNative(skipSystemClasses)
        );
        try {
          const addGlobalReference = api2["art::JavaVMExt::AddGlobalRef"];
          const { vm: vmHandle } = api2;
          result = JSON.parse(json.readUtf8String()).map((group) => {
            const loaderObj = group.loader;
            group.loader = loaderObj !== 0 ? addGlobalReference(vmHandle, thread, ptr(loaderObj)) : null;
            return group;
          });
        } finally {
          cm.dealloc(json);
        }
      });
    }
    return result;
  }
  constructor(handle) {
    this.handle = handle;
  }
  has(member) {
    return cm.has(this.handle, Memory.allocUtf8String(member)) !== 0;
  }
  find(member) {
    return cm.find(this.handle, Memory.allocUtf8String(member)).readUtf8String();
  }
  list() {
    const str = cm.list(this.handle);
    try {
      return JSON.parse(str.readUtf8String());
    } finally {
      cm.dealloc(str);
    }
  }
};
function ensureInitialized(env) {
  if (cm === null) {
    cm = compileModule(env);
    unwrap = makeHandleUnwrapper(cm, env.vm);
  }
}
function compileModule(env) {
  const { pointerSize: pointerSize9 } = Process;
  const lockSize = 8;
  const modelsSize = pointerSize9;
  const javaApiSize = 6 * pointerSize9;
  const artApiSize = 10 * 4 + 5 * pointerSize9;
  const dataSize = lockSize + modelsSize + javaApiSize + artApiSize;
  const data = Memory.alloc(dataSize);
  const lock = data;
  const models = lock.add(lockSize);
  const javaApi = models.add(modelsSize);
  const { getDeclaredMethods, getDeclaredFields } = env.javaLangClass();
  const method = env.javaLangReflectMethod();
  const field = env.javaLangReflectField();
  let j = javaApi;
  [
    getDeclaredMethods,
    getDeclaredFields,
    method.getName,
    method.getModifiers,
    field.getName,
    field.getModifiers
  ].forEach((value) => {
    j = j.writePointer(value).add(pointerSize9);
  });
  const artApi = javaApi.add(javaApiSize);
  const { vm: vm3 } = env;
  const artClass = getArtClassSpec(vm3);
  if (artClass !== null) {
    const c = artClass.offset;
    const m = getArtMethodSpec(vm3);
    const f = getArtFieldSpec(vm3);
    let s = artApi;
    [
      1,
      c.ifields,
      c.methods,
      c.sfields,
      c.copiedMethodsOffset,
      m.size,
      m.offset.accessFlags,
      f.size,
      f.offset.accessFlags,
      4294967295
    ].forEach((value) => {
      s = s.writeUInt(value).add(4);
    });
    const api2 = getApi();
    [
      api2.artClassLinker.address,
      api2["art::ClassLinker::VisitClasses"],
      api2["art::mirror::Class::GetDescriptor"],
      api2["art::ArtMethod::PrettyMethod"],
      Process.getModuleByName("libc.so").getExportByName("free")
    ].forEach((value, i) => {
      if (value === void 0) {
        value = NULL;
      }
      s = s.writePointer(value).add(pointerSize9);
    });
  }
  const cm2 = new CModule(code2, {
    lock,
    models,
    java_api: javaApi,
    art_api: artApi
  });
  const reentrantOptions = { exceptions: "propagate" };
  const fastOptions = { exceptions: "propagate", scheduling: "exclusive" };
  return {
    handle: cm2,
    mode: artClass !== null ? "full" : "basic",
    new: new NativeFunction(cm2.model_new, "pointer", ["pointer", "pointer", "pointer"], reentrantOptions),
    has: new NativeFunction(cm2.model_has, "bool", ["pointer", "pointer"], fastOptions),
    find: new NativeFunction(cm2.model_find, "pointer", ["pointer", "pointer"], fastOptions),
    list: new NativeFunction(cm2.model_list, "pointer", ["pointer"], fastOptions),
    enumerateMethodsArt: new NativeFunction(
      cm2.enumerate_methods_art,
      "pointer",
      ["pointer", "pointer", "bool", "bool", "bool"],
      reentrantOptions
    ),
    enumerateMethodsJvm: new NativeFunction(cm2.enumerate_methods_jvm, "pointer", [
      "pointer",
      "pointer",
      "bool",
      "bool",
      "bool",
      "pointer",
      "pointer"
    ], reentrantOptions),
    dealloc: new NativeFunction(cm2.dealloc, "void", ["pointer"], fastOptions)
  };
}
function makeHandleUnwrapper(cm2, vm3) {
  if (cm2.mode === "basic") {
    return nullUnwrap;
  }
  const decodeGlobal = getApi()["art::JavaVMExt::DecodeGlobal"];
  return function(handle, env, fn) {
    let result;
    withRunnableArtThread(vm3, env, (thread) => {
      const object = decodeGlobal(vm3, thread, handle);
      result = fn(object);
    });
    return result;
  };
}
function nullUnwrap(handle, env, fn) {
  return fn(NULL);
}
function boolToNative(val) {
  return val ? 1 : 0;
}

// node_modules/frida-java-bridge/lib/lru.js
var LRU = class {
  constructor(capacity, destroy) {
    this.items = /* @__PURE__ */ new Map();
    this.capacity = capacity;
    this.destroy = destroy;
  }
  dispose(env) {
    const { items, destroy } = this;
    items.forEach((val) => {
      destroy(val, env);
    });
    items.clear();
  }
  get(key) {
    const { items } = this;
    const item = items.get(key);
    if (item !== void 0) {
      items.delete(key);
      items.set(key, item);
    }
    return item;
  }
  set(key, val, env) {
    const { items } = this;
    const existingVal = items.get(key);
    if (existingVal !== void 0) {
      items.delete(key);
      this.destroy(existingVal, env);
    } else if (items.size === this.capacity) {
      const oldestKey = items.keys().next().value;
      const oldestVal = items.get(oldestKey);
      items.delete(oldestKey);
      this.destroy(oldestVal, env);
    }
    items.set(key, val);
  }
};

// node_modules/frida-java-bridge/lib/mkdex.js
var kAccPublic2 = 1;
var kAccNative2 = 256;
var kAccConstructor = 65536;
var kEndianTag = 305419896;
var kClassDefSize = 32;
var kProtoIdSize = 12;
var kFieldIdSize = 8;
var kMethodIdSize = 8;
var kTypeIdSize = 4;
var kStringIdSize = 4;
var kMapItemSize = 12;
var TYPE_HEADER_ITEM = 0;
var TYPE_STRING_ID_ITEM = 1;
var TYPE_TYPE_ID_ITEM = 2;
var TYPE_PROTO_ID_ITEM = 3;
var TYPE_FIELD_ID_ITEM = 4;
var TYPE_METHOD_ID_ITEM = 5;
var TYPE_CLASS_DEF_ITEM = 6;
var TYPE_MAP_LIST = 4096;
var TYPE_TYPE_LIST = 4097;
var TYPE_ANNOTATION_SET_ITEM = 4099;
var TYPE_CLASS_DATA_ITEM = 8192;
var TYPE_CODE_ITEM = 8193;
var TYPE_STRING_DATA_ITEM = 8194;
var TYPE_DEBUG_INFO_ITEM = 8195;
var TYPE_ANNOTATION_ITEM = 8196;
var TYPE_ANNOTATIONS_DIRECTORY_ITEM = 8198;
var VALUE_TYPE = 24;
var VALUE_ARRAY = 28;
var VISIBILITY_SYSTEM = 2;
var kDefaultConstructorSize = 24;
var kDefaultConstructorDebugInfo = Buffer2.from([3, 0, 7, 14, 0]);
var kDalvikAnnotationTypeThrows = "Ldalvik/annotation/Throws;";
var kNullTerminator = Buffer2.from([0]);
function mkdex(spec) {
  const builder = new DexBuilder();
  const fullSpec = Object.assign({}, spec);
  builder.addClass(fullSpec);
  return builder.build();
}
var DexBuilder = class {
  constructor() {
    this.classes = [];
  }
  addClass(spec) {
    this.classes.push(spec);
  }
  build() {
    const model = computeModel(this.classes);
    const {
      classes,
      interfaces,
      fields,
      methods,
      protos,
      parameters,
      annotationDirectories,
      annotationSets,
      throwsAnnotations,
      types,
      strings
    } = model;
    let offset = 0;
    const headerOffset = 0;
    const checksumOffset = 8;
    const signatureOffset = 12;
    const signatureSize = 20;
    const headerSize = 112;
    offset += headerSize;
    const stringIdsOffset = offset;
    const stringIdsSize = strings.length * kStringIdSize;
    offset += stringIdsSize;
    const typeIdsOffset = offset;
    const typeIdsSize = types.length * kTypeIdSize;
    offset += typeIdsSize;
    const protoIdsOffset = offset;
    const protoIdsSize = protos.length * kProtoIdSize;
    offset += protoIdsSize;
    const fieldIdsOffset = offset;
    const fieldIdsSize = fields.length * kFieldIdSize;
    offset += fieldIdsSize;
    const methodIdsOffset = offset;
    const methodIdsSize = methods.length * kMethodIdSize;
    offset += methodIdsSize;
    const classDefsOffset = offset;
    const classDefsSize = classes.length * kClassDefSize;
    offset += classDefsSize;
    const dataOffset = offset;
    const annotationSetOffsets = annotationSets.map((set) => {
      const setOffset = offset;
      set.offset = setOffset;
      offset += 4 + set.items.length * 4;
      return setOffset;
    });
    const javaCodeItems = classes.reduce((result, klass) => {
      const constructorMethods = klass.classData.constructorMethods;
      constructorMethods.forEach((method) => {
        const [, accessFlags, superConstructor] = method;
        if ((accessFlags & kAccNative2) === 0 && superConstructor >= 0) {
          method.push(offset);
          result.push({ offset, superConstructor });
          offset += kDefaultConstructorSize;
        }
      });
      return result;
    }, []);
    annotationDirectories.forEach((dir) => {
      dir.offset = offset;
      offset += 16 + dir.methods.length * 8;
    });
    const interfaceOffsets = interfaces.map((iface) => {
      offset = align(offset, 4);
      const ifaceOffset = offset;
      iface.offset = ifaceOffset;
      offset += 4 + 2 * iface.types.length;
      return ifaceOffset;
    });
    const parameterOffsets = parameters.map((param) => {
      offset = align(offset, 4);
      const paramOffset = offset;
      param.offset = paramOffset;
      offset += 4 + 2 * param.types.length;
      return paramOffset;
    });
    const stringChunks = [];
    const stringOffsets = strings.map((str) => {
      const strOffset = offset;
      const header = Buffer2.from(createUleb128(str.length));
      const data = Buffer2.from(str, "utf8");
      const chunk = Buffer2.concat([header, data, kNullTerminator]);
      stringChunks.push(chunk);
      offset += chunk.length;
      return strOffset;
    });
    const debugInfoOffsets = javaCodeItems.map((codeItem) => {
      const debugOffset = offset;
      offset += kDefaultConstructorDebugInfo.length;
      return debugOffset;
    });
    const throwsAnnotationBlobs = throwsAnnotations.map((annotation) => {
      const blob = makeThrowsAnnotation(annotation);
      annotation.offset = offset;
      offset += blob.length;
      return blob;
    });
    const classDataBlobs = classes.map((klass, index) => {
      klass.classData.offset = offset;
      const blob = makeClassData(klass);
      offset += blob.length;
      return blob;
    });
    const linkSize = 0;
    const linkOffset = 0;
    offset = align(offset, 4);
    const mapOffset = offset;
    const typeListLength = interfaces.length + parameters.length;
    const mapNumItems = 4 + (fields.length > 0 ? 1 : 0) + 2 + annotationSets.length + javaCodeItems.length + annotationDirectories.length + (typeListLength > 0 ? 1 : 0) + 1 + debugInfoOffsets.length + throwsAnnotations.length + classes.length + 1;
    const mapSize = 4 + mapNumItems * kMapItemSize;
    offset += mapSize;
    const dataSize = offset - dataOffset;
    const fileSize = offset;
    const dex = Buffer2.alloc(fileSize);
    dex.write("dex\n035");
    dex.writeUInt32LE(fileSize, 32);
    dex.writeUInt32LE(headerSize, 36);
    dex.writeUInt32LE(kEndianTag, 40);
    dex.writeUInt32LE(linkSize, 44);
    dex.writeUInt32LE(linkOffset, 48);
    dex.writeUInt32LE(mapOffset, 52);
    dex.writeUInt32LE(strings.length, 56);
    dex.writeUInt32LE(stringIdsOffset, 60);
    dex.writeUInt32LE(types.length, 64);
    dex.writeUInt32LE(typeIdsOffset, 68);
    dex.writeUInt32LE(protos.length, 72);
    dex.writeUInt32LE(protoIdsOffset, 76);
    dex.writeUInt32LE(fields.length, 80);
    dex.writeUInt32LE(fields.length > 0 ? fieldIdsOffset : 0, 84);
    dex.writeUInt32LE(methods.length, 88);
    dex.writeUInt32LE(methodIdsOffset, 92);
    dex.writeUInt32LE(classes.length, 96);
    dex.writeUInt32LE(classDefsOffset, 100);
    dex.writeUInt32LE(dataSize, 104);
    dex.writeUInt32LE(dataOffset, 108);
    stringOffsets.forEach((offset2, index) => {
      dex.writeUInt32LE(offset2, stringIdsOffset + index * kStringIdSize);
    });
    types.forEach((id, index) => {
      dex.writeUInt32LE(id, typeIdsOffset + index * kTypeIdSize);
    });
    protos.forEach((proto, index) => {
      const [shortyIndex, returnTypeIndex, params] = proto;
      const protoOffset = protoIdsOffset + index * kProtoIdSize;
      dex.writeUInt32LE(shortyIndex, protoOffset);
      dex.writeUInt32LE(returnTypeIndex, protoOffset + 4);
      dex.writeUInt32LE(params !== null ? params.offset : 0, protoOffset + 8);
    });
    fields.forEach((field, index) => {
      const [classIndex, typeIndex, nameIndex] = field;
      const fieldOffset = fieldIdsOffset + index * kFieldIdSize;
      dex.writeUInt16LE(classIndex, fieldOffset);
      dex.writeUInt16LE(typeIndex, fieldOffset + 2);
      dex.writeUInt32LE(nameIndex, fieldOffset + 4);
    });
    methods.forEach((method, index) => {
      const [classIndex, protoIndex, nameIndex] = method;
      const methodOffset = methodIdsOffset + index * kMethodIdSize;
      dex.writeUInt16LE(classIndex, methodOffset);
      dex.writeUInt16LE(protoIndex, methodOffset + 2);
      dex.writeUInt32LE(nameIndex, methodOffset + 4);
    });
    classes.forEach((klass, index) => {
      const { interfaces: interfaces2, annotationsDirectory } = klass;
      const interfacesOffset = interfaces2 !== null ? interfaces2.offset : 0;
      const annotationsOffset = annotationsDirectory !== null ? annotationsDirectory.offset : 0;
      const staticValuesOffset = 0;
      const classOffset = classDefsOffset + index * kClassDefSize;
      dex.writeUInt32LE(klass.index, classOffset);
      dex.writeUInt32LE(klass.accessFlags, classOffset + 4);
      dex.writeUInt32LE(klass.superClassIndex, classOffset + 8);
      dex.writeUInt32LE(interfacesOffset, classOffset + 12);
      dex.writeUInt32LE(klass.sourceFileIndex, classOffset + 16);
      dex.writeUInt32LE(annotationsOffset, classOffset + 20);
      dex.writeUInt32LE(klass.classData.offset, classOffset + 24);
      dex.writeUInt32LE(staticValuesOffset, classOffset + 28);
    });
    annotationSets.forEach((set, index) => {
      const { items } = set;
      const setOffset = annotationSetOffsets[index];
      dex.writeUInt32LE(items.length, setOffset);
      items.forEach((item, index2) => {
        dex.writeUInt32LE(item.offset, setOffset + 4 + index2 * 4);
      });
    });
    javaCodeItems.forEach((codeItem, index) => {
      const { offset: offset2, superConstructor } = codeItem;
      const registersSize = 1;
      const insSize = 1;
      const outsSize = 1;
      const triesSize = 0;
      const insnsSize = 4;
      dex.writeUInt16LE(registersSize, offset2);
      dex.writeUInt16LE(insSize, offset2 + 2);
      dex.writeUInt16LE(outsSize, offset2 + 4);
      dex.writeUInt16LE(triesSize, offset2 + 6);
      dex.writeUInt32LE(debugInfoOffsets[index], offset2 + 8);
      dex.writeUInt32LE(insnsSize, offset2 + 12);
      dex.writeUInt16LE(4208, offset2 + 16);
      dex.writeUInt16LE(superConstructor, offset2 + 18);
      dex.writeUInt16LE(0, offset2 + 20);
      dex.writeUInt16LE(14, offset2 + 22);
    });
    annotationDirectories.forEach((dir) => {
      const dirOffset = dir.offset;
      const classAnnotationsOffset = 0;
      const fieldsSize = 0;
      const annotatedMethodsSize = dir.methods.length;
      const annotatedParametersSize = 0;
      dex.writeUInt32LE(classAnnotationsOffset, dirOffset);
      dex.writeUInt32LE(fieldsSize, dirOffset + 4);
      dex.writeUInt32LE(annotatedMethodsSize, dirOffset + 8);
      dex.writeUInt32LE(annotatedParametersSize, dirOffset + 12);
      dir.methods.forEach((method, index) => {
        const entryOffset = dirOffset + 16 + index * 8;
        const [methodIndex, annotationSet] = method;
        dex.writeUInt32LE(methodIndex, entryOffset);
        dex.writeUInt32LE(annotationSet.offset, entryOffset + 4);
      });
    });
    interfaces.forEach((iface, index) => {
      const ifaceOffset = interfaceOffsets[index];
      dex.writeUInt32LE(iface.types.length, ifaceOffset);
      iface.types.forEach((type, typeIndex) => {
        dex.writeUInt16LE(type, ifaceOffset + 4 + typeIndex * 2);
      });
    });
    parameters.forEach((param, index) => {
      const paramOffset = parameterOffsets[index];
      dex.writeUInt32LE(param.types.length, paramOffset);
      param.types.forEach((type, typeIndex) => {
        dex.writeUInt16LE(type, paramOffset + 4 + typeIndex * 2);
      });
    });
    stringChunks.forEach((chunk, index) => {
      chunk.copy(dex, stringOffsets[index]);
    });
    debugInfoOffsets.forEach((debugInfoOffset) => {
      kDefaultConstructorDebugInfo.copy(dex, debugInfoOffset);
    });
    throwsAnnotationBlobs.forEach((annotationBlob, index) => {
      annotationBlob.copy(dex, throwsAnnotations[index].offset);
    });
    classDataBlobs.forEach((classDataBlob, index) => {
      classDataBlob.copy(dex, classes[index].classData.offset);
    });
    dex.writeUInt32LE(mapNumItems, mapOffset);
    const mapItems = [
      [TYPE_HEADER_ITEM, 1, headerOffset],
      [TYPE_STRING_ID_ITEM, strings.length, stringIdsOffset],
      [TYPE_TYPE_ID_ITEM, types.length, typeIdsOffset],
      [TYPE_PROTO_ID_ITEM, protos.length, protoIdsOffset]
    ];
    if (fields.length > 0) {
      mapItems.push([TYPE_FIELD_ID_ITEM, fields.length, fieldIdsOffset]);
    }
    mapItems.push([TYPE_METHOD_ID_ITEM, methods.length, methodIdsOffset]);
    mapItems.push([TYPE_CLASS_DEF_ITEM, classes.length, classDefsOffset]);
    annotationSets.forEach((set, index) => {
      mapItems.push([TYPE_ANNOTATION_SET_ITEM, set.items.length, annotationSetOffsets[index]]);
    });
    javaCodeItems.forEach((codeItem) => {
      mapItems.push([TYPE_CODE_ITEM, 1, codeItem.offset]);
    });
    annotationDirectories.forEach((dir) => {
      mapItems.push([TYPE_ANNOTATIONS_DIRECTORY_ITEM, 1, dir.offset]);
    });
    if (typeListLength > 0) {
      mapItems.push([TYPE_TYPE_LIST, typeListLength, interfaceOffsets.concat(parameterOffsets)[0]]);
    }
    mapItems.push([TYPE_STRING_DATA_ITEM, strings.length, stringOffsets[0]]);
    debugInfoOffsets.forEach((debugInfoOffset) => {
      mapItems.push([TYPE_DEBUG_INFO_ITEM, 1, debugInfoOffset]);
    });
    throwsAnnotations.forEach((annotation) => {
      mapItems.push([TYPE_ANNOTATION_ITEM, 1, annotation.offset]);
    });
    classes.forEach((klass) => {
      mapItems.push([TYPE_CLASS_DATA_ITEM, 1, klass.classData.offset]);
    });
    mapItems.push([TYPE_MAP_LIST, 1, mapOffset]);
    mapItems.forEach((item, index) => {
      const [type, size, offset2] = item;
      const itemOffset = mapOffset + 4 + index * kMapItemSize;
      dex.writeUInt16LE(type, itemOffset);
      dex.writeUInt32LE(size, itemOffset + 4);
      dex.writeUInt32LE(offset2, itemOffset + 8);
    });
    const hash = new Checksum("sha1");
    hash.update(dex.slice(signatureOffset + signatureSize));
    Buffer2.from(hash.getDigest()).copy(dex, signatureOffset);
    dex.writeUInt32LE(adler32(dex, signatureOffset), checksumOffset);
    return dex;
  }
};
function makeClassData(klass) {
  const { instanceFields, constructorMethods, virtualMethods } = klass.classData;
  const staticFieldsSize = 0;
  return Buffer2.from([
    staticFieldsSize
  ].concat(createUleb128(instanceFields.length)).concat(createUleb128(constructorMethods.length)).concat(createUleb128(virtualMethods.length)).concat(instanceFields.reduce((result, [indexDiff, accessFlags]) => {
    return result.concat(createUleb128(indexDiff)).concat(createUleb128(accessFlags));
  }, [])).concat(constructorMethods.reduce((result, [indexDiff, accessFlags, , codeOffset]) => {
    return result.concat(createUleb128(indexDiff)).concat(createUleb128(accessFlags)).concat(createUleb128(codeOffset || 0));
  }, [])).concat(virtualMethods.reduce((result, [indexDiff, accessFlags]) => {
    const codeOffset = 0;
    return result.concat(createUleb128(indexDiff)).concat(createUleb128(accessFlags)).concat([codeOffset]);
  }, [])));
}
function makeThrowsAnnotation(annotation) {
  const { thrownTypes } = annotation;
  return Buffer2.from(
    [
      VISIBILITY_SYSTEM
    ].concat(createUleb128(annotation.type)).concat([1]).concat(createUleb128(annotation.value)).concat([VALUE_ARRAY, thrownTypes.length]).concat(thrownTypes.reduce((result, type) => {
      result.push(VALUE_TYPE, type);
      return result;
    }, []))
  );
}
function computeModel(classes) {
  const strings = /* @__PURE__ */ new Set();
  const types = /* @__PURE__ */ new Set();
  const protos = {};
  const fields = [];
  const methods = [];
  const throwsAnnotations = {};
  const javaConstructors = /* @__PURE__ */ new Set();
  const superConstructors = /* @__PURE__ */ new Set();
  classes.forEach((klass) => {
    const { name, superClass, sourceFileName } = klass;
    strings.add("this");
    strings.add(name);
    types.add(name);
    strings.add(superClass);
    types.add(superClass);
    strings.add(sourceFileName);
    klass.interfaces.forEach((iface) => {
      strings.add(iface);
      types.add(iface);
    });
    klass.fields.forEach((field) => {
      const [fieldName, fieldType] = field;
      strings.add(fieldName);
      strings.add(fieldType);
      types.add(fieldType);
      fields.push([klass.name, fieldType, fieldName]);
    });
    if (!klass.methods.some(([methodName]) => methodName === "<init>")) {
      klass.methods.unshift(["<init>", "V", []]);
      javaConstructors.add(name);
    }
    klass.methods.forEach((method) => {
      const [methodName, retType, argTypes, thrownTypes = [], accessFlags] = method;
      strings.add(methodName);
      const protoId = addProto(retType, argTypes);
      let throwsAnnotationId = null;
      if (thrownTypes.length > 0) {
        const typesNormalized = thrownTypes.slice();
        typesNormalized.sort();
        throwsAnnotationId = typesNormalized.join("|");
        let throwsAnnotation = throwsAnnotations[throwsAnnotationId];
        if (throwsAnnotation === void 0) {
          throwsAnnotation = {
            id: throwsAnnotationId,
            types: typesNormalized
          };
          throwsAnnotations[throwsAnnotationId] = throwsAnnotation;
        }
        strings.add(kDalvikAnnotationTypeThrows);
        types.add(kDalvikAnnotationTypeThrows);
        thrownTypes.forEach((type) => {
          strings.add(type);
          types.add(type);
        });
        strings.add("value");
      }
      methods.push([klass.name, protoId, methodName, throwsAnnotationId, accessFlags]);
      if (methodName === "<init>") {
        superConstructors.add(name + "|" + protoId);
        const superConstructorId = superClass + "|" + protoId;
        if (javaConstructors.has(name) && !superConstructors.has(superConstructorId)) {
          methods.push([superClass, protoId, methodName, null, 0]);
          superConstructors.add(superConstructorId);
        }
      }
    });
  });
  function addProto(retType, argTypes) {
    const signature = [retType].concat(argTypes);
    const id = signature.join("|");
    if (protos[id] !== void 0) {
      return id;
    }
    strings.add(retType);
    types.add(retType);
    argTypes.forEach((argType) => {
      strings.add(argType);
      types.add(argType);
    });
    const shorty = signature.map(typeToShorty).join("");
    strings.add(shorty);
    protos[id] = [id, shorty, retType, argTypes];
    return id;
  }
  const stringItems = Array.from(strings);
  stringItems.sort();
  const stringToIndex = stringItems.reduce((result, string, index) => {
    result[string] = index;
    return result;
  }, {});
  const typeItems = Array.from(types).map((name) => stringToIndex[name]);
  typeItems.sort(compareNumbers);
  const typeToIndex = typeItems.reduce((result, stringIndex, typeIndex) => {
    result[stringItems[stringIndex]] = typeIndex;
    return result;
  }, {});
  const literalProtoItems = Object.keys(protos).map((id) => protos[id]);
  literalProtoItems.sort(compareProtoItems);
  const parameters = {};
  const protoItems = literalProtoItems.map((item) => {
    const [, shorty, retType, argTypes] = item;
    let params;
    if (argTypes.length > 0) {
      const argTypesSig = argTypes.join("|");
      params = parameters[argTypesSig];
      if (params === void 0) {
        params = {
          types: argTypes.map((type) => typeToIndex[type]),
          offset: -1
        };
        parameters[argTypesSig] = params;
      }
    } else {
      params = null;
    }
    return [
      stringToIndex[shorty],
      typeToIndex[retType],
      params
    ];
  });
  const protoToIndex = literalProtoItems.reduce((result, item, index) => {
    const [id] = item;
    result[id] = index;
    return result;
  }, {});
  const parameterItems = Object.keys(parameters).map((id) => parameters[id]);
  const fieldItems = fields.map((field) => {
    const [klass, fieldType, fieldName] = field;
    return [
      typeToIndex[klass],
      typeToIndex[fieldType],
      stringToIndex[fieldName]
    ];
  });
  fieldItems.sort(compareFieldItems);
  const methodItems = methods.map((method) => {
    const [klass, protoId, name, annotationsId, accessFlags] = method;
    return [
      typeToIndex[klass],
      protoToIndex[protoId],
      stringToIndex[name],
      annotationsId,
      accessFlags
    ];
  });
  methodItems.sort(compareMethodItems);
  const throwsAnnotationItems = Object.keys(throwsAnnotations).map((id) => throwsAnnotations[id]).map((item) => {
    return {
      id: item.id,
      type: typeToIndex[kDalvikAnnotationTypeThrows],
      value: stringToIndex.value,
      thrownTypes: item.types.map((type) => typeToIndex[type]),
      offset: -1
    };
  });
  const annotationSetItems = throwsAnnotationItems.map((item) => {
    return {
      id: item.id,
      items: [item],
      offset: -1
    };
  });
  const annotationSetIdToIndex = annotationSetItems.reduce((result, item, index) => {
    result[item.id] = index;
    return result;
  }, {});
  const interfaceLists = {};
  const annotationDirectories = [];
  const classItems = classes.map((klass) => {
    const classIndex = typeToIndex[klass.name];
    const accessFlags = kAccPublic2;
    const superClassIndex = typeToIndex[klass.superClass];
    let ifaceList;
    const ifaces = klass.interfaces.map((type) => typeToIndex[type]);
    if (ifaces.length > 0) {
      ifaces.sort(compareNumbers);
      const ifacesId = ifaces.join("|");
      ifaceList = interfaceLists[ifacesId];
      if (ifaceList === void 0) {
        ifaceList = {
          types: ifaces,
          offset: -1
        };
        interfaceLists[ifacesId] = ifaceList;
      }
    } else {
      ifaceList = null;
    }
    const sourceFileIndex = stringToIndex[klass.sourceFileName];
    const classMethods = methodItems.reduce((result, method, index) => {
      const [holder, protoIndex, name, annotationsId, accessFlags2] = method;
      if (holder === classIndex) {
        result.push([index, name, annotationsId, protoIndex, accessFlags2]);
      }
      return result;
    }, []);
    let annotationsDirectory = null;
    const methodAnnotations = classMethods.filter(([, , annotationsId]) => {
      return annotationsId !== null;
    }).map(([index, , annotationsId]) => {
      return [index, annotationSetItems[annotationSetIdToIndex[annotationsId]]];
    });
    if (methodAnnotations.length > 0) {
      annotationsDirectory = {
        methods: methodAnnotations,
        offset: -1
      };
      annotationDirectories.push(annotationsDirectory);
    }
    const instanceFields = fieldItems.reduce((result, field, index) => {
      const [holder] = field;
      if (holder === classIndex) {
        result.push([index > 0 ? 1 : 0, kAccPublic2]);
      }
      return result;
    }, []);
    const constructorNameIndex = stringToIndex["<init>"];
    const constructorMethods = classMethods.filter(([, name]) => name === constructorNameIndex).map(([index, , , protoIndex]) => {
      if (javaConstructors.has(klass.name)) {
        let superConstructor = -1;
        const numMethodItems = methodItems.length;
        for (let i = 0; i !== numMethodItems; i++) {
          const [methodClass, methodProto, methodName] = methodItems[i];
          if (methodClass === superClassIndex && methodName === constructorNameIndex && methodProto === protoIndex) {
            superConstructor = i;
            break;
          }
        }
        return [index, kAccPublic2 | kAccConstructor, superConstructor];
      } else {
        return [index, kAccPublic2 | kAccConstructor | kAccNative2, -1];
      }
    });
    const virtualMethods = compressClassMethodIndexes(classMethods.filter(([, name]) => name !== constructorNameIndex).map(([index, , , , accessFlags2]) => {
      return [index, accessFlags2 | kAccPublic2 | kAccNative2];
    }));
    const classData = {
      instanceFields,
      constructorMethods,
      virtualMethods,
      offset: -1
    };
    return {
      index: classIndex,
      accessFlags,
      superClassIndex,
      interfaces: ifaceList,
      sourceFileIndex,
      annotationsDirectory,
      classData
    };
  });
  const interfaceItems = Object.keys(interfaceLists).map((id) => interfaceLists[id]);
  return {
    classes: classItems,
    interfaces: interfaceItems,
    fields: fieldItems,
    methods: methodItems,
    protos: protoItems,
    parameters: parameterItems,
    annotationDirectories,
    annotationSets: annotationSetItems,
    throwsAnnotations: throwsAnnotationItems,
    types: typeItems,
    strings: stringItems
  };
}
function compressClassMethodIndexes(items) {
  let previousIndex = 0;
  return items.map(([index, accessFlags], elementIndex) => {
    let result;
    if (elementIndex === 0) {
      result = [index, accessFlags];
    } else {
      result = [index - previousIndex, accessFlags];
    }
    previousIndex = index;
    return result;
  });
}
function compareNumbers(a, b) {
  return a - b;
}
function compareProtoItems(a, b) {
  const [, , aRetType, aArgTypes] = a;
  const [, , bRetType, bArgTypes] = b;
  if (aRetType < bRetType) {
    return -1;
  }
  if (aRetType > bRetType) {
    return 1;
  }
  const aArgTypesSig = aArgTypes.join("|");
  const bArgTypesSig = bArgTypes.join("|");
  if (aArgTypesSig < bArgTypesSig) {
    return -1;
  }
  if (aArgTypesSig > bArgTypesSig) {
    return 1;
  }
  return 0;
}
function compareFieldItems(a, b) {
  const [aClass, aType, aName] = a;
  const [bClass, bType, bName] = b;
  if (aClass !== bClass) {
    return aClass - bClass;
  }
  if (aName !== bName) {
    return aName - bName;
  }
  return aType - bType;
}
function compareMethodItems(a, b) {
  const [aClass, aProto, aName] = a;
  const [bClass, bProto, bName] = b;
  if (aClass !== bClass) {
    return aClass - bClass;
  }
  if (aName !== bName) {
    return aName - bName;
  }
  return aProto - bProto;
}
function typeToShorty(type) {
  const firstCharacter = type[0];
  return firstCharacter === "L" || firstCharacter === "[" ? "L" : type;
}
function createUleb128(value) {
  if (value <= 127) {
    return [value];
  }
  const result = [];
  let moreSlicesNeeded = false;
  do {
    let slice2 = value & 127;
    value >>= 7;
    moreSlicesNeeded = value !== 0;
    if (moreSlicesNeeded) {
      slice2 |= 128;
    }
    result.push(slice2);
  } while (moreSlicesNeeded);
  return result;
}
function align(value, alignment) {
  const alignmentDelta = value % alignment;
  if (alignmentDelta === 0) {
    return value;
  }
  return value + alignment - alignmentDelta;
}
function adler32(buffer, offset) {
  let a = 1;
  let b = 0;
  const length = buffer.length;
  for (let i = offset; i < length; i++) {
    a = (a + buffer[i]) % 65521;
    b = (b + a) % 65521;
  }
  return (b << 16 | a) >>> 0;
}
var mkdex_default = mkdex;

// node_modules/frida-java-bridge/lib/types.js
var JNILocalRefType = 1;
var vm = null;
var primitiveArrayHandler = null;
function initialize(_vm) {
  vm = _vm;
}
function getType(typeName, unbox, factory) {
  let type = getPrimitiveType(typeName);
  if (type === null) {
    if (typeName.indexOf("[") === 0) {
      type = getArrayType(typeName, unbox, factory);
    } else {
      if (typeName[0] === "L" && typeName[typeName.length - 1] === ";") {
        typeName = typeName.substring(1, typeName.length - 1);
      }
      type = getObjectType(typeName, unbox, factory);
    }
  }
  return Object.assign({ className: typeName }, type);
}
var primitiveTypes = {
  boolean: {
    name: "Z",
    type: "uint8",
    size: 1,
    byteSize: 1,
    defaultValue: false,
    isCompatible(v) {
      return typeof v === "boolean";
    },
    fromJni(v) {
      return !!v;
    },
    toJni(v) {
      return v ? 1 : 0;
    },
    read(address) {
      return address.readU8();
    },
    write(address, value) {
      address.writeU8(value);
    },
    toString() {
      return this.name;
    }
  },
  byte: {
    name: "B",
    type: "int8",
    size: 1,
    byteSize: 1,
    defaultValue: 0,
    isCompatible(v) {
      return Number.isInteger(v) && v >= -128 && v <= 127;
    },
    fromJni: identity,
    toJni: identity,
    read(address) {
      return address.readS8();
    },
    write(address, value) {
      address.writeS8(value);
    },
    toString() {
      return this.name;
    }
  },
  char: {
    name: "C",
    type: "uint16",
    size: 1,
    byteSize: 2,
    defaultValue: 0,
    isCompatible(v) {
      if (typeof v !== "string" || v.length !== 1) {
        return false;
      }
      const code3 = v.charCodeAt(0);
      return code3 >= 0 && code3 <= 65535;
    },
    fromJni(c) {
      return String.fromCharCode(c);
    },
    toJni(s) {
      return s.charCodeAt(0);
    },
    read(address) {
      return address.readU16();
    },
    write(address, value) {
      address.writeU16(value);
    },
    toString() {
      return this.name;
    }
  },
  short: {
    name: "S",
    type: "int16",
    size: 1,
    byteSize: 2,
    defaultValue: 0,
    isCompatible(v) {
      return Number.isInteger(v) && v >= -32768 && v <= 32767;
    },
    fromJni: identity,
    toJni: identity,
    read(address) {
      return address.readS16();
    },
    write(address, value) {
      address.writeS16(value);
    },
    toString() {
      return this.name;
    }
  },
  int: {
    name: "I",
    type: "int32",
    size: 1,
    byteSize: 4,
    defaultValue: 0,
    isCompatible(v) {
      return Number.isInteger(v) && v >= -2147483648 && v <= 2147483647;
    },
    fromJni: identity,
    toJni: identity,
    read(address) {
      return address.readS32();
    },
    write(address, value) {
      address.writeS32(value);
    },
    toString() {
      return this.name;
    }
  },
  long: {
    name: "J",
    type: "int64",
    size: 2,
    byteSize: 8,
    defaultValue: 0,
    isCompatible(v) {
      return typeof v === "number" || v instanceof Int64;
    },
    fromJni: identity,
    toJni: identity,
    read(address) {
      return address.readS64();
    },
    write(address, value) {
      address.writeS64(value);
    },
    toString() {
      return this.name;
    }
  },
  float: {
    name: "F",
    type: "float",
    size: 1,
    byteSize: 4,
    defaultValue: 0,
    isCompatible(v) {
      return typeof v === "number";
    },
    fromJni: identity,
    toJni: identity,
    read(address) {
      return address.readFloat();
    },
    write(address, value) {
      address.writeFloat(value);
    },
    toString() {
      return this.name;
    }
  },
  double: {
    name: "D",
    type: "double",
    size: 2,
    byteSize: 8,
    defaultValue: 0,
    isCompatible(v) {
      return typeof v === "number";
    },
    fromJni: identity,
    toJni: identity,
    read(address) {
      return address.readDouble();
    },
    write(address, value) {
      address.writeDouble(value);
    },
    toString() {
      return this.name;
    }
  },
  void: {
    name: "V",
    type: "void",
    size: 0,
    byteSize: 0,
    defaultValue: void 0,
    isCompatible(v) {
      return v === void 0;
    },
    fromJni() {
      return void 0;
    },
    toJni() {
      return NULL;
    },
    toString() {
      return this.name;
    }
  }
};
var primitiveTypesNames = new Set(Object.values(primitiveTypes).map((t) => t.name));
function getPrimitiveType(name) {
  const result = primitiveTypes[name];
  return result !== void 0 ? result : null;
}
function getObjectType(typeName, unbox, factory) {
  const cache = factory._types[unbox ? 1 : 0];
  let type = cache[typeName];
  if (type !== void 0) {
    return type;
  }
  if (typeName === "java.lang.Object") {
    type = getJavaLangObjectType(factory);
  } else {
    type = getAnyObjectType(typeName, unbox, factory);
  }
  cache[typeName] = type;
  return type;
}
function getJavaLangObjectType(factory) {
  return {
    name: "Ljava/lang/Object;",
    type: "pointer",
    size: 1,
    defaultValue: NULL,
    isCompatible(v) {
      if (v === null) {
        return true;
      }
      if (v === void 0) {
        return false;
      }
      const isWrapper = v.$h instanceof NativePointer;
      if (isWrapper) {
        return true;
      }
      return typeof v === "string";
    },
    fromJni(h, env, owned) {
      if (h.isNull()) {
        return null;
      }
      return factory.cast(h, factory.use("java.lang.Object"), owned);
    },
    toJni(o, env) {
      if (o === null) {
        return NULL;
      }
      if (typeof o === "string") {
        return env.newStringUtf(o);
      }
      return o.$h;
    }
  };
}
function getAnyObjectType(typeName, unbox, factory) {
  let cachedClass = null;
  let cachedIsInstance = null;
  let cachedIsDefaultString = null;
  function getClass() {
    if (cachedClass === null) {
      cachedClass = factory.use(typeName).class;
    }
    return cachedClass;
  }
  function isInstance(v) {
    const klass = getClass();
    if (cachedIsInstance === null) {
      cachedIsInstance = klass.isInstance.overload("java.lang.Object");
    }
    return cachedIsInstance.call(klass, v);
  }
  function typeIsDefaultString() {
    if (cachedIsDefaultString === null) {
      const x = getClass();
      cachedIsDefaultString = factory.use("java.lang.String").class.isAssignableFrom(x);
    }
    return cachedIsDefaultString;
  }
  return {
    name: makeJniObjectTypeName(typeName),
    type: "pointer",
    size: 1,
    defaultValue: NULL,
    isCompatible(v) {
      if (v === null) {
        return true;
      }
      if (v === void 0) {
        return false;
      }
      const isWrapper = v.$h instanceof NativePointer;
      if (isWrapper) {
        return isInstance(v);
      }
      return typeof v === "string" && typeIsDefaultString();
    },
    fromJni(h, env, owned) {
      if (h.isNull()) {
        return null;
      }
      if (typeIsDefaultString() && unbox) {
        return env.stringFromJni(h);
      }
      return factory.cast(h, factory.use(typeName), owned);
    },
    toJni(o, env) {
      if (o === null) {
        return NULL;
      }
      if (typeof o === "string") {
        return env.newStringUtf(o);
      }
      return o.$h;
    },
    toString() {
      return this.name;
    }
  };
}
var primitiveArrayTypes = [
  ["Z", "boolean"],
  ["B", "byte"],
  ["C", "char"],
  ["D", "double"],
  ["F", "float"],
  ["I", "int"],
  ["J", "long"],
  ["S", "short"]
].reduce((result, [shorty, name]) => {
  result["[" + shorty] = makePrimitiveArrayType("[" + shorty, name);
  return result;
}, {});
function makePrimitiveArrayType(shorty, name) {
  const envProto = Env.prototype;
  const nameTitled = toTitleCase(name);
  const spec = {
    typeName: name,
    newArray: envProto["new" + nameTitled + "Array"],
    setRegion: envProto["set" + nameTitled + "ArrayRegion"],
    getElements: envProto["get" + nameTitled + "ArrayElements"],
    releaseElements: envProto["release" + nameTitled + "ArrayElements"]
  };
  return {
    name: shorty,
    type: "pointer",
    size: 1,
    defaultValue: NULL,
    isCompatible(v) {
      return isCompatiblePrimitiveArray(v, name);
    },
    fromJni(h, env, owned) {
      return fromJniPrimitiveArray(h, spec, env, owned);
    },
    toJni(arr, env) {
      return toJniPrimitiveArray(arr, spec, env);
    }
  };
}
function getArrayType(typeName, unbox, factory) {
  const primitiveType = primitiveArrayTypes[typeName];
  if (primitiveType !== void 0) {
    return primitiveType;
  }
  if (typeName.indexOf("[") !== 0) {
    throw new Error("Unsupported type: " + typeName);
  }
  let elementTypeName = typeName.substring(1);
  const elementType = getType(elementTypeName, unbox, factory);
  let numInternalArrays = 0;
  const end = elementTypeName.length;
  while (numInternalArrays !== end && elementTypeName[numInternalArrays] === "[") {
    numInternalArrays++;
  }
  elementTypeName = elementTypeName.substring(numInternalArrays);
  if (elementTypeName[0] === "L" && elementTypeName[elementTypeName.length - 1] === ";") {
    elementTypeName = elementTypeName.substring(1, elementTypeName.length - 1);
  }
  let internalElementTypeName = elementTypeName.replace(/\./g, "/");
  if (primitiveTypesNames.has(internalElementTypeName)) {
    internalElementTypeName = "[".repeat(numInternalArrays) + internalElementTypeName;
  } else {
    internalElementTypeName = "[".repeat(numInternalArrays) + "L" + internalElementTypeName + ";";
  }
  const internalTypeName = "[" + internalElementTypeName;
  elementTypeName = "[".repeat(numInternalArrays) + elementTypeName;
  return {
    name: typeName.replace(/\./g, "/"),
    type: "pointer",
    size: 1,
    defaultValue: NULL,
    isCompatible(v) {
      if (v === null) {
        return true;
      }
      if (typeof v !== "object" || v.length === void 0) {
        return false;
      }
      return v.every(function(element) {
        return elementType.isCompatible(element);
      });
    },
    fromJni(arr, env, owned) {
      if (arr.isNull()) {
        return null;
      }
      const result = [];
      const n = env.getArrayLength(arr);
      for (let i = 0; i !== n; i++) {
        const element = env.getObjectArrayElement(arr, i);
        try {
          result.push(elementType.fromJni(element, env));
        } finally {
          env.deleteLocalRef(element);
        }
      }
      try {
        result.$w = factory.cast(arr, factory.use(internalTypeName), owned);
      } catch (e) {
        factory.use("java.lang.reflect.Array").newInstance(factory.use(elementTypeName).class, 0);
        result.$w = factory.cast(arr, factory.use(internalTypeName), owned);
      }
      result.$dispose = disposeObjectArray;
      return result;
    },
    toJni(elements, env) {
      if (elements === null) {
        return NULL;
      }
      if (!(elements instanceof Array)) {
        throw new Error("Expected an array");
      }
      const wrapper = elements.$w;
      if (wrapper !== void 0) {
        return wrapper.$h;
      }
      const n = elements.length;
      const klassObj = factory.use(elementTypeName);
      const classHandle = klassObj.$borrowClassHandle(env);
      try {
        const result = env.newObjectArray(n, classHandle.value, NULL);
        env.throwIfExceptionPending();
        for (let i = 0; i !== n; i++) {
          const handle = elementType.toJni(elements[i], env);
          try {
            env.setObjectArrayElement(result, i, handle);
          } finally {
            if (elementType.type === "pointer" && env.getObjectRefType(handle) === JNILocalRefType) {
              env.deleteLocalRef(handle);
            }
          }
          env.throwIfExceptionPending();
        }
        return result;
      } finally {
        classHandle.unref(env);
      }
    }
  };
}
function disposeObjectArray() {
  const n = this.length;
  for (let i = 0; i !== n; i++) {
    const obj = this[i];
    if (obj === null) {
      continue;
    }
    const dispose = obj.$dispose;
    if (dispose === void 0) {
      break;
    }
    dispose.call(obj);
  }
  this.$w.$dispose();
}
function fromJniPrimitiveArray(arr, spec, env, owned) {
  if (arr.isNull()) {
    return null;
  }
  const type = getPrimitiveType(spec.typeName);
  const length = env.getArrayLength(arr);
  return new PrimitiveArray(arr, spec, type, length, env, owned);
}
function toJniPrimitiveArray(arr, spec, env) {
  if (arr === null) {
    return NULL;
  }
  const handle = arr.$h;
  if (handle !== void 0) {
    return handle;
  }
  const length = arr.length;
  const type = getPrimitiveType(spec.typeName);
  const result = spec.newArray.call(env, length);
  if (result.isNull()) {
    throw new Error("Unable to construct array");
  }
  if (length > 0) {
    const elementSize = type.byteSize;
    const writeElement = type.write;
    const unparseElementValue = type.toJni;
    const elements = Memory.alloc(length * type.byteSize);
    for (let index = 0; index !== length; index++) {
      writeElement(elements.add(index * elementSize), unparseElementValue(arr[index]));
    }
    spec.setRegion.call(env, result, 0, length, elements);
    env.throwIfExceptionPending();
  }
  return result;
}
function isCompatiblePrimitiveArray(value, typeName) {
  if (value === null) {
    return true;
  }
  if (value instanceof PrimitiveArray) {
    return value.$s.typeName === typeName;
  }
  const isArrayLike = typeof value === "object" && value.length !== void 0;
  if (!isArrayLike) {
    return false;
  }
  const elementType = getPrimitiveType(typeName);
  return Array.prototype.every.call(value, (element) => elementType.isCompatible(element));
}
function PrimitiveArray(handle, spec, type, length, env, owned = true) {
  if (owned) {
    const h = env.newGlobalRef(handle);
    this.$h = h;
    this.$r = Script.bindWeak(this, env.vm.makeHandleDestructor(h));
  } else {
    this.$h = handle;
    this.$r = null;
  }
  this.$s = spec;
  this.$t = type;
  this.length = length;
  return new Proxy(this, primitiveArrayHandler);
}
primitiveArrayHandler = {
  has(target, property) {
    if (property in target) {
      return true;
    }
    return target.tryParseIndex(property) !== null;
  },
  get(target, property, receiver) {
    const index = target.tryParseIndex(property);
    if (index === null) {
      return target[property];
    }
    return target.readElement(index);
  },
  set(target, property, value, receiver) {
    const index = target.tryParseIndex(property);
    if (index === null) {
      target[property] = value;
      return true;
    }
    target.writeElement(index, value);
    return true;
  },
  ownKeys(target) {
    const keys = [];
    const { length } = target;
    for (let i = 0; i !== length; i++) {
      const key = i.toString();
      keys.push(key);
    }
    keys.push("length");
    return keys;
  },
  getOwnPropertyDescriptor(target, property) {
    const index = target.tryParseIndex(property);
    if (index !== null) {
      return {
        writable: true,
        configurable: true,
        enumerable: true
      };
    }
    return Object.getOwnPropertyDescriptor(target, property);
  }
};
Object.defineProperties(PrimitiveArray.prototype, {
  $dispose: {
    enumerable: true,
    value() {
      const ref = this.$r;
      if (ref !== null) {
        this.$r = null;
        Script.unbindWeak(ref);
      }
    }
  },
  $clone: {
    value(env) {
      return new PrimitiveArray(this.$h, this.$s, this.$t, this.length, env);
    }
  },
  tryParseIndex: {
    value(rawIndex) {
      if (typeof rawIndex === "symbol") {
        return null;
      }
      const index = parseInt(rawIndex);
      if (isNaN(index) || index < 0 || index >= this.length) {
        return null;
      }
      return index;
    }
  },
  readElement: {
    value(index) {
      return this.withElements((elements) => {
        const type = this.$t;
        return type.fromJni(type.read(elements.add(index * type.byteSize)));
      });
    }
  },
  writeElement: {
    value(index, value) {
      const { $h: handle, $s: spec, $t: type } = this;
      const env = vm.getEnv();
      const element = Memory.alloc(type.byteSize);
      type.write(element, type.toJni(value));
      spec.setRegion.call(env, handle, index, 1, element);
    }
  },
  withElements: {
    value(perform) {
      const { $h: handle, $s: spec } = this;
      const env = vm.getEnv();
      const elements = spec.getElements.call(env, handle);
      if (elements.isNull()) {
        throw new Error("Unable to get array elements");
      }
      try {
        return perform(elements);
      } finally {
        spec.releaseElements.call(env, handle, elements);
      }
    }
  },
  toJSON: {
    value() {
      const { length, $t: type } = this;
      const { byteSize: elementSize, fromJni, read: read2 } = type;
      return this.withElements((elements) => {
        const values = [];
        for (let i = 0; i !== length; i++) {
          const value = fromJni(read2(elements.add(i * elementSize)));
          values.push(value);
        }
        return values;
      });
    }
  },
  toString: {
    value() {
      return this.toJSON().toString();
    }
  }
});
function makeJniObjectTypeName(typeName) {
  return "L" + typeName.replace(/\./g, "/") + ";";
}
function toTitleCase(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}
function identity(value) {
  return value;
}

// node_modules/frida-java-bridge/lib/class-factory.js
var jsizeSize3 = 4;
var {
  ensureClassInitialized: ensureClassInitialized3,
  makeMethodMangler: makeMethodMangler3
} = android_exports;
var kAccStatic2 = 8;
var CONSTRUCTOR_METHOD = 1;
var STATIC_METHOD = 2;
var INSTANCE_METHOD = 3;
var STATIC_FIELD = 1;
var INSTANCE_FIELD = 2;
var STRATEGY_VIRTUAL = 1;
var STRATEGY_DIRECT = 2;
var PENDING_USE = Symbol("PENDING_USE");
var DEFAULT_CACHE_DIR = "/data/local/tmp";
var {
  getCurrentThreadId,
  pointerSize: pointerSize7
} = Process;
var factoryCache = {
  state: "empty",
  factories: [],
  loaders: null,
  Integer: null
};
var vm2 = null;
var api = null;
var isArtVm = null;
var wrapperHandler = null;
var dispatcherPrototype = null;
var methodPrototype = null;
var valueOfPrototype = null;
var cachedLoaderInvoke = null;
var cachedLoaderMethod = null;
var ignoredThreads = /* @__PURE__ */ new Map();
var ClassFactory = class _ClassFactory {
  static _initialize(_vm, _api) {
    vm2 = _vm;
    api = _api;
    isArtVm = _api.flavor === "art";
    if (_api.flavor === "jvm") {
      ensureClassInitialized3 = ensureClassInitialized2;
      makeMethodMangler3 = makeMethodMangler2;
    }
  }
  static _disposeAll(env) {
    factoryCache.factories.forEach((factory) => {
      factory._dispose(env);
    });
  }
  static get(classLoader) {
    const cache = getFactoryCache();
    const defaultFactory = cache.factories[0];
    if (classLoader === null) {
      return defaultFactory;
    }
    const indexObj = cache.loaders.get(classLoader);
    if (indexObj !== null) {
      const index = defaultFactory.cast(indexObj, cache.Integer);
      return cache.factories[index.intValue()];
    }
    const factory = new _ClassFactory();
    factory.loader = classLoader;
    factory.cacheDir = defaultFactory.cacheDir;
    addFactoryToCache(factory, classLoader);
    return factory;
  }
  constructor() {
    this.cacheDir = DEFAULT_CACHE_DIR;
    this.codeCacheDir = DEFAULT_CACHE_DIR + "/dalvik-cache";
    this.tempFileNaming = {
      prefix: "frida",
      suffix: ""
    };
    this._classes = {};
    this._classHandles = new LRU(10, releaseClassHandle);
    this._patchedMethods = /* @__PURE__ */ new Set();
    this._loader = null;
    this._types = [{}, {}];
    factoryCache.factories.push(this);
  }
  _dispose(env) {
    Array.from(this._patchedMethods).forEach((method) => {
      method.implementation = null;
    });
    this._patchedMethods.clear();
    revertGlobalPatches();
    this._classHandles.dispose(env);
    this._classes = {};
  }
  get loader() {
    return this._loader;
  }
  set loader(value) {
    const isInitial = this._loader === null && value !== null;
    this._loader = value;
    if (isInitial && factoryCache.state === "ready" && this === factoryCache.factories[0]) {
      addFactoryToCache(this, value);
    }
  }
  use(className, options = {}) {
    const allowCached = options.cache !== "skip";
    let C = allowCached ? this._getUsedClass(className) : void 0;
    if (C === void 0) {
      try {
        const env = vm2.getEnv();
        const { _loader: loader } = this;
        const getClassHandle = loader !== null ? makeLoaderClassHandleGetter(className, loader, env) : makeBasicClassHandleGetter(className);
        C = this._make(className, getClassHandle, env);
      } finally {
        if (allowCached) {
          this._setUsedClass(className, C);
        }
      }
    }
    return C;
  }
  _getUsedClass(className) {
    let c;
    while ((c = this._classes[className]) === PENDING_USE) {
      Thread.sleep(0.05);
    }
    if (c === void 0) {
      this._classes[className] = PENDING_USE;
    }
    return c;
  }
  _setUsedClass(className, c) {
    if (c !== void 0) {
      this._classes[className] = c;
    } else {
      delete this._classes[className];
    }
  }
  _make(name, getClassHandle, env) {
    const C = makeClassWrapperConstructor();
    const proto = Object.create(Wrapper.prototype, {
      [Symbol.for("n")]: {
        value: name
      },
      $n: {
        get() {
          return this[Symbol.for("n")];
        }
      },
      [Symbol.for("C")]: {
        value: C
      },
      $C: {
        get() {
          return this[Symbol.for("C")];
        }
      },
      [Symbol.for("w")]: {
        value: null,
        writable: true
      },
      $w: {
        get() {
          return this[Symbol.for("w")];
        },
        set(val) {
          this[Symbol.for("w")] = val;
        }
      },
      [Symbol.for("_s")]: {
        writable: true
      },
      $_s: {
        get() {
          return this[Symbol.for("_s")];
        },
        set(val) {
          this[Symbol.for("_s")] = val;
        }
      },
      [Symbol.for("c")]: {
        value: [null]
      },
      $c: {
        get() {
          return this[Symbol.for("c")];
        }
      },
      [Symbol.for("m")]: {
        value: /* @__PURE__ */ new Map()
      },
      $m: {
        get() {
          return this[Symbol.for("m")];
        }
      },
      [Symbol.for("l")]: {
        value: null,
        writable: true
      },
      $l: {
        get() {
          return this[Symbol.for("l")];
        },
        set(val) {
          this[Symbol.for("l")] = val;
        }
      },
      [Symbol.for("gch")]: {
        value: getClassHandle
      },
      $gch: {
        get() {
          return this[Symbol.for("gch")];
        }
      },
      [Symbol.for("f")]: {
        value: this
      },
      $f: {
        get() {
          return this[Symbol.for("f")];
        }
      }
    });
    C.prototype = proto;
    const classWrapper = new C(null);
    proto[Symbol.for("w")] = classWrapper;
    proto.$w = classWrapper;
    const h = classWrapper.$borrowClassHandle(env);
    try {
      const classHandle = h.value;
      ensureClassInitialized3(env, classHandle);
      proto.$l = Model.build(classHandle, env);
    } finally {
      h.unref(env);
    }
    return classWrapper;
  }
  retain(obj) {
    const env = vm2.getEnv();
    return obj.$clone(env);
  }
  cast(obj, klass, owned) {
    const env = vm2.getEnv();
    let handle = obj.$h;
    if (handle === void 0) {
      handle = obj;
    }
    const h = klass.$borrowClassHandle(env);
    try {
      const isValidCast = env.isInstanceOf(handle, h.value);
      if (!isValidCast) {
        throw new Error(`Cast from '${env.getObjectClassName(handle)}' to '${klass.$n}' isn't possible`);
      }
    } finally {
      h.unref(env);
    }
    const C = klass.$C;
    return new C(handle, STRATEGY_VIRTUAL, env, owned);
  }
  wrap(handle, klass, env) {
    const C = klass.$C;
    const wrapper = new C(handle, STRATEGY_VIRTUAL, env, false);
    wrapper.$r = Script.bindWeak(wrapper, vm2.makeHandleDestructor(handle));
    return wrapper;
  }
  array(type, elements) {
    const env = vm2.getEnv();
    const primitiveType = getPrimitiveType(type);
    if (primitiveType !== null) {
      type = primitiveType.name;
    }
    const arrayType = getArrayType("[" + type, false, this);
    const rawArray = arrayType.toJni(elements, env);
    return arrayType.fromJni(rawArray, env, true);
  }
  registerClass(spec) {
    const env = vm2.getEnv();
    const tempHandles = [];
    try {
      const Class = this.use("java.lang.Class");
      const Method = env.javaLangReflectMethod();
      const invokeObjectMethodNoArgs = env.vaMethod("pointer", []);
      const className = spec.name;
      const interfaces = spec.implements || [];
      const superClass = spec.superClass || this.use("java.lang.Object");
      const dexFields = [];
      const dexMethods = [];
      const dexSpec = {
        name: makeJniObjectTypeName(className),
        sourceFileName: makeSourceFileName(className),
        superClass: makeJniObjectTypeName(superClass.$n),
        interfaces: interfaces.map((iface) => makeJniObjectTypeName(iface.$n)),
        fields: dexFields,
        methods: dexMethods
      };
      const allInterfaces = interfaces.slice();
      interfaces.forEach((iface) => {
        Array.prototype.slice.call(iface.class.getInterfaces()).forEach((baseIface) => {
          const baseIfaceName = this.cast(baseIface, Class).getCanonicalName();
          allInterfaces.push(this.use(baseIfaceName));
        });
      });
      const fields = spec.fields || {};
      Object.getOwnPropertyNames(fields).forEach((name) => {
        const fieldType = this._getType(fields[name]);
        dexFields.push([name, fieldType.name]);
      });
      const baseMethods = {};
      const pendingOverloads = {};
      allInterfaces.forEach((iface) => {
        const h = iface.$borrowClassHandle(env);
        tempHandles.push(h);
        const ifaceHandle = h.value;
        iface.$ownMembers.filter((name) => {
          return iface[name].overloads !== void 0;
        }).forEach((name) => {
          const method = iface[name];
          const overloads = method.overloads;
          const overloadIds = overloads.map((overload) => makeOverloadId(name, overload.returnType, overload.argumentTypes));
          baseMethods[name] = [method, overloadIds, ifaceHandle];
          overloads.forEach((overload, index) => {
            const id = overloadIds[index];
            pendingOverloads[id] = [overload, ifaceHandle];
          });
        });
      });
      const methods = spec.methods || {};
      const methodNames = Object.keys(methods);
      const methodEntries = methodNames.reduce((result, name) => {
        const entry = methods[name];
        const rawName = name === "$init" ? "<init>" : name;
        if (entry instanceof Array) {
          result.push(...entry.map((e) => [rawName, e]));
        } else {
          result.push([rawName, entry]);
        }
        return result;
      }, []);
      const implMethods = [];
      methodEntries.forEach(([name, methodValue]) => {
        let type = INSTANCE_METHOD;
        let returnType;
        let argumentTypes;
        let thrownTypeNames = [];
        let impl;
        if (typeof methodValue === "function") {
          const m = baseMethods[name];
          if (m !== void 0 && Array.isArray(m)) {
            const [baseMethod, overloadIds, parentTypeHandle] = m;
            if (overloadIds.length > 1) {
              throw new Error(`More than one overload matching '${name}': signature must be specified`);
            }
            delete pendingOverloads[overloadIds[0]];
            const overload = baseMethod.overloads[0];
            type = overload.type;
            returnType = overload.returnType;
            argumentTypes = overload.argumentTypes;
            impl = methodValue;
            const reflectedMethod = env.toReflectedMethod(parentTypeHandle, overload.handle, 0);
            const thrownTypes = invokeObjectMethodNoArgs(env.handle, reflectedMethod, Method.getGenericExceptionTypes);
            thrownTypeNames = readTypeNames(env, thrownTypes).map(makeJniObjectTypeName);
            env.deleteLocalRef(thrownTypes);
            env.deleteLocalRef(reflectedMethod);
          } else {
            returnType = this._getType("void");
            argumentTypes = [];
            impl = methodValue;
          }
        } else {
          if (methodValue.isStatic) {
            type = STATIC_METHOD;
          }
          returnType = this._getType(methodValue.returnType || "void");
          argumentTypes = (methodValue.argumentTypes || []).map((name2) => this._getType(name2));
          impl = methodValue.implementation;
          if (typeof impl !== "function") {
            throw new Error("Expected a function implementation for method: " + name);
          }
          const id = makeOverloadId(name, returnType, argumentTypes);
          const pendingOverload = pendingOverloads[id];
          if (pendingOverload !== void 0) {
            const [overload, parentTypeHandle] = pendingOverload;
            delete pendingOverloads[id];
            type = overload.type;
            returnType = overload.returnType;
            argumentTypes = overload.argumentTypes;
            const reflectedMethod = env.toReflectedMethod(parentTypeHandle, overload.handle, 0);
            const thrownTypes = invokeObjectMethodNoArgs(env.handle, reflectedMethod, Method.getGenericExceptionTypes);
            thrownTypeNames = readTypeNames(env, thrownTypes).map(makeJniObjectTypeName);
            env.deleteLocalRef(thrownTypes);
            env.deleteLocalRef(reflectedMethod);
          }
        }
        const returnTypeName = returnType.name;
        const argumentTypeNames = argumentTypes.map((t) => t.name);
        const signature = "(" + argumentTypeNames.join("") + ")" + returnTypeName;
        dexMethods.push([name, returnTypeName, argumentTypeNames, thrownTypeNames, type === STATIC_METHOD ? kAccStatic2 : 0]);
        implMethods.push([name, signature, type, returnType, argumentTypes, impl]);
      });
      const unimplementedMethodIds = Object.keys(pendingOverloads);
      if (unimplementedMethodIds.length > 0) {
        throw new Error("Missing implementation for: " + unimplementedMethodIds.join(", "));
      }
      const dex = DexFile.fromBuffer(mkdex_default(dexSpec), this);
      try {
        dex.load();
      } finally {
        dex.file.delete();
      }
      const classWrapper = this.use(spec.name);
      const numMethods = methodEntries.length;
      if (numMethods > 0) {
        const methodElementSize = 3 * pointerSize7;
        const methodElements = Memory.alloc(numMethods * methodElementSize);
        const nativeMethods = [];
        const temporaryHandles = [];
        implMethods.forEach(([name, signature, type, returnType, argumentTypes, impl], index) => {
          const rawName = Memory.allocUtf8String(name);
          const rawSignature = Memory.allocUtf8String(signature);
          const rawImpl = implement(name, classWrapper, type, returnType, argumentTypes, impl);
          methodElements.add(index * methodElementSize).writePointer(rawName);
          methodElements.add(index * methodElementSize + pointerSize7).writePointer(rawSignature);
          methodElements.add(index * methodElementSize + 2 * pointerSize7).writePointer(rawImpl);
          temporaryHandles.push(rawName, rawSignature);
          nativeMethods.push(rawImpl);
        });
        const h = classWrapper.$borrowClassHandle(env);
        tempHandles.push(h);
        const classHandle = h.value;
        env.registerNatives(classHandle, methodElements, numMethods);
        env.throwIfExceptionPending();
        classWrapper.$nativeMethods = nativeMethods;
      }
      return classWrapper;
    } finally {
      tempHandles.forEach((h) => {
        h.unref(env);
      });
    }
  }
  choose(specifier, callbacks) {
    const env = vm2.getEnv();
    const { flavor } = api;
    if (flavor === "jvm") {
      this._chooseObjectsJvm(specifier, env, callbacks);
    } else if (flavor === "art") {
      const legacyApiMissing = api["art::gc::Heap::VisitObjects"] === void 0;
      if (legacyApiMissing) {
        const preA12ApiMissing = api["art::gc::Heap::GetInstances"] === void 0;
        if (preA12ApiMissing) {
          return this._chooseObjectsJvm(specifier, env, callbacks);
        }
      }
      withRunnableArtThread(vm2, env, (thread) => {
        if (legacyApiMissing) {
          this._chooseObjectsArtPreA12(specifier, env, thread, callbacks);
        } else {
          this._chooseObjectsArtLegacy(specifier, env, thread, callbacks);
        }
      });
    } else {
      this._chooseObjectsDalvik(specifier, env, callbacks);
    }
  }
  _chooseObjectsJvm(className, env, callbacks) {
    const classWrapper = this.use(className);
    const { jvmti } = api;
    const JVMTI_ITERATION_CONTINUE = 1;
    const JVMTI_HEAP_OBJECT_EITHER = 3;
    const h = classWrapper.$borrowClassHandle(env);
    const tag = int64(h.value.toString());
    try {
      const heapObjectCallback = new NativeCallback((classTag, size, tagPtr2, userData) => {
        tagPtr2.writeS64(tag);
        return JVMTI_ITERATION_CONTINUE;
      }, "int", ["int64", "int64", "pointer", "pointer"]);
      jvmti.iterateOverInstancesOfClass(h.value, JVMTI_HEAP_OBJECT_EITHER, heapObjectCallback, h.value);
      const tagPtr = Memory.alloc(8);
      tagPtr.writeS64(tag);
      const countPtr = Memory.alloc(jsizeSize3);
      const objectsPtr = Memory.alloc(pointerSize7);
      jvmti.getObjectsWithTags(1, tagPtr, countPtr, objectsPtr, NULL);
      const count = countPtr.readS32();
      const objects = objectsPtr.readPointer();
      const handles = [];
      for (let i = 0; i !== count; i++) {
        handles.push(objects.add(i * pointerSize7).readPointer());
      }
      jvmti.deallocate(objects);
      try {
        for (const handle of handles) {
          const instance = this.cast(handle, classWrapper);
          const result = callbacks.onMatch(instance);
          if (result === "stop") {
            break;
          }
        }
        callbacks.onComplete();
      } finally {
        handles.forEach((handle) => {
          env.deleteLocalRef(handle);
        });
      }
    } finally {
      h.unref(env);
    }
  }
  _chooseObjectsArtPreA12(className, env, thread, callbacks) {
    const classWrapper = this.use(className);
    const scope = VariableSizedHandleScope.$new(thread, vm2);
    let needle;
    const h = classWrapper.$borrowClassHandle(env);
    try {
      const object = api["art::JavaVMExt::DecodeGlobal"](api.vm, thread, h.value);
      needle = scope.newHandle(object);
    } finally {
      h.unref(env);
    }
    const maxCount = 0;
    const instances = HandleVector.$new();
    api["art::gc::Heap::GetInstances"](api.artHeap, scope, needle, maxCount, instances);
    const instanceHandles = instances.handles.map((handle) => env.newGlobalRef(handle));
    instances.$delete();
    scope.$delete();
    try {
      for (const handle of instanceHandles) {
        const instance = this.cast(handle, classWrapper);
        const result = callbacks.onMatch(instance);
        if (result === "stop") {
          break;
        }
      }
      callbacks.onComplete();
    } finally {
      instanceHandles.forEach((handle) => {
        env.deleteGlobalRef(handle);
      });
    }
  }
  _chooseObjectsArtLegacy(className, env, thread, callbacks) {
    const classWrapper = this.use(className);
    const instanceHandles = [];
    const addGlobalReference = api["art::JavaVMExt::AddGlobalRef"];
    const vmHandle = api.vm;
    let needle;
    const h = classWrapper.$borrowClassHandle(env);
    try {
      needle = api["art::JavaVMExt::DecodeGlobal"](vmHandle, thread, h.value).toInt32();
    } finally {
      h.unref(env);
    }
    const collectMatchingInstanceHandles = makeObjectVisitorPredicate(needle, (object) => {
      instanceHandles.push(addGlobalReference(vmHandle, thread, object));
    });
    api["art::gc::Heap::VisitObjects"](api.artHeap, collectMatchingInstanceHandles, NULL);
    try {
      for (const handle of instanceHandles) {
        const instance = this.cast(handle, classWrapper);
        const result = callbacks.onMatch(instance);
        if (result === "stop") {
          break;
        }
      }
    } finally {
      instanceHandles.forEach((handle) => {
        env.deleteGlobalRef(handle);
      });
    }
    callbacks.onComplete();
  }
  _chooseObjectsDalvik(className, callerEnv, callbacks) {
    const classWrapper = this.use(className);
    if (api.addLocalReference === null) {
      const libdvm = Process.getModuleByName("libdvm.so");
      let pattern;
      switch (Process.arch) {
        case "arm":
          pattern = "2d e9 f0 41 05 46 15 4e 0c 46 7e 44 11 b3 43 68";
          break;
        case "ia32":
          pattern = "8d 64 24 d4 89 5c 24 1c 89 74 24 20 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 85 d2";
          break;
      }
      Memory.scan(libdvm.base, libdvm.size, pattern, {
        onMatch: (address, size) => {
          let wrapper;
          if (Process.arch === "arm") {
            address = address.or(1);
            wrapper = new NativeFunction(address, "pointer", ["pointer", "pointer"]);
          } else {
            const thunk = Memory.alloc(Process.pageSize);
            Memory.patchCode(thunk, 16, (code3) => {
              const cw = new X86Writer(code3, { pc: thunk });
              cw.putMovRegRegOffsetPtr("eax", "esp", 4);
              cw.putMovRegRegOffsetPtr("edx", "esp", 8);
              cw.putJmpAddress(address);
              cw.flush();
            });
            wrapper = new NativeFunction(thunk, "pointer", ["pointer", "pointer"]);
            wrapper._thunk = thunk;
          }
          api.addLocalReference = wrapper;
          vm2.perform((env) => {
            enumerateInstances(this, env);
          });
          return "stop";
        },
        onError(reason) {
        },
        onComplete() {
          if (api.addLocalReference === null) {
            callbacks.onComplete();
          }
        }
      });
    } else {
      enumerateInstances(this, callerEnv);
    }
    function enumerateInstances(factory, env) {
      const { DVM_JNI_ENV_OFFSET_SELF: DVM_JNI_ENV_OFFSET_SELF2 } = android_exports;
      const thread = env.handle.add(DVM_JNI_ENV_OFFSET_SELF2).readPointer();
      let ptrClassObject;
      const h = classWrapper.$borrowClassHandle(env);
      try {
        ptrClassObject = api.dvmDecodeIndirectRef(thread, h.value);
      } finally {
        h.unref(env);
      }
      const pattern = ptrClassObject.toMatchPattern();
      const heapSourceBase = api.dvmHeapSourceGetBase();
      const heapSourceLimit = api.dvmHeapSourceGetLimit();
      const size = heapSourceLimit.sub(heapSourceBase).toInt32();
      Memory.scan(heapSourceBase, size, pattern, {
        onMatch: (address, size2) => {
          if (api.dvmIsValidObject(address)) {
            vm2.perform((env2) => {
              const thread2 = env2.handle.add(DVM_JNI_ENV_OFFSET_SELF2).readPointer();
              let instance;
              const localReference = api.addLocalReference(thread2, address);
              try {
                instance = factory.cast(localReference, classWrapper);
              } finally {
                env2.deleteLocalRef(localReference);
              }
              const result = callbacks.onMatch(instance);
              if (result === "stop") {
                return "stop";
              }
            });
          }
        },
        onError(reason) {
        },
        onComplete() {
          callbacks.onComplete();
        }
      });
    }
  }
  openClassFile(filePath) {
    return new DexFile(filePath, null, this);
  }
  _getType(typeName, unbox = true) {
    return getType(typeName, unbox, this);
  }
};
function makeClassWrapperConstructor() {
  return function(handle, strategy, env, owned) {
    return Wrapper.call(this, handle, strategy, env, owned);
  };
}
function Wrapper(handle, strategy, env, owned = true) {
  if (handle !== null) {
    if (owned) {
      const h = env.newGlobalRef(handle);
      this.$h = h;
      this.$r = Script.bindWeak(this, vm2.makeHandleDestructor(h));
    } else {
      this.$h = handle;
      this.$r = null;
    }
  } else {
    this.$h = null;
    this.$r = null;
  }
  this.$t = strategy;
  return new Proxy(this, wrapperHandler);
}
wrapperHandler = {
  has(target, property) {
    if (property in target) {
      return true;
    }
    return target.$has(property);
  },
  get(target, property, receiver) {
    if (typeof property !== "string" || property.startsWith("$") || property === "class") {
      return target[property];
    }
    const unwrap2 = target.$find(property);
    if (unwrap2 !== null) {
      return unwrap2(receiver);
    }
    return target[property];
  },
  set(target, property, value, receiver) {
    target[property] = value;
    return true;
  },
  ownKeys(target) {
    return target.$list();
  },
  getOwnPropertyDescriptor(target, property) {
    if (Object.prototype.hasOwnProperty.call(target, property)) {
      return Object.getOwnPropertyDescriptor(target, property);
    }
    return {
      writable: false,
      configurable: true,
      enumerable: true
    };
  }
};
Object.defineProperties(Wrapper.prototype, {
  [Symbol.for("new")]: {
    enumerable: false,
    get() {
      return this.$getCtor("allocAndInit");
    }
  },
  $new: {
    enumerable: true,
    get() {
      return this[Symbol.for("new")];
    }
  },
  [Symbol.for("alloc")]: {
    enumerable: false,
    value() {
      const env = vm2.getEnv();
      const h = this.$borrowClassHandle(env);
      try {
        const obj = env.allocObject(h.value);
        const factory = this.$f;
        return factory.cast(obj, this);
      } finally {
        h.unref(env);
      }
    }
  },
  $alloc: {
    enumerable: true,
    get() {
      return this[Symbol.for("alloc")];
    }
  },
  [Symbol.for("init")]: {
    enumerable: false,
    get() {
      return this.$getCtor("initOnly");
    }
  },
  $init: {
    enumerable: true,
    get() {
      return this[Symbol.for("init")];
    }
  },
  [Symbol.for("dispose")]: {
    enumerable: false,
    value() {
      const ref = this.$r;
      if (ref !== null) {
        this.$r = null;
        Script.unbindWeak(ref);
      }
      if (this.$h !== null) {
        this.$h = void 0;
      }
    }
  },
  $dispose: {
    enumerable: true,
    get() {
      return this[Symbol.for("dispose")];
    }
  },
  [Symbol.for("clone")]: {
    enumerable: false,
    value(env) {
      const C = this.$C;
      return new C(this.$h, this.$t, env);
    }
  },
  $clone: {
    value(env) {
      return this[Symbol.for("clone")](env);
    }
  },
  [Symbol.for("class")]: {
    enumerable: false,
    get() {
      const env = vm2.getEnv();
      const h = this.$borrowClassHandle(env);
      try {
        const factory = this.$f;
        return factory.cast(h.value, factory.use("java.lang.Class"));
      } finally {
        h.unref(env);
      }
    }
  },
  class: {
    enumerable: true,
    get() {
      return this[Symbol.for("class")];
    }
  },
  [Symbol.for("className")]: {
    enumerable: false,
    get() {
      const handle = this.$h;
      if (handle === null) {
        return this.$n;
      }
      return vm2.getEnv().getObjectClassName(handle);
    }
  },
  $className: {
    enumerable: true,
    get() {
      return this[Symbol.for("className")];
    }
  },
  [Symbol.for("ownMembers")]: {
    enumerable: false,
    get() {
      const model = this.$l;
      return model.list();
    }
  },
  $ownMembers: {
    enumerable: true,
    get() {
      return this[Symbol.for("ownMembers")];
    }
  },
  [Symbol.for("super")]: {
    enumerable: false,
    get() {
      const env = vm2.getEnv();
      const C = this.$s.$C;
      return new C(this.$h, STRATEGY_DIRECT, env);
    }
  },
  $super: {
    enumerable: true,
    get() {
      return this[Symbol.for("super")];
    }
  },
  [Symbol.for("s")]: {
    enumerable: false,
    get() {
      const proto = Object.getPrototypeOf(this);
      let superWrapper = proto.$_s;
      if (superWrapper === void 0) {
        const env = vm2.getEnv();
        const h = this.$borrowClassHandle(env);
        try {
          const superHandle = env.getSuperclass(h.value);
          if (!superHandle.isNull()) {
            try {
              const superClassName = env.getClassName(superHandle);
              const factory = proto.$f;
              superWrapper = factory._getUsedClass(superClassName);
              if (superWrapper === void 0) {
                try {
                  const getSuperClassHandle = makeSuperHandleGetter(this);
                  superWrapper = factory._make(superClassName, getSuperClassHandle, env);
                } finally {
                  factory._setUsedClass(superClassName, superWrapper);
                }
              }
            } finally {
              env.deleteLocalRef(superHandle);
            }
          } else {
            superWrapper = null;
          }
        } finally {
          h.unref(env);
        }
        proto.$_s = superWrapper;
      }
      return superWrapper;
    }
  },
  $s: {
    get() {
      return this[Symbol.for("s")];
    }
  },
  [Symbol.for("isSameObject")]: {
    enumerable: false,
    value(obj) {
      const env = vm2.getEnv();
      return env.isSameObject(obj.$h, this.$h);
    }
  },
  $isSameObject: {
    value(obj) {
      return this[Symbol.for("isSameObject")](obj);
    }
  },
  [Symbol.for("getCtor")]: {
    enumerable: false,
    value(type) {
      const slot = this.$c;
      let ctor = slot[0];
      if (ctor === null) {
        const env = vm2.getEnv();
        const h = this.$borrowClassHandle(env);
        try {
          ctor = makeConstructor(h.value, this.$w, env);
          slot[0] = ctor;
        } finally {
          h.unref(env);
        }
      }
      return ctor[type];
    }
  },
  $getCtor: {
    value(type) {
      return this[Symbol.for("getCtor")](type);
    }
  },
  [Symbol.for("borrowClassHandle")]: {
    enumerable: false,
    value(env) {
      const className = this.$n;
      const classHandles = this.$f._classHandles;
      let handle = classHandles.get(className);
      if (handle === void 0) {
        handle = new ClassHandle(this.$gch(env), env);
        classHandles.set(className, handle, env);
      }
      return handle.ref();
    }
  },
  $borrowClassHandle: {
    value(env) {
      return this[Symbol.for("borrowClassHandle")](env);
    }
  },
  [Symbol.for("copyClassHandle")]: {
    enumerable: false,
    value(env) {
      const h = this.$borrowClassHandle(env);
      try {
        return env.newLocalRef(h.value);
      } finally {
        h.unref(env);
      }
    }
  },
  $copyClassHandle: {
    value(env) {
      return this[Symbol.for("copyClassHandle")](env);
    }
  },
  [Symbol.for("getHandle")]: {
    enumerable: false,
    value(env) {
      const handle = this.$h;
      const isDisposed = handle === void 0;
      if (isDisposed) {
        throw new Error("Wrapper is disposed; perhaps it was borrowed from a hook instead of calling Java.retain() to make a long-lived wrapper?");
      }
      return handle;
    }
  },
  $getHandle: {
    value(env) {
      return this[Symbol.for("getHandle")](env);
    }
  },
  [Symbol.for("list")]: {
    enumerable: false,
    value() {
      const superWrapper = this.$s;
      const superMembers = superWrapper !== null ? superWrapper.$list() : [];
      const model = this.$l;
      return Array.from(new Set(superMembers.concat(model.list())));
    }
  },
  $list: {
    get() {
      return this[Symbol.for("list")];
    }
  },
  [Symbol.for("has")]: {
    enumerable: false,
    value(member) {
      const members = this.$m;
      if (members.has(member)) {
        return true;
      }
      const model = this.$l;
      if (model.has(member)) {
        return true;
      }
      const superWrapper = this.$s;
      if (superWrapper !== null && superWrapper.$has(member)) {
        return true;
      }
      return false;
    }
  },
  $has: {
    value(member) {
      return this[Symbol.for("has")](member);
    }
  },
  [Symbol.for("find")]: {
    enumerable: false,
    value(member) {
      const members = this.$m;
      let value = members.get(member);
      if (value !== void 0) {
        return value;
      }
      const model = this.$l;
      const spec = model.find(member);
      if (spec !== null) {
        const env = vm2.getEnv();
        const h = this.$borrowClassHandle(env);
        try {
          value = makeMember(member, spec, h.value, this.$w, env);
        } finally {
          h.unref(env);
        }
        members.set(member, value);
        return value;
      }
      const superWrapper = this.$s;
      if (superWrapper !== null) {
        return superWrapper.$find(member);
      }
      return null;
    }
  },
  $find: {
    value(member) {
      return this[Symbol.for("find")](member);
    }
  },
  [Symbol.for("toJSON")]: {
    enumerable: false,
    value() {
      const wrapperName = this.$n;
      const handle = this.$h;
      if (handle === null) {
        return `<class: ${wrapperName}>`;
      }
      const actualName = this.$className;
      if (wrapperName === actualName) {
        return `<instance: ${wrapperName}>`;
      }
      return `<instance: ${wrapperName}, $className: ${actualName}>`;
    }
  },
  toJSON: {
    get() {
      return this[Symbol.for("toJSON")];
    }
  }
});
function ClassHandle(value, env) {
  this.value = env.newGlobalRef(value);
  env.deleteLocalRef(value);
  this.refs = 1;
}
ClassHandle.prototype.ref = function() {
  this.refs++;
  return this;
};
ClassHandle.prototype.unref = function(env) {
  if (--this.refs === 0) {
    env.deleteGlobalRef(this.value);
  }
};
function releaseClassHandle(handle, env) {
  handle.unref(env);
}
function makeBasicClassHandleGetter(className) {
  const canonicalClassName = className.replace(/\./g, "/");
  return function(env) {
    const tid = getCurrentThreadId();
    ignore(tid);
    try {
      return env.findClass(canonicalClassName);
    } finally {
      unignore(tid);
    }
  };
}
function makeLoaderClassHandleGetter(className, usedLoader, callerEnv) {
  if (cachedLoaderMethod === null) {
    cachedLoaderInvoke = callerEnv.vaMethod("pointer", ["pointer"]);
    cachedLoaderMethod = usedLoader.loadClass.overload("java.lang.String").handle;
  }
  callerEnv = null;
  return function(env) {
    const classNameValue = env.newStringUtf(className);
    const tid = getCurrentThreadId();
    ignore(tid);
    try {
      const result = cachedLoaderInvoke(env.handle, usedLoader.$h, cachedLoaderMethod, classNameValue);
      env.throwIfExceptionPending();
      return result;
    } finally {
      unignore(tid);
      env.deleteLocalRef(classNameValue);
    }
  };
}
function makeSuperHandleGetter(classWrapper) {
  return function(env) {
    const h = classWrapper.$borrowClassHandle(env);
    try {
      return env.getSuperclass(h.value);
    } finally {
      h.unref(env);
    }
  };
}
function makeConstructor(classHandle, classWrapper, env) {
  const { $n: className, $f: factory } = classWrapper;
  const methodName = basename(className);
  const Class = env.javaLangClass();
  const Constructor = env.javaLangReflectConstructor();
  const invokeObjectMethodNoArgs = env.vaMethod("pointer", []);
  const invokeUInt8MethodNoArgs = env.vaMethod("uint8", []);
  const jsCtorMethods = [];
  const jsInitMethods = [];
  const jsRetType = factory._getType(className, false);
  const jsVoidType = factory._getType("void", false);
  const constructors = invokeObjectMethodNoArgs(env.handle, classHandle, Class.getDeclaredConstructors);
  try {
    const n = env.getArrayLength(constructors);
    if (n !== 0) {
      for (let i = 0; i !== n; i++) {
        let methodId, types;
        const constructor = env.getObjectArrayElement(constructors, i);
        try {
          methodId = env.fromReflectedMethod(constructor);
          types = invokeObjectMethodNoArgs(env.handle, constructor, Constructor.getGenericParameterTypes);
        } finally {
          env.deleteLocalRef(constructor);
        }
        let jsArgTypes;
        try {
          jsArgTypes = readTypeNames(env, types).map((name) => factory._getType(name));
        } finally {
          env.deleteLocalRef(types);
        }
        jsCtorMethods.push(makeMethod(methodName, classWrapper, CONSTRUCTOR_METHOD, methodId, jsRetType, jsArgTypes, env));
        jsInitMethods.push(makeMethod(methodName, classWrapper, INSTANCE_METHOD, methodId, jsVoidType, jsArgTypes, env));
      }
    } else {
      const isInterface = invokeUInt8MethodNoArgs(env.handle, classHandle, Class.isInterface);
      if (isInterface) {
        throw new Error("cannot instantiate an interface");
      }
      const defaultClass = env.javaLangObject();
      const defaultConstructor = env.getMethodId(defaultClass, "<init>", "()V");
      jsCtorMethods.push(makeMethod(methodName, classWrapper, CONSTRUCTOR_METHOD, defaultConstructor, jsRetType, [], env));
      jsInitMethods.push(makeMethod(methodName, classWrapper, INSTANCE_METHOD, defaultConstructor, jsVoidType, [], env));
    }
  } finally {
    env.deleteLocalRef(constructors);
  }
  if (jsInitMethods.length === 0) {
    throw new Error("no supported overloads");
  }
  return {
    allocAndInit: makeMethodDispatcher(jsCtorMethods),
    initOnly: makeMethodDispatcher(jsInitMethods)
  };
}
function makeMember(name, spec, classHandle, classWrapper, env) {
  if (spec.startsWith("m")) {
    return makeMethodFromSpec(name, spec, classHandle, classWrapper, env);
  }
  return makeFieldFromSpec(name, spec, classHandle, classWrapper, env);
}
function makeMethodFromSpec(name, spec, classHandle, classWrapper, env) {
  const { $f: factory } = classWrapper;
  const overloads = spec.split(":").slice(1);
  const Method = env.javaLangReflectMethod();
  const invokeObjectMethodNoArgs = env.vaMethod("pointer", []);
  const invokeUInt8MethodNoArgs = env.vaMethod("uint8", []);
  const methods = overloads.map((params) => {
    const type = params[0] === "s" ? STATIC_METHOD : INSTANCE_METHOD;
    const methodId = ptr(params.substr(1));
    let jsRetType;
    const jsArgTypes = [];
    const handle = env.toReflectedMethod(classHandle, methodId, type === STATIC_METHOD ? 1 : 0);
    try {
      const isVarArgs = !!invokeUInt8MethodNoArgs(env.handle, handle, Method.isVarArgs);
      const retType = invokeObjectMethodNoArgs(env.handle, handle, Method.getGenericReturnType);
      env.throwIfExceptionPending();
      try {
        jsRetType = factory._getType(env.getTypeName(retType));
      } finally {
        env.deleteLocalRef(retType);
      }
      const argTypes = invokeObjectMethodNoArgs(env.handle, handle, Method.getParameterTypes);
      try {
        const n = env.getArrayLength(argTypes);
        for (let i = 0; i !== n; i++) {
          const t = env.getObjectArrayElement(argTypes, i);
          let argClassName;
          try {
            argClassName = isVarArgs && i === n - 1 ? env.getArrayTypeName(t) : env.getTypeName(t);
          } finally {
            env.deleteLocalRef(t);
          }
          const argType = factory._getType(argClassName);
          jsArgTypes.push(argType);
        }
      } finally {
        env.deleteLocalRef(argTypes);
      }
    } catch (e) {
      return null;
    } finally {
      env.deleteLocalRef(handle);
    }
    return makeMethod(name, classWrapper, type, methodId, jsRetType, jsArgTypes, env);
  }).filter((m) => m !== null);
  if (methods.length === 0) {
    throw new Error("No supported overloads");
  }
  if (name === "valueOf") {
    ensureDefaultValueOfImplemented(methods);
  }
  const result = makeMethodDispatcher(methods);
  return function(receiver) {
    return result;
  };
}
function makeMethodDispatcher(overloads) {
  const m = makeMethodDispatcherCallable();
  Object.setPrototypeOf(m, dispatcherPrototype);
  m._o = overloads;
  return m;
}
function makeMethodDispatcherCallable() {
  const m = function() {
    return m.invoke(this, arguments);
  };
  return m;
}
dispatcherPrototype = Object.create(Function.prototype, {
  overloads: {
    enumerable: true,
    get() {
      return this._o;
    }
  },
  overload: {
    value(...args) {
      const overloads = this._o;
      const numArgs = args.length;
      const signature = args.join(":");
      for (let i = 0; i !== overloads.length; i++) {
        const method = overloads[i];
        const { argumentTypes } = method;
        if (argumentTypes.length !== numArgs) {
          continue;
        }
        const s = argumentTypes.map((t) => t.className).join(":");
        if (s === signature) {
          return method;
        }
      }
      throwOverloadError(this.methodName, this.overloads, "specified argument types do not match any of:");
    }
  },
  methodName: {
    enumerable: true,
    get() {
      return this._o[0].methodName;
    }
  },
  holder: {
    enumerable: true,
    get() {
      return this._o[0].holder;
    }
  },
  type: {
    enumerable: true,
    get() {
      return this._o[0].type;
    }
  },
  handle: {
    enumerable: true,
    get() {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].handle;
    }
  },
  implementation: {
    enumerable: true,
    get() {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].implementation;
    },
    set(fn) {
      throwIfDispatcherAmbiguous(this);
      this._o[0].implementation = fn;
    }
  },
  returnType: {
    enumerable: true,
    get() {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].returnType;
    }
  },
  argumentTypes: {
    enumerable: true,
    get() {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].argumentTypes;
    }
  },
  canInvokeWith: {
    enumerable: true,
    get(args) {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].canInvokeWith;
    }
  },
  clone: {
    enumerable: true,
    value(options) {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].clone(options);
    }
  },
  invoke: {
    value(receiver, args) {
      const overloads = this._o;
      const isInstance = receiver.$h !== null;
      for (let i = 0; i !== overloads.length; i++) {
        const method = overloads[i];
        if (!method.canInvokeWith(args)) {
          continue;
        }
        if (method.type === INSTANCE_METHOD && !isInstance) {
          const name = this.methodName;
          if (name === "toString") {
            return `<class: ${receiver.$n}>`;
          }
          throw new Error(name + ": cannot call instance method without an instance");
        }
        return method.apply(receiver, args);
      }
      if (this.methodName === "toString") {
        return `<class: ${receiver.$n}>`;
      }
      throwOverloadError(this.methodName, this.overloads, "argument types do not match any of:");
    }
  }
});
function makeOverloadId(name, returnType, argumentTypes) {
  return `${returnType.className} ${name}(${argumentTypes.map((t) => t.className).join(", ")})`;
}
function throwIfDispatcherAmbiguous(dispatcher) {
  const methods = dispatcher._o;
  if (methods.length > 1) {
    throwOverloadError(methods[0].methodName, methods, "has more than one overload, use .overload(<signature>) to choose from:");
  }
}
function throwOverloadError(name, methods, message) {
  const methodsSortedByArity = methods.slice().sort((a, b) => a.argumentTypes.length - b.argumentTypes.length);
  const overloads = methodsSortedByArity.map((m) => {
    const argTypes = m.argumentTypes;
    if (argTypes.length > 0) {
      return ".overload('" + m.argumentTypes.map((t) => t.className).join("', '") + "')";
    } else {
      return ".overload()";
    }
  });
  throw new Error(`${name}(): ${message}
	${overloads.join("\n	")}`);
}
function makeMethod(methodName, classWrapper, type, methodId, retType, argTypes, env, invocationOptions) {
  const rawRetType = retType.type;
  const rawArgTypes = argTypes.map((t) => t.type);
  if (env === null) {
    env = vm2.getEnv();
  }
  let callVirtually, callDirectly;
  if (type === INSTANCE_METHOD) {
    callVirtually = env.vaMethod(rawRetType, rawArgTypes, invocationOptions);
    callDirectly = env.nonvirtualVaMethod(rawRetType, rawArgTypes, invocationOptions);
  } else if (type === STATIC_METHOD) {
    callVirtually = env.staticVaMethod(rawRetType, rawArgTypes, invocationOptions);
    callDirectly = callVirtually;
  } else {
    callVirtually = env.constructor(rawArgTypes, invocationOptions);
    callDirectly = callVirtually;
  }
  return makeMethodInstance([methodName, classWrapper, type, methodId, retType, argTypes, callVirtually, callDirectly]);
}
function makeMethodInstance(params) {
  const m = makeMethodCallable();
  Object.setPrototypeOf(m, methodPrototype);
  m._p = params;
  return m;
}
function makeMethodCallable() {
  const m = function() {
    return m.invoke(this, arguments);
  };
  return m;
}
methodPrototype = Object.create(Function.prototype, {
  methodName: {
    enumerable: true,
    get() {
      return this._p[0];
    }
  },
  holder: {
    enumerable: true,
    get() {
      return this._p[1];
    }
  },
  type: {
    enumerable: true,
    get() {
      return this._p[2];
    }
  },
  handle: {
    enumerable: true,
    get() {
      return this._p[3];
    }
  },
  implementation: {
    enumerable: true,
    get() {
      const replacement = this._r;
      return replacement !== void 0 ? replacement : null;
    },
    set(fn) {
      const params = this._p;
      const holder = params[1];
      const type = params[2];
      if (type === CONSTRUCTOR_METHOD) {
        throw new Error("Reimplementing $new is not possible; replace implementation of $init instead");
      }
      const existingReplacement = this._r;
      if (existingReplacement !== void 0) {
        holder.$f._patchedMethods.delete(this);
        const mangler = existingReplacement._m;
        mangler.revert(vm2);
        this._r = void 0;
      }
      if (fn !== null) {
        const [methodName, classWrapper, type2, methodId, retType, argTypes] = params;
        const replacement = implement(methodName, classWrapper, type2, retType, argTypes, fn, this);
        const mangler = makeMethodMangler3(methodId);
        replacement._m = mangler;
        this._r = replacement;
        mangler.replace(replacement, type2 === INSTANCE_METHOD, argTypes, vm2, api);
        holder.$f._patchedMethods.add(this);
      }
    }
  },
  returnType: {
    enumerable: true,
    get() {
      return this._p[4];
    }
  },
  argumentTypes: {
    enumerable: true,
    get() {
      return this._p[5];
    }
  },
  canInvokeWith: {
    enumerable: true,
    value(args) {
      const argTypes = this._p[5];
      if (args.length !== argTypes.length) {
        return false;
      }
      return argTypes.every((t, i) => {
        return t.isCompatible(args[i]);
      });
    }
  },
  clone: {
    enumerable: true,
    value(options) {
      const params = this._p.slice(0, 6);
      return makeMethod(...params, null, options);
    }
  },
  invoke: {
    value(receiver, args) {
      const env = vm2.getEnv();
      const params = this._p;
      const type = params[2];
      const retType = params[4];
      const argTypes = params[5];
      const replacement = this._r;
      const isInstanceMethod = type === INSTANCE_METHOD;
      const numArgs = args.length;
      const frameCapacity = 2 + numArgs;
      env.pushLocalFrame(frameCapacity);
      let borrowedHandle = null;
      try {
        let jniThis;
        if (isInstanceMethod) {
          jniThis = receiver.$getHandle();
        } else {
          borrowedHandle = receiver.$borrowClassHandle(env);
          jniThis = borrowedHandle.value;
        }
        let methodId;
        let strategy = receiver.$t;
        if (replacement === void 0) {
          methodId = params[3];
        } else {
          const mangler = replacement._m;
          methodId = mangler.resolveTarget(receiver, isInstanceMethod, env, api);
          if (isArtVm) {
            const pendingCalls = replacement._c;
            if (pendingCalls.has(getCurrentThreadId())) {
              strategy = STRATEGY_DIRECT;
            }
          }
        }
        const jniArgs = [
          env.handle,
          jniThis,
          methodId
        ];
        for (let i = 0; i !== numArgs; i++) {
          jniArgs.push(argTypes[i].toJni(args[i], env));
        }
        let jniCall;
        if (strategy === STRATEGY_VIRTUAL) {
          jniCall = params[6];
        } else {
          jniCall = params[7];
          if (isInstanceMethod) {
            jniArgs.splice(2, 0, receiver.$copyClassHandle(env));
          }
        }
        const jniRetval = jniCall.apply(null, jniArgs);
        env.throwIfExceptionPending();
        return retType.fromJni(jniRetval, env, true);
      } finally {
        if (borrowedHandle !== null) {
          borrowedHandle.unref(env);
        }
        env.popLocalFrame(NULL);
      }
    }
  },
  toString: {
    enumerable: true,
    value() {
      return `function ${this.methodName}(${this.argumentTypes.map((t) => t.className).join(", ")}): ${this.returnType.className}`;
    }
  }
});
function implement(methodName, classWrapper, type, retType, argTypes, handler, fallback = null) {
  const pendingCalls = /* @__PURE__ */ new Set();
  const f = makeMethodImplementation([methodName, classWrapper, type, retType, argTypes, handler, fallback, pendingCalls]);
  const impl = new NativeCallback(f, retType.type, ["pointer", "pointer"].concat(argTypes.map((t) => t.type)));
  impl._c = pendingCalls;
  return impl;
}
function makeMethodImplementation(params) {
  return function() {
    return handleMethodInvocation(arguments, params);
  };
}
function handleMethodInvocation(jniArgs, params) {
  const env = new Env(jniArgs[0], vm2);
  const [methodName, classWrapper, type, retType, argTypes, handler, fallback, pendingCalls] = params;
  const ownedObjects = [];
  let self;
  if (type === INSTANCE_METHOD) {
    const C = classWrapper.$C;
    self = new C(jniArgs[1], STRATEGY_VIRTUAL, env, false);
  } else {
    self = classWrapper;
  }
  const tid = getCurrentThreadId();
  env.pushLocalFrame(3);
  let haveFrame = true;
  vm2.link(tid, env);
  try {
    pendingCalls.add(tid);
    let fn;
    if (fallback === null || !ignoredThreads.has(tid)) {
      fn = handler;
    } else {
      fn = fallback;
    }
    const args = [];
    const numArgs = jniArgs.length - 2;
    for (let i = 0; i !== numArgs; i++) {
      const t = argTypes[i];
      const value = t.fromJni(jniArgs[2 + i], env, false);
      args.push(value);
      ownedObjects.push(value);
    }
    const retval = fn.apply(self, args);
    if (!retType.isCompatible(retval)) {
      throw new Error(`Implementation for ${methodName} expected return value compatible with ${retType.className}`);
    }
    let jniRetval = retType.toJni(retval, env);
    if (retType.type === "pointer") {
      jniRetval = env.popLocalFrame(jniRetval);
      haveFrame = false;
      ownedObjects.push(retval);
    }
    return jniRetval;
  } catch (e) {
    const jniException = e.$h;
    if (jniException !== void 0) {
      env.throw(jniException);
    } else {
      Script.nextTick(() => {
        throw e;
      });
    }
    return retType.defaultValue;
  } finally {
    vm2.unlink(tid);
    if (haveFrame) {
      env.popLocalFrame(NULL);
    }
    pendingCalls.delete(tid);
    ownedObjects.forEach((obj) => {
      if (obj === null) {
        return;
      }
      const dispose = obj.$dispose;
      if (dispose !== void 0) {
        dispose.call(obj);
      }
    });
  }
}
function ensureDefaultValueOfImplemented(methods) {
  const { holder, type } = methods[0];
  const hasDefaultValueOf = methods.some((m) => m.type === type && m.argumentTypes.length === 0);
  if (hasDefaultValueOf) {
    return;
  }
  methods.push(makeValueOfMethod([holder, type]));
}
function makeValueOfMethod(params) {
  const m = makeValueOfCallable();
  Object.setPrototypeOf(m, valueOfPrototype);
  m._p = params;
  return m;
}
function makeValueOfCallable() {
  const m = function() {
    return this;
  };
  return m;
}
valueOfPrototype = Object.create(Function.prototype, {
  methodName: {
    enumerable: true,
    get() {
      return "valueOf";
    }
  },
  holder: {
    enumerable: true,
    get() {
      return this._p[0];
    }
  },
  type: {
    enumerable: true,
    get() {
      return this._p[1];
    }
  },
  handle: {
    enumerable: true,
    get() {
      return NULL;
    }
  },
  implementation: {
    enumerable: true,
    get() {
      return null;
    },
    set(fn) {
    }
  },
  returnType: {
    enumerable: true,
    get() {
      const classWrapper = this.holder;
      return classWrapper.$f.use(classWrapper.$n);
    }
  },
  argumentTypes: {
    enumerable: true,
    get() {
      return [];
    }
  },
  canInvokeWith: {
    enumerable: true,
    value(args) {
      return args.length === 0;
    }
  },
  clone: {
    enumerable: true,
    value(options) {
      throw new Error("Invalid operation");
    }
  }
});
function makeFieldFromSpec(name, spec, classHandle, classWrapper, env) {
  const type = spec[2] === "s" ? STATIC_FIELD : INSTANCE_FIELD;
  const id = ptr(spec.substr(3));
  const { $f: factory } = classWrapper;
  let fieldType;
  const field = env.toReflectedField(classHandle, id, type === STATIC_FIELD ? 1 : 0);
  try {
    fieldType = env.vaMethod("pointer", [])(env.handle, field, env.javaLangReflectField().getGenericType);
    env.throwIfExceptionPending();
  } finally {
    env.deleteLocalRef(field);
  }
  let rtype;
  try {
    rtype = factory._getType(env.getTypeName(fieldType));
  } finally {
    env.deleteLocalRef(fieldType);
  }
  let getValue, setValue;
  const rtypeJni = rtype.type;
  if (type === STATIC_FIELD) {
    getValue = env.getStaticField(rtypeJni);
    setValue = env.setStaticField(rtypeJni);
  } else {
    getValue = env.getField(rtypeJni);
    setValue = env.setField(rtypeJni);
  }
  return makeFieldFromParams([type, rtype, id, getValue, setValue]);
}
function makeFieldFromParams(params) {
  return function(receiver) {
    return new Field([receiver].concat(params));
  };
}
function Field(params) {
  this._p = params;
}
Object.defineProperties(Field.prototype, {
  value: {
    enumerable: true,
    get() {
      const [holder, type, rtype, id, getValue] = this._p;
      const env = vm2.getEnv();
      env.pushLocalFrame(4);
      let borrowedHandle = null;
      try {
        let jniThis;
        if (type === INSTANCE_FIELD) {
          jniThis = holder.$getHandle();
          if (jniThis === null) {
            throw new Error("Cannot access an instance field without an instance");
          }
        } else {
          borrowedHandle = holder.$borrowClassHandle(env);
          jniThis = borrowedHandle.value;
        }
        const jniRetval = getValue(env.handle, jniThis, id);
        env.throwIfExceptionPending();
        return rtype.fromJni(jniRetval, env, true);
      } finally {
        if (borrowedHandle !== null) {
          borrowedHandle.unref(env);
        }
        env.popLocalFrame(NULL);
      }
    },
    set(value) {
      const [holder, type, rtype, id, , setValue] = this._p;
      const env = vm2.getEnv();
      env.pushLocalFrame(4);
      let borrowedHandle = null;
      try {
        let jniThis;
        if (type === INSTANCE_FIELD) {
          jniThis = holder.$getHandle();
          if (jniThis === null) {
            throw new Error("Cannot access an instance field without an instance");
          }
        } else {
          borrowedHandle = holder.$borrowClassHandle(env);
          jniThis = borrowedHandle.value;
        }
        if (!rtype.isCompatible(value)) {
          throw new Error(`Expected value compatible with ${rtype.className}`);
        }
        const jniValue = rtype.toJni(value, env);
        setValue(env.handle, jniThis, id, jniValue);
        env.throwIfExceptionPending();
      } finally {
        if (borrowedHandle !== null) {
          borrowedHandle.unref(env);
        }
        env.popLocalFrame(NULL);
      }
    }
  },
  holder: {
    enumerable: true,
    get() {
      return this._p[0];
    }
  },
  fieldType: {
    enumerable: true,
    get() {
      return this._p[1];
    }
  },
  fieldReturnType: {
    enumerable: true,
    get() {
      return this._p[2];
    }
  },
  toString: {
    enumerable: true,
    value() {
      const inlineString = `Java.Field{holder: ${this.holder}, fieldType: ${this.fieldType}, fieldReturnType: ${this.fieldReturnType}, value: ${this.value}}`;
      if (inlineString.length < 200) {
        return inlineString;
      }
      const multilineString = `Java.Field{
	holder: ${this.holder},
	fieldType: ${this.fieldType},
	fieldReturnType: ${this.fieldReturnType},
	value: ${this.value},
}`;
      return multilineString.split("\n").map((l) => l.length > 200 ? l.slice(0, l.indexOf(" ") + 1) + "...," : l).join("\n");
    }
  }
});
var DexFile = class _DexFile {
  static fromBuffer(buffer, factory) {
    const fileValue = createTemporaryDex(factory);
    const filePath = fileValue.getCanonicalPath().toString();
    const file = new File(filePath, "w");
    file.write(buffer.buffer);
    file.close();
    setReadOnlyDex(filePath, factory);
    return new _DexFile(filePath, fileValue, factory);
  }
  constructor(path, file, factory) {
    this.path = path;
    this.file = file;
    this._factory = factory;
  }
  load() {
    const { _factory: factory } = this;
    const { codeCacheDir } = factory;
    const DexClassLoader = factory.use("dalvik.system.DexClassLoader");
    const JFile = factory.use("java.io.File");
    let file = this.file;
    if (file === null) {
      file = factory.use("java.io.File").$new(this.path);
    }
    if (!file.exists()) {
      throw new Error("File not found");
    }
    JFile.$new(codeCacheDir).mkdirs();
    factory.loader = DexClassLoader.$new(file.getCanonicalPath(), codeCacheDir, null, factory.loader);
    vm2.preventDetachDueToClassLoader();
  }
  getClassNames() {
    const { _factory: factory } = this;
    const DexFile2 = factory.use("dalvik.system.DexFile");
    const optimizedDex = createTemporaryDex(factory);
    const dx = DexFile2.loadDex(this.path, optimizedDex.getCanonicalPath(), 0);
    const classNames = [];
    const enumeratorClassNames = dx.entries();
    while (enumeratorClassNames.hasMoreElements()) {
      classNames.push(enumeratorClassNames.nextElement().toString());
    }
    return classNames;
  }
};
function createTemporaryDex(factory) {
  const { cacheDir, tempFileNaming } = factory;
  const JFile = factory.use("java.io.File");
  const cacheDirValue = JFile.$new(cacheDir);
  cacheDirValue.mkdirs();
  return JFile.createTempFile(tempFileNaming.prefix, tempFileNaming.suffix + ".dex", cacheDirValue);
}
function setReadOnlyDex(filePath, factory) {
  const JFile = factory.use("java.io.File");
  const file = JFile.$new(filePath);
  file.setWritable(false, false);
}
function getFactoryCache() {
  switch (factoryCache.state) {
    case "empty": {
      factoryCache.state = "pending";
      const defaultFactory = factoryCache.factories[0];
      const HashMap = defaultFactory.use("java.util.HashMap");
      const Integer = defaultFactory.use("java.lang.Integer");
      factoryCache.loaders = HashMap.$new();
      factoryCache.Integer = Integer;
      const loader = defaultFactory.loader;
      if (loader !== null) {
        addFactoryToCache(defaultFactory, loader);
      }
      factoryCache.state = "ready";
      return factoryCache;
    }
    case "pending":
      do {
        Thread.sleep(0.05);
      } while (factoryCache.state === "pending");
      return factoryCache;
    case "ready":
      return factoryCache;
  }
}
function addFactoryToCache(factory, loader) {
  const { factories, loaders, Integer } = factoryCache;
  const index = Integer.$new(factories.indexOf(factory));
  loaders.put(loader, index);
  for (let l = loader.getParent(); l !== null; l = l.getParent()) {
    if (loaders.containsKey(l)) {
      break;
    }
    loaders.put(l, index);
  }
}
function ignore(threadId) {
  let count = ignoredThreads.get(threadId);
  if (count === void 0) {
    count = 0;
  }
  count++;
  ignoredThreads.set(threadId, count);
}
function unignore(threadId) {
  let count = ignoredThreads.get(threadId);
  if (count === void 0) {
    throw new Error(`Thread ${threadId} is not ignored`);
  }
  count--;
  if (count === 0) {
    ignoredThreads.delete(threadId);
  } else {
    ignoredThreads.set(threadId, count);
  }
}
function basename(className) {
  return className.slice(className.lastIndexOf(".") + 1);
}
function readTypeNames(env, types) {
  const names = [];
  const n = env.getArrayLength(types);
  for (let i = 0; i !== n; i++) {
    const t = env.getObjectArrayElement(types, i);
    try {
      names.push(env.getTypeName(t));
    } finally {
      env.deleteLocalRef(t);
    }
  }
  return names;
}
function makeSourceFileName(className) {
  const tokens = className.split(".");
  return tokens[tokens.length - 1] + ".java";
}

// node_modules/frida-java-bridge/index.js
var jsizeSize4 = 4;
var pointerSize8 = Process.pointerSize;
var Runtime = class {
  ACC_PUBLIC = 1;
  ACC_PRIVATE = 2;
  ACC_PROTECTED = 4;
  ACC_STATIC = 8;
  ACC_FINAL = 16;
  ACC_SYNCHRONIZED = 32;
  ACC_BRIDGE = 64;
  ACC_VARARGS = 128;
  ACC_NATIVE = 256;
  ACC_ABSTRACT = 1024;
  ACC_STRICT = 2048;
  ACC_SYNTHETIC = 4096;
  constructor() {
    this.classFactory = null;
    this.ClassFactory = ClassFactory;
    this.vm = null;
    this.api = null;
    this._initialized = false;
    this._apiError = null;
    this._wakeupHandler = null;
    this._pollListener = null;
    this._pendingMainOps = [];
    this._pendingVmOps = [];
    this._cachedIsAppProcess = null;
    try {
      this._tryInitialize();
    } catch (e) {
    }
  }
  _tryInitialize() {
    if (this._initialized) {
      return true;
    }
    if (this._apiError !== null) {
      throw this._apiError;
    }
    let api2;
    try {
      api2 = api_default();
      this.api = api2;
    } catch (e) {
      this._apiError = e;
      throw e;
    }
    if (api2 === null) {
      return false;
    }
    const vm3 = new VM(api2);
    this.vm = vm3;
    initialize(vm3);
    ClassFactory._initialize(vm3, api2);
    this.classFactory = new ClassFactory();
    this._initialized = true;
    return true;
  }
  _dispose() {
    if (this.api === null) {
      return;
    }
    const { vm: vm3 } = this;
    vm3.perform((env) => {
      ClassFactory._disposeAll(env);
      Env.dispose(env);
    });
    Script.nextTick(() => {
      VM.dispose(vm3);
    });
  }
  get available() {
    return this._tryInitialize();
  }
  get androidVersion() {
    return getAndroidVersion();
  }
  synchronized(obj, fn) {
    const { $h: objHandle = obj } = obj;
    if (!(objHandle instanceof NativePointer)) {
      throw new Error("Java.synchronized: the first argument `obj` must be either a pointer or a Java instance");
    }
    const env = this.vm.getEnv();
    checkJniResult("VM::MonitorEnter", env.monitorEnter(objHandle));
    try {
      fn();
    } finally {
      env.monitorExit(objHandle);
    }
  }
  enumerateLoadedClasses(callbacks) {
    this._checkAvailable();
    const { flavor } = this.api;
    if (flavor === "jvm") {
      this._enumerateLoadedClassesJvm(callbacks);
    } else if (flavor === "art") {
      this._enumerateLoadedClassesArt(callbacks);
    } else {
      this._enumerateLoadedClassesDalvik(callbacks);
    }
  }
  enumerateLoadedClassesSync() {
    const classes = [];
    this.enumerateLoadedClasses({
      onMatch(c) {
        classes.push(c);
      },
      onComplete() {
      }
    });
    return classes;
  }
  enumerateClassLoaders(callbacks) {
    this._checkAvailable();
    const { flavor } = this.api;
    if (flavor === "jvm") {
      this._enumerateClassLoadersJvm(callbacks);
    } else if (flavor === "art") {
      this._enumerateClassLoadersArt(callbacks);
    } else {
      throw new Error("Enumerating class loaders is not supported on Dalvik");
    }
  }
  enumerateClassLoadersSync() {
    const loaders = [];
    this.enumerateClassLoaders({
      onMatch(c) {
        loaders.push(c);
      },
      onComplete() {
      }
    });
    return loaders;
  }
  _enumerateLoadedClassesJvm(callbacks) {
    const { api: api2, vm: vm3 } = this;
    const { jvmti } = api2;
    const env = vm3.getEnv();
    const countPtr = Memory.alloc(jsizeSize4);
    const classesPtr = Memory.alloc(pointerSize8);
    jvmti.getLoadedClasses(countPtr, classesPtr);
    const count = countPtr.readS32();
    const classes = classesPtr.readPointer();
    const handles = [];
    for (let i = 0; i !== count; i++) {
      handles.push(classes.add(i * pointerSize8).readPointer());
    }
    jvmti.deallocate(classes);
    try {
      for (const handle of handles) {
        const className = env.getClassName(handle);
        callbacks.onMatch(className, handle);
      }
      callbacks.onComplete();
    } finally {
      handles.forEach((handle) => {
        env.deleteLocalRef(handle);
      });
    }
  }
  _enumerateClassLoadersJvm(callbacks) {
    this.choose("java.lang.ClassLoader", callbacks);
  }
  _enumerateLoadedClassesArt(callbacks) {
    const { vm: vm3, api: api2 } = this;
    const env = vm3.getEnv();
    const addGlobalReference = api2["art::JavaVMExt::AddGlobalRef"];
    const { vm: vmHandle } = api2;
    withRunnableArtThread(vm3, env, (thread) => {
      const collectClassHandles = makeArtClassVisitor((klass) => {
        const handle = addGlobalReference(vmHandle, thread, klass);
        try {
          const className = env.getClassName(handle);
          callbacks.onMatch(className, handle);
        } finally {
          env.deleteGlobalRef(handle);
        }
        return true;
      });
      api2["art::ClassLinker::VisitClasses"](api2.artClassLinker.address, collectClassHandles);
    });
    callbacks.onComplete();
  }
  _enumerateClassLoadersArt(callbacks) {
    const { classFactory: factory, vm: vm3, api: api2 } = this;
    const env = vm3.getEnv();
    const visitClassLoaders = api2["art::ClassLinker::VisitClassLoaders"];
    if (visitClassLoaders === void 0) {
      throw new Error("This API is only available on Android >= 7.0");
    }
    const ClassLoader = factory.use("java.lang.ClassLoader");
    const loaderHandles = [];
    const addGlobalReference = api2["art::JavaVMExt::AddGlobalRef"];
    const { vm: vmHandle } = api2;
    withRunnableArtThread(vm3, env, (thread) => {
      const collectLoaderHandles = makeArtClassLoaderVisitor((loader) => {
        loaderHandles.push(addGlobalReference(vmHandle, thread, loader));
        return true;
      });
      withAllArtThreadsSuspended(() => {
        visitClassLoaders(api2.artClassLinker.address, collectLoaderHandles);
      });
    });
    try {
      loaderHandles.forEach((handle) => {
        const loader = factory.cast(handle, ClassLoader);
        callbacks.onMatch(loader);
      });
    } finally {
      loaderHandles.forEach((handle) => {
        env.deleteGlobalRef(handle);
      });
    }
    callbacks.onComplete();
  }
  _enumerateLoadedClassesDalvik(callbacks) {
    const { api: api2 } = this;
    const HASH_TOMBSTONE = ptr("0xcbcacccd");
    const loadedClassesOffset = 172;
    const hashEntrySize = 8;
    const ptrLoadedClassesHashtable = api2.gDvm.add(loadedClassesOffset);
    const hashTable = ptrLoadedClassesHashtable.readPointer();
    const tableSize = hashTable.readS32();
    const ptrpEntries = hashTable.add(12);
    const pEntries = ptrpEntries.readPointer();
    const end = tableSize * hashEntrySize;
    for (let offset = 0; offset < end; offset += hashEntrySize) {
      const pEntryPtr = pEntries.add(offset);
      const dataPtr = pEntryPtr.add(4).readPointer();
      if (dataPtr.isNull() || dataPtr.equals(HASH_TOMBSTONE)) {
        continue;
      }
      const descriptionPtr = dataPtr.add(24).readPointer();
      const description = descriptionPtr.readUtf8String();
      if (description.startsWith("L")) {
        const name = description.substring(1, description.length - 1).replace(/\//g, ".");
        callbacks.onMatch(name);
      }
    }
    callbacks.onComplete();
  }
  enumerateMethods(query) {
    const { classFactory: factory } = this;
    const env = this.vm.getEnv();
    const ClassLoader = factory.use("java.lang.ClassLoader");
    return Model.enumerateMethods(query, this.api, env).map((group) => {
      const handle = group.loader;
      group.loader = handle !== null ? factory.wrap(handle, ClassLoader, env) : null;
      return group;
    });
  }
  scheduleOnMainThread(fn) {
    this.performNow(() => {
      this._pendingMainOps.push(fn);
      let { _wakeupHandler: wakeupHandler } = this;
      if (wakeupHandler === null) {
        const { classFactory: factory } = this;
        const Handler = factory.use("android.os.Handler");
        const Looper = factory.use("android.os.Looper");
        wakeupHandler = Handler.$new(Looper.getMainLooper());
        this._wakeupHandler = wakeupHandler;
      }
      if (this._pollListener === null) {
        this._pollListener = Interceptor.attach(Process.getModuleByName("libc.so").getExportByName("epoll_wait"), this._makePollHook());
        Interceptor.flush();
      }
      wakeupHandler.sendEmptyMessage(1);
    });
  }
  _makePollHook() {
    const mainThreadId = Process.id;
    const { _pendingMainOps: pending } = this;
    return function() {
      if (this.threadId !== mainThreadId) {
        return;
      }
      let fn;
      while ((fn = pending.shift()) !== void 0) {
        try {
          fn();
        } catch (e) {
          Script.nextTick(() => {
            throw e;
          });
        }
      }
    };
  }
  perform(fn) {
    this._checkAvailable();
    if (!this._isAppProcess() || this.classFactory.loader !== null) {
      try {
        this.vm.perform(fn);
      } catch (e) {
        Script.nextTick(() => {
          throw e;
        });
      }
    } else {
      this._pendingVmOps.push(fn);
      if (this._pendingVmOps.length === 1) {
        this._performPendingVmOpsWhenReady();
      }
    }
  }
  performNow(fn) {
    this._checkAvailable();
    return this.vm.perform(() => {
      const { classFactory: factory } = this;
      if (this._isAppProcess() && factory.loader === null) {
        const ActivityThread = factory.use("android.app.ActivityThread");
        const app = ActivityThread.currentApplication();
        if (app !== null) {
          initFactoryFromApplication(factory, app);
        }
      }
      return fn();
    });
  }
  _performPendingVmOpsWhenReady() {
    this.vm.perform(() => {
      const { classFactory: factory } = this;
      const ActivityThread = factory.use("android.app.ActivityThread");
      const app = ActivityThread.currentApplication();
      if (app !== null) {
        initFactoryFromApplication(factory, app);
        this._performPendingVmOps();
        return;
      }
      const runtime2 = this;
      let initialized = false;
      let hookpoint = "early";
      const handleBindApplication = ActivityThread.handleBindApplication;
      handleBindApplication.implementation = function(data) {
        if (data.instrumentationName.value !== null) {
          hookpoint = "late";
          const LoadedApk = factory.use("android.app.LoadedApk");
          const makeApplication = LoadedApk.makeApplication;
          makeApplication.implementation = function(forceDefaultAppClass, instrumentation) {
            if (!initialized) {
              initialized = true;
              initFactoryFromLoadedApk(factory, this);
              runtime2._performPendingVmOps();
            }
            return makeApplication.apply(this, arguments);
          };
        }
        handleBindApplication.apply(this, arguments);
      };
      const getPackageInfoCandidates = ActivityThread.getPackageInfo.overloads.map((m) => [m.argumentTypes.length, m]).sort(([arityA], [arityB]) => arityB - arityA).map(([_, method]) => method);
      const getPackageInfo = getPackageInfoCandidates[0];
      getPackageInfo.implementation = function(...args) {
        const apk = getPackageInfo.call(this, ...args);
        if (!initialized && hookpoint === "early") {
          initialized = true;
          initFactoryFromLoadedApk(factory, apk);
          runtime2._performPendingVmOps();
        }
        return apk;
      };
    });
  }
  _performPendingVmOps() {
    const { vm: vm3, _pendingVmOps: pending } = this;
    let fn;
    while ((fn = pending.shift()) !== void 0) {
      try {
        vm3.perform(fn);
      } catch (e) {
        Script.nextTick(() => {
          throw e;
        });
      }
    }
  }
  use(className, options) {
    return this.classFactory.use(className, options);
  }
  openClassFile(filePath) {
    return this.classFactory.openClassFile(filePath);
  }
  choose(specifier, callbacks) {
    this.classFactory.choose(specifier, callbacks);
  }
  retain(obj) {
    return this.classFactory.retain(obj);
  }
  cast(obj, C) {
    return this.classFactory.cast(obj, C);
  }
  array(type, elements) {
    return this.classFactory.array(type, elements);
  }
  backtrace(options) {
    return backtrace(this.vm, options);
  }
  // Reference: http://stackoverflow.com/questions/2848575/how-to-detect-ui-thread-on-android
  isMainThread() {
    const Looper = this.classFactory.use("android.os.Looper");
    const mainLooper = Looper.getMainLooper();
    const myLooper = Looper.myLooper();
    if (myLooper === null) {
      return false;
    }
    return mainLooper.$isSameObject(myLooper);
  }
  registerClass(spec) {
    return this.classFactory.registerClass(spec);
  }
  deoptimizeEverything() {
    const { vm: vm3 } = this;
    return deoptimizeEverything(vm3, vm3.getEnv());
  }
  deoptimizeBootImage() {
    const { vm: vm3 } = this;
    return deoptimizeBootImage(vm3, vm3.getEnv());
  }
  deoptimizeMethod(method) {
    const { vm: vm3 } = this;
    return deoptimizeMethod(vm3, vm3.getEnv(), method);
  }
  _checkAvailable() {
    if (!this.available) {
      throw new Error("Java API not available");
    }
  }
  _isAppProcess() {
    let result = this._cachedIsAppProcess;
    if (result === null) {
      if (this.api.flavor === "jvm") {
        result = false;
        this._cachedIsAppProcess = result;
        return result;
      }
      const readlink = new NativeFunction(Module.getGlobalExportByName("readlink"), "pointer", ["pointer", "pointer", "pointer"], {
        exceptions: "propagate"
      });
      const pathname = Memory.allocUtf8String("/proc/self/exe");
      const bufferSize = 1024;
      const buffer = Memory.alloc(bufferSize);
      const size = readlink(pathname, buffer, ptr(bufferSize)).toInt32();
      if (size !== -1) {
        const exe = buffer.readUtf8String(size);
        result = /^\/system\/bin\/app_process/.test(exe);
      } else {
        result = true;
      }
      this._cachedIsAppProcess = result;
    }
    return result;
  }
};
function initFactoryFromApplication(factory, app) {
  const Process2 = factory.use("android.os.Process");
  factory.loader = app.getClassLoader();
  if (Process2.myUid() === Process2.SYSTEM_UID.value) {
    factory.cacheDir = "/data/system";
    factory.codeCacheDir = "/data/dalvik-cache";
  } else {
    if ("getCodeCacheDir" in app) {
      factory.cacheDir = app.getCacheDir().getCanonicalPath();
      factory.codeCacheDir = app.getCodeCacheDir().getCanonicalPath();
    } else {
      factory.cacheDir = app.getFilesDir().getCanonicalPath();
      factory.codeCacheDir = app.getCacheDir().getCanonicalPath();
    }
  }
}
function initFactoryFromLoadedApk(factory, apk) {
  const JFile = factory.use("java.io.File");
  factory.loader = apk.getClassLoader();
  const dataDir = JFile.$new(apk.getDataDir()).getCanonicalPath();
  factory.cacheDir = dataDir;
  factory.codeCacheDir = dataDir + "/cache";
}
var runtime = new Runtime();
Script.bindWeak(runtime, () => {
  runtime._dispose();
});

let Java = runtime;

var fridamp =
{
  "version": 3,
  "sources": ["frida-shim:node_modules/@frida/base64-js/index.js", "frida-shim:node_modules/@frida/ieee754/index.js", "frida-shim:node_modules/@frida/buffer/index.js", "node_modules/frida-java-bridge/lib/android.js", "node_modules/frida-java-bridge/lib/alloc.js", "node_modules/frida-java-bridge/lib/result.js", "node_modules/frida-java-bridge/lib/jvmti.js", "node_modules/frida-java-bridge/lib/machine-code.js", "node_modules/frida-java-bridge/lib/memoize.js", "node_modules/frida-java-bridge/lib/env.js", "node_modules/frida-java-bridge/lib/vm.js", "node_modules/frida-java-bridge/lib/jvm.js", "node_modules/frida-java-bridge/lib/api.js", "node_modules/frida-java-bridge/lib/class-model.js", "node_modules/frida-java-bridge/lib/lru.js", "node_modules/frida-java-bridge/lib/mkdex.js", "node_modules/frida-java-bridge/lib/types.js", "node_modules/frida-java-bridge/lib/class-factory.js", "node_modules/frida-java-bridge/index.js", "test.ts"],
  "mappings": "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;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA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AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;AAAA;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",
  "names": ["Buffer", "fill", "copy", "Buffer", "compare", "read", "i", "write", "byteLength", "code", "slice", "pointerSize", "vm", "vm", "pointerSize", "nativeFunctionOptions", "proxy", "pointerSize", "api", "initialize", "vtable", "handle", "vm", "pointerSize", "nativeFunctionOptions", "vm", "runtime", "api", "vtable", "write", "code", "cm", "size", "env", "read", "begin", "jsizeSize", "pointerSize", "nativeFunctionOptions", "cachedApi", "getApi", "_getApi", "api", "vm", "ensureClassInitialized", "vtable", "makeMethodMangler", "getApi", "code", "api", "pointerSize", "vm", "cm", "kAccPublic", "kAccNative", "Buffer", "offset", "interfaces", "index", "accessFlags", "slice", "code", "read", "jsizeSize", "ensureClassInitialized", "makeMethodMangler", "kAccStatic", "pointerSize", "vm", "name", "tagPtr", "code", "DVM_JNI_ENV_OFFSET_SELF", "size", "env", "thread", "unwrap", "type", "DexFile", "jsizeSize", "pointerSize", "api", "vm", "runtime", "Process"]
}

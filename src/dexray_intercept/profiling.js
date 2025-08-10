📦
635990 /agent/hooking_profile_loader.js
✄
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

// agent/utils/logging.ts
function getStackTrace(context) {
  try {
    if (context) {
      return Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).map((s) => `${s.address} ${s.name || "<unknown>"} (${s.moduleName || "<unknown module>"})`).join("\n");
    } else {
      const modules = Process.enumerateModules();
      const moduleInfo = modules.slice(0, 3).map((m) => `${m.name}: ${m.base}`).join("\n");
      return `Stack trace context unavailable
Loaded modules:
${moduleInfo}`;
    }
  } catch (e) {
    return `<stacktrace unavailable: ${e}>`;
  }
}
function log(str, context) {
  var message = {};
  message["profileType"] = "console";
  const now = (/* @__PURE__ */ new Date()).toISOString();
  message["timestamp"] = now;
  message["console"] = str;
  if (enable_stacktrace) {
    message["stacktrace"] = escapeJsonString(getStackTrace(context));
  }
  send(message);
}
function devlog(str, context) {
  var message = {};
  message["profileType"] = "console_dev";
  message["console_dev"] = str;
  const now = (/* @__PURE__ */ new Date()).toISOString();
  message["timestamp"] = now;
  if (enable_stacktrace) {
    message["stacktrace"] = escapeJsonString(getStackTrace(context));
  }
  send(message);
}
var CACHE_LOG = "";
var CACHE_LOG_TEL = "";
function escapeJsonString(str) {
  return str.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\r/g, "\\r").replace(/\t/g, "\\t").replace(/\x08/g, "\\b").replace(/\f/g, "\\f");
}
function am_send(hooking_type, str, data, context) {
  if (hooking_type === "IPC_BINDER" || hooking_type === "PROCESS_NATIVE_LIB") {
    if (str.toString() == CACHE_LOG.toString())
      return;
  } else if (hooking_type === "TELEPHONY") {
    if (str.toString() == CACHE_LOG_TEL.toString())
      return;
  }
  var message = {};
  message["profileType"] = hooking_type;
  message["profileContent"] = str;
  const now = (/* @__PURE__ */ new Date()).toISOString();
  message["timestamp"] = now;
  if (enable_stacktrace) {
    console.log("Stacktrace enabled, adding stacktrace to message");
    message["stacktrace"] = escapeJsonString(getStackTrace(context));
  }
  if (data === void 0) {
    send(message);
  } else {
    send(message, data);
  }
}

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
      const fieldInstance = env.getFieldId(clazzRef, "name", "Ljava/lang/String;");
      const fieldStatic = env.getStaticFieldId(clazzRef, "MAX_PRIORITY", "I");
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
      const methodInstance = env.getMethodId(clazzRef, "getName", "()Ljava/lang/String;");
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
  const api2 = getApi();
  const runtimeOffset = getArtRuntimeSpec(api2).offset;
  const jniIdManagerOffset = runtimeOffset.jniIdManager;
  const jniIdsIndirectionOffset = runtimeOffset.jniIdsIndirection;
  if (jniIdManagerOffset !== null && jniIdsIndirectionOffset !== null) {
    const runtime2 = api2.artRuntime;
    const jniIdsIndirection = runtime2.add(jniIdsIndirectionOffset).readInt();
    if (jniIdsIndirection !== kPointer) {
      const jniIdManager = runtime2.add(jniIdManagerOffset).readPointer();
      return api2["art::jni::JniIdManager::DecodeMethodId"](jniIdManager, methodId);
    }
  }
  return methodId;
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
var frida_java_bridge_default = runtime;

// agent/utils/javalib.ts
var Java;
var javaLegacy = globalThis.Java;
if (javaLegacy && typeof javaLegacy.perform === "function") {
  devlog("[frida-java-bridge] Pre-v17 Frida detected. Using legacy global Java bridge.");
  Java = javaLegacy;
} else {
  devlog("[frida-java-bridge] Frida >=17 detected. Using 'frida-java-bridge' module.");
  Java = frida_java_bridge_default;
}

// agent/utils/misc.ts
function isPatternPresent(path, patterns) {
  for (var i = 0; i < patterns.length; i++)
    if (path.indexOf(patterns[i]) > -1) {
      return true;
    }
  return false;
}
function Where(stack) {
  var at = "";
  for (var i = 0; i < stack.length; ++i) {
    at += stack[i].toString() + "\n";
  }
  return at;
}
function bytesToHex(bytes) {
  var hex = [];
  for (var i = 0; i < bytes.length; i++) {
    hex.push((bytes[i] >>> 4).toString(16));
    hex.push((bytes[i] & 15).toString(16));
  }
  return hex.join("");
}

// agent/file/file_system_hooks.ts
var PROFILE_HOOKING_TYPE = "FILE_SYSTEM";
var TraceFD = {};
var TraceFS = {};
var TraceFile = {};
var CONFIG = {
  // if TRUE enable data dump 
  printEnable: true,
  // if TRUE enable libc.so open/read/write hook
  printLibc: false,
  // if TRUE print the stack trace for each hook
  printStackTrace: false,
  // to filter the file path whose data want to be dumped in ASCII 
  dump_ascii_If_Path_contains: [".log", ".xml", ".prop"],
  // to filter the file path whose data want to be NOT dumped in hexdump (useful for big chunk and excessive reads) 
  dump_hex_If_Path_NOT_contains: [".png", "/proc/self/task", "/system/lib", "base.apk", "cacert", "jar", "dex"],
  // to filter the file path whose data want to be NOT dumped fron libc read/write (useful for big chunk and excessive reads) 
  dump_raw_If_Path_NOT_contains: [".png", "/proc/self/task", "/system/lib", "base.apk", "cacert"],
  // filter file access which is typically not of interest
  filter_out_access_to_these_files: ["anon_inode", "/dev/urandom", "/system/framework/", "/data/dalvik-cache/"],
  // Maximum length of data to display (bytes)
  max_output_length: 1024
};
function isFileFromInterest(file_string) {
  if (!file_string.startsWith("/proc") && !file_string.startsWith("/system/lib")) {
    return true;
  } else if (file_string.endsWith("cgroup") || file_string.endsWith("primary.prof") || file_string.endsWith("cmdline") || file_string === "/proc" || file_string.startsWith("/proc/self/maps") || file_string.endsWith("jar.cur.prof")) {
    return false;
  } else if (file_string.startsWith("/system/lib") || file_string.startsWith("[unknown") || file_string.startsWith("/proc") && file_string.endsWith("maps")) {
    return false;
  }
  return true;
}
function createFileSystemEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}
function bytesToHexSafe(bytes) {
  if (!bytes || bytes.length === 0)
    return "";
  return bytesToHex(new Uint8Array(bytes));
}
function shouldSkipFile(filePath) {
  for (const filter of CONFIG.filter_out_access_to_these_files) {
    if (filePath.includes(filter)) {
      return true;
    }
  }
  return !isFileFromInterest(filePath);
}
function hook_filesystem_accesses() {
  var createdFiles = /* @__PURE__ */ new Set();
  var createdFileStreams = /* @__PURE__ */ new Set();
  Java.perform(function() {
    var CLS = {
      File: Java.use("java.io.File"),
      FileInputStream: Java.use("java.io.FileInputStream"),
      FileOutputStream: Java.use("java.io.FileOutputStream"),
      String: Java.use("java.lang.String"),
      FileChannel: Java.use("java.nio.channels.FileChannel"),
      FileDescriptor: Java.use("java.io.FileDescriptor"),
      Thread: Java.use("java.lang.Thread"),
      StackTraceElement: Java.use("java.lang.StackTraceElement"),
      AndroidDbSQLite: Java.use("android.database.sqlite.SQLiteDatabase")
    };
    var File2 = {
      new: [
        CLS.File.$init.overload("java.io.File", "java.lang.String"),
        CLS.File.$init.overload("java.lang.String"),
        CLS.File.$init.overload("java.lang.String", "java.lang.String"),
        CLS.File.$init.overload("java.net.URI")
      ]
    };
    var FileInputStream = {
      new: [
        CLS.FileInputStream.$init.overload("java.io.File"),
        CLS.FileInputStream.$init.overload("java.io.FileDescriptor"),
        CLS.FileInputStream.$init.overload("java.lang.String")
      ],
      read: [
        CLS.FileInputStream.read.overload(),
        CLS.FileInputStream.read.overload("[B"),
        CLS.FileInputStream.read.overload("[B", "int", "int")
      ]
    };
    var FileOuputStream = {
      new: [
        CLS.FileOutputStream.$init.overload("java.io.File"),
        CLS.FileOutputStream.$init.overload("java.io.File", "boolean"),
        CLS.FileOutputStream.$init.overload("java.io.FileDescriptor"),
        CLS.FileOutputStream.$init.overload("java.lang.String"),
        CLS.FileOutputStream.$init.overload("java.lang.String", "boolean")
      ],
      write: [
        CLS.FileOutputStream.write.overload("[B"),
        CLS.FileOutputStream.write.overload("int"),
        CLS.FileOutputStream.write.overload("[B", "int", "int")
      ]
    };
    File2.new[1].implementation = function(a0) {
      var file_path = a0;
      if (!createdFiles.has(file_path)) {
        if (file_path.length > 2 && !shouldSkipFile(file_path)) {
          createFileSystemEvent("file.create", {
            operation: "File.new",
            variant: 1,
            file_path,
            method: "java.io.File.init(String)"
          });
          createdFiles.add(file_path);
        }
      }
      var ret = File2.new[1].call(this, file_path);
      TraceFile["f" + this.hashCode()] = file_path;
      return ret;
    };
    File2.new[2].implementation = function(a0, a1) {
      var file_path = a0 + "/" + a1;
      if (!createdFiles.has(file_path) && file_path.length > 3 && !shouldSkipFile(file_path)) {
        createFileSystemEvent("file.create", {
          operation: "File.new",
          variant: 2,
          file_path,
          parent_path: a0,
          child_path: a1,
          method: "java.io.File.init(String, String)"
        });
        createdFiles.add(file_path);
      }
      var ret = File2.new[2].call(this, a0, a1);
      TraceFile["f" + this.hashCode()] = file_path;
      return ret;
    };
    FileInputStream.new[0].implementation = function(a0) {
      var file = Java.cast(a0, CLS.File);
      var fname = TraceFile["f" + file.hashCode()];
      if (fname == null) {
        var p = file.getAbsolutePath();
        if (p !== null)
          fname = TraceFile["f" + file.hashCode()] = p;
      }
      if (fname == null) {
        devlog("FileInputStream.new[0]: p-->" + p);
        devlog("FileInputStream.new[0]: file-->" + file);
        fname = "[unknown]";
        const filePath = file.toString();
        if (isPatternPresent(filePath, ["/"])) {
          fname = filePath;
        }
      }
      if (!shouldSkipFile(fname)) {
        if (!createdFileStreams.has(fname)) {
          createFileSystemEvent("file.stream.create", {
            operation: "FileInputStream.new",
            variant: 0,
            file_path: fname,
            stream_type: "input",
            method: "java.io.FileInputStream.init(File)"
          });
          createdFileStreams.add(fname);
        }
      }
      var fis = FileInputStream.new[0].call(this, a0);
      TraceFS["fd" + this.hashCode()] = fname;
      var fd = Java.cast(this.getFD(), CLS.FileDescriptor);
      TraceFD["fd" + fd.hashCode()] = fname;
      return fis;
    };
    FileInputStream.read[1].implementation = function(a0) {
      var fname = TraceFS["fd" + this.hashCode()];
      var fd = null;
      if (fname == null) {
        fd = Java.cast(this.getFD(), CLS.FileDescriptor);
        fname = TraceFD["fd" + fd.hashCode()];
      }
      if (fname == null) {
        devlog("FileInputStream.read[1]: fd-->" + fd);
        fname = "[unknown]";
      }
      var result = FileInputStream.read[1].call(this, a0);
      var b = Java.array("byte", a0);
      if (!shouldSkipFile(fname)) {
        const shouldDumpAscii = isPatternPresent(fname, CONFIG.dump_ascii_If_Path_contains);
        const shouldDumpHex = !isPatternPresent(fname, CONFIG.dump_hex_If_Path_NOT_contains);
        createFileSystemEvent("file.read", {
          operation: "FileInputStream.read",
          variant: 1,
          file_path: fname,
          buffer_size: a0.length,
          bytes_read: result,
          data_hex: shouldDumpHex || shouldDumpAscii ? bytesToHexSafe(b) : null,
          should_dump_ascii: shouldDumpAscii,
          should_dump_hex: shouldDumpHex,
          method: "java.io.FileInputStream.read(byte[])"
        });
      }
      return result;
    };
    FileInputStream.read[2].implementation = function(a0, a1, a2) {
      var fname = TraceFS["fd" + this.hashCode()];
      var fd = null;
      if (fname == null) {
        fd = Java.cast(this.getFD(), CLS.FileDescriptor);
        fname = TraceFD["fd" + fd.hashCode()];
      }
      if (fname == null) {
        devlog("FileInputStream.read[2]: fd-->" + fd);
        fname = "[unknown]";
      }
      var result = FileInputStream.read[2].call(this, a0, a1, a2);
      var b = Java.array("byte", a0);
      if (!shouldSkipFile(fname)) {
        const shouldDumpAscii = isPatternPresent(fname, CONFIG.dump_ascii_If_Path_contains);
        const shouldDumpHex = !isPatternPresent(fname, CONFIG.dump_hex_If_Path_NOT_contains);
        createFileSystemEvent("file.read", {
          operation: "FileInputStream.read",
          variant: 2,
          file_path: fname,
          buffer_size: a0.length,
          offset: a1,
          length: a2,
          bytes_read: result,
          data_hex: shouldDumpHex || shouldDumpAscii ? bytesToHexSafe(b) : null,
          should_dump_ascii: shouldDumpAscii,
          should_dump_hex: shouldDumpHex,
          method: "java.io.FileInputStream.read(byte[], int, int)"
        });
      }
      return result;
    };
    FileOuputStream.write[2].implementation = function(a0, a1, a2) {
      var fname = TraceFS["fd" + this.hashCode()];
      var fd = null;
      if (fname == null) {
        fd = Java.cast(this.getFD(), CLS.FileDescriptor);
        fname = TraceFD["fd" + fd.hashCode()];
      }
      if (fname == null) {
        devlog("FileOuputStream.write[2]: fd-->" + fd);
        fname = "[unknown]";
      }
      var result = FileOuputStream.write[2].call(this, a0, a1, a2);
      if (!shouldSkipFile(fname)) {
        const shouldDumpAscii = isPatternPresent(fname, CONFIG.dump_ascii_If_Path_contains);
        const shouldDumpHex = !isPatternPresent(fname, CONFIG.dump_hex_If_Path_NOT_contains);
        const isLargeData = a2 > CONFIG.max_output_length;
        const isApkDexJar = fname.endsWith(".apk") || fname.endsWith(".dex") || fname.endsWith(".jar");
        const isXmlFile = fname.endsWith(".xml");
        createFileSystemEvent("file.write", {
          operation: "FileOutputStream.write",
          variant: 2,
          file_path: fname,
          buffer_size: a0.length,
          offset: a1,
          length: a2,
          data_hex: shouldDumpHex || shouldDumpAscii || isApkDexJar || isXmlFile ? bytesToHexSafe(a0) : null,
          should_dump_ascii: shouldDumpAscii,
          should_dump_hex: shouldDumpHex,
          is_large_data: isLargeData,
          max_display_length: CONFIG.max_output_length,
          file_type: isApkDexJar ? "binary" : isXmlFile ? "xml" : "other",
          method: "java.io.FileOutputStream.write(byte[], int, int)"
        });
      }
      return result;
    };
  });
}
function hook_filesystem_deletes() {
  var printedPaths = /* @__PURE__ */ new Set();
  Java.perform(() => {
    const File2 = Java.use("java.io.File");
    File2.delete.implementation = function() {
      const path = this.getAbsolutePath();
      if (path.includes("jar") || path.endsWith("dex")) {
        createFileSystemEvent("file.delete.java", { file_path: path });
        printedPaths.add(path);
      }
      return true;
    };
  });
  var unlinkPtr = null;
  for (const module of Process.enumerateModules()) {
    try {
      unlinkPtr = module.findExportByName("unlink");
      if (unlinkPtr)
        break;
    } catch (e) {
      continue;
    }
  }
  if (unlinkPtr) {
    Interceptor.attach(unlinkPtr, {
      onEnter(args) {
        var ptr_to_file = ptr(args[0]);
        this.file_path = ptr_to_file.readUtf8String();
      },
      onLeave() {
        if (!this.file_path.endsWith("flock")) {
          if (!printedPaths.has(this.file_path)) {
            createFileSystemEvent("file.delete.native", {
              file_path: this.file_path
            });
          }
        }
      }
    });
  }
  if (deactivate_unlink) {
    var unlink = new NativeFunction(unlinkPtr, "int", []);
    Interceptor.replace(unlinkPtr, new NativeCallback(function() {
      am_send(PROFILE_HOOKING_TYPE, "unlink() encountered, skipping it.");
      return 0;
    }, "int", []));
  }
}
function install_file_system_hooks() {
  devlog("\n");
  devlog("install filesystem hooks");
  hook_filesystem_accesses();
  hook_filesystem_deletes();
}

// agent/database/sql.ts
var PROFILE_HOOKING_TYPE2 = "DATABASE";
function createDatabaseEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE2, JSON.stringify(event));
}
var PATH_FILTERS = [];
var PATH_FILTER_ENABLED = false;
function shouldLogDatabasePath(dbPath) {
  if (!PATH_FILTER_ENABLED) {
    return true;
  }
  if (!dbPath || dbPath === "unknown") {
    return true;
  }
  for (const filter of PATH_FILTERS) {
    if (filter.includes("*")) {
      const filterPattern = filter.replace(/\*/g, "");
      if (dbPath.includes(filterPattern)) {
        return true;
      }
    } else if (dbPath === filter) {
      return true;
    }
  }
  return false;
}
recv("path_filters", (message) => {
  if (message.payload && message.payload.length > 0) {
    PATH_FILTERS = message.payload;
    PATH_FILTER_ENABLED = true;
  } else {
    PATH_FILTER_ENABLED = false;
  }
});
function hook_java_sql() {
  setImmediate(function() {
    Java.perform(function() {
      var sqliteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
      sqliteDatabase.execSQL.overload("java.lang.String").implementation = function(var0) {
        var dbPath = "unknown";
        try {
          dbPath = this.getPath();
        } catch (e) {
          dbPath = "Error getting path: " + e;
        }
        if (shouldLogDatabasePath(dbPath)) {
          createDatabaseEvent("database.sqlite.exec", {
            method: "SQLiteDatabase.execSQL(String)",
            database_path: dbPath,
            sql: var0
          });
        }
        var execSQLRes = this.execSQL(var0);
        return execSQLRes;
      };
      sqliteDatabase.execSQL.overload("java.lang.String", "[Ljava.lang.Object;").implementation = function(var0, var1) {
        var dbPath = "unknown";
        try {
          dbPath = this.getPath();
        } catch (e) {
          dbPath = "Error getting path: " + e;
        }
        if (shouldLogDatabasePath(dbPath)) {
          var bindArgs = [];
          if (var1 && var1.length > 0) {
            for (var i = 0; i < var1.length; i++) {
              bindArgs.push(var1[i]);
            }
          }
          createDatabaseEvent("database.sqlite.exec", {
            method: "SQLiteDatabase.execSQL(String, Object[])",
            database_path: dbPath,
            sql: var0,
            bind_args: bindArgs
          });
        }
        var execSQLRes = this.execSQL(var0, var1);
        return execSQLRes;
      };
      sqliteDatabase.query.overload("boolean", "java.lang.String", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String").implementation = function(var0, var1, var2, var3, var4, var5, var6, var7, var8) {
        var methodVal = "SQLiteDatabase.query called.";
        var logVal = "Table: " + var1 + ", selection value: " + var3 + ", selectionArgs: " + var4 + " distinct: " + var0;
        am_send(PROFILE_HOOKING_TYPE2, methodVal + " " + logVal + "\n");
        var queryRes = this.query(var0, var1, var2, var3, var4, var5, var6, var7, var8);
        return queryRes;
      };
      sqliteDatabase.query.overload("java.lang.String", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String").implementation = function(var0, var1, var2, var3, var4, var5, var6, var7) {
        var dbPath = "unknown";
        try {
          dbPath = this.getPath();
        } catch (e) {
          dbPath = "Error getting path: " + e;
        }
        if (shouldLogDatabasePath(dbPath)) {
          var columns = var1 ? Array.prototype.slice.call(var1) : [];
          var selectionArgs = var3 ? Array.prototype.slice.call(var3) : [];
          createDatabaseEvent("database.sqlite.query", {
            method: "SQLiteDatabase.query(String, String[], String, String[], String, String, String, String)",
            database_path: dbPath,
            table: var0,
            columns,
            where_clause: var2,
            where_args: selectionArgs,
            group_by: var4,
            having: var5,
            order_by: var6,
            limit: var7
          });
        }
        var queryRes = this.query(var0, var1, var2, var3, var4, var5, var6, var7);
        return queryRes;
      };
      sqliteDatabase.query.overload("boolean", "java.lang.String", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String", "android.os.CancellationSignal").implementation = function(var0, var1, var2, var3, var4, var5, var6, var7, var8, var9) {
        var methodVal = "SQLiteDatabase.query called.";
        var logVal = "Table: " + var1 + ", selection value: " + var3 + ", selectionArgs: " + var4;
        am_send(PROFILE_HOOKING_TYPE2, methodVal + " " + logVal + "\n");
        var queryRes = this.query(var0, var1, var2, var3, var4, var5, var6, var7, var8, var9);
        return queryRes;
      };
      sqliteDatabase.query.overload("java.lang.String", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String", "java.lang.String", "java.lang.String").implementation = function(var0, var1, var2, var3, var4, var5, var6) {
        var methodVal = "SQLiteDatabase.query called.";
        var logVal = "Table: " + var0 + ", selection value: " + var2 + ", selectionArgs: " + var3;
        am_send(PROFILE_HOOKING_TYPE2, methodVal + " " + logVal + "\n");
        var queryRes = this.query(var0, var1, var2, var3, var4, var5, var6);
        return queryRes;
      };
      sqliteDatabase.queryWithFactory.overload("android.database.sqlite.SQLiteDatabase$CursorFactory", "boolean", "java.lang.String", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String").implementation = function(var0, var1, var2, var3, var4, var5, var6, var7, var8, var9) {
        var methodVal = "SQLiteDatabase.queryWithFactory called.";
        var logVal = "Table: " + var2 + ", selection value: " + var4 + ", selectionArgs: " + var5 + " distinct: " + var1;
        am_send(PROFILE_HOOKING_TYPE2, methodVal + " " + logVal + "\n");
        var queryWithFactoryRes = this.queryWithFactory(var0, var1, var2, var3, var4, var5, var6, var7, var8, var9);
        return queryWithFactoryRes;
      };
      sqliteDatabase.queryWithFactory.overload("android.database.sqlite.SQLiteDatabase$CursorFactory", "boolean", "java.lang.String", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String", "android.os.CancellationSignal").implementation = function(var0, var1, var2, var3, var4, var5, var6, var7, var8, var9, var10) {
        var methodVal = "SQLiteDatabase.queryWithFactory called.";
        var logVal = "Table: " + var2 + ", selection value: " + var4 + ", selectionArgs: " + var5 + " distinct: " + var1;
        am_send(PROFILE_HOOKING_TYPE2, methodVal + " " + logVal + "\n");
        var queryWithFactoryRes = this.queryWithFactory(var0, var1, var2, var3, var4, var5, var6, var7, var8, var9, var10);
        return queryWithFactoryRes;
      };
      sqliteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;").implementation = function(var0, var1) {
        var dbPath = "unknown";
        try {
          dbPath = this.getPath();
        } catch (e) {
          dbPath = "Error getting path: " + e;
        }
        if (shouldLogDatabasePath(dbPath)) {
          var selectionArgs = [];
          if (var1 && var1.length > 0) {
            for (var i = 0; i < var1.length; i++) {
              selectionArgs.push(var1[i]);
            }
          }
          createDatabaseEvent("database.sqlite.query", {
            method: "SQLiteDatabase.rawQuery(String, String[])",
            database_path: dbPath,
            sql: var0,
            where_args: selectionArgs
          });
        }
        var rawQueryRes = this.rawQuery(var0, var1);
        return rawQueryRes;
      };
      sqliteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;", "android.os.CancellationSignal").implementation = function(var0, var1, var2) {
        var dbPath = "unknown";
        try {
          dbPath = this.getPath();
        } catch (e) {
          dbPath = "Error getting path: " + e;
        }
        if (shouldLogDatabasePath(dbPath)) {
          var selectionArgs = [];
          if (var1 && var1.length > 0) {
            for (var i = 0; i < var1.length; i++) {
              selectionArgs.push(var1[i]);
            }
          }
          createDatabaseEvent("database.sqlite.query", {
            method: "SQLiteDatabase.rawQuery(String, String[], CancellationSignal)",
            database_path: dbPath,
            sql: var0,
            where_args: selectionArgs,
            cancellation_signal: true
          });
        }
        var rawQueryRes = this.rawQuery(var0, var1, var2);
        return rawQueryRes;
      };
      sqliteDatabase.rawQueryWithFactory.overload("android.database.sqlite.SQLiteDatabase$CursorFactory", "java.lang.String", "[Ljava.lang.String;", "java.lang.String", "android.os.CancellationSignal").implementation = function(var0, var1, var2, var3, var4) {
        var type = "\x1B[1;34mevent_type: SQLiteRawQuery\x1B[0m";
        var methodVal = "SQLiteDatabase.rawQueryWithFactory";
        var dbPath = "unknown";
        try {
          dbPath = this.getPath();
        } catch (e) {
          dbPath = "Error getting path: " + e;
        }
        if (shouldLogDatabasePath(dbPath)) {
          var argsStr = "";
          if (var2 && var2.length > 0) {
            for (var i = 0; i < var2.length; i++) {
              argsStr += "\n    - [" + i + "] " + var2[i];
            }
          }
          var logVal = "\nDatabase: \x1B[31m" + dbPath + "\x1B[0m\nSQL Query: \x1B[36m" + var1 + "\x1B[0m\nEdit table: \x1B[35m" + (var3 ? var3 : "null") + "\x1B[0m\nSelection args:" + (argsStr ? "\x1B[33m" + argsStr + "\x1B[0m" : " none") + "\nWith factory: \x1B[32m" + (var0 ? "Custom factory" : "null") + "\x1B[0m\nWith cancellation signal: \x1B[90mtrue\x1B[0m\n";
          am_send(PROFILE_HOOKING_TYPE2, type + " " + methodVal + logVal);
        }
        var rawQueryWithFactoryRes = this.rawQueryWithFactory(var0, var1, var2, var3, var4);
        return rawQueryWithFactoryRes;
      };
      sqliteDatabase.rawQueryWithFactory.overload("android.database.sqlite.SQLiteDatabase$CursorFactory", "java.lang.String", "[Ljava.lang.String;", "java.lang.String").implementation = function(var0, var1, var2, var3) {
        var type = "\x1B[1;34mevent_type: SQLiteRawQuery\x1B[0m";
        var methodVal = "SQLiteDatabase.rawQueryWithFactory";
        var dbPath = "unknown";
        try {
          dbPath = this.getPath();
        } catch (e) {
          dbPath = "Error getting path: " + e;
        }
        if (shouldLogDatabasePath(dbPath)) {
          var argsStr = "";
          if (var2 && var2.length > 0) {
            for (var i = 0; i < var2.length; i++) {
              argsStr += "\n    - [" + i + "] " + var2[i];
            }
          }
          var logVal = "\nDatabase: \x1B[31m" + dbPath + "\x1B[0m\nSQL Query: \x1B[36m" + var1 + "\x1B[0m\nEdit table: \x1B[35m" + (var3 ? var3 : "null") + "\x1B[0m\nSelection args:" + (argsStr ? "\x1B[33m" + argsStr + "\x1B[0m" : " none") + "\nWith factory: \x1B[32m" + (var0 ? "Custom factory" : "null") + "\x1B[0m\n";
          am_send(PROFILE_HOOKING_TYPE2, type + " " + methodVal + logVal);
        }
        var rawQueryWithFactoryRes = this.rawQueryWithFactory(var0, var1, var2, var3);
        return rawQueryWithFactoryRes;
      };
      sqliteDatabase.insert.overload("java.lang.String", "java.lang.String", "android.content.ContentValues").implementation = function(var0, var1, var2) {
        var dbPath = "unknown";
        try {
          dbPath = this.getPath();
        } catch (e) {
          dbPath = "Error getting path: " + e;
        }
        if (shouldLogDatabasePath(dbPath)) {
          var contentValues = {};
          if (var2) {
            var keyset = var2.keySet();
            var iter = keyset.iterator();
            while (iter.hasNext()) {
              var key = iter.next();
              var value = var2.get(key);
              contentValues[key] = value;
            }
          }
          createDatabaseEvent("database.sqlite.insert", {
            method: "SQLiteDatabase.insert(String, String, ContentValues)",
            database_path: dbPath,
            table: var0,
            null_column_hack: var1,
            content_values: contentValues
          });
        }
        var insertValueRes = this.insert(var0, var1, var2);
        return insertValueRes;
      };
      sqliteDatabase.insertOrThrow.overload("java.lang.String", "java.lang.String", "android.content.ContentValues").implementation = function(var0, var1, var2) {
        var dbPath = "unknown";
        try {
          dbPath = this.getPath();
        } catch (e) {
          dbPath = "Error getting path: " + e;
        }
        if (shouldLogDatabasePath(dbPath)) {
          var contentValues = {};
          if (var2) {
            var keyset = var2.keySet();
            var iter = keyset.iterator();
            while (iter.hasNext()) {
              var key = iter.next();
              var value = var2.get(key);
              contentValues[key] = value;
            }
          }
          createDatabaseEvent("database.sqlite.insert", {
            method: "SQLiteDatabase.insertOrThrow(String, String, ContentValues)",
            database_path: dbPath,
            table: var0,
            null_column_hack: var1,
            content_values: contentValues,
            throw_on_error: true
          });
        }
        var insertValueRes = this.insertOrThrow(var0, var1, var2);
        return insertValueRes;
      };
      sqliteDatabase.insertWithOnConflict.overload("java.lang.String", "java.lang.String", "android.content.ContentValues", "int").implementation = function(var0, var1, var2, var3) {
        var type = "\x1B[1;33mevent_type: SQLiteInsert\x1B[0m";
        var methodVal = "SQLiteDatabase.insertWithOnConflict";
        var dbPath = "unknown";
        try {
          dbPath = this.getPath();
        } catch (e) {
          dbPath = "Error getting path: " + e;
        }
        if (shouldLogDatabasePath(dbPath)) {
          var valuesStr = "";
          if (var2) {
            var keyset = var2.keySet();
            var iter = keyset.iterator();
            while (iter.hasNext()) {
              var key = iter.next();
              var value = var2.get(key);
              valuesStr += "\n    - " + key + " = " + value;
            }
          }
          var logVal = "\nDatabase: \x1B[31m" + dbPath + "\x1B[0m\nInsert (with conflict handling) into table: \x1B[36m" + var0 + "\x1B[0m\nNull column hack: \x1B[35m" + (var1 ? var1 : "null") + "\x1B[0m\nValues to insert:" + (valuesStr ? "\x1B[32m" + valuesStr + "\x1B[0m" : " none") + "\nConflict algorithm: \x1B[34m" + var3 + "\x1B[0m\n";
          am_send(PROFILE_HOOKING_TYPE2, type + " " + methodVal + logVal);
        }
        var insertValueRes = this.insertWithOnConflict(var0, var1, var2, var3);
        return insertValueRes;
      };
      function interpretDatabaseFlags(flags) {
        const flagsMap = {
          0: "OPEN_READONLY",
          1: "OPEN_READWRITE",
          2: "CREATE_IF_NECESSARY",
          4: "NO_LOCALIZED_COLLATORS",
          8: "ENABLE_WRITE_AHEAD_LOGGING",
          16: "OPEN_URI",
          32: "ENABLE_FOREIGN_KEY_CONSTRAINTS",
          536870912: "OPEN_NOMUTEX",
          268435456: "OPEN_FULLMUTEX"
        };
        let flagDescriptions = [];
        for (let flag in flagsMap) {
          const numericFlag = parseInt(flag);
          if ((flags & numericFlag) === numericFlag) {
            flagDescriptions.push(flagsMap[flag]);
          }
        }
        return flagDescriptions.length > 0 ? flagDescriptions.join(" | ") : "UNKNOWN_FLAG";
      }
      sqliteDatabase.openDatabase.overload("java.lang.String", "android.database.sqlite.SQLiteDatabase$CursorFactory", "int").implementation = function(path, factory, flags) {
        if (shouldLogDatabasePath(path)) {
          var flagsDescription = interpretDatabaseFlags(flags);
          createDatabaseEvent("database.sqlite.open", {
            method: "SQLiteDatabase.openDatabase(String, CursorFactory, int)",
            database_path: path,
            flags,
            flags_description: flagsDescription,
            has_factory: factory !== null
          });
        }
        var dbResult = this.openDatabase(path, factory, flags);
        return dbResult;
      };
      sqliteDatabase.openDatabase.overload("java.lang.String", "android.database.sqlite.SQLiteDatabase$CursorFactory", "int", "android.database.DatabaseErrorHandler").implementation = function(path, factory, flags, errorHandler) {
        var type = "\x1B[1;36mevent_type: SQLiteOpenDatabase\x1B[0m";
        var methodVal = "SQLiteDatabase.openDatabase";
        if (shouldLogDatabasePath(path)) {
          var flagsDescription = interpretDatabaseFlags(flags);
          var logVal = "\nOpening database: \x1B[36m" + path + "\x1B[0m\nFlags: \x1B[33m" + flags + " (" + flagsDescription + ")\x1B[0m\nFactory: " + (factory ? "\x1B[32mCustom factory provided\x1B[0m" : "\x1B[90mnull\x1B[0m") + "\nError handler: " + (errorHandler ? "\x1B[35mCustom error handler provided\x1B[0m" : "\x1B[90mnull\x1B[0m") + "\n";
          am_send(PROFILE_HOOKING_TYPE2, type + " " + methodVal + logVal);
        }
        var dbResult = this.openDatabase(path, factory, flags, errorHandler);
        return dbResult;
      };
      sqliteDatabase.openOrCreateDatabase.overload("java.lang.String", "android.database.sqlite.SQLiteDatabase$CursorFactory").implementation = function(path, factory) {
        if (shouldLogDatabasePath(path)) {
          createDatabaseEvent("database.sqlite.open", {
            method: "SQLiteDatabase.openOrCreateDatabase(String, CursorFactory)",
            database_path: path,
            has_factory: factory !== null,
            create_if_necessary: true
          });
        }
        var dbResult = this.openOrCreateDatabase(path, factory);
        return dbResult;
      };
      sqliteDatabase.openOrCreateDatabase.overload("java.lang.String", "android.database.sqlite.SQLiteDatabase$CursorFactory", "android.database.DatabaseErrorHandler").implementation = function(path, factory, errorHandler) {
        var type = "\x1B[1;36mevent_type: SQLiteOpenDatabase\x1B[0m";
        var methodVal = "SQLiteDatabase.openOrCreateDatabase";
        if (shouldLogDatabasePath(path)) {
          var logVal = "\nOpening or creating database: \x1B[36m" + path + "\x1B[0m\nFactory: " + (factory ? "\x1B[32mCustom factory provided\x1B[0m" : "\x1B[90mnull\x1B[0m") + "\nError handler: " + (errorHandler ? "\x1B[35mCustom error handler provided\x1B[0m" : "\x1B[90mnull\x1B[0m") + "\n";
          am_send(PROFILE_HOOKING_TYPE2, type + " " + methodVal + logVal);
        }
        var dbResult = this.openOrCreateDatabase(path, factory, errorHandler);
        return dbResult;
      };
      sqliteDatabase.update.overload("java.lang.String", "android.content.ContentValues", "java.lang.String", "[Ljava.lang.String;").implementation = function(var0, var1, var2, var3) {
        var dbPath = "unknown";
        try {
          dbPath = this.getPath();
        } catch (e) {
          dbPath = "Error getting path: " + e;
        }
        if (shouldLogDatabasePath(dbPath)) {
          var contentValues = {};
          if (var1) {
            var keyset = var1.keySet();
            var iter = keyset.iterator();
            while (iter.hasNext()) {
              var key = iter.next();
              var value = var1.get(key);
              contentValues[key] = value;
            }
          }
          var whereArgs = [];
          if (var3 && var3.length > 0) {
            for (var i = 0; i < var3.length; i++) {
              whereArgs.push(var3[i]);
            }
          }
          createDatabaseEvent("database.sqlite.update", {
            method: "SQLiteDatabase.update(String, ContentValues, String, String[])",
            database_path: dbPath,
            table: var0,
            content_values: contentValues,
            where_clause: var2,
            where_args: whereArgs
          });
        }
        var updateRes = this.update(var0, var1, var2, var3);
        return updateRes;
      };
      sqliteDatabase.updateWithOnConflict.overload("java.lang.String", "android.content.ContentValues", "java.lang.String", "[Ljava.lang.String;", "int").implementation = function(var0, var1, var2, var3, var4) {
        var type = "\x1B[1;32mevent_type: SQLiteUpdate\x1B[0m";
        var methodVal = "SQLiteDatabase.updateWithOnConflict";
        var dbPath = "unknown";
        try {
          dbPath = this.getPath();
        } catch (e) {
          dbPath = "Error getting path: " + e;
        }
        if (shouldLogDatabasePath(dbPath)) {
          var valuesStr = "";
          if (var1) {
            var keyset = var1.keySet();
            var iter = keyset.iterator();
            while (iter.hasNext()) {
              var key = iter.next();
              var value = var1.get(key);
              valuesStr += "\n    - " + key + " = " + value;
            }
          }
          var whereArgsStr = "";
          if (var3 && var3.length > 0) {
            for (var i = 0; i < var3.length; i++) {
              whereArgsStr += "\n    - [" + i + "] " + var3[i];
            }
          }
          var logVal = "\nDatabase: \x1B[31m" + dbPath + "\x1B[0m\nUpdate table: \x1B[36m" + var0 + "\x1B[0m\nWhere clause: \x1B[35m" + var2 + "\x1B[0m\nWhere args:" + (whereArgsStr ? "\x1B[33m" + whereArgsStr + "\x1B[0m" : " none") + "\nValues to update:" + (valuesStr ? "\x1B[32m" + valuesStr + "\x1B[0m" : " none") + "\nConflict algorithm: \x1B[34m" + var4 + "\x1B[0m\n";
          am_send(PROFILE_HOOKING_TYPE2, type + " " + methodVal + logVal);
        }
        var updateRes = this.updateWithOnConflict(var0, var1, var2, var3, var4);
        return updateRes;
      };
      sqliteDatabase.delete.overload("java.lang.String", "java.lang.String", "[Ljava.lang.String;").implementation = function(var0, var1, var2) {
        var dbPath = "unknown";
        try {
          dbPath = this.getPath();
        } catch (e) {
          dbPath = "Error getting path: " + e;
        }
        if (shouldLogDatabasePath(dbPath)) {
          var whereArgs = [];
          if (var2 && var2.length > 0) {
            for (var i = 0; i < var2.length; i++) {
              whereArgs.push(var2[i]);
            }
          }
          createDatabaseEvent("database.sqlite.delete", {
            method: "SQLiteDatabase.delete(String, String, String[])",
            database_path: dbPath,
            table: var0,
            where_clause: var1,
            where_args: whereArgs
          });
        }
        var deleteRes = this.delete(var0, var1, var2);
        if (shouldLogDatabasePath(dbPath)) {
          createDatabaseEvent("database.sqlite.delete_result", {
            method: "SQLiteDatabase.delete(String, String, String[])",
            database_path: dbPath,
            table: var0,
            rows_affected: deleteRes
          });
        }
        return deleteRes;
      };
    });
  });
}
function hook_SQLCipher() {
  setImmediate(function() {
    Java.perform(function() {
      var SQLiteOpenHelper = Java.use("net.sqlcipher.database.SQLiteOpenHelper");
      SQLiteOpenHelper.getWritableDatabase.overload("java.lang.String").implementation = function(password) {
        createDatabaseEvent("database.sqlcipher.open", {
          method: "SQLiteOpenHelper.getWritableDatabase(String)",
          password,
          database_type: "SQLCipher",
          access_type: "writable"
        });
        return this.getWritableDatabase.overload("java.lang.String").apply(this, arguments);
      };
      const SQLiteDatabase = Java.use("net.sqlcipher.database.SQLiteDatabase");
      SQLiteDatabase.openOrCreateDatabase.overload("java.io.File", "java.lang.String").implementation = function(file, password) {
        createDatabaseEvent("database.sqlcipher.open", {
          method: "SQLiteDatabase.openOrCreateDatabase(File, String)",
          database_path: file.getAbsolutePath(),
          password,
          database_type: "SQLCipher",
          create_if_necessary: true
        });
        const result = this.openOrCreateDatabase(file, password);
        return result;
      };
      const sendLog = (eventType, methodName, logMessage) => {
        const log2 = `event_type: ${eventType}, method: ${methodName}, ${logMessage}`;
        am_send(PROFILE_HOOKING_TYPE2, log2);
      };
      SQLiteDatabase.openOrCreateDatabase.overload("java.io.File", "java.lang.String").implementation = function(file, password) {
        const method = "openOrCreateDatabase(File, String)";
        sendLog("SQLCipher.database.SQLiteDatabase", method, `Accessing SQLCipher database at ${file.getAbsolutePath()} with password: ${password}`);
        return this.openOrCreateDatabase(file, password);
      };
      SQLiteDatabase.openOrCreateDatabase.overload("java.lang.String", "[C").implementation = function(path, password) {
        const method = "openOrCreateDatabase(String, char[])";
        const passwordStr = password ? Java.array("char", password).join("") : "null";
        sendLog("SQLCipher.database.SQLiteDatabase", method, `Accessing SQLCipher database at ${path} with password: ${passwordStr}`);
        return this.openOrCreateDatabase(path, password);
      };
      SQLiteDatabase.rawExecSQL.overload("java.lang.String").implementation = function(sql) {
        const method = "rawExecSQL(String)";
        sendLog("SQLCipher.database.SQLiteDatabase", method, `Executing raw SQL: ${sql}`);
        return this.rawExecSQL(sql);
      };
      SQLiteDatabase.execSQL.overload("java.lang.String").implementation = function(sql) {
        createDatabaseEvent("database.sqlcipher.exec", {
          method: "SQLiteDatabase.execSQL(String)",
          sql,
          database_type: "SQLCipher"
        });
        return this.execSQL(sql);
      };
      SQLiteDatabase.getWritableDatabase.overload("java.lang.String").implementation = function(password) {
        createDatabaseEvent("database.sqlcipher.open", {
          method: "SQLiteDatabase.getWritableDatabase(String)",
          password,
          database_type: "SQLCipher",
          access_type: "writable"
        });
        return this.getWritableDatabase(password);
      };
      SQLiteDatabase.getReadableDatabase.overload("java.lang.String").implementation = function(password) {
        createDatabaseEvent("database.sqlcipher.open", {
          method: "SQLiteDatabase.getReadableDatabase(String)",
          password,
          database_type: "SQLCipher",
          access_type: "readable"
        });
        return this.getReadableDatabase(password);
      };
      SQLiteDatabase.close.implementation = function() {
        const method = "close()";
        sendLog("SQLCipher.database.SQLiteDatabase", method, "Closing SQLCipher database");
        return this.close();
      };
      SQLiteDatabase.beginTransaction.implementation = function() {
        createDatabaseEvent("database.sqlcipher.transaction", {
          method: "SQLiteDatabase.beginTransaction()",
          database_type: "SQLCipher",
          transaction_action: "begin"
        });
        return this.beginTransaction();
      };
      SQLiteDatabase.endTransaction.implementation = function() {
        createDatabaseEvent("database.sqlcipher.transaction", {
          method: "SQLiteDatabase.endTransaction()",
          database_type: "SQLCipher",
          transaction_action: "end"
        });
        return this.endTransaction();
      };
    });
  });
}
function hook_sql_related_stuff() {
}
function hook_room_library() {
  setImmediate(function() {
    Java.perform(function() {
      const Room = Java.use("androidx.room.Room");
      Room.databaseBuilder.overload("android.content.Context", "java.lang.Class", "java.lang.String").implementation = function(context, klass, dbName) {
        createDatabaseEvent("database.room.builder", {
          method: "Room.databaseBuilder(Context, Class, String)",
          database_name: dbName,
          database_class: klass.toString(),
          database_type: "Room"
        });
        const result = this.databaseBuilder(context, klass, dbName);
        return result;
      };
      const SQLiteDatabase = Java.use("net.sqlcipher.database.SQLiteDatabase");
      SQLiteDatabase.openOrCreateDatabase.overload("java.io.File", "java.lang.String").implementation = function(file, password) {
        const methodVal = "SQLiteDatabase.openOrCreateDatabase(File, String), ";
        const logVal = `Opening or creating database with file: ${file.getAbsolutePath()} and password: ${password}`;
        am_send(PROFILE_HOOKING_TYPE2, `event_type: SQLCipher.database.SQLiteDatabase, ${methodVal}${logVal}`);
        return this.openOrCreateDatabase(file, password);
      };
      SQLiteDatabase.openOrCreateDatabase.overload("java.lang.String", "java.lang.String").implementation = function(path, password) {
        const methodVal = "SQLiteDatabase.openOrCreateDatabase(String, String), ";
        const logVal = `Opening or creating database with path: ${path} and password: ${password}`;
        am_send(PROFILE_HOOKING_TYPE2, `event_type: SQLCipher.database.SQLiteDatabase, ${methodVal}${logVal}`);
        return this.openOrCreateDatabase(path, password);
      };
      const SupportSQLiteOpenHelper_Callback = Java.use("androidx.sqlite.db.SupportSQLiteOpenHelper$Callback");
      SupportSQLiteOpenHelper_Callback.onCreate.implementation = function(db) {
        createDatabaseEvent("database.room.callback", {
          method: "SupportSQLiteOpenHelper.Callback.onCreate(SupportSQLiteDatabase)",
          database_object: db.toString(),
          callback_type: "onCreate",
          database_type: "Room"
        });
        return this.onCreate(db);
      };
      SupportSQLiteOpenHelper_Callback.onOpen.implementation = function(db) {
        createDatabaseEvent("database.room.callback", {
          method: "SupportSQLiteOpenHelper.Callback.onOpen(SupportSQLiteDatabase)",
          database_object: db.toString(),
          callback_type: "onOpen",
          database_type: "Room"
        });
        return this.onOpen(db);
      };
      SQLiteDatabase.execSQL.overload("java.lang.String").implementation = function(sql) {
        if (sql.toLowerCase().includes("pragma key")) {
          createDatabaseEvent("database.sqlcipher.pragma", {
            method: "SQLiteDatabase.execSQL(String)",
            sql,
            pragma_type: "key",
            database_type: "SQLCipher"
          });
        }
        return this.execSQL(sql);
      };
      const Dao = Java.use("androidx.room.RoomDatabase");
      Dao.insert.overload("java.lang.Object").implementation = function(entity) {
        createDatabaseEvent("database.room.dao", {
          method: "RoomDatabase.insert(Object)",
          entity: entity.toString(),
          dao_operation: "insert",
          database_type: "Room"
        });
        return this.insert(entity);
      };
      Dao.update.overload("java.lang.Object").implementation = function(entity) {
        createDatabaseEvent("database.room.dao", {
          method: "RoomDatabase.update(Object)",
          entity: entity.toString(),
          dao_operation: "update",
          database_type: "Room"
        });
        return this.update(entity);
      };
      Dao.delete.overload("java.lang.Object").implementation = function(entity) {
        createDatabaseEvent("database.room.dao", {
          method: "RoomDatabase.delete(Object)",
          entity: entity.toString(),
          dao_operation: "delete",
          database_type: "Room"
        });
        return this.delete(entity);
      };
      const RoomDatabaseQuery = Java.use("androidx.room.RoomDatabase");
      RoomDatabaseQuery.query.overload("androidx.sqlite.db.SupportSQLiteQuery").implementation = function(query) {
        const methodVal = "RoomDatabase.query, ";
        const logVal = `Query executed: ${query.toString()}`;
        am_send(PROFILE_HOOKING_TYPE2, `event_type: Room.Database, ${methodVal}${logVal}`);
        return this.query(query);
      };
      const SupportSQLiteDatabase = Java.use("androidx.sqlite.db.SupportSQLiteDatabase");
      SupportSQLiteDatabase.execSQL.overload("java.lang.String").implementation = function(sql) {
        const methodVal = "SupportSQLiteDatabase.execSQL, ";
        const logVal = `Executing SQL: ${sql}`;
        am_send(PROFILE_HOOKING_TYPE2, `event_type: Room.Database, ${methodVal}${logVal}`);
        return this.execSQL(sql);
      };
      const LiveData = Java.use("androidx.lifecycle.LiveData");
      LiveData.observe.overload("androidx.lifecycle.LifecycleOwner", "androidx.lifecycle.Observer").implementation = function(owner, observer) {
        const methodVal = "LiveData.observe, ";
        const logVal = `LiveData observed with LifecycleOwner: ${owner.toString()}`;
        am_send(PROFILE_HOOKING_TYPE2, `event_type: Room.LiveData, ${methodVal}${logVal}`);
        return this.observe(owner, observer);
      };
      const FlowCollector = Java.use("kotlinx.coroutines.flow.FlowCollector");
      FlowCollector.emit.overload("java.lang.Object").implementation = function(value) {
        const methodVal = "FlowCollector.emit, ";
        const logVal = `Flow emitted value: ${value}`;
        am_send(PROFILE_HOOKING_TYPE2, `event_type: Room.Flow, ${methodVal}${logVal}`);
        return this.emit(value);
      };
    });
  });
}
function hook_wcdb() {
  setImmediate(function() {
    Java.perform(function() {
      try {
        let interpretDatabaseFlags2 = function(flags) {
          const flagsMap = {
            0: "OPEN_READONLY",
            1: "OPEN_READWRITE",
            2: "CREATE_IF_NECESSARY",
            4: "NO_LOCALIZED_COLLATORS",
            8: "ENABLE_WRITE_AHEAD_LOGGING",
            16: "OPEN_URI",
            32: "ENABLE_FOREIGN_KEY_CONSTRAINTS",
            536870912: "OPEN_NOMUTEX",
            268435456: "OPEN_FULLMUTEX"
          };
          let flagDescriptions = [];
          for (let flag in flagsMap) {
            const numericFlag = parseInt(flag);
            if ((flags & numericFlag) === numericFlag) {
              flagDescriptions.push(flagsMap[flag]);
            }
          }
          return flagDescriptions.length > 0 ? flagDescriptions.join(" | ") : "UNKNOWN_FLAG";
        };
        var interpretDatabaseFlags = interpretDatabaseFlags2;
        const wcdbDatabase = Java.use("com.tencent.wcdb.database.SQLiteDatabase");
        devlog("WCDB hooks being installed");
        wcdbDatabase.openDatabase.overload("java.lang.String", "com.tencent.wcdb.database.SQLiteDatabase$CursorFactory", "int").implementation = function(path, factory, flags) {
          var type = "\x1B[1;36mevent_type: WCDBOpenDatabase\x1B[0m";
          var methodVal = "WCDB.SQLiteDatabase.openDatabase";
          if (shouldLogDatabasePath(path)) {
            var flagsDescription = interpretDatabaseFlags2(flags);
            var logVal = "\nOpening WCDB database: \x1B[36m" + path + "\x1B[0m\nFlags: \x1B[33m" + flags + " (" + flagsDescription + ")\x1B[0m\nFactory: " + (factory ? "\x1B[32mCustom factory provided\x1B[0m" : "\x1B[90mnull\x1B[0m") + "\n";
            am_send(PROFILE_HOOKING_TYPE2, type + " " + methodVal + logVal);
          }
          var dbResult = this.openDatabase(path, factory, flags);
          return dbResult;
        };
        wcdbDatabase.openOrCreateDatabase.overload("java.lang.String", "com.tencent.wcdb.database.SQLiteDatabase$CursorFactory").implementation = function(path, factory) {
          var type = "\x1B[1;36mevent_type: WCDBOpenDatabase\x1B[0m";
          var methodVal = "WCDB.SQLiteDatabase.openOrCreateDatabase";
          if (shouldLogDatabasePath(path)) {
            var logVal = "\nOpening or creating WCDB database: \x1B[36m" + path + "\x1B[0m\nFactory: " + (factory ? "\x1B[32mCustom factory provided\x1B[0m" : "\x1B[90mnull\x1B[0m") + "\n";
            am_send(PROFILE_HOOKING_TYPE2, type + " " + methodVal + logVal);
          }
          var dbResult = this.openOrCreateDatabase(path, factory);
          return dbResult;
        };
        wcdbDatabase.execSQL.overload("java.lang.String").implementation = function(sql) {
          var type = "\x1B[1;35mevent_type: WCDBExecSQL\x1B[0m";
          var methodVal = "WCDB.SQLiteDatabase.execSQL";
          var dbPath = "unknown";
          try {
            dbPath = this.getPath();
          } catch (e) {
            dbPath = "Error getting path: " + e;
          }
          if (shouldLogDatabasePath(dbPath)) {
            var logVal = "\nDatabase: \x1B[31m" + dbPath + "\x1B[0m\nExecuting SQL: \x1B[36m" + sql + "\x1B[0m\n";
            am_send(PROFILE_HOOKING_TYPE2, type + " " + methodVal + logVal);
          }
          var execSQLRes = this.execSQL(sql);
          return execSQLRes;
        };
        wcdbDatabase.execSQL.overload("java.lang.String", "[Ljava.lang.Object;").implementation = function(sql, bindArgs) {
          var type = "\x1B[1;35mevent_type: WCDBExecSQL\x1B[0m";
          var methodVal = "WCDB.SQLiteDatabase.execSQL";
          var dbPath = "unknown";
          try {
            dbPath = this.getPath();
          } catch (e) {
            dbPath = "Error getting path: " + e;
          }
          if (shouldLogDatabasePath(dbPath)) {
            var argsStr = "";
            if (bindArgs && bindArgs.length > 0) {
              for (var i = 0; i < bindArgs.length; i++) {
                argsStr += "\n    - [" + i + "] " + bindArgs[i];
              }
            }
            var logVal = "\nDatabase: \x1B[31m" + dbPath + "\x1B[0m\nExecuting SQL: \x1B[36m" + sql + "\x1B[0m\nBind arguments:" + (argsStr ? "\x1B[33m" + argsStr + "\x1B[0m" : " none") + "\n";
            am_send(PROFILE_HOOKING_TYPE2, type + " " + methodVal + logVal);
          }
          var execSQLRes = this.execSQL(sql, bindArgs);
          return execSQLRes;
        };
        wcdbDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;").implementation = function(sql, selectionArgs) {
          var type = "\x1B[1;34mevent_type: WCDBRawQuery\x1B[0m";
          var methodVal = "WCDB.SQLiteDatabase.rawQuery";
          var dbPath = "unknown";
          try {
            dbPath = this.getPath();
          } catch (e) {
            dbPath = "Error getting path: " + e;
          }
          if (shouldLogDatabasePath(dbPath)) {
            var argsStr = "";
            if (selectionArgs && selectionArgs.length > 0) {
              for (var i = 0; i < selectionArgs.length; i++) {
                argsStr += "\n    - [" + i + "] " + selectionArgs[i];
              }
            }
            var logVal = "\nDatabase: \x1B[31m" + dbPath + "\x1B[0m\nSQL Query: \x1B[36m" + sql + "\x1B[0m\nSelection args:" + (argsStr ? "\x1B[33m" + argsStr + "\x1B[0m" : " none") + "\n";
            am_send(PROFILE_HOOKING_TYPE2, type + " " + methodVal + logVal);
          }
          var rawQueryRes = this.rawQuery(sql, selectionArgs);
          return rawQueryRes;
        };
        wcdbDatabase.insert.overload("java.lang.String", "java.lang.String", "android.content.ContentValues").implementation = function(table, nullColumnHack, values) {
          var type = "\x1B[1;33mevent_type: WCDBInsert\x1B[0m";
          var methodVal = "WCDB.SQLiteDatabase.insert";
          var dbPath = "unknown";
          try {
            dbPath = this.getPath();
          } catch (e) {
            dbPath = "Error getting path: " + e;
          }
          if (shouldLogDatabasePath(dbPath)) {
            var valuesStr = "";
            if (values) {
              var keyset = values.keySet();
              var iter = keyset.iterator();
              while (iter.hasNext()) {
                var key = iter.next();
                var value = values.get(key);
                valuesStr += "\n    - " + key + " = " + value;
              }
            }
            var logVal = "\nDatabase: \x1B[31m" + dbPath + "\x1B[0m\nInsert into table: \x1B[36m" + table + "\x1B[0m\nNull column hack: \x1B[35m" + (nullColumnHack ? nullColumnHack : "null") + "\x1B[0m\nValues to insert:" + (valuesStr ? "\x1B[32m" + valuesStr + "\x1B[0m" : " none") + "\n";
            am_send(PROFILE_HOOKING_TYPE2, type + " " + methodVal + logVal);
          }
          var insertValueRes = this.insert(table, nullColumnHack, values);
          return insertValueRes;
        };
        wcdbDatabase.update.overload("java.lang.String", "android.content.ContentValues", "java.lang.String", "[Ljava.lang.String;").implementation = function(table, values, whereClause, whereArgs) {
          var type = "\x1B[1;32mevent_type: WCDBUpdate\x1B[0m";
          var methodVal = "WCDB.SQLiteDatabase.update";
          var dbPath = "unknown";
          try {
            dbPath = this.getPath();
          } catch (e) {
            dbPath = "Error getting path: " + e;
          }
          if (shouldLogDatabasePath(dbPath)) {
            var valuesStr = "";
            if (values) {
              var keyset = values.keySet();
              var iter = keyset.iterator();
              while (iter.hasNext()) {
                var key = iter.next();
                var value = values.get(key);
                valuesStr += "\n    - " + key + " = " + value;
              }
            }
            var whereArgsStr = "";
            if (whereArgs && whereArgs.length > 0) {
              for (var i = 0; i < whereArgs.length; i++) {
                whereArgsStr += "\n    - [" + i + "] " + whereArgs[i];
              }
            }
            var logVal = "\nDatabase: \x1B[31m" + dbPath + "\x1B[0m\nUpdate table: \x1B[36m" + table + "\x1B[0m\nWhere clause: \x1B[35m" + whereClause + "\x1B[0m\nWhere args:" + (whereArgsStr ? "\x1B[33m" + whereArgsStr + "\x1B[0m" : " none") + "\nValues to update:" + (valuesStr ? "\x1B[32m" + valuesStr + "\x1B[0m" : " none") + "\n";
            am_send(PROFILE_HOOKING_TYPE2, type + " " + methodVal + logVal);
          }
          var updateRes = this.update(table, values, whereClause, whereArgs);
          return updateRes;
        };
        wcdbDatabase.delete.overload("java.lang.String", "java.lang.String", "[Ljava.lang.String;").implementation = function(table, whereClause, whereArgs) {
          var type = "\x1B[1;31mevent_type: WCDBDelete\x1B[0m";
          var methodVal = "WCDB.SQLiteDatabase.delete";
          var dbPath = "unknown";
          try {
            dbPath = this.getPath();
          } catch (e) {
            dbPath = "Error getting path: " + e;
          }
          if (shouldLogDatabasePath(dbPath)) {
            var whereArgsStr = "";
            if (whereArgs && whereArgs.length > 0) {
              for (var i = 0; i < whereArgs.length; i++) {
                whereArgsStr += "\n    - [" + i + "] " + whereArgs[i];
              }
            }
            var logVal = "\nDatabase: \x1B[31m" + dbPath + "\x1B[0m\nDelete from table: \x1B[36m" + table + "\x1B[0m\nWhere clause: \x1B[35m" + (whereClause ? whereClause : "null (delete all rows)") + "\x1B[0m\nWhere args:" + (whereArgsStr ? "\x1B[33m" + whereArgsStr + "\x1B[0m" : " none") + "\n";
            am_send(PROFILE_HOOKING_TYPE2, type + " " + methodVal + logVal);
          }
          var deleteRes = this.delete(table, whereClause, whereArgs);
          if (shouldLogDatabasePath(dbPath)) {
            var rowCountMsg = "Rows affected: \x1B[32m" + deleteRes + "\x1B[0m";
            am_send(PROFILE_HOOKING_TYPE2, type + " " + methodVal + " " + rowCountMsg);
          }
          return deleteRes;
        };
        wcdbDatabase.beginTransaction.implementation = function() {
          var type = "\x1B[1;90mevent_type: WCDBTransaction\x1B[0m";
          var methodVal = "WCDB.SQLiteDatabase.beginTransaction";
          var dbPath = "unknown";
          try {
            dbPath = this.getPath();
          } catch (e) {
            dbPath = "Error getting path: " + e;
          }
          if (shouldLogDatabasePath(dbPath)) {
            var logVal = "\nDatabase: \x1B[31m" + dbPath + "\x1B[0m\nBeginning transaction\n";
            am_send(PROFILE_HOOKING_TYPE2, type + " " + methodVal + logVal);
          }
          return this.beginTransaction();
        };
        wcdbDatabase.endTransaction.implementation = function() {
          var type = "\x1B[1;90mevent_type: WCDBTransaction\x1B[0m";
          var methodVal = "WCDB.SQLiteDatabase.endTransaction";
          var dbPath = "unknown";
          try {
            dbPath = this.getPath();
          } catch (e) {
            dbPath = "Error getting path: " + e;
          }
          if (shouldLogDatabasePath(dbPath)) {
            var logVal = "\nDatabase: \x1B[31m" + dbPath + "\x1B[0m\nEnding transaction\n";
            am_send(PROFILE_HOOKING_TYPE2, type + " " + methodVal + logVal);
          }
          return this.endTransaction();
        };
        wcdbDatabase.setTransactionSuccessful.implementation = function() {
          var type = "\x1B[1;90mevent_type: WCDBTransaction\x1B[0m";
          var methodVal = "WCDB.SQLiteDatabase.setTransactionSuccessful";
          var dbPath = "unknown";
          try {
            dbPath = this.getPath();
          } catch (e) {
            dbPath = "Error getting path: " + e;
          }
          if (shouldLogDatabasePath(dbPath)) {
            var logVal = "\nDatabase: \x1B[31m" + dbPath + "\x1B[0m\nMarking transaction as successful\n";
            am_send(PROFILE_HOOKING_TYPE2, type + " " + methodVal + logVal);
          }
          return this.setTransactionSuccessful();
        };
      } catch (e) {
        devlog("WCDB hooking failed: " + e);
      }
    });
  });
}
function install_database_hooks() {
  devlog("\n");
  devlog("install sql hooks");
  hook_java_sql();
  hook_SQLCipher();
  hook_wcdb();
  hook_room_library();
  hook_sql_related_stuff();
}

// agent/utils/android_runtime_requests.ts
function getAndroidVersion2() {
  var version = 0;
  if (Java.available) {
    var version = parseInt(Java.androidVersion);
  } else {
    devlog("Error: cannot get android version");
  }
  return version;
}
function get_filename(path) {
  var filename = "";
  let lastSlashIndex = path.lastIndexOf("/");
  filename = path.substring(lastSlashIndex + 1);
  return filename;
}
function removeLeadingColon(input) {
  if (input.startsWith(":")) {
    return input.substring(1);
  }
  return input;
}
function copy_file(PROFILE_HOOKING_TYPE22, source, destinationPath) {
  var filename = get_filename(source);
  var destination = destinationPath + "/" + filename;
  Java.perform(function() {
    am_send(PROFILE_HOOKING_TYPE22, "creating local copy of unpacked file");
    const File2 = Java.use("java.io.File");
    const FileInputStream = Java.use("java.io.FileInputStream");
    const FileOutputStream = Java.use("java.io.FileOutputStream");
    var sourceFile = File2.$new(source);
    if (sourceFile.exists() && sourceFile.canRead()) {
      var fis = FileInputStream.$new(sourceFile);
      var inputChannel = fis.getChannel();
      var destinationFile = File2.$new(destination);
      destinationFile.createNewFile();
      var fos = FileOutputStream.$new(destinationFile);
      var outputChannel = fos.getChannel();
      inputChannel.transferTo(0, inputChannel.size(), outputChannel);
      fis.close();
      fos.close();
      am_send(PROFILE_HOOKING_TYPE22, "dumped successfully @ " + destination + "\n");
    } else {
      am_send(PROFILE_HOOKING_TYPE22, "file has already been deleted");
    }
  });
}

// agent/dex/dex_unpacking.ts
var PROFILE_HOOKING_TYPE3 = "DEX_LOADING";
function createDEXEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE3, JSON.stringify(event));
}
function get_package_name() {
  var package_name = "";
  Java.perform(function() {
    try {
      var context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
      var packageName = context.getPackageName();
      package_name = packageName;
    } catch (e) {
    }
  });
  return package_name;
}
function readStdString(ptr_str) {
  const isTiny = (ptr_str.readU8() & 1) === 0;
  if (isTiny) {
    return ptr_str.add(1).readUtf8String();
  }
  return ptr_str.add(2 * Process.pointerSize).readPointer().readUtf8String();
}
function getFunctionName(g_AndroidOSVersion) {
  var i = 0;
  var functionName = "";
  if (g_AndroidOSVersion > 4) {
    const soName = g_AndroidOSVersion >= 10 ? "libdexfile.so" : "libart.so";
    const artModule = Process.getModuleByName(soName);
    var artExports = artModule.enumerateExports();
    for (i = 0; i < artExports.length; i++) {
      if (artExports[i].name.indexOf("OpenMemory") !== -1) {
        functionName = artExports[i].name;
        break;
      } else if (artExports[i].name.indexOf("OpenCommon") !== -1) {
        if (g_AndroidOSVersion >= 10 && artExports[i].name.indexOf("ArtDexFileLoader") !== -1)
          continue;
        functionName = artExports[i].name;
        break;
      }
    }
  } else {
    const dvmModule = Process.getModuleByName("libdvm.so");
    var dvmExports = dvmModule.enumerateExports();
    if (dvmExports.length !== 0) {
      for (i = 0; i < dvmExports.length; i++) {
        if (dvmExports[i].name.indexOf("dexFileParse") !== -1) {
          functionName = dvmExports[i].name;
          break;
        }
      }
    } else {
      const libartModule = Process.getModuleByName("libart.so");
      dvmExports = libartModule.enumerateExports();
      for (i = 0; i < dvmExports.length; i++) {
        if (dvmExports[i].name.indexOf("OpenMemory") !== -1) {
          functionName = dvmExports[i].name;
          break;
        }
      }
    }
  }
  return functionName;
}
function getg_processName() {
  let g_processName = "";
  const libcModule = Process.getModuleByName("libc.so");
  var fopenPtr = libcModule.findExportByName("fopen");
  var fgetsPtr = libcModule.findExportByName("fgets");
  var fclosePtr = libcModule.findExportByName("fclose");
  var fopenFunc = new NativeFunction(fopenPtr, "pointer", ["pointer", "pointer"]);
  var fgetsFunc = new NativeFunction(fgetsPtr, "int", ["pointer", "int", "pointer"]);
  var fcloseFunc = new NativeFunction(fclosePtr, "int", ["pointer"]);
  var pathPtr = Memory.allocUtf8String("/proc/self/cmdline");
  var openFlagsPtr = Memory.allocUtf8String("r");
  var fp = fopenFunc(pathPtr, openFlagsPtr);
  if (fp.isNull() === false) {
    var buffData = Memory.alloc(128);
    var ret = fgetsFunc(buffData, 128, fp);
    if (ret !== 0) {
      g_processName = buffData.readCString();
    }
    fcloseFunc(fp);
  }
  return g_processName;
}
function checkMagic(dataAddr) {
  let dexMagic = "dex\n";
  let dexVersions = ["035", "037", "038", "039", "040"];
  let odexVersions = ["036"];
  let kDexMagic = "cdex";
  let kDexVersions = ["001"];
  let magicTrailing = 0;
  let readData;
  try {
    readData = dataAddr.readByteArray(8);
  } catch (e) {
    devlog("Error reading memory at address" + dataAddr);
    return { found: false, wrongMagic: 3735928559 };
  }
  let magic = Array.from(new Uint8Array(readData));
  let foundStart = magic.slice(0, 4).map((i) => String.fromCharCode(i)).join("");
  let foundVersion = magic.slice(4, 7).map((i) => String.fromCharCode(i)).join("");
  let foundMagicString = foundStart.replace("\n", "") + foundVersion;
  if (foundStart === dexMagic && dexVersions.includes(foundVersion) && magic[7] === magicTrailing) {
    return { found: true, ext: "dex", sizeOffset: 32, magicString: foundMagicString };
  } else if (foundStart === dexMagic && odexVersions.includes(foundVersion) && magic[7] === magicTrailing) {
    return { found: true, ext: "odex", sizeOffset: 28, magicString: foundMagicString };
  } else if (foundStart === kDexMagic && kDexVersions.includes(foundVersion) && magic[7] === magicTrailing) {
    return { found: true, ext: "cdex", sizeOffset: 32, magicString: foundMagicString };
  } else {
    return { found: false, wrongMagic: magic };
  }
}
function dumpDexToFile(begin, dexInfo, processName, location, hooked_fct) {
  const dexSize = begin.add(dexInfo.sizeOffset).readInt();
  let dexPath = "/data/data/" + processName + "/" + dexSize + "." + dexInfo.ext;
  let dexFile;
  try {
    dexFile = new File(dexPath, "wb");
  } catch (e) {
    const g_package_name = get_package_name();
    dexPath = "/data/data/" + g_package_name + "/" + dexSize + "." + dexInfo.ext;
    if (g_package_name.length > 4) {
      createDEXEvent("dex.unpacking.file_creation", {
        attempted_path: dexPath,
        package_name: g_package_name
      });
    }
    dexFile = new File(dexPath, "wb");
  }
  const dexBuffer = begin.readByteArray(dexSize);
  if (dexBuffer) {
    dexFile.write(dexBuffer);
  }
  dexFile.flush();
  dexFile.close();
  createDEXEvent("dex.unpacking.detected", {
    hooked_function: hooked_fct,
    magic: dexInfo.magicString,
    version: dexInfo.version,
    size: dexSize,
    original_location: location,
    dumped_path: dexPath,
    file_type: dexInfo.ext
  });
}
function dumpDex(moduleFuncName, g_processName, g_AndroidOSVersion) {
  let wrongMagic0;
  if (moduleFuncName == "") {
    devlog("Error: cannot find correct module function.");
    return;
  }
  var hookFunction;
  var hooked_fct;
  if (g_AndroidOSVersion > 4) {
    const libartModule = Process.getModuleByName("libart.so");
    hookFunction = libartModule.findExportByName(moduleFuncName);
    hooked_fct = "Libart.so::" + moduleFuncName;
  } else {
    const libdvmModule = Process.getModuleByName("libdvm.so");
    hookFunction = libdvmModule.findExportByName(moduleFuncName);
    if (hookFunction == null) {
      const libartModule = Process.getModuleByName("libart.so");
      hookFunction = libartModule.findExportByName(moduleFuncName);
      hooked_fct = "Libart.so::" + moduleFuncName;
    } else {
      hooked_fct = "Libdvm.so::" + moduleFuncName;
    }
  }
  Interceptor.attach(hookFunction, {
    onEnter: function(args) {
      let begin, dexInfo, location;
      dexInfo = checkMagic(args[0]);
      begin = args[0];
      if (!dexInfo.found) {
        wrongMagic0 = dexInfo.wrongMagic;
        dexInfo = checkMagic(args[1]);
        begin = args[1];
      }
      if (!dexInfo.found) {
        throw new Error("Could not identify magic, found invalid values " + wrongMagic0.map((i) => i.toString(16).padStart(2, "0")).join("") + " " + dexInfo.wrongMagic.map((i) => i.toString(16).padStart(2, "0")).join(""));
      }
      for (let i = 0; i < 10; i++) {
        try {
          location = readStdString(args[i]);
        } catch {
        }
        if (location != null && location.length > 0 && location.includes("/")) {
          break;
        }
      }
      dumpDexToFile(begin, dexInfo, g_processName, location, hooked_fct);
    }
  });
}
function install_dex_memory_hooks() {
  devlog("Installing DEX memory-based unpacking hooks");
  const g_AndroidOSVersion = getAndroidVersion2();
  const g_moduleFunctionName = getFunctionName(g_AndroidOSVersion);
  const g_processName = getg_processName();
  if (g_moduleFunctionName !== "" && g_processName !== "") {
    dumpDex(g_moduleFunctionName, g_processName, g_AndroidOSVersion);
    dex_api_unpacking(g_processName);
  }
}
function install_dex_classloader_hooks() {
  devlog("Installing DEX class loader hooks");
  const g_processName = getg_processName();
  if (g_processName !== "") {
    dex_api_unpacking(g_processName);
  }
}
function dump(file_path, dst_path) {
  const location = removeLeadingColon(file_path);
  createDEXEvent("dex.file_copy", {
    original_location: location,
    destination_path: dst_path
  });
  copy_file(PROFILE_HOOKING_TYPE3, location, dst_path);
}
function dex_api_unpacking(g_processName) {
  Java.perform(() => {
    const filename = "/data/data/" + g_processName + "/dump.dex";
    const dst_path = "/data/data/" + g_processName;
    const dexclassLoader = Java.use("dalvik.system.DexClassLoader");
    dexclassLoader.$init.implementation = function(filepath, b, c, d) {
      createDEXEvent("dex.classloader.creation", {
        class_loader_type: "DexClassLoader",
        file_path: filepath,
        method: "$init(String, String, String, ClassLoader)"
      });
      dump(filepath, dst_path);
      return this.$init(filepath, b, c, d);
    };
    const pathLoader = Java.use("dalvik.system.PathClassLoader");
    pathLoader.$init.overload("java.lang.String", "java.lang.ClassLoader").implementation = function(file_path, parent) {
      createDEXEvent("dex.classloader.creation", {
        class_loader_type: "PathClassLoader",
        file_path,
        method: "$init(String, ClassLoader)"
      });
      dump(file_path, dst_path);
      return this.$init(file_path, parent);
    };
    pathLoader.$init.overload("java.lang.String", "java.lang.String", "java.lang.ClassLoader").implementation = function(file_path, librarySearchPath, parent) {
      createDEXEvent("dex.classloader.creation", {
        class_loader_type: "PathClassLoader",
        file_path,
        library_search_path: librarySearchPath,
        method: "$init(String, String, ClassLoader)"
      });
      dump(file_path, dst_path);
      return this.$init(file_path, librarySearchPath, parent);
    };
    const delegateLoader = Java.use("dalvik.system.DelegateLastClassLoader");
    delegateLoader.$init.overload("java.lang.String", "java.lang.ClassLoader").implementation = function(file_path, parent) {
      createDEXEvent("dex.classloader.creation", {
        class_loader_type: "DelegateLastClassLoader",
        file_path,
        method: "$init(String, ClassLoader)"
      });
      dump(file_path, dst_path);
      return this.$init(file_path, parent);
    };
    delegateLoader.$init.overload("java.lang.String", "java.lang.String", "java.lang.ClassLoader").implementation = function(file_path, librarySearchPath, parent) {
      createDEXEvent("dex.classloader.creation", {
        class_loader_type: "DelegateLastClassLoader",
        file_path,
        library_search_path: librarySearchPath,
        method: "$init(String, String, ClassLoader)"
      });
      dump(file_path, dst_path);
      return this.$init(file_path, librarySearchPath, parent);
    };
    if (Java.use("android.os.Build$VERSION").SDK_INT.value > 28) {
      delegateLoader.$init.overload("java.lang.String", "java.lang.String", "java.lang.ClassLoader", "boolean").implementation = function(file_path, librarySearchPath, parent, resourceLoading) {
        createDEXEvent("dex.classloader.creation", {
          class_loader_type: "DelegateLastClassLoader",
          file_path,
          library_search_path: librarySearchPath,
          resource_loading: resourceLoading,
          method: "$init(String, String, ClassLoader, boolean)"
        });
        dump(file_path, dst_path);
        return this.$init(file_path, librarySearchPath, parent, resourceLoading);
      };
    }
    const memoryclassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
    memoryclassLoader.$init.overload("java.nio.ByteBuffer", "java.lang.ClassLoader").implementation = function(dexbuffer, loader) {
      const remaining = dexbuffer.remaining();
      createDEXEvent("dex.in_memory_loader", {
        class_loader_type: "InMemoryDexClassLoader",
        buffer_size: remaining,
        method: "$init(ByteBuffer, ClassLoader)"
      });
      const object = this.$init(dexbuffer, loader);
      createDEXEvent("dex.memory_dump", {
        file_name: filename,
        bytes_to_write: remaining
      });
      const f = new File(filename, "wb");
      const buf = new Uint8Array(remaining);
      for (let i = 0; i < remaining; i++) {
        buf[i] = dexbuffer.get();
      }
      const numberArray = Array.from(buf);
      f.write(numberArray);
      f.close();
      const remainingAfter = dexbuffer.remaining();
      if (remainingAfter > 0) {
        createDEXEvent("dex.dump_error", {
          remaining_bytes: remainingAfter,
          file_name: filename
        });
      } else {
        createDEXEvent("dex.dump_success", {
          file_name: filename,
          bytes_written: remaining
        });
      }
      return object;
    };
  });
}
function advanced_unpacking_procedure() {
}
function install_dex_unpacking_hooks() {
  devlog("\n");
  devlog("Installing DEX unpacking hooks");
  install_dex_memory_hooks();
  install_dex_classloader_hooks();
  advanced_unpacking_procedure();
}

// agent/dex/load_library.ts
var PROFILE_HOOKING_TYPE4 = "DYNAMIC_LIB_LOADING";
function createLibraryEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE4, JSON.stringify(event));
}
function install_system_library_hooks() {
  devlog("Installing System library loading hooks");
  Java.perform(() => {
    const SystemDef = Java.use("java.lang.System");
    const SystemLoad_1 = SystemDef.load.overload("java.lang.String");
    const SystemLoad_2 = SystemDef.loadLibrary.overload("java.lang.String");
    SystemLoad_1.implementation = function(library) {
      createLibraryEvent("library.system.load", {
        method: "System.load(String)",
        library_path: library,
        loader_type: "System"
      });
      return SystemLoad_1.call(this, library);
    };
    SystemLoad_2.implementation = function(library) {
      createLibraryEvent("library.system.load_library", {
        method: "System.loadLibrary(String)",
        library_name: library,
        loader_type: "System"
      });
      SystemLoad_2.call(this, library);
    };
  });
}
function install_runtime_library_hooks() {
  devlog("Installing Runtime library loading hooks");
  Java.perform(() => {
    const RuntimeDef = Java.use("java.lang.Runtime");
    const RuntimeLoad_1 = RuntimeDef.load.overload("java.lang.String");
    const RuntimeLoad_2 = RuntimeDef.loadLibrary.overload("java.lang.String");
    RuntimeLoad_1.implementation = function(library) {
      createLibraryEvent("library.runtime.load", {
        method: "Runtime.load(String)",
        library_path: library,
        loader_type: "Runtime"
      });
      RuntimeLoad_1.call(this, library);
    };
    RuntimeLoad_2.implementation = function(library) {
      createLibraryEvent("library.runtime.load_library", {
        method: "Runtime.loadLibrary(String)",
        library_name: library,
        loader_type: "Runtime"
      });
      RuntimeLoad_2.call(this, library);
    };
  });
}
function install_java_dex_unpacking_hooks() {
  devlog("\n");
  devlog("Installing library loading hooks");
  try {
    install_system_library_hooks();
    install_runtime_library_hooks();
  } catch (e) {
    createLibraryEvent("library.hook_error", {
      error: e.toString()
    });
  }
}

// agent/ipc/shared_prefs.ts
var PROFILE_HOOKING_TYPE5 = "IPC_SHARED-PREF";
function createSharedPrefEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE5, JSON.stringify(event));
}
function install_shared_preferences_hooks() {
  devlog("Installing SharedPreferences hooks");
  Java.perform(() => {
    const SharedPrefs = Java.use("android.app.SharedPreferencesImpl");
    const SharedPrefsEditor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
    SharedPrefs.$init.overload("java.io.File", "int").implementation = function(file, mode) {
      const result = this.$init(file, mode);
      createSharedPrefEvent("shared_prefs.init", {
        method: "SharedPreferencesImpl.$init",
        file: file.getAbsolutePath(),
        mode
      });
      return result;
    };
    SharedPrefsEditor.putString.overload("java.lang.String", "java.lang.String").implementation = function(key, value) {
      createSharedPrefEvent("shared_prefs.put_string", {
        method: "putString",
        key,
        value
      });
      return this.putString(key, value);
    };
    const editorMethods = [
      { method: "putInt", args: ["java.lang.String", "int"] },
      { method: "putLong", args: ["java.lang.String", "long"] },
      { method: "putFloat", args: ["java.lang.String", "float"] },
      { method: "putBoolean", args: ["java.lang.String", "boolean"] }
    ];
    editorMethods.forEach(({ method, args }) => {
      try {
        SharedPrefsEditor[method].overload(...args).implementation = function(key, value) {
          createSharedPrefEvent(`shared_prefs.${method.toLowerCase()}`, {
            method,
            key,
            value: value.toString()
          });
          return this[method](key, value);
        };
      } catch (e) {
        devlog(`Could not hook SharedPrefsEditor.${method}: ${e}`);
      }
    });
  });
}
function install_datastore_hooks() {
  devlog("Installing DataStore hooks");
  Java.perform(() => {
    try {
      const DataStore = Java.use("androidx.datastore.core.DataStore");
      DataStore.updateData.overload("kotlin.coroutines.Continuation").implementation = function(continuation) {
        const result = this.updateData(continuation);
        result.then((data) => {
          createSharedPrefEvent("datastore.update", {
            method: "updateData",
            data: data ? data.toString() : null
          });
        });
        return result;
      };
      if (DataStore.getData) {
        DataStore.getData.overload().implementation = function() {
          const flow = this.getData();
          flow.collect((data) => {
            createSharedPrefEvent("datastore.get", {
              method: "getData",
              data: data ? data.toString() : null
            });
          });
          return flow;
        };
      }
    } catch (e) {
      devlog(`DataStore not available: ${e}`);
    }
    try {
      const Preferences = Java.use("androidx.datastore.preferences.core.Preferences");
      Preferences.get.overload("androidx.datastore.preferences.core.Preferences$Key").implementation = function(key) {
        const value = this.get(key);
        createSharedPrefEvent("datastore_prefs.get", {
          method: "get",
          key: key ? key.toString() : "unknown",
          value: value ? value.toString() : null
        });
        return value;
      };
      const PreferencesKey = Java.use("androidx.datastore.preferences.core.Preferences$Key");
      PreferencesKey.$init.overload("java.lang.String").implementation = function(keyName) {
        createSharedPrefEvent("datastore_prefs.key_init", {
          method: "$init",
          key: keyName
        });
        return this.$init(keyName);
      };
    } catch (e) {
      devlog(`Preferences DataStore not available: ${e}`);
    }
  });
}
function install_shared_prefs_hooks() {
  devlog("\n");
  devlog("Installing shared preferences hooks");
  install_shared_preferences_hooks();
  install_datastore_hooks();
}

// agent/ipc/binder.ts
var PROFILE_HOOKING_TYPE6 = "IPC_BINDER";
function createBinderEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE6, JSON.stringify(event));
}
var binder_driver_command_protocol = {
  "BC_TRANSACTION": 0,
  "BC_REPLY": 1,
  "BC_ACQUIRE_RESULT": 2,
  "BC_FREE_BUFFER": 3,
  "BC_INCREFS": 4,
  "BC_ACQUIRE": 5,
  "BC_RELEASE": 6,
  "BC_DECREFS": 7,
  "BC_INCREFS_DONE": 8,
  "BC_ACQUIRE_DONE": 9,
  "BC_ATTEMPT_ACQUIRE": 10,
  "BC_REGISTER_LOOPER": 11,
  "BC_ENTER_LOOPER": 12,
  "BC_EXIT_LOOPER": 13,
  "BC_REQUEST_DEATH_NOTIFICATION": 14,
  "BC_CLEAR_DEATH_NOTIFICATION": 15,
  "BC_DEAD_BINDER_DONE": 16
};
function parse_binder_transaction_data(binder_transaction_data) {
  return {
    "target": {
      "handle": binder_transaction_data.readU32(),
      "ptr": binder_transaction_data.readPointer()
    },
    "cookie": binder_transaction_data.add(8).readPointer(),
    "code": binder_transaction_data.add(16).readU32(),
    "flags": binder_transaction_data.add(20).readU32(),
    "sender_pid": binder_transaction_data.add(24).readS32(),
    "sender_euid": binder_transaction_data.add(28).readU32(),
    "data_size": binder_transaction_data.add(32).readU64(),
    "offsets_size": binder_transaction_data.add(40).readU64(),
    "data": {
      "ptr": {
        "buffer": binder_transaction_data.add(48).readPointer(),
        "offsets": binder_transaction_data.add(56).readPointer()
      },
      "buf": binder_transaction_data.add(48).readByteArray(8)
    }
  };
}
function handle_write(write_buffer, write_size, write_consumed) {
  var cmd = write_buffer.readU32() & 255;
  var ptr2 = write_buffer.add(write_consumed + 4);
  var end = write_buffer.add(write_size);
  switch (cmd) {
    // Implement cases from binder_driver_command_protocol, we're only interested in BC_TRANSACTION / BC_REPLY
    case binder_driver_command_protocol.BC_TRANSACTION:
    case binder_driver_command_protocol.BC_REPLY:
      var binder_transaction_data = parse_binder_transaction_data(ptr2);
      const payload = hexdump(binder_transaction_data.data.ptr.buffer, {
        length: binder_transaction_data.data_size,
        ansi: true
      });
      createBinderEvent("binder.transaction", {
        transaction_type: cmd === binder_driver_command_protocol.BC_TRANSACTION ? "BC_TRANSACTION" : "BC_REPLY",
        target_handle: binder_transaction_data.target.handle,
        code: binder_transaction_data.code,
        flags: binder_transaction_data.flags,
        sender_pid: binder_transaction_data.sender_pid,
        sender_euid: binder_transaction_data.sender_euid,
        data_size: binder_transaction_data.data_size,
        offsets_size: binder_transaction_data.offsets_size,
        payload_hex: payload
      });
      break;
    default:
  }
}
function parse_struct_binder_write_read(binder_write_read) {
  var offset = 8;
  return {
    "write_size": binder_write_read.readU64(),
    "write_consumed": binder_write_read.add(offset).readU64(),
    "write_buffer": binder_write_read.add(offset * 2).readPointer(),
    "read_size": binder_write_read.add(offset * 3).readU64(),
    "read_consumed": binder_write_read.add(offset * 4).readU64(),
    "read_buffer": binder_write_read.add(offset * 5).readPointer()
  };
}
function hook_binder() {
  Java.perform(function() {
    const libBinderModule = Process.getModuleByName("libbinder.so");
    var ioctl = libBinderModule.findExportByName("ioctl");
    Interceptor.attach(ioctl, {
      onEnter: function(args) {
        var fd = args[0];
        var cmd = args[1];
        if (cmd != ptr(3224396289))
          return;
        var data = args[2];
        var binder_write_read = parse_struct_binder_write_read(data);
        if (binder_write_read.write_size > 0) {
          handle_write(binder_write_read.write_buffer, binder_write_read.write_size, binder_write_read.write_consumed);
        }
      }
    });
  });
}
function install_binder_hooks() {
  devlog("\n");
  devlog("install binder hooks");
  hook_binder();
}

// agent/ipc/intents.ts
var PROFILE_HOOKING_TYPE7 = "IPC_INTENT";
function createIntentEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE7, JSON.stringify(event));
}
function getStackTrace2() {
  const threadDef = Java.use("java.lang.Thread");
  const threadInstance = threadDef.$new();
  return Where(threadInstance.currentThread().getStackTrace());
}
function extractIntentData(intent) {
  const intentData = {};
  try {
    const component = intent.getComponent();
    if (component) {
      intentData.component = component.getClassName();
    }
    const action = intent.getAction();
    if (action) {
      intentData.action = action;
    }
    const data = intent.getData();
    if (data) {
      intentData.data_uri = data.toString();
    }
    const type = intent.getType();
    if (type) {
      intentData.mime_type = type;
    }
    const flags = intent.getFlags();
    if (flags) {
      intentData.flags = flags;
    }
    const extras = intent.getExtras();
    if (extras) {
      const extrasData = {};
      const keys = extras.keySet().iterator();
      while (keys.hasNext()) {
        const key = keys.next();
        let value = extras.get(key);
        let type2 = "null";
        if (value) {
          try {
            type2 = value.getClass().getSimpleName();
            if (value.getClass().isArray()) {
              value = Java.use("org.json.JSONArray").$new(value);
            }
            value = value.toString();
          } catch (error) {
            value = `<error extracting value: ${error}>`;
          }
        }
        extrasData[key] = {
          type: type2,
          value
        };
      }
      intentData.extras = extrasData;
    }
    intentData.intent_string = intent.toString();
  } catch (error) {
    intentData.error = `Error extracting intent: ${error}`;
  }
  return intentData;
}
function hookGetData() {
  const intentData = extractIntentData(this);
  createIntentEvent("intent.data_accessed", {
    intent: intentData,
    method: "getData",
    stack_trace: getStackTrace2()
  });
  return this.getData();
}
function intent_hooks() {
  setTimeout(() => {
    Java.perform(() => {
      const Intent = Java.use("android.content.Intent");
      Intent.getData.implementation = hookGetData;
    });
  }, 0);
}
function install_intent_hooks() {
  devlog("\n");
  devlog("install intent hooks");
  intent_hooks();
}

// agent/ipc/broadcast.ts
var PROFILE_HOOKING_TYPE8 = "IPC_BROADCAST";
function createBroadcastEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE8, JSON.stringify(event));
}
function getStackTrace3() {
  const threadDef = Java.use("java.lang.Thread");
  const threadInstance = threadDef.$new();
  return Where(threadInstance.currentThread().getStackTrace());
}
function hook_broadcasts() {
  Java.perform(() => {
    try {
      const ContextWrapper = Java.use("android.content.ContextWrapper");
      const getIntentInfo = (intent) => {
        const intentData = {};
        try {
          intentData.intent_string = intent.toString();
          const component = intent.getComponent();
          if (component) {
            intentData.component = component.getClassName();
          }
          const action = intent.getAction();
          if (action) {
            intentData.action = action;
          }
          const data = intent.getData();
          if (data) {
            intentData.data_uri = data.toString();
          }
          const extras = intent.getExtras();
          if (extras) {
            intentData.extras = extras.toString();
          }
          intentData.flags = intent.getFlags();
        } catch (e) {
          intentData.error = `Error extracting intent: ${e}`;
        }
        return intentData;
      };
      if (ContextWrapper.sendBroadcast) {
        ContextWrapper.sendBroadcast.overload("android.content.Intent").implementation = function(intent) {
          const intentInfo = getIntentInfo(intent);
          createBroadcastEvent("broadcast.sent", {
            class: "android.content.ContextWrapper",
            method: "sendBroadcast",
            intent: intentInfo,
            stack_trace: getStackTrace3()
          });
          return this.sendBroadcast.overload("android.content.Intent").apply(this, arguments);
        };
        ContextWrapper.sendBroadcast.overload("android.content.Intent", "java.lang.String").implementation = function(intent, receiverPermission) {
          const intentInfo = getIntentInfo(intent);
          createBroadcastEvent("broadcast.sent", {
            class: "android.content.ContextWrapper",
            method: "sendBroadcast",
            intent: intentInfo,
            receiver_permission: receiverPermission,
            stack_trace: getStackTrace3()
          });
          return this.sendBroadcast.overload("android.content.Intent", "java.lang.String").apply(this, arguments);
        };
      }
      if (ContextWrapper.sendStickyBroadcast) {
        ContextWrapper.sendStickyBroadcast.overload("android.content.Intent").implementation = function(intent) {
          const intentInfo = getIntentInfo(intent);
          createBroadcastEvent("broadcast.sticky_sent", {
            class: "android.content.ContextWrapper",
            method: "sendStickyBroadcast",
            intent: intentInfo,
            stack_trace: getStackTrace3()
          });
          return this.sendStickyBroadcast.overload("android.content.Intent").apply(this, arguments);
        };
      }
      if (ContextWrapper.startActivity) {
        ContextWrapper.startActivity.overload("android.content.Intent").implementation = function(intent) {
          const intentInfo = getIntentInfo(intent);
          createBroadcastEvent("activity.started", {
            class: "android.content.ContextWrapper",
            method: "startActivity",
            intent: intentInfo,
            stack_trace: getStackTrace3()
          });
          return this.startActivity.overload("android.content.Intent").apply(this, arguments);
        };
        ContextWrapper.startActivity.overload("android.content.Intent", "android.os.Bundle").implementation = function(intent, bundle) {
          const intentInfo = getIntentInfo(intent);
          createBroadcastEvent("activity.started", {
            class: "android.content.ContextWrapper",
            method: "startActivity",
            intent: intentInfo,
            bundle: bundle ? bundle.toString() : null,
            stack_trace: getStackTrace3()
          });
          return this.startActivity.overload("android.content.Intent", "android.os.Bundle").apply(this, arguments);
        };
      }
      if (ContextWrapper.startService) {
        ContextWrapper.startService.implementation = function(service) {
          const intentInfo = getIntentInfo(service);
          createBroadcastEvent("service.started", {
            class: "android.content.ContextWrapper",
            method: "startService",
            service: intentInfo,
            stack_trace: getStackTrace3()
          });
          return this.startService.apply(this, arguments);
        };
      }
      if (ContextWrapper.stopService) {
        ContextWrapper.stopService.implementation = function(name) {
          const intentInfo = getIntentInfo(name);
          createBroadcastEvent("service.stopped", {
            class: "android.content.ContextWrapper",
            method: "stopService",
            service: intentInfo,
            stack_trace: getStackTrace3()
          });
          return this.stopService.apply(this, arguments);
        };
      }
      if (ContextWrapper.registerReceiver) {
        ContextWrapper.registerReceiver.overload("android.content.BroadcastReceiver", "android.content.IntentFilter").implementation = function(receiver, filter) {
          return this.registerReceiver.apply(this, arguments);
        };
        ContextWrapper.registerReceiver.overload("android.content.BroadcastReceiver", "android.content.IntentFilter", "java.lang.String", "android.os.Handler").implementation = function(receiver, filter, broadcastPermission, scheduler) {
          return this.registerReceiver.apply(this, arguments);
        };
      }
    } catch (error) {
      createBroadcastEvent("broadcast.error", {
        error: error.toString(),
        stack_trace: getStackTrace3()
      });
    }
  });
}
function install_broadcast_hooks() {
  devlog("\n");
  devlog("install broadcast hooks");
  hook_broadcasts();
}

// agent/crypto/aes.ts
var PROFILE_HOOKING_TYPE9 = "CRYPTO_AES";
var activeCipherSessions = /* @__PURE__ */ new Map();
function createAESEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE9, JSON.stringify(event));
}
function bytesToHexSafe2(bytes) {
  if (!bytes || bytes.length === 0)
    return "";
  return bytesToHex(new Uint8Array(bytes));
}
function extractPlaintext(hexData, opmode) {
  if (!hexData)
    return null;
  try {
    const bytes = hexData.match(/.{2}/g)?.map((byte) => parseInt(byte, 16)) || [];
    return String.fromCharCode(...bytes.filter((b) => b >= 32 && b <= 126));
  } catch {
    return null;
  }
}
function install_aes_secrets() {
  devlog("Installing AES secrets hooks (keys and IVs)");
  Java.perform(() => {
    const secretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    const ivParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
    secretKeySpec.$init.overload("[B", "java.lang.String").implementation = function(keyBytes, algorithm) {
      createAESEvent("crypto.key.creation", {
        algorithm,
        key_length: keyBytes.length,
        key_hex: bytesToHexSafe2(keyBytes)
      });
      return this.$init(keyBytes, algorithm);
    };
    secretKeySpec.$init.overload("[B", "int", "int", "java.lang.String").implementation = function(keyBytes, offset, length, algorithm) {
      createAESEvent("crypto.key.creation", {
        algorithm,
        key_length: length,
        key_hex: bytesToHexSafe2(keyBytes.slice(offset, offset + length))
      });
      return this.$init(keyBytes, offset, length, algorithm);
    };
    ivParameterSpec.$init.overload("[B").implementation = function(ivBytes) {
      createAESEvent("crypto.iv.creation", {
        iv_length: ivBytes.length,
        iv_hex: bytesToHexSafe2(ivBytes)
      });
      return this.$init(ivBytes);
    };
  });
}
function install_aes_keys() {
  devlog("Installing AES keys hooks (cipher initialization)");
  Java.perform(() => {
    const cipher = Java.use("javax.crypto.Cipher");
    cipher.init.overload("int", "java.security.Key").implementation = function(opmode, key) {
      const cipherId = this.hashCode();
      const keyBytes = key.getEncoded();
      activeCipherSessions.set(cipherId, {
        id: cipherId,
        key: keyBytes,
        opmode
      });
      return this.init(opmode, key);
    };
    cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function(opmode, key, params) {
      const cipherId = this.hashCode();
      const keyBytes = key.getEncoded();
      activeCipherSessions.set(cipherId, {
        id: cipherId,
        key: keyBytes,
        opmode
      });
      return this.init(opmode, key, params);
    };
  });
}
function install_aes_info() {
  devlog("Installing AES info hooks (cipher operations)");
  Java.perform(() => {
    const cipher = Java.use("javax.crypto.Cipher");
    const threadDef = Java.use("java.lang.Thread");
    const threadInstance = threadDef.$new();
    cipher.doFinal.overload("[B").implementation = function(inputBytes) {
      const result = this.doFinal(inputBytes);
      const cipherId = this.hashCode();
      const session = activeCipherSessions.get(cipherId);
      if (session) {
        const algorithm = this.getAlgorithm();
        const iv = this.getIV();
        const inputHex = bytesToHexSafe2(inputBytes);
        const outputHex = bytesToHexSafe2(result);
        const stack = threadInstance.currentThread().getStackTrace();
        createAESEvent("crypto.cipher.operation", {
          algorithm,
          operation_mode: session.opmode,
          key_hex: bytesToHexSafe2(session.key),
          iv_hex: bytesToHexSafe2(iv),
          input_hex: inputHex,
          output_hex: outputHex,
          input_length: inputBytes.length,
          output_length: result.length,
          plaintext: session.opmode === 1 ? extractPlaintext(inputHex, session.opmode) : extractPlaintext(outputHex, session.opmode),
          stack_trace: Where(stack)
        });
        activeCipherSessions.delete(cipherId);
      }
      return result;
    };
    const updateMethods = [
      cipher.update.overload("[B"),
      cipher.update.overload("[B", "int", "int"),
      cipher.update.overload("[B", "int", "int", "[B"),
      cipher.update.overload("[B", "int", "int", "[B", "int")
    ];
    updateMethods.forEach((method, index) => {
      method.implementation = function(...args) {
        const cipherId = this.hashCode();
        const session = activeCipherSessions.get(cipherId);
        if (session) {
          createAESEvent("crypto.cipher.update", {
            algorithm: this.getAlgorithm(),
            operation_mode: session.opmode,
            update_call: index + 1
          });
        }
        return method.apply(this, args);
      };
    });
    const doFinalMethods = [
      cipher.doFinal.overload(),
      cipher.doFinal.overload("[B", "int"),
      cipher.doFinal.overload("[B", "int", "int"),
      cipher.doFinal.overload("[B", "int", "int", "[B"),
      cipher.doFinal.overload("[B", "int", "int", "[B", "int")
    ];
    doFinalMethods.forEach((method, index) => {
      method.implementation = function(...args) {
        const result = method.apply(this, args);
        const cipherId = this.hashCode();
        const session = activeCipherSessions.get(cipherId);
        if (session) {
          const algorithm = this.getAlgorithm();
          const iv = this.getIV();
          const stack = threadInstance.currentThread().getStackTrace();
          createAESEvent("crypto.cipher.operation", {
            algorithm,
            operation_mode: session.opmode,
            key_hex: bytesToHexSafe2(session.key),
            iv_hex: bytesToHexSafe2(iv),
            doFinal_variant: index + 1,
            stack_trace: Where(stack)
          });
          activeCipherSessions.delete(cipherId);
        }
        return result;
      };
    });
  });
}
function install_aes_hooks() {
  devlog("\n");
  devlog("install aes hooks");
  install_aes_secrets();
  install_aes_keys();
  install_aes_info();
}

// agent/crypto/encodings.ts
var PROFILE_HOOKING_TYPE10 = "CRYPTO_ENCODING";
function createEncodingEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE10, JSON.stringify(event));
}
function bytesToHexSafe3(bytes) {
  if (!bytes || bytes.length === 0)
    return "";
  return bytesToHex(new Uint8Array(bytes));
}
function bytesToStringSafe(bytes) {
  if (!bytes || bytes.length === 0)
    return "";
  try {
    return String.fromCharCode(...bytes.filter((b) => b >= 32 && b <= 126));
  } catch {
    return "";
  }
}
function install_base64_hooks() {
  devlog("Installing Base64 encoding/decoding hooks");
  Java.perform(() => {
    const base64 = Java.use("android.util.Base64");
    const threadDef = Java.use("java.lang.Thread");
    const threadInstance = threadDef.$new();
    base64.decode.overload("java.lang.String", "int").implementation = function(str, flag) {
      const result = this.decode(str, flag);
      if (result.length !== 0) {
        const stack = threadInstance.currentThread().getStackTrace();
        createEncodingEvent("crypto.base64.decode", {
          method: "decode(String, int)",
          input_string: str,
          flag,
          input_length: str.length,
          output_length: result.length,
          output_hex: bytesToHexSafe3(result),
          decoded_content: bytesToStringSafe(result),
          stack_trace: Where(stack)
        });
      }
      return result;
    };
    base64.decode.overload("[B", "int").implementation = function(input, flag) {
      const result = this.decode(input, flag);
      if (result.length !== 0) {
        const stack = threadInstance.currentThread().getStackTrace();
        createEncodingEvent("crypto.base64.decode", {
          method: "decode(byte[], int)",
          flag,
          input_length: input.length,
          input_hex: bytesToHexSafe3(input),
          output_length: result.length,
          output_hex: bytesToHexSafe3(result),
          decoded_content: bytesToStringSafe(result),
          stack_trace: Where(stack)
        });
      }
      return result;
    };
    base64.decode.overload("[B", "int", "int", "int").implementation = function(input, offset, len, flags) {
      const result = this.decode(input, offset, len, flags);
      if (result.length !== 0) {
        const stack = threadInstance.currentThread().getStackTrace();
        createEncodingEvent("crypto.base64.decode", {
          method: "decode(byte[], int, int, int)",
          offset,
          length: len,
          flags,
          input_length: input.length,
          input_hex: bytesToHexSafe3(input.slice(offset, offset + len)),
          output_length: result.length,
          output_hex: bytesToHexSafe3(result),
          decoded_content: bytesToStringSafe(result),
          stack_trace: Where(stack)
        });
      }
      return result;
    };
    base64.encode.overload("[B", "int").implementation = function(input, flags) {
      const result = this.encode(input, flags);
      if (input.length !== 0) {
        const stack = threadInstance.currentThread().getStackTrace();
        createEncodingEvent("crypto.base64.encode", {
          method: "encode(byte[], int)",
          flags,
          input_length: input.length,
          input_hex: bytesToHexSafe3(input),
          input_content: bytesToStringSafe(input),
          output_length: result.length,
          output_hex: bytesToHexSafe3(result),
          stack_trace: Where(stack)
        });
      }
      return result;
    };
    base64.encode.overload("[B", "int", "int", "int").implementation = function(input, offset, len, flags) {
      const result = this.encode(input, offset, len, flags);
      if (input.length !== 0) {
        const stack = threadInstance.currentThread().getStackTrace();
        createEncodingEvent("crypto.base64.encode", {
          method: "encode(byte[], int, int, int)",
          offset,
          length: len,
          flags,
          input_length: input.length,
          input_hex: bytesToHexSafe3(input.slice(offset, offset + len)),
          input_content: bytesToStringSafe(input.slice(offset, offset + len)),
          output_length: result.length,
          output_hex: bytesToHexSafe3(result),
          stack_trace: Where(stack)
        });
      }
      return result;
    };
    base64.encodeToString.overload("[B", "int", "int", "int").implementation = function(input, offset, len, flags) {
      const result = this.encodeToString(input, offset, len, flags);
      if (input.length !== 0) {
        const stack = threadInstance.currentThread().getStackTrace();
        createEncodingEvent("crypto.base64.encode_to_string", {
          method: "encodeToString(byte[], int, int, int)",
          offset,
          length: len,
          flags,
          input_length: input.length,
          input_hex: bytesToHexSafe3(input.slice(offset, offset + len)),
          input_content: bytesToStringSafe(input.slice(offset, offset + len)),
          output_string: result,
          output_length: result.length,
          stack_trace: Where(stack)
        });
      }
      return result;
    };
    base64.encodeToString.overload("[B", "int").implementation = function(input, flags) {
      const result = this.encodeToString(input, flags);
      if (input.length !== 0) {
        const stack = threadInstance.currentThread().getStackTrace();
        createEncodingEvent("crypto.base64.encode_to_string", {
          method: "encodeToString(byte[], int)",
          flags,
          input_length: input.length,
          input_hex: bytesToHexSafe3(input),
          input_content: bytesToStringSafe(input),
          output_string: result,
          output_length: result.length,
          stack_trace: Where(stack)
        });
      }
      return result;
    };
  });
}
function install_encodings_hooks() {
  devlog("\n");
  devlog("Installing encodings hooks");
  install_base64_hooks();
}

// agent/crypto/keystore.ts
var PROFILE_HOOKING_TYPE11 = "CRYPTO_KEYSTORE";
var keystoreList = [];
var StringCls = null;
function createKeystoreEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE11, JSON.stringify(event));
}
Java.perform(() => {
  StringCls = Java.use("java.lang.String");
});
function hookKeystoreConstructor() {
  const keyStoreConstructor = Java.use("java.security.KeyStore").$init.overload("java.security.KeyStoreSpi", "java.security.Provider", "java.lang.String");
  keyStoreConstructor.implementation = function(keyStoreSpi, provider, type) {
    createKeystoreEvent("crypto.keystore.constructor", {
      keystore_spi: keyStoreSpi ? keyStoreSpi.toString() : null,
      provider: provider ? provider.toString() : null,
      type
    });
    return this.$init(keyStoreSpi, provider, type);
  };
}
function hookKeystoreGetInstance() {
  const keyStoreGetInstance = Java.use("java.security.KeyStore")["getInstance"].overload("java.lang.String");
  keyStoreGetInstance.implementation = function(type) {
    createKeystoreEvent("crypto.keystore.get_instance", {
      method: "getInstance(String)",
      type
    });
    const tmp = this.getInstance(type);
    keystoreList.push(tmp);
    return tmp;
  };
}
function hookKeystoreGetInstance_Provider() {
  const keyStoreGetInstance = Java.use("java.security.KeyStore")["getInstance"].overload("java.lang.String", "java.lang.String");
  keyStoreGetInstance.implementation = function(type, provider) {
    createKeystoreEvent("crypto.keystore.get_instance", {
      method: "getInstance(String, String)",
      type,
      provider
    });
    const tmp = this.getInstance(type, provider);
    keystoreList.push(tmp);
    return tmp;
  };
}
function hookKeystoreGetInstance_Provider2() {
  const keyStoreGetInstance = Java.use("java.security.KeyStore")["getInstance"].overload("java.lang.String", "java.security.Provider");
  keyStoreGetInstance.implementation = function(type, provider) {
    createKeystoreEvent("crypto.keystore.get_instance", {
      method: "getInstance(String, Provider)",
      type,
      provider: provider ? provider.toString() : null
    });
    const tmp = this.getInstance(type, provider);
    keystoreList.push(tmp);
    return tmp;
  };
}
function hookKeystoreLoad(dump2) {
  const keyStoreLoad = Java.use("java.security.KeyStore")["load"].overload("java.security.KeyStore$LoadStoreParameter");
  keyStoreLoad.implementation = function(param) {
    createKeystoreEvent("crypto.keystore.load", {
      method: "load(LoadStoreParameter)",
      keystore_type: this.getType(),
      parameter: param ? param.toString() : null
    });
    this.load(param);
    if (dump2) {
      createKeystoreEvent("crypto.keystore.aliases", {
        keystore_type: this.getType(),
        aliases: ListAliasesObj(this)
      });
    }
  };
}
function hookKeystoreLoadStream(dump2) {
  const keyStoreLoadStream = Java.use("java.security.KeyStore")["load"].overload("java.io.InputStream", "[C");
  keyStoreLoadStream.implementation = function(stream, charArray) {
    createKeystoreEvent("crypto.keystore.load", {
      method: "load(InputStream, char[])",
      keystore_type: this.getType(),
      password: charArrayToString(charArray),
      input_stream: stream ? stream.toString() : null
    });
    this.load(stream, charArray);
    if (dump2) {
      createKeystoreEvent("crypto.keystore.aliases", {
        keystore_type: this.getType(),
        aliases: ListAliasesObj(this)
      });
    }
  };
}
function hookKeystoreStore() {
  var keyStoreStoreStream = Java.use("java.security.KeyStore")["store"].overload("java.security.KeyStore$LoadStoreParameter");
  keyStoreStoreStream.implementation = function(param) {
    am_send(PROFILE_HOOKING_TYPE11, "[Keystore.store()]: keystoreType: " + this.getType() + ", param: '" + param);
    this.store(param);
  };
}
function hookKeystoreStoreStream() {
  var keyStoreStoreStream = Java.use("java.security.KeyStore")["store"].overload("java.io.OutputStream", "[C");
  keyStoreStoreStream.implementation = function(stream, charArray) {
    am_send(PROFILE_HOOKING_TYPE11, "[Keystore.store(OutputStream, char[])]: keystoreType: " + this.getType() + ", password: '" + charArrayToString(charArray) + "', outputSteam: " + stream);
    this.store(stream, charArray);
  };
}
function hookKeystoreGetKey() {
  const keyStoreGetKey = Java.use("java.security.KeyStore")["getKey"].overload("java.lang.String", "[C");
  keyStoreGetKey.implementation = function(alias, charArray) {
    createKeystoreEvent("crypto.keystore.get_key", {
      alias,
      password: charArrayToString(charArray)
    });
    return this.getKey(alias, charArray);
  };
}
function hookKeystoreSetEntry() {
  var keyStoreSetKeyEntry = Java.use("java.security.KeyStore")["setEntry"].overload("java.lang.String", "java.security.KeyStore$Entry", "java.security.KeyStore$ProtectionParameter");
  keyStoreSetKeyEntry.implementation = function(alias, entry, protection) {
    am_send(PROFILE_HOOKING_TYPE11, "[Keystore.setEntry()]: alias: " + alias + ", entry: " + dumpKeyStoreEntry(entry) + "', protection: " + dumpProtectionParameter(protection));
    return this.setEntry(alias, entry, protection);
  };
}
function hookKeystoreSetKeyEntry() {
  var keyStoreSetKeyEntry = Java.use("java.security.KeyStore")["setKeyEntry"].overload("java.lang.String", "java.security.Key", "[C", "[Ljava.security.cert.Certificate;");
  keyStoreSetKeyEntry.implementation = function(alias, key, charArray, certs) {
    am_send(PROFILE_HOOKING_TYPE11, "[Keystore.setKeyEntry()]: alias: " + alias + ", key: " + key + ", password: '" + charArrayToString(charArray) + "', certs: " + certs);
    return this.setKeyEntry(alias, key, charArray, certs);
  };
}
function hookKeystoreSetKeyEntry2() {
  var keyStoreSetKeyEntry = Java.use("java.security.KeyStore")["setKeyEntry"].overload("java.lang.String", "[B", "[Ljava.security.cert.Certificate;");
  keyStoreSetKeyEntry.implementation = function(alias, key, certs) {
    am_send(PROFILE_HOOKING_TYPE11, "[Keystore.setKeyEntry2()]: alias: " + alias + ", key: " + key + "', certs: " + certs);
    return this.setKeyEntry(alias, key, certs);
  };
}
function hookKeystoreGetCertificate() {
  const keyStoreGetCertificate = Java.use("java.security.KeyStore")["getCertificate"].overload("java.lang.String");
  keyStoreGetCertificate.implementation = function(alias) {
    createKeystoreEvent("crypto.keystore.get_certificate", {
      alias
    });
    return this.getCertificate(alias);
  };
}
function hookKeystoreGetCertificateChain() {
  var keyStoreGetCertificate = Java.use("java.security.KeyStore")["getCertificateChain"].overload("java.lang.String");
  keyStoreGetCertificate.implementation = function(alias) {
    am_send(PROFILE_HOOKING_TYPE11, "[Keystore.getCertificateChain()]: alias: " + alias);
    return this.getCertificateChain(alias);
  };
}
function hookKeystoreGetEntry() {
  var keyStoreGetEntry = Java.use("java.security.KeyStore")["getEntry"].overload("java.lang.String", "java.security.KeyStore$ProtectionParameter");
  keyStoreGetEntry.implementation = function(alias, protection) {
    am_send(PROFILE_HOOKING_TYPE11, "[Keystore.getEntry()]: alias: " + alias + ", protection: '" + dumpProtectionParameter(protection) + "'");
    var entry = this.getEntry(alias, protection);
    am_send(PROFILE_HOOKING_TYPE11, "[getEntry()]: Entry: " + dumpKeyStoreEntry(entry));
    return entry;
  };
}
function dumpProtectionParameter(protection) {
  if (protection != null) {
    var protectionCls = protection.$className;
    if (protectionCls.localeCompare("android.security.keystore.KeyProtection") == 0) {
      return "" + protectionCls + " [implement dumping if needed]";
    } else if (protectionCls.localeCompare("java.security.KeyStore.CallbackHandlerProtection") == 0) {
      return "" + protectionCls + " [implement dumping if needed]";
    } else if (protectionCls.localeCompare("java.security.KeyStore.PasswordProtection") == 0) {
      var getPasswordMethod = Java.use("java.security.KeyStore.PasswordProtection")["getPassword"];
      var password = getPasswordMethod.call(protection);
      return "password: " + charArrayToString(password);
    } else if (protectionCls.localeCompare("android.security.KeyStoreParameter") == 0) {
      var isEncryptionRequiredMethod = Java.use("android.security.KeyStoreParameter")["isEncryptionRequired"];
      var result = isEncryptionRequiredMethod.call(protection);
      return "isEncryptionRequired: " + result;
    } else
      return "Unknown protection parameter type: " + protectionCls;
  } else
    return "null";
}
function dumpKeyStoreEntry(entry) {
  if (entry != null) {
    var entryCls = entry.$className;
    var castedEntry = Java.cast(entry, Java.use(entryCls));
    if (entryCls.localeCompare("java.security.KeyStore$PrivateKeyEntry") == 0) {
      var getPrivateKeyEntryMethod = Java.use("java.security.KeyStore$PrivateKeyEntry")["getPrivateKey"];
      var key = getPrivateKeyEntryMethod.call(castedEntry);
      return "" + entryCls + " [implement key dumping if needed] " + key.$className;
    } else if (entryCls.localeCompare("java.security.KeyStore$SecretKeyEntry") == 0) {
      var getSecretKeyMethod = Java.use("java.security.KeyStore$SecretKeyEntry")["getSecretKey"];
      var key = getSecretKeyMethod.call(castedEntry);
      var keyGetFormatMethod = Java.use(key.$className)["getFormat"];
      var keyGetEncodedMethod = Java.use(key.$className)["getEncoded"];
      if (key.$className.localeCompare("android.security.keystore.AndroidKeyStoreSecretKey") == 0)
        return "keyClass: android.security.keystore.AndroidKeyStoreSecretKey can't dump";
      return "keyFormat: " + keyGetFormatMethod.call(key) + ", encodedKey: '" + keyGetEncodedMethod.call(key) + "', key: " + key;
    } else if (entryCls.localeCompare("java.security.KeyStore$TrustedCertificateEntry") == 0) {
      return "" + entryCls + " [implement key dumping if needed]";
    } else if (entryCls.localeCompare("android.security.WrappedKeyEntry") == 0) {
      return "" + entryCls + " [implement key dumping if needed]";
    } else
      return "Unknown key entry type: " + entryCls;
  } else
    return "null";
}
function ListAliasesObj(obj) {
  var result = [];
  Java.perform(function() {
    var aliases = obj.aliases();
    while (aliases.hasMoreElements()) {
      result.push(aliases.nextElement() + "");
    }
  });
  return result;
}
function charArrayToString(charArray) {
  if (charArray == null)
    return "(null)";
  else
    return StringCls.$new(charArray);
}
function install_keystore_constructor_hooks() {
  devlog("Installing keystore constructor hooks");
  Java.perform(() => {
    hookKeystoreConstructor();
    hookKeystoreGetInstance();
    hookKeystoreGetInstance_Provider();
    hookKeystoreGetInstance_Provider2();
  });
}
function install_keystore_load_hooks() {
  devlog("Installing keystore load/store hooks");
  Java.perform(() => {
    hookKeystoreLoad(false);
    hookKeystoreLoadStream(false);
    hookKeystoreStore();
    hookKeystoreStoreStream();
  });
}
function install_keystore_access_hooks() {
  devlog("Installing keystore access hooks");
  Java.perform(() => {
    hookKeystoreGetKey();
    hookKeystoreGetCertificate();
    hookKeystoreGetCertificateChain();
    hookKeystoreGetEntry();
    hookKeystoreSetEntry();
    hookKeystoreSetKeyEntry();
    hookKeystoreSetKeyEntry2();
  });
}
function install_keystore_hooks() {
  devlog("\n");
  devlog("Installing keystore hooks");
  install_keystore_constructor_hooks();
  install_keystore_load_hooks();
  install_keystore_access_hooks();
}

// agent/network/web.ts
var PROFILE_HOOKING_TYPE12 = "WEB";
function safeHookClass(className, hookFunction) {
  try {
    const clazz = Java.use(className);
    hookFunction(clazz);
    devlog(`Successfully hooked ${className}`);
    return true;
  } catch (e) {
    devlog(`Class ${className} not available: ${e}`);
    return false;
  }
}
function createWebEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE12, JSON.stringify(event));
}
function install_url_hooks() {
  devlog("Installing URL hooks");
  Java.perform(() => {
    safeHookClass("java.net.URL", (URL) => {
      URL.$init.overload("java.lang.String").implementation = function(urlString) {
        const result = this.$init(urlString);
        if (!urlString.startsWith("null")) {
          createWebEvent("url.creation", {
            url: urlString,
            req_method: "GET"
          });
        }
        return result;
      };
      URL.openConnection.overload().implementation = function() {
        const result = this.openConnection();
        createWebEvent("url.open_connection", {
          url: result.getURL().toString(),
          req_method: "GET"
        });
        return result;
      };
    });
    safeHookClass("java.net.HttpURLConnection", (HttpURLConnection) => {
      HttpURLConnection.connect.implementation = function() {
        createWebEvent("url.connection", {
          url: this.getURL().toString(),
          req_method: this.getRequestMethod ? this.getRequestMethod() : "GET"
        });
        return this.connect();
      };
    });
    safeHookClass("java.net.URI", (URI) => {
      URI.$init.overload("java.lang.String").implementation = function(uriString) {
        const result = this.$init(uriString);
        createWebEvent("uri.creation", {
          class: "java.net.URI",
          method: "URI(String)",
          uri: uriString
        });
        return result;
      };
    });
  });
}
function install_http_hooks() {
  devlog("Installing HTTP communication hooks");
  Java.perform(() => {
    safeHookClass("java.net.HttpURLConnection", (HttpURLConnection) => {
      HttpURLConnection.setRequestMethod.implementation = function(method) {
        createWebEvent("http.request_method", {
          method,
          url: this.getURL ? this.getURL().toString() : "unknown"
        });
        return this.setRequestMethod(method);
      };
      HttpURLConnection.connect.implementation = function() {
        const result = this.connect();
        try {
          const responseCode = this.getResponseCode();
          createWebEvent("http.connect", {
            url: this.getURL ? this.getURL().toString() : "unknown",
            status_code: responseCode,
            method: this.getRequestMethod ? this.getRequestMethod() : "GET"
          });
        } catch (e) {
          createWebEvent("http.connect", {
            url: this.getURL ? this.getURL().toString() : "unknown",
            method: this.getRequestMethod ? this.getRequestMethod() : "GET"
          });
        }
        return result;
      };
      HttpURLConnection.getOutputStream.implementation = function() {
        const outputStream = this.getOutputStream();
        createWebEvent("http.output_stream", {
          url: this.getURL ? this.getURL().toString() : "unknown",
          method: this.getRequestMethod ? this.getRequestMethod() : "GET"
        });
        return outputStream;
      };
      HttpURLConnection.getInputStream.implementation = function() {
        const inputStream = this.getInputStream();
        const url = this.getURL ? this.getURL().toString() : "unknown";
        const method = this.getRequestMethod ? this.getRequestMethod() : "GET";
        createWebEvent("http.input_stream", {
          url,
          method
        });
        return inputStream;
      };
    });
  });
}
function install_https_hooks() {
  devlog("Installing HTTPS communication hooks");
  Java.perform(() => {
    safeHookClass("javax.net.ssl.HttpsURLConnection", (HttpsURLConnection) => {
      HttpsURLConnection.setRequestMethod.implementation = function(method) {
        createWebEvent("https.request_method", {
          method,
          url: this.getURL ? this.getURL().toString() : "unknown"
        });
        return this.setRequestMethod(method);
      };
      HttpsURLConnection.connect.implementation = function() {
        const result = this.connect();
        try {
          const responseCode = this.getResponseCode();
          createWebEvent("https.connect", {
            url: this.getURL ? this.getURL().toString() : "unknown",
            status_code: responseCode,
            method: this.getRequestMethod ? this.getRequestMethod() : "GET"
          });
        } catch (e) {
          createWebEvent("https.connect", {
            url: this.getURL ? this.getURL().toString() : "unknown",
            method: this.getRequestMethod ? this.getRequestMethod() : "GET"
          });
        }
        return result;
      };
      HttpsURLConnection.getInputStream.implementation = function() {
        const inputStream = this.getInputStream();
        const url = this.getURL ? this.getURL().toString() : "unknown";
        const method = this.getRequestMethod ? this.getRequestMethod() : "GET";
        createWebEvent("https.input_stream", {
          url,
          method
        });
        return inputStream;
      };
    });
  });
}
function install_okhttp_hooks() {
  devlog("Installing OkHTTP hooks");
  Java.perform(() => {
    safeHookClass("okhttp3.OkHttpClient", (OkHttpClient) => {
      OkHttpClient.newCall.overload("okhttp3.Request").implementation = function(request) {
        const headers = {};
        try {
          const requestHeaders = request.headers();
          const headerNames = requestHeaders.names().toArray();
          for (let i = 0; i < headerNames.length; i++) {
            headers[headerNames[i]] = requestHeaders.get(headerNames[i]);
          }
        } catch (e) {
          devlog(`Error reading OkHttp headers: ${e}`);
        }
        createWebEvent("okhttp.request", {
          url: request.url().toString(),
          method: request.method(),
          headers,
          body: request.body() ? request.body().toString() : null
        });
        return this.newCall(request);
      };
    });
    safeHookClass("okhttp.OkHttpClient", (OkHttpClientOld) => {
      OkHttpClientOld.newCall.overload("okhttp.Request").implementation = function(request) {
        createWebEvent("okhttp_old.request", {
          url: request.url().toString(),
          method: request.method()
        });
        return this.newCall(request);
      };
    });
    safeHookClass("com.android.okhttp.internal.huc.HttpURLConnectionImpl", (HttpURLConnectionImpl) => {
      HttpURLConnectionImpl.setRequestProperty.implementation = function(name, value) {
        createWebEvent("okhttp.request_property", {
          url: this.getURL ? this.getURL().toString() : "unknown",
          method: "setRequestProperty",
          data: `${name}: ${value}`
        });
        return this.setRequestProperty(name, value);
      };
      HttpURLConnectionImpl.setRequestMethod.implementation = function(method) {
        createWebEvent("okhttp.request_method", {
          url: this.getURL ? this.getURL().toString() : "unknown",
          method
        });
        return this.setRequestMethod(method);
      };
    });
  });
}
function install_webview_hooks() {
  devlog("Installing WebView hooks");
  Java.perform(() => {
    safeHookClass("android.webkit.WebView", (WebView) => {
      WebView.loadUrl.overload("java.lang.String").implementation = function(url) {
        createWebEvent("webview.load_url", {
          url,
          method: "loadUrl"
        });
        return this.loadUrl(url);
      };
      if (WebView.loadUrl.overloads.length > 1) {
        WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function(url, additionalHttpHeaders) {
          createWebEvent("webview.load_url_with_headers", {
            url,
            headers: additionalHttpHeaders || {},
            method: "loadUrl"
          });
          return this.loadUrl(url, additionalHttpHeaders);
        };
      }
      WebView.loadData.implementation = function(data, mimeType, encoding) {
        createWebEvent("webview.load_data", {
          data: data.length > 100 ? data.substring(0, 100) + "..." : data,
          mime_type: mimeType,
          encoding,
          method: "loadData"
        });
        return this.loadData(data, mimeType, encoding);
      };
      if (WebView.postUrl) {
        WebView.postUrl.implementation = function(url, postData) {
          createWebEvent("webview.post_url", {
            url,
            method: "postUrl",
            data: postData ? `[Binary data: ${postData.length} bytes]` : null
          });
          return this.postUrl(url, postData);
        };
      }
    });
    safeHookClass("android.webkit.WebViewClient", (WebViewClient) => {
      WebViewClient.onPageStarted.implementation = function(view, url, favicon) {
        createWebEvent("webview.page_started", {
          url,
          method: "onPageStarted"
        });
        return this.onPageStarted(view, url, favicon);
      };
      WebViewClient.onPageFinished.implementation = function(view, url) {
        createWebEvent("webview.page_finished", {
          url,
          method: "onPageFinished"
        });
        return this.onPageFinished(view, url);
      };
      WebViewClient.shouldOverrideUrlLoading.overload("android.webkit.WebView", "java.lang.String").implementation = function(view, url) {
        createWebEvent("webview.url_override", {
          url,
          method: "shouldOverrideUrlLoading"
        });
        return this.shouldOverrideUrlLoading(view, url);
      };
    });
  });
}
function install_retrofit_hooks() {
  devlog("Installing Retrofit hooks");
  Java.perform(() => {
    safeHookClass("retrofit2.OkHttpCall", (OkHttpCall) => {
      OkHttpCall.execute.implementation = function() {
        const request = this.request();
        if (request) {
          createWebEvent("retrofit.request", {
            url: request.url().toString(),
            method: request.method()
          });
        }
        const response = this.execute();
        if (response) {
          createWebEvent("retrofit.response", {
            url: request ? request.url().toString() : "unknown",
            status_code: response.code()
          });
        }
        return response;
      };
    });
    safeHookClass("retrofit2.Call", (Call) => {
      Call.enqueue.implementation = function(callback) {
        const request = this.request();
        if (request) {
          createWebEvent("retrofit.async_request", {
            url: request.url().toString(),
            method: request.method()
          });
        }
        return this.enqueue(callback);
      };
    });
  });
}
function install_volley_hooks() {
  devlog("Installing Volley hooks");
  Java.perform(() => {
    safeHookClass("com.android.volley.toolbox.StringRequest", (StringRequest) => {
      StringRequest.$init.overload("int", "java.lang.String", "com.android.volley.Response$Listener", "com.android.volley.Response$ErrorListener").implementation = function(method, url, listener, errorListener) {
        createWebEvent("volley.string_request", {
          url,
          method: method === 0 ? "GET" : method === 1 ? "POST" : method === 2 ? "PUT" : method === 3 ? "DELETE" : "UNKNOWN"
        });
        return this.$init(method, url, listener, errorListener);
      };
    });
    safeHookClass("com.android.volley.RequestQueue", (RequestQueue) => {
      RequestQueue.add.implementation = function(request) {
        if (request.getUrl) {
          createWebEvent("volley.queue_request", {
            url: request.getUrl(),
            method: request.getMethod ? request.getMethod().toString() : "UNKNOWN"
          });
        }
        return this.add(request);
      };
    });
  });
}
function install_websocket_hooks() {
  devlog("Installing WebSocket hooks");
  Java.perform(() => {
    safeHookClass("okhttp3.WebSocket", (WebSocket) => {
      WebSocket.send.overload("java.lang.String").implementation = function(text) {
        createWebEvent("websocket.send_text", {
          data: text.length > 200 ? text.substring(0, 200) + "..." : text,
          method: "send"
        });
        return this.send(text);
      };
    });
    safeHookClass("okhttp3.WebSocketListener", (WebSocketListener) => {
      WebSocketListener.onOpen.implementation = function(webSocket, response) {
        createWebEvent("websocket.opened", {
          status_code: response.code(),
          url: response.request().url().toString()
        });
        return this.onOpen(webSocket, response);
      };
      WebSocketListener.onMessage.overload("okhttp3.WebSocket", "java.lang.String").implementation = function(webSocket, text) {
        createWebEvent("websocket.message_received", {
          data: text.length > 200 ? text.substring(0, 200) + "..." : text
        });
        return this.onMessage(webSocket, text);
      };
    });
  });
}
function install_web_hooks() {
  devlog("\n");
  devlog("Installing comprehensive web hooks");
  install_url_hooks();
  install_http_hooks();
  install_https_hooks();
  install_okhttp_hooks();
  install_retrofit_hooks();
  install_volley_hooks();
  install_websocket_hooks();
  install_webview_hooks();
  devlog("Comprehensive web hooks installation completed");
}

// agent/network/sockets.ts
var PROFILE_HOOKING_TYPE13 = "NETWORK_SOCKETS";
function createSocketEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE13, JSON.stringify(event));
}
function getStackTrace4() {
  const threadDef = Java.use("java.lang.Thread");
  const threadInstance = threadDef.$new();
  return Where(threadInstance.currentThread().getStackTrace());
}
function isTcpEndpointAddress(address) {
  return "ip" in address;
}
function hook_java_socket_communication() {
  var ServerSocket = Java.use("java.net.ServerSocket");
  var Socket2 = Java.use("java.net.Socket");
  var LocalServerSocket = Java.use("android.net.LocalServerSocket");
  var DatagramSocket = Java.use("java.net.DatagramSocket");
  var threadef = Java.use("java.lang.Thread");
  var threadinstance = threadef.$new();
  ServerSocket.accept.overload().implementation = function() {
    var result = this.accept();
    createSocketEvent("socket.java.server_accept", {
      class: "java.net.ServerSocket",
      method: "accept",
      server_info: this.toString(),
      stack_trace: getStackTrace4()
    });
    return result;
  };
  Socket2.$init.overload("java.lang.String", "int").implementation = function(host, port) {
    var result = this.$init(host, port);
    createSocketEvent("socket.java.init", {
      class: "java.net.Socket",
      method: "$init",
      host,
      port,
      connection_string: `${host}:${port}`,
      stack_trace: getStackTrace4()
    });
    return result;
  };
  Socket2.connect.overload("java.net.SocketAddress", "int").implementation = function(p_endpoint, p_timeout) {
    var result = this.connect(p_endpoint, p_timeout);
    createSocketEvent("socket.java.connect", {
      class: "java.net.Socket",
      method: "connect",
      endpoint: p_endpoint.toString(),
      timeout: p_timeout,
      stack_trace: getStackTrace4()
    });
    return result;
  };
  Socket2.connect.overload("java.net.SocketAddress").implementation = function(p_endpoint) {
    var result = this.connect(p_endpoint);
    createSocketEvent("socket.java.connect", {
      class: "java.net.Socket",
      method: "connect",
      endpoint: p_endpoint.toString(),
      stack_trace: getStackTrace4()
    });
    return result;
  };
  LocalServerSocket.accept.overload().implementation = function() {
    var result = this.accept();
    createSocketEvent("socket.java.local_accept", {
      class: "android.net.LocalServerSocket",
      method: "accept",
      server_info: this.toString(),
      stack_trace: getStackTrace4()
    });
    return result;
  };
  DatagramSocket.connect.overload("java.net.InetAddress", "int").implementation = function(address, port) {
    var result = this.connect(address, port);
    createSocketEvent("socket.java.datagram_connect", {
      class: "java.net.DatagramSocket",
      method: "connect",
      address: address.toString(),
      port,
      connection_string: `${address}:${port}`,
      stack_trace: getStackTrace4()
    });
    return result;
  };
}
function hook_bionic_socket_commuication() {
  const libcModule = Process.getModuleByName("libc.so");
  var socket_ptr = libcModule.findExportByName("socket");
  var bind_ptr = libcModule.findExportByName("bind");
  var connect_ptr = libcModule.findExportByName("connect");
  var read_ptr = libcModule.findExportByName("read");
  var write_ptr = libcModule.findExportByName("write");
  var close_ptr = libcModule.findExportByName("close");
  var sendto_ptr = libcModule.findExportByName("sendto");
  var recvfrom_ptr = libcModule.findExportByName("recvfrom");
  var send_ptr = libcModule.findExportByName("send");
  var recv_ptr = libcModule.findExportByName("recv");
  var sendmsg_ptr = libcModule.findExportByName("sendmsg");
  var recvmsg_ptr = libcModule.findExportByName("recvmsg");
  const socket_list = [];
  function swap162(val) {
    return (val & 255) << 8 | val >> 8 & 255;
  }
  function getTimestamp() {
    var seconds = (/* @__PURE__ */ new Date()).getTime() / 1e3;
    return seconds;
  }
  function findSocket(sd) {
    for (const [index, socket] of socket_list.entries()) {
      if (socket === sd) {
        return index;
      }
    }
    return -1;
  }
  function addSocketToList(sd, type) {
    for (var i in socket_list) {
      if (socket_list[i] == sd) {
        return i;
      }
    }
    socket_list.unshift(sd);
    createSocketEvent("socket.native.created", {
      method: "socket",
      socket_descriptor: sd,
      socket_type: type
    });
    return -1;
  }
  Interceptor.attach(socket_ptr, {
    onEnter(args) {
      this.domain = args[0].toInt32();
      this.type = args[1].toInt32();
      this.protocol = args[2].toInt32();
    },
    onLeave(retval) {
      try {
        var sd = retval.toInt32();
        var sockType = Socket.type(sd);
        if (sockType == void 0 || sockType == null || sockType === "unix:stream")
          return;
        if (this.domain == 2 || this.domain == 22) {
          socket_list.unshift(sd);
          var data = { "event_type": "Libc::socket", "method": "socket", "sd": sd, "type": sockType };
        }
      } catch (error) {
      }
    }
  });
  Interceptor.attach(bind_ptr, {
    onEnter: function(args) {
      this.sd = args[0].toInt32();
      this.addr = args[1];
      this.addrlen = args[2].toInt32();
    },
    onLeave: function(retval) {
      if (retval.toInt32() != 0)
        return;
      var sockType = Socket.type(this.sd);
      if (sockType === "udp" || sockType === "udp6" || sockType === "tcp" || sockType === "tcp6") {
        const sockLocal = Socket.localAddress(this.sd);
        var local;
        if (isTcpEndpointAddress(sockLocal)) {
          local = sockLocal;
        } else {
          return;
        }
        addSocketToList(this.sd, sockType);
        createSocketEvent("socket.native.bind", {
          method: "bind",
          socket_descriptor: this.sd,
          socket_type: sockType,
          local_ip: local.ip,
          local_port: local.port
        });
      }
    }
  });
  Interceptor.attach(connect_ptr, {
    onEnter: function(args) {
      this.sd = args[0].toInt32();
    },
    onLeave: function(retval) {
      if (retval.toInt32() == -1)
        return;
      const sockType = Socket.type(this.sd);
      const sockLocal = Socket.localAddress(this.sd);
      var local;
      if (isTcpEndpointAddress(sockLocal)) {
        local = sockLocal;
      } else {
        am_send(PROFILE_HOOKING_TYPE13, JSON.stringify(sockLocal));
        return;
      }
      const sockRemote = Socket.peerAddress(this.sd);
      const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : void 0;
      retval |= 0;
      if (retval != 0 || sockType === "unix:stream" || sockType == null || sockType === void 0 || local === void 0 || remote === void 0) {
        return;
      }
      addSocketToList(this.sd, sockType);
      createSocketEvent("socket.native.connect", {
        method: "connect",
        socket_descriptor: this.sd,
        socket_type: sockType,
        local_ip: local.ip,
        local_port: local.port,
        remote_ip: remote.ip,
        remote_port: remote.port
      });
    }
  });
  Interceptor.attach(write_ptr, {
    onEnter: function(args) {
      this.sd = args[0].toInt32();
      this.addr = args[1];
      this.buflen = args[2].toInt32();
    },
    onLeave: function(retval) {
      var len = retval.toInt32();
      if (len == -1 || len > this.buflen)
        return;
      const sockType = Socket.type(this.sd);
      const sockLocal = Socket.localAddress(this.sd);
      const local = sockLocal && isTcpEndpointAddress(sockLocal) ? sockLocal : void 0;
      const sockRemote = Socket.peerAddress(this.sd);
      const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : void 0;
      if (sockType === "unix:stream" || sockType == null || sockType === void 0 || local === void 0 || remote === void 0) {
        return;
      }
      var buffer;
      var buf = ptr(this.addr);
      if (!buf.isNull()) {
        buffer = buf.readByteArray(len);
      }
      addSocketToList(this.sd, sockType);
      createSocketEvent("socket.native.write", {
        method: "write",
        socket_descriptor: this.sd,
        socket_type: sockType,
        local_ip: local.ip,
        local_port: local.port,
        remote_ip: remote.ip,
        remote_port: remote.port,
        data_length: len,
        has_buffer: buffer !== void 0
      });
      if (buffer) {
        am_send(PROFILE_HOOKING_TYPE13, JSON.stringify({
          event_type: "socket.native.write_data",
          timestamp: Date.now(),
          socket_descriptor: this.sd,
          data_length: len
        }), buffer);
      }
    }
  });
  Interceptor.attach(read_ptr, {
    onEnter: function(args) {
      this.sd = args[0].toInt32();
      this.addr = args[1];
      this.buflen = args[2].toInt32();
    },
    onLeave: function(retval) {
      var len = retval.toInt32();
      if (len == -1 || len > this.buflen)
        return;
      const sockType = Socket.type(this.sd);
      const sockLocal = Socket.localAddress(this.sd);
      const local = sockLocal && isTcpEndpointAddress(sockLocal) ? sockLocal : void 0;
      const sockRemote = Socket.peerAddress(this.sd);
      const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : void 0;
      if (sockType === "unix:stream" || sockType == null || sockType === void 0 || local === void 0 || remote === void 0) {
        return;
      }
      var buffer;
      var buf = ptr(this.addr);
      if (!buf.isNull()) {
        buffer = buf.readByteArray(len);
      }
      addSocketToList(this.sd, sockType);
      createSocketEvent("socket.native.read", {
        method: "read",
        socket_descriptor: this.sd,
        socket_type: sockType,
        local_ip: local.ip,
        local_port: local.port,
        remote_ip: remote.ip,
        remote_port: remote.port,
        data_length: len,
        has_buffer: buffer !== void 0
      });
      if (buffer) {
        am_send(PROFILE_HOOKING_TYPE13, JSON.stringify({
          event_type: "socket.native.read_data",
          timestamp: Date.now(),
          socket_descriptor: this.sd,
          data_length: len
        }), buffer);
      }
    }
  });
  Interceptor.attach(sendto_ptr, {
    onEnter: function(args) {
      this.sd = args[0].toInt32();
      this.addr = args[1];
      this.buflen = args[2].toInt32();
      this.ipAddr = args[4];
    },
    onLeave: function(retval) {
      var len = retval.toInt32();
      if (len == -1 || len > this.buflen)
        return;
      var data;
      const sockType = Socket.type(this.sd);
      const sockLocal = Socket.localAddress(this.sd);
      const local = sockLocal && isTcpEndpointAddress(sockLocal) ? sockLocal : void 0;
      if (sockType === "unix:stream" || sockType == null || sockType === void 0 || local === void 0)
        return;
      var buffer;
      var buf = ptr(this.addr);
      if (!buf.isNull()) {
        buffer = buf.readByteArray(len);
      }
      if (this.ipAddr.toInt32() == 0) {
        const sockRemote = Socket.peerAddress(this.sd);
        const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : void 0;
        if (remote === void 0)
          return;
        addSocketToList(this.sd, sockType);
        createSocketEvent("socket.native.sendto", {
          method: "sendto",
          socket_descriptor: this.sd,
          socket_type: sockType,
          local_ip: local.ip,
          local_port: local.port,
          remote_ip: remote.ip,
          remote_port: remote.port,
          data_length: len,
          has_buffer: buffer !== void 0
        });
        if (buffer) {
          am_send(PROFILE_HOOKING_TYPE13, JSON.stringify({
            event_type: "socket.native.sendto_data",
            timestamp: Date.now(),
            socket_descriptor: this.sd,
            data_length: len
          }), buffer);
        }
      } else {
        var dest_addr = ptr(this.ipAddr);
        if (dest_addr.isNull() == true)
          return;
        var family = dest_addr.readS16();
        if (family == 1) {
          var port = swap162(dest_addr.add(2).readU16());
          var addr_b0 = dest_addr.add(4).readU8();
          var addr_b1 = dest_addr.add(5).readU8();
          var addr_b2 = dest_addr.add(6).readU8();
          var addr_b3 = dest_addr.add(7).readU8();
          var ip_string = addr_b0 + "." + addr_b1 + "." + addr_b2 + "." + addr_b3;
          addSocketToList(this.sd, sockType);
          createSocketEvent("socket.native.sendto", {
            method: "sendto",
            socket_descriptor: this.sd,
            socket_type: sockType,
            local_ip: local.ip,
            local_port: local.port,
            remote_ip: ip_string,
            remote_port: port,
            address_family: family,
            data_length: len,
            has_buffer: buffer !== void 0
          });
          if (buffer) {
            am_send(PROFILE_HOOKING_TYPE13, JSON.stringify({
              event_type: "socket.native.sendto_data",
              timestamp: Date.now(),
              socket_descriptor: this.sd,
              data_length: len
            }), buffer);
          }
        }
      }
    }
  });
  Interceptor.attach(recvfrom_ptr, {
    onEnter: function(args) {
      this.sd = args[0].toInt32();
      this.addr = args[1];
      this.buflen = args[2].toInt32();
      this.ipAddr = args[4];
    },
    onLeave: function(retval) {
      var len = retval.toInt32();
      if (len == -1 || len > this.buflen)
        return;
      var data;
      var buffer;
      var buf = ptr(this.addr);
      if (!buf.isNull()) {
        buffer = buf.readByteArray(len);
      }
      const sockType = Socket.type(this.sd);
      const sockLocal = Socket.localAddress(this.sd);
      const local = sockLocal && isTcpEndpointAddress(sockLocal) ? sockLocal : void 0;
      if (sockType === "unix:stream" || sockType == null || sockType === void 0 || local === void 0)
        return;
      if (this.ipAddr.toInt32() == 0) {
        const sockRemote = Socket.peerAddress(this.sd);
        const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : void 0;
        if (remote === void 0)
          return;
        addSocketToList(this.sd, sockType);
        data = { "event_type": "Libc::recvfrom", "method": "recvfrom", "sd": this.sd, "src_ip": remote.ip, "src_port": remote.port, "dst_ip": local.ip, "dst_port": local.port, "len": len, "type": sockType };
        am_send(PROFILE_HOOKING_TYPE13, JSON.stringify(data), buffer);
      } else {
        var src_addr = ptr(this.ipAddr);
        if (src_addr.isNull() == true)
          return;
        var family = src_addr.readS16();
        if (family == 1) {
          var port = swap162(src_addr.add(2).readU16());
          var addr_b0 = src_addr.add(4).readU8();
          var addr_b1 = src_addr.add(5).readU8();
          var addr_b2 = src_addr.add(6).readU8();
          var addr_b3 = src_addr.add(7).readU8();
          var ip_string = addr_b0 + "." + addr_b1 + "." + addr_b2 + "." + addr_b3;
          addSocketToList(this.sd, sockType);
          data = { "event_type": "Libc::recvfrom", "method": "recvfrom", "sd": this.sd, "len": len, "src_ip": local.ip, "src_port": local.port, "dst_ip": ip_string, "dst_port": port, "dst_family": family, "type": sockType };
          am_send(PROFILE_HOOKING_TYPE13, JSON.stringify(data), buffer);
        }
      }
    }
  });
  Interceptor.attach(send_ptr, {
    onEnter: function(args) {
      this.sd = args[0].toInt32();
      this.addr = args[1];
      this.buflen = args[2].toInt32();
    },
    onLeave: function(retval) {
      var len = retval.toInt32();
      if (len == -1 || len > this.buflen)
        return;
      var buffer;
      var buf = ptr(this.addr);
      if (!buf.isNull()) {
        buffer = buf.readByteArray(len);
      }
      const sockType = Socket.type(this.sd);
      const sockLocal = Socket.localAddress(this.sd);
      const local = sockLocal && isTcpEndpointAddress(sockLocal) ? sockLocal : void 0;
      const sockRemote = Socket.peerAddress(this.sd);
      const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : void 0;
      if (this.sockType === "unix:stream" || sockType == null || sockType === void 0 || local === void 0 || remote === void 0) {
        return;
      }
      addSocketToList(this.sd, sockType);
      var data = { "event_type": "Libc::send", "method": "send", "sd": this.sd, "src_ip": local.ip, "src_port": local.port, "dst_ip": remote.ip, "dst_port": remote.port, "len": len, "type": sockType };
      am_send(PROFILE_HOOKING_TYPE13, JSON.stringify(data), buffer);
    }
  });
  Interceptor.attach(recv_ptr, {
    onEnter: function(args) {
      this.sd = args[0].toInt32();
      this.addr = args[1];
      this.buflen = args[2].toInt32();
    },
    onLeave: function(retval) {
      var len = retval.toInt32();
      if (len == -1 || len > this.buflen)
        return;
      var buffer;
      var buf = ptr(this.addr);
      if (!buf.isNull()) {
        buffer = buf.readByteArray(this.len);
      }
      const sockType = Socket.type(this.sd);
      const sockLocal = Socket.localAddress(this.sd);
      const local = sockLocal && isTcpEndpointAddress(sockLocal) ? sockLocal : void 0;
      const sockRemote = Socket.peerAddress(this.sd);
      const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : void 0;
      if (sockType === "unix:stream" || sockType == null || sockType === void 0 || local === void 0 || remote === void 0) {
        return;
      }
      addSocketToList(this.sd, sockType);
      var data = { "event_type": "Libc::recv", "method": "recv", "sd": this.sd, "src_ip": remote.ip, "src_port": remote.port, "dst_ip": local.ip, "dst_port": local.port, "len": len, "type": sockType };
      am_send(PROFILE_HOOKING_TYPE13, JSON.stringify(data), buffer);
    }
  });
  Interceptor.attach(sendmsg_ptr, {
    onEnter: function(args) {
      this.sd = args[0].toInt32();
    },
    onLeave: function(retval) {
      var len = retval.toInt32();
      if (len == -1)
        return;
      const sockType = Socket.type(this.sd);
      const sockLocal = Socket.localAddress(this.sd);
      const local = sockLocal && isTcpEndpointAddress(sockLocal) ? sockLocal : void 0;
      const sockRemote = Socket.peerAddress(this.sd);
      const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : void 0;
      if (sockType === "unix:stream" || sockType == null || sockType === void 0 || local === void 0 || remote === void 0) {
        return;
      }
      addSocketToList(this.sd, sockType);
      var buffer;
      var data = { "event_type": "Libc::sendmsg", "method": "sendmsg", "sd": this.sd, "src_ip": local.ip, "src_port": local.port, "dst_ip": remote.ip, "dst_port": remote.port, "len": len, "type": sockType };
      am_send(PROFILE_HOOKING_TYPE13, JSON.stringify(data), buffer);
    }
  });
  Interceptor.attach(recvmsg_ptr, {
    onEnter: function(args) {
      this.sd = args[0].toInt32();
      this.addr = args[1];
    },
    onLeave: function(retval) {
      var len = retval.toInt32();
      if (len == -1)
        return;
      const sockType = Socket.type(this.sd);
      const sockLocal = Socket.localAddress(this.sd);
      const local = sockLocal && isTcpEndpointAddress(sockLocal) ? sockLocal : void 0;
      const sockRemote = Socket.peerAddress(this.sd);
      const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : void 0;
      if (sockType === "unix:stream" || sockType == null || sockType === void 0 || local === void 0 || remote === void 0) {
        return;
      }
      addSocketToList(this.sd, sockType);
      var buffer;
      var data = { "event_type": "Libc::recvmsg", "method": "recvmsg", "sd": this.sd, "src_ip": remote.ip, "src_port": remote.port, "dst_ip": local.ip, "dst_port": local.port, "len": len, "type": sockType };
      am_send(PROFILE_HOOKING_TYPE13, JSON.stringify(data));
    }
  });
  Interceptor.attach(close_ptr, {
    onEnter: function(args) {
      this.sd = args[0].toInt32();
    },
    onLeave: function(retval) {
      if (retval.toInt32() != 0)
        return;
      var socketIndex = findSocket(this.sd);
      if (socketIndex == -1)
        return;
      socket_list.splice(socketIndex, 1);
      const sockType = Socket.type(this.sd);
      const sockLocal = Socket.localAddress(this.sd);
      const local = sockLocal && isTcpEndpointAddress(sockLocal) ? sockLocal : void 0;
      const sockRemote = Socket.peerAddress(this.sd);
      const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : void 0;
      if (sockType === "unix:stream" || sockType == null || sockType === void 0 || local === void 0 || remote === void 0) {
        return;
      }
      var data = { "event_type": "Libc::close", "method": "close", "sd": this.sd, "src_ip": remote.ip, "src_port": remote.port, "dst_ip": local.ip, "dst_port": local.port };
    }
  });
}
function install_socket_hooks() {
  devlog("\n");
  devlog("install socket hooks");
  hook_java_socket_communication();
  hook_bionic_socket_commuication();
}

// agent/process/nativelibrary.ts
var PROFILE_HOOKING_TYPE14 = "PROCESS_NATIVE_LIB";
function createNativeLibEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE14, JSON.stringify(event));
}
function hook_native_lib_loading() {
  var dlopen = null;
  for (const module of Process.enumerateModules()) {
    try {
      dlopen = module.findExportByName("dlopen");
      if (dlopen)
        break;
    } catch (e) {
      continue;
    }
  }
  if (dlopen != null) {
    devlog(`Found dlopen at: ${dlopen}`);
    Interceptor.attach(dlopen, {
      onEnter: function(args) {
        const soName = args[0].readCString();
        const threadDef = Java.use("java.lang.Thread");
        const threadInstance = threadDef.$new();
        const stack = threadInstance.currentThread().getStackTrace();
        createNativeLibEvent("native.library.load", {
          library_name: soName,
          load_method: "dlopen",
          library_path: soName,
          module_base: dlopen.toString(),
          stack_trace: Where(stack)
        });
        if (soName && soName.indexOf("libc.so") !== -1) {
          this.hook_libc = true;
        }
        this.library_name = soName;
      },
      onLeave: function(retval) {
        if (retval && !retval.isNull()) {
          createNativeLibEvent("native.library.loaded", {
            library_name: this.library_name,
            load_method: "dlopen",
            handle: retval.toString(),
            success: true
          });
          if (this.hook_libc) {
            devlog("libc.so loaded, additional hooks could be installed here");
          }
        } else {
          createNativeLibEvent("native.library.load_failed", {
            library_name: this.library_name,
            load_method: "dlopen",
            error: "dlopen returned NULL"
          });
        }
      }
    });
  }
  var android_dlopen_ext = null;
  for (const module of Process.enumerateModules()) {
    try {
      android_dlopen_ext = module.findExportByName("android_dlopen_ext");
      if (android_dlopen_ext)
        break;
    } catch (e) {
      continue;
    }
  }
  if (android_dlopen_ext != null) {
    devlog(`Found android_dlopen_ext at: ${android_dlopen_ext}`);
    Interceptor.attach(android_dlopen_ext, {
      onEnter: function(args) {
        const soName = args[0].readCString();
        const flags = args[1];
        const extinfo = args[2];
        const threadDef = Java.use("java.lang.Thread");
        const threadInstance = threadDef.$new();
        const stack = threadInstance.currentThread().getStackTrace();
        createNativeLibEvent("native.library.load", {
          library_name: soName,
          load_method: "android_dlopen_ext",
          library_path: soName,
          flags: flags ? flags.toInt32() : null,
          extinfo: extinfo ? extinfo.toString() : null,
          module_base: android_dlopen_ext.toString(),
          stack_trace: Where(stack)
        });
        if (soName && soName.indexOf("libc.so") !== -1) {
          this.hook_libc = true;
        }
        this.library_name = soName;
      },
      onLeave: function(retval) {
        if (retval && !retval.isNull()) {
          createNativeLibEvent("native.library.loaded", {
            library_name: this.library_name,
            load_method: "android_dlopen_ext",
            handle: retval.toString(),
            success: true
          });
          if (this.hook_libc) {
            devlog("libc.so loaded via android_dlopen_ext");
          }
        } else {
          createNativeLibEvent("native.library.load_failed", {
            library_name: this.library_name,
            load_method: "android_dlopen_ext",
            error: "android_dlopen_ext returned NULL"
          });
        }
      }
    });
  }
}
function install_native_library_hooks() {
  devlog("\n");
  devlog("install native hooks");
  hook_native_lib_loading();
}

// agent/process/process.ts
var PROFILE_HOOKING_TYPE15 = "PROCESS_CREATION";
function createProcessEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE15, JSON.stringify(event));
}
function hook_java_process_creation() {
  Java.perform(() => {
    try {
      const Process2 = Java.use("android.os.Process");
      const threadDef = Java.use("java.lang.Thread");
      const threadInstance = threadDef.$new();
      if (Process2.start) {
        Process2.start.implementation = function(processClass, niceName, uid, gid, gids, debugFlags, mountExternal, targetSdkVersion, seInfo, abi, instructionSet, appDataDir, zygoteArgs) {
          const stack = threadInstance.currentThread().getStackTrace();
          createProcessEvent("process.creation", {
            library: "android.os.Process",
            method: "start",
            process_class: processClass ? processClass.toString() : null,
            nice_name: niceName,
            uid,
            gid,
            gids: gids ? Array.isArray(gids) ? gids : gids.toString() : null,
            debug_flags: debugFlags,
            mount_external: mountExternal,
            target_sdk_version: targetSdkVersion,
            selinux_info: seInfo,
            abi,
            instruction_set: instructionSet,
            app_data_dir: appDataDir,
            zygote_args: zygoteArgs ? zygoteArgs.toString() : null,
            stack_trace: Where(stack)
          });
          return this.start.apply(this, arguments);
        };
      }
      if (Process2.killProcess) {
        Process2.killProcess.implementation = function(pid) {
          createProcessEvent("process.kill", {
            library: "android.os.Process",
            method: "killProcess",
            target_pid: pid
          });
          return this.killProcess(pid);
        };
      }
      if (Process2.sendSignal) {
        Process2.sendSignal.implementation = function(pid, signal) {
          createProcessEvent("process.signal", {
            library: "android.os.Process",
            method: "sendSignal",
            target_pid: pid,
            signal
          });
          return this.sendSignal(pid, signal);
        };
      }
    } catch (error) {
      createProcessEvent("process.error", {
        error_message: error.toString(),
        error_type: "hook_java_process_creation"
      });
    }
  });
}
function hook_native_process_creation() {
  const forkPtr = Process.getModuleByName("libc.so").getExportByName("fork");
  if (forkPtr) {
    Interceptor.attach(forkPtr, {
      onEnter: function(args) {
        createProcessEvent("process.fork.attempt", {
          native_function: "fork",
          caller_pid: Process.id
        });
      },
      onLeave: function(retval) {
        const pid = retval.toInt32();
        createProcessEvent("process.fork.result", {
          native_function: "fork",
          caller_pid: Process.id,
          child_pid: pid,
          success: pid >= 0
        });
      }
    });
  }
  const execvePtr = Process.getModuleByName("libc.so").getExportByName("execve");
  if (execvePtr) {
    Interceptor.attach(execvePtr, {
      onEnter: function(args) {
        const pathname = args[0].readCString();
        createProcessEvent("process.execve.attempt", {
          native_function: "execve",
          pathname,
          caller_pid: Process.id
        });
      },
      onLeave: function(retval) {
        const result = retval.toInt32();
        createProcessEvent("process.execve.result", {
          native_function: "execve",
          return_value: result,
          success: result === 0
        });
      }
    });
  }
  const systemPtr = Process.getModuleByName("libc.so").getExportByName("system");
  if (systemPtr) {
    Interceptor.attach(systemPtr, {
      onEnter: function(args) {
        const command = args[0].readCString();
        createProcessEvent("process.system.call", {
          native_function: "system",
          command,
          caller_pid: Process.id
        });
      },
      onLeave: function(retval) {
        const result = retval.toInt32();
        createProcessEvent("process.system.result", {
          native_function: "system",
          return_value: result,
          success: result !== -1
        });
      }
    });
  }
}
function install_process_hooks() {
  devlog("\n");
  devlog("install process hooks");
  hook_java_process_creation();
  hook_native_process_creation();
}

// agent/process/runtime.ts
var PROFILE_HOOKING_TYPE16 = "RUNTIME_HOOKS";
function createRuntimeEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE16, JSON.stringify(event));
}
function hook_runtime() {
  Java.perform(() => {
    try {
      const Runtime2 = Java.use("java.lang.Runtime");
      const threadDef = Java.use("java.lang.Thread");
      const threadInstance = threadDef.$new();
      for (let i = 0; i < 6; i++) {
        if (Runtime2.exec.overloads[i]) {
          Runtime2.exec.overloads[i].implementation = function(command, envp, dir) {
            const stack = threadInstance.currentThread().getStackTrace();
            let commandStr = null;
            if (command) {
              if (Array.isArray(command)) {
                commandStr = command.join(" ");
              } else {
                commandStr = command.toString();
              }
            }
            createRuntimeEvent("runtime.exec", {
              library: "java.lang.Runtime",
              method: "exec",
              overload_index: i,
              command: commandStr,
              environment: envp ? envp.toString() : null,
              working_directory: dir ? dir.toString() : null,
              stack_trace: Where(stack)
            });
            return Runtime2.exec.overloads[i].apply(this, arguments);
          };
        }
      }
      for (let i = 0; i < 2; i++) {
        if (Runtime2.loadLibrary.overloads[i]) {
          Runtime2.loadLibrary.overloads[i].implementation = function(libname) {
            const stack = threadInstance.currentThread().getStackTrace();
            createRuntimeEvent("runtime.load_library", {
              library: "java.lang.Runtime",
              method: "loadLibrary",
              overload_index: i,
              library_name: libname ? libname.toString() : null,
              stack_trace: Where(stack)
            });
            return Runtime2.loadLibrary.overloads[i].apply(this, arguments);
          };
        }
      }
      for (let i = 0; i < 2; i++) {
        if (Runtime2.load.overloads[i]) {
          Runtime2.load.overloads[i].implementation = function(filename) {
            const stack = threadInstance.currentThread().getStackTrace();
            createRuntimeEvent("runtime.load", {
              library: "java.lang.Runtime",
              method: "load",
              overload_index: i,
              filename: filename ? filename.toString() : null,
              stack_trace: Where(stack)
            });
            return Runtime2.load.overloads[i].apply(this, arguments);
          };
        }
      }
    } catch (error) {
      createRuntimeEvent("runtime.error", {
        error_message: error.toString(),
        error_type: "hook_runtime"
      });
    }
  });
}
function trace_reflection() {
  Java.perform(() => {
    try {
      const internalClasses = ["android.", "com.android", "java.lang", "java.io"];
      const threadDef = Java.use("java.lang.Thread");
      const threadInstance = threadDef.$new();
      const classDef = Java.use("java.lang.Class");
      const classLoaderDef = Java.use("java.lang.ClassLoader");
      const Method = Java.use("java.lang.reflect.Method");
      const forName = classDef.forName.overload("java.lang.String", "boolean", "java.lang.ClassLoader");
      const loadClass = classLoaderDef.loadClass.overload("java.lang.String", "boolean");
      const getMethod = classDef.getMethod.overload("java.lang.String", "[Ljava.lang.Class;");
      const getDeclaredMethod = classDef.getDeclaredMethod.overload("java.lang.String", "[Ljava.lang.Class;");
      const invoke = Method.invoke.overload("java.lang.Object", "[Ljava.lang.Object;");
      getMethod.implementation = function(methodName, paramTypes) {
        const method = getMethod.call(this, methodName, paramTypes);
        const stack = threadInstance.currentThread().getStackTrace();
        createRuntimeEvent("reflection.get_method", {
          library: "java.lang.Class",
          method: "getMethod",
          method_name: methodName,
          method_signature: method.toGenericString(),
          class_name: this.getName(),
          access_type: "public",
          stack_trace: Where(stack)
        });
        return method;
      };
      getDeclaredMethod.implementation = function(methodName, paramTypes) {
        const method = getDeclaredMethod.call(this, methodName, paramTypes);
        const stack = threadInstance.currentThread().getStackTrace();
        createRuntimeEvent("reflection.get_declared_method", {
          library: "java.lang.Class",
          method: "getDeclaredMethod",
          method_name: methodName,
          method_signature: method.toGenericString(),
          class_name: this.getName(),
          access_type: "any",
          stack_trace: Where(stack)
        });
        return method;
      };
      forName.implementation = function(class_name, flag, class_loader) {
        let isInternal = false;
        for (const internalClass of internalClasses) {
          if (class_name.startsWith(internalClass)) {
            isInternal = true;
            break;
          }
        }
        if (!isInternal) {
          const stack = threadInstance.currentThread().getStackTrace();
          createRuntimeEvent("reflection.class_for_name", {
            library: "java.lang.Class",
            method: "forName",
            class_name,
            initialize: flag,
            class_loader: class_loader ? class_loader.toString() : null,
            is_internal: isInternal,
            stack_trace: Where(stack)
          });
        }
        return forName.call(this, class_name, flag, class_loader);
      };
      loadClass.implementation = function(class_name, resolve) {
        let isInternal = false;
        for (const internalClass of internalClasses) {
          if (class_name.startsWith(internalClass)) {
            isInternal = true;
            break;
          }
        }
        if (!isInternal) {
          const stack = threadInstance.currentThread().getStackTrace();
          createRuntimeEvent("reflection.load_class", {
            library: "java.lang.ClassLoader",
            method: "loadClass",
            class_name,
            resolve,
            is_internal: isInternal,
            stack_trace: Where(stack)
          });
        }
        return loadClass.call(this, class_name, resolve);
      };
      invoke.implementation = function(instance, args) {
        const stack = threadInstance.currentThread().getStackTrace();
        const result = invoke.call(this, instance, args);
        let argumentsStr = null;
        if (args) {
          try {
            argumentsStr = args.map((arg) => arg ? arg.toString() : "null").join(", ");
          } catch (e) {
            argumentsStr = "arguments_processing_error";
          }
        }
        createRuntimeEvent("reflection.method_invoke", {
          library: "java.lang.reflect.Method",
          method: "invoke",
          method_name: this.getName(),
          method_signature: this.toGenericString(),
          target_instance: instance ? instance.toString() : null,
          arguments: argumentsStr,
          result: result ? result.toString() : null,
          stack_trace: Where(stack)
        });
        return result;
      };
    } catch (error) {
      createRuntimeEvent("reflection.error", {
        error_message: error.toString(),
        error_type: "trace_reflection"
      });
    }
  });
}
function install_runtime_hooks() {
  devlog("\n");
  devlog("install runtime hooks");
  hook_runtime();
  trace_reflection();
}

// agent/services/bluetooth.ts
var PROFILE_HOOKING_TYPE17 = "BLUETOOTH";
function createBluetoothEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE17, JSON.stringify(event));
}
function hook_bluetooth() {
  Java.perform(() => {
    try {
      const BluetoothGatt = Java.use("android.bluetooth.BluetoothGatt");
      const BluetoothGattCharacteristic = Java.use("android.bluetooth.BluetoothGattCharacteristic");
      const BluetoothAdapter = Java.use("android.bluetooth.BluetoothAdapter");
      const BluetoothDevice = Java.use("android.bluetooth.BluetoothDevice");
      const threadDef = Java.use("java.lang.Thread");
      const threadInstance = threadDef.$new();
      BluetoothGatt.readCharacteristic.overload("android.bluetooth.BluetoothGattCharacteristic").implementation = function(characteristic) {
        const stack = threadInstance.currentThread().getStackTrace();
        const uuid = characteristic.getUuid().toString();
        const value = characteristic.getValue();
        createBluetoothEvent("bluetooth.gatt.read_characteristic", {
          library: "android.bluetooth.BluetoothGatt",
          method: "readCharacteristic",
          characteristic_uuid: uuid,
          characteristic_value: value ? bytesToHex(new Uint8Array(value)) : null,
          stack_trace: Where(stack)
        });
        return this.readCharacteristic.overload("android.bluetooth.BluetoothGattCharacteristic").apply(this, arguments);
      };
      BluetoothGattCharacteristic.setValue.overload("[B").implementation = function(value) {
        const stack = threadInstance.currentThread().getStackTrace();
        const uuid = this.getUuid().toString();
        createBluetoothEvent("bluetooth.gatt.set_characteristic_value", {
          library: "android.bluetooth.BluetoothGattCharacteristic",
          method: "setValue",
          characteristic_uuid: uuid,
          value_hex: value ? bytesToHex(new Uint8Array(value)) : null,
          value_length: value ? value.length : 0,
          stack_trace: Where(stack)
        });
        return this.setValue.overload("[B").apply(this, arguments);
      };
      if (BluetoothAdapter.getDefaultAdapter) {
        BluetoothAdapter.getDefaultAdapter.implementation = function() {
          const stack = threadInstance.currentThread().getStackTrace();
          const result = this.getDefaultAdapter();
          createBluetoothEvent("bluetooth.adapter.get_default", {
            library: "android.bluetooth.BluetoothAdapter",
            method: "getDefaultAdapter",
            adapter_available: result !== null,
            stack_trace: Where(stack)
          });
          return result;
        };
      }
      BluetoothAdapter.enable.implementation = function() {
        const stack = threadInstance.currentThread().getStackTrace();
        const result = this.enable();
        createBluetoothEvent("bluetooth.adapter.enable", {
          library: "android.bluetooth.BluetoothAdapter",
          method: "enable",
          success: result,
          stack_trace: Where(stack)
        });
        return result;
      };
      BluetoothAdapter.disable.implementation = function() {
        const stack = threadInstance.currentThread().getStackTrace();
        const result = this.disable();
        createBluetoothEvent("bluetooth.adapter.disable", {
          library: "android.bluetooth.BluetoothAdapter",
          method: "disable",
          success: result,
          stack_trace: Where(stack)
        });
        return result;
      };
      BluetoothAdapter.startDiscovery.implementation = function() {
        const stack = threadInstance.currentThread().getStackTrace();
        const result = this.startDiscovery();
        createBluetoothEvent("bluetooth.adapter.start_discovery", {
          library: "android.bluetooth.BluetoothAdapter",
          method: "startDiscovery",
          success: result,
          stack_trace: Where(stack)
        });
        return result;
      };
      BluetoothDevice.createBond.implementation = function() {
        const stack = threadInstance.currentThread().getStackTrace();
        const deviceAddress = this.getAddress();
        const deviceName = this.getName();
        const result = this.createBond();
        createBluetoothEvent("bluetooth.device.create_bond", {
          library: "android.bluetooth.BluetoothDevice",
          method: "createBond",
          device_address: deviceAddress,
          device_name: deviceName,
          success: result,
          stack_trace: Where(stack)
        });
        return result;
      };
    } catch (error) {
      createBluetoothEvent("bluetooth.error", {
        error_message: error.toString(),
        error_type: "hook_bluetooth"
      });
    }
  });
}
function install_bluetooth_hooks() {
  devlog("\n");
  devlog("install bluetooth hooks");
  hook_bluetooth();
}

// agent/services/camera.ts
var PROFILE_HOOKING_TYPE18 = "CAMERA";
function createCameraEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE18, JSON.stringify(event));
}
function hook_camera() {
  Java.perform(() => {
    try {
      const Camera = Java.use("android.hardware.Camera");
      const Camera2CameraManager = Java.use("android.hardware.camera2.CameraManager");
      const threadDef = Java.use("java.lang.Thread");
      const threadInstance = threadDef.$new();
      if (Camera.open) {
        Camera.open.overload().implementation = function() {
          const stack = threadInstance.currentThread().getStackTrace();
          const result = this.open();
          createCameraEvent("camera.legacy.open", {
            library: "android.hardware.Camera",
            method: "open",
            camera_id: "default",
            success: result !== null,
            stack_trace: Where(stack)
          });
          return result;
        };
        Camera.open.overload("int").implementation = function(cameraId) {
          const stack = threadInstance.currentThread().getStackTrace();
          const result = this.open(cameraId);
          createCameraEvent("camera.legacy.open", {
            library: "android.hardware.Camera",
            method: "open",
            camera_id: cameraId,
            success: result !== null,
            stack_trace: Where(stack)
          });
          return result;
        };
      }
      if (Camera2CameraManager.openCamera) {
        Camera2CameraManager.openCamera.overload("java.lang.String", "android.hardware.camera2.CameraDevice$StateCallback", "android.os.Handler").implementation = function(cameraId, callback, handler) {
          const stack = threadInstance.currentThread().getStackTrace();
          createCameraEvent("camera.camera2.open", {
            library: "android.hardware.camera2.CameraManager",
            method: "openCamera",
            camera_id: cameraId,
            has_callback: callback !== null,
            has_handler: handler !== null,
            stack_trace: Where(stack)
          });
          return this.openCamera(cameraId, callback, handler);
        };
      }
      if (Camera2CameraManager.getCameraIdList) {
        Camera2CameraManager.getCameraIdList.implementation = function() {
          const stack = threadInstance.currentThread().getStackTrace();
          const result = this.getCameraIdList();
          createCameraEvent("camera.camera2.get_camera_list", {
            library: "android.hardware.camera2.CameraManager",
            method: "getCameraIdList",
            camera_count: result ? result.length : 0,
            camera_ids: result ? result : [],
            stack_trace: Where(stack)
          });
          return result;
        };
      }
    } catch (error) {
      createCameraEvent("camera.error", {
        error_message: error.toString(),
        error_type: "hook_camera"
      });
    }
  });
}
function install_camera_hooks() {
  devlog("\n");
  devlog("install camera hooks");
  hook_camera();
}

// agent/services/clipboard.ts
var PROFILE_HOOKING_TYPE19 = "CLIPBOARD";
function createClipboardEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE19, JSON.stringify(event));
}
function hook_clipboard() {
  Java.perform(() => {
    try {
      const Context = Java.use("android.content.Context");
      const ClipboardManager = Java.use("android.content.ClipboardManager");
      const threadDef = Java.use("java.lang.Thread");
      const threadInstance = threadDef.$new();
      ClipboardManager.setPrimaryClip.implementation = function(clip) {
        const stack = threadInstance.currentThread().getStackTrace();
        for (let i = 0; i < clip.getItemCount(); i++) {
          const item = clip.getItemAt(i);
          let contentType = "unknown";
          let content = null;
          if (item.getIntent()) {
            contentType = "intent";
            content = item.getIntent().toString();
          } else if (item.getHtmlText()) {
            contentType = "html_text";
            content = item.getHtmlText().toString();
          } else if (item.getUri()) {
            contentType = "uri";
            content = item.getUri().toString();
          } else if (item.getText()) {
            contentType = "text";
            content = item.getText().toString();
          } else {
            contentType = "string";
            content = item.toString();
          }
          createClipboardEvent("clipboard.set_primary_clip", {
            library: "android.content.ClipboardManager",
            method: "setPrimaryClip",
            item_index: i,
            total_items: clip.getItemCount(),
            content_type: contentType,
            content,
            content_length: content ? content.length : 0,
            stack_trace: Where(stack)
          });
        }
        return this.setPrimaryClip.apply(this, arguments);
      };
      ClipboardManager.getPrimaryClip.implementation = function() {
        const stack = threadInstance.currentThread().getStackTrace();
        const result = this.getPrimaryClip();
        createClipboardEvent("clipboard.get_primary_clip", {
          library: "android.content.ClipboardManager",
          method: "getPrimaryClip",
          has_clip: result !== null,
          item_count: result ? result.getItemCount() : 0,
          stack_trace: Where(stack)
        });
        return result;
      };
    } catch (error) {
      createClipboardEvent("clipboard.error", {
        error_message: error.toString(),
        error_type: "hook_clipboard"
      });
    }
  });
}
function install_clipboard_hooks() {
  devlog("\n");
  devlog("install clipboard hooks");
  hook_clipboard();
}

// agent/services/location.ts
var PROFILE_HOOKING_TYPE20 = "LOCATION_ACCESS";
function createLocationEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE20, JSON.stringify(event));
}
function hook_location() {
  Java.perform(() => {
    try {
      const LocationManager = Java.use("android.location.LocationManager");
      const Location = Java.use("android.location.Location");
      const threadDef = Java.use("java.lang.Thread");
      const threadInstance = threadDef.$new();
      LocationManager.getLastKnownLocation.overload("java.lang.String").implementation = function(provider) {
        const result = this.getLastKnownLocation(provider);
        const stack = threadInstance.currentThread().getStackTrace();
        if (result !== null) {
          const latitude = result.getLatitude();
          const longitude = result.getLongitude();
          const accuracy = result.getAccuracy();
          createLocationEvent("location.last_known_location", {
            library: "android.location.LocationManager",
            method: "getLastKnownLocation",
            provider,
            latitude,
            longitude,
            accuracy,
            has_location: true,
            stack_trace: Where(stack)
          });
        } else {
          createLocationEvent("location.last_known_location", {
            library: "android.location.LocationManager",
            method: "getLastKnownLocation",
            provider,
            has_location: false,
            stack_trace: Where(stack)
          });
        }
        return result;
      };
      LocationManager.requestLocationUpdates.overload("java.lang.String", "long", "float", "android.location.LocationListener").implementation = function(provider, minTime, minDistance, listener) {
        const stack = threadInstance.currentThread().getStackTrace();
        createLocationEvent("location.request_updates", {
          library: "android.location.LocationManager",
          method: "requestLocationUpdates",
          provider,
          min_time_ms: minTime,
          min_distance_m: minDistance,
          has_listener: listener !== null,
          overload: "basic",
          stack_trace: Where(stack)
        });
        return this.requestLocationUpdates(provider, minTime, minDistance, listener);
      };
      if (LocationManager.requestLocationUpdates.overload("java.lang.String", "long", "float", "android.location.LocationListener", "android.os.Looper")) {
        LocationManager.requestLocationUpdates.overload("java.lang.String", "long", "float", "android.location.LocationListener", "android.os.Looper").implementation = function(provider, minTime, minDistance, listener, looper) {
          const stack = threadInstance.currentThread().getStackTrace();
          createLocationEvent("location.request_updates", {
            library: "android.location.LocationManager",
            method: "requestLocationUpdates",
            provider,
            min_time_ms: minTime,
            min_distance_m: minDistance,
            has_listener: listener !== null,
            has_looper: looper !== null,
            overload: "with_looper",
            stack_trace: Where(stack)
          });
          return this.requestLocationUpdates(provider, minTime, minDistance, listener, looper);
        };
      }
      Location.getLatitude.implementation = function() {
        const latitude = this.getLatitude();
        const stack = threadInstance.currentThread().getStackTrace();
        createLocationEvent("location.get_latitude", {
          library: "android.location.Location",
          method: "getLatitude",
          latitude,
          stack_trace: Where(stack)
        });
        return latitude;
      };
      Location.getLongitude.implementation = function() {
        const longitude = this.getLongitude();
        const stack = threadInstance.currentThread().getStackTrace();
        createLocationEvent("location.get_longitude", {
          library: "android.location.Location",
          method: "getLongitude",
          longitude,
          stack_trace: Where(stack)
        });
        return longitude;
      };
    } catch (error) {
      createLocationEvent("location.error", {
        error_message: error.toString(),
        error_type: "hook_location"
      });
    }
  });
}
function hook_playstore_location_api() {
  Java.perform(() => {
    try {
      const FusedLocationProviderClient = Java.use("com.google.android.gms.location.FusedLocationProviderClient");
      const threadDef = Java.use("java.lang.Thread");
      const threadInstance = threadDef.$new();
      FusedLocationProviderClient.getLastLocation.overload().implementation = function() {
        const stack = threadInstance.currentThread().getStackTrace();
        const result = this.getLastLocation();
        createLocationEvent("location.fused_provider.get_last_location", {
          library: "com.google.android.gms.location.FusedLocationProviderClient",
          method: "getLastLocation",
          provider: "google_play_services",
          stack_trace: Where(stack)
        });
        return result;
      };
    } catch (error) {
      devlog("Google Play Services location API not available: " + error.toString());
    }
  });
}
function install_location_hooks() {
  devlog("\n");
  devlog("install location hooks");
  hook_location();
  hook_playstore_location_api();
}

// agent/services/telephony.ts
var PROFILE_HOOKING_TYPE21 = "TELEPHONY";
function createTelephonyEvent(eventType, data) {
  const event = {
    event_type: eventType,
    timestamp: Date.now(),
    ...data
  };
  am_send(PROFILE_HOOKING_TYPE21, JSON.stringify(event));
}
function hook_sms() {
  Java.perform(() => {
    try {
      const SmsManager = Java.use("android.telephony.SmsManager");
      const threadDef = Java.use("java.lang.Thread");
      const threadInstance = threadDef.$new();
      SmsManager.sendTextMessage.overload("java.lang.String", "java.lang.String", "java.lang.String", "android.app.PendingIntent", "android.app.PendingIntent").implementation = function(destinationAddress, scAddress, text, sentIntent, deliveryIntent) {
        const stack = threadInstance.currentThread().getStackTrace();
        createTelephonyEvent("telephony.sms.send_text", {
          library: "android.telephony.SmsManager",
          method: "sendTextMessage",
          destination_address: destinationAddress,
          service_center_address: scAddress,
          message_text: text,
          text_length: text ? text.length : 0,
          has_sent_intent: sentIntent !== null,
          has_delivery_intent: deliveryIntent !== null,
          stack_trace: Where(stack)
        });
        return this.sendTextMessage(destinationAddress, scAddress, text, sentIntent, deliveryIntent);
      };
      SmsManager.sendMultipartTextMessage.overload("java.lang.String", "java.lang.String", "java.util.ArrayList", "java.util.ArrayList", "java.util.ArrayList").implementation = function(destinationAddress, scAddress, parts, sentIntents, deliveryIntents) {
        const stack = threadInstance.currentThread().getStackTrace();
        const partsArray = parts ? parts.toArray() : [];
        createTelephonyEvent("telephony.sms.send_multipart", {
          library: "android.telephony.SmsManager",
          method: "sendMultipartTextMessage",
          destination_address: destinationAddress,
          service_center_address: scAddress,
          message_parts: partsArray,
          parts_count: partsArray.length,
          has_sent_intents: sentIntents !== null,
          has_delivery_intents: deliveryIntents !== null,
          stack_trace: Where(stack)
        });
        return this.sendMultipartTextMessage(destinationAddress, scAddress, parts, sentIntents, deliveryIntents);
      };
    } catch (error) {
      createTelephonyEvent("telephony.sms.error", {
        error_message: error.toString(),
        error_type: "hook_sms"
      });
    }
  });
}
function hook_device_infos() {
  Java.perform(() => {
    try {
      const secureSettings = Java.use("android.provider.Settings$Secure");
      const contentResolver = Java.use("android.content.ContentResolver");
      const wifiInfo = Java.use("android.net.wifi.WifiInfo");
      const bluetoothAdapter = Java.use("android.bluetooth.BluetoothAdapter");
      const telephonyManager = Java.use("android.telephony.TelephonyManager");
      const build = Java.use("android.os.Build");
      const systemProperties = Java.use("android.os.SystemProperties");
      const threadDef = Java.use("java.lang.Thread");
      const threadInstance = threadDef.$new();
      const seenEvents = {};
      systemProperties.get.overload("java.lang.String").implementation = function(key_value) {
        const result = this.get(key_value);
        const stack = threadInstance.currentThread().getStackTrace();
        const eventKey = `system_prop:${key_value}`;
        if (seenEvents[eventKey] !== result) {
          seenEvents[eventKey] = result;
          createTelephonyEvent("telephony.system_properties.get", {
            library: "android.os.SystemProperties",
            method: "get",
            property_key: key_value,
            property_value: result,
            stack_trace: Where(stack)
          });
        }
        return result;
      };
      const buildProperties = [
        "MODEL",
        "DEVICE",
        "BOARD",
        "PRODUCT",
        "HARDWARE",
        "FINGERPRINT",
        "MANUFACTURER",
        "BOOTLOADER",
        "BRAND",
        "HOST",
        "ID",
        "DISPLAY",
        "TAGS",
        "SERIAL",
        "TYPE",
        "USER",
        "UNKNOWN"
      ];
      buildProperties.forEach((prop) => {
        Object.defineProperty(build, prop, {
          get: function() {
            const result = build[prop].value;
            createTelephonyEvent("telephony.build.get_property", {
              library: "android.os.Build",
              method: `android.os.Build.${prop}`,
              property: prop,
              value: result
            });
            return result;
          },
          set: function(newValue) {
            createTelephonyEvent("telephony.build.set_property", {
              library: "android.os.Build",
              method: `android.os.Build.${prop}`,
              property: prop,
              attempted_value: newValue
            });
          },
          configurable: true
        });
      });
      telephonyManager.getLine1Number.overloads[0].implementation = function() {
        const result = this.getLine1Number();
        const stack = threadInstance.currentThread().getStackTrace();
        createTelephonyEvent("telephony.manager.get_phone_number", {
          library: "android.telephony.TelephonyManager",
          method: "getLine1Number",
          phone_number: result,
          stack_trace: Where(stack)
        });
        return result;
      };
      telephonyManager.getSubscriberId.overload().implementation = function() {
        const result = this.getSubscriberId();
        const stack = threadInstance.currentThread().getStackTrace();
        createTelephonyEvent("telephony.manager.get_imsi", {
          library: "android.telephony.TelephonyManager",
          method: "getSubscriberId",
          imsi: result,
          stack_trace: Where(stack)
        });
        return result;
      };
      telephonyManager.getDeviceId.overloads[0].implementation = function() {
        const result = this.getDeviceId();
        const stack = threadInstance.currentThread().getStackTrace();
        createTelephonyEvent("telephony.manager.get_device_id", {
          library: "android.telephony.TelephonyManager",
          method: "getDeviceId",
          device_id: result,
          stack_trace: Where(stack)
        });
        return result;
      };
      telephonyManager.getImei.overloads[0].implementation = function() {
        const result = this.getImei();
        const stack = threadInstance.currentThread().getStackTrace();
        createTelephonyEvent("telephony.manager.get_imei", {
          library: "android.telephony.TelephonyManager",
          method: "getImei",
          imei: result,
          stack_trace: Where(stack)
        });
        return result;
      };
      telephonyManager.getSimOperator.overload().implementation = function() {
        const result = this.getSimOperator();
        const stack = threadInstance.currentThread().getStackTrace();
        createTelephonyEvent("telephony.manager.get_sim_operator", {
          library: "android.telephony.TelephonyManager",
          method: "getSimOperator",
          sim_operator: result,
          stack_trace: Where(stack)
        });
        return result;
      };
      bluetoothAdapter.getAddress.implementation = function() {
        const result = this.getAddress();
        const stack = threadInstance.currentThread().getStackTrace();
        createTelephonyEvent("telephony.bluetooth.get_address", {
          library: "android.bluetooth.BluetoothAdapter",
          method: "getAddress",
          mac_address: result,
          stack_trace: Where(stack)
        });
        return result;
      };
      wifiInfo.getMacAddress.implementation = function() {
        const result = this.getMacAddress();
        const stack = threadInstance.currentThread().getStackTrace();
        createTelephonyEvent("telephony.wifi.get_mac_address", {
          library: "android.net.wifi.WifiInfo",
          method: "getMacAddress",
          mac_address: result,
          stack_trace: Where(stack)
        });
        return result;
      };
      wifiInfo.getSSID.implementation = function() {
        const result = this.getSSID();
        const stack = threadInstance.currentThread().getStackTrace();
        createTelephonyEvent("telephony.wifi.get_ssid", {
          library: "android.net.wifi.WifiInfo",
          method: "getSSID",
          ssid: result,
          stack_trace: Where(stack)
        });
        return result;
      };
      wifiInfo.getBSSID.implementation = function() {
        const result = this.getBSSID();
        const stack = threadInstance.currentThread().getStackTrace();
        createTelephonyEvent("telephony.wifi.get_bssid", {
          library: "android.net.wifi.WifiInfo",
          method: "getBSSID",
          bssid: result,
          stack_trace: Where(stack)
        });
        return result;
      };
      contentResolver.query.overload("android.net.Uri", "[Ljava.lang.String;", "android.os.Bundle", "android.os.CancellationSignal").implementation = function(uri, str, bundle, sig) {
        const stack = threadInstance.currentThread().getStackTrace();
        if (uri == "content://com.google.android.gsf.gservicesa") {
          createTelephonyEvent("telephony.content_resolver.query_gsf", {
            library: "android.content.ContentResolver",
            method: "query",
            uri,
            action: "cloaking_gsf_query",
            stack_trace: Where(stack)
          });
          return null;
        } else {
          const result = this.query(uri, str, bundle, sig);
          createTelephonyEvent("telephony.content_resolver.query", {
            library: "android.content.ContentResolver",
            method: "query",
            uri,
            has_result: result !== null,
            stack_trace: Where(stack)
          });
          return result;
        }
      };
      contentResolver.query.overload("android.net.Uri", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String").implementation = function(uri, astr, bstr, cstr, dstr) {
        const stack = threadInstance.currentThread().getStackTrace();
        if (uri == "content://com.google.android.gsf.gservicesa") {
          createTelephonyEvent("telephony.content_resolver.query_gsf", {
            library: "android.content.ContentResolver",
            method: "query",
            uri,
            action: "cloaking_gsf_query",
            stack_trace: Where(stack)
          });
          return null;
        } else {
          const result = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext().getContentResolver().query(uri, astr, bstr, cstr, dstr);
          createTelephonyEvent("telephony.content_resolver.query", {
            library: "android.content.ContentResolver",
            method: "query",
            uri,
            has_result: result !== null,
            stack_trace: Where(stack)
          });
          return result;
        }
      };
      contentResolver.query.overload("android.net.Uri", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String", "android.os.CancellationSignal").implementation = function(uri, astr, bstr, cstr, sig) {
        const stack = threadInstance.currentThread().getStackTrace();
        if (uri == "content://com.google.android.gsf.gservicesa") {
          createTelephonyEvent("telephony.content_resolver.query_gsf", {
            library: "android.content.ContentResolver",
            method: "query",
            uri,
            action: "cloaking_gsf_query",
            stack_trace: Where(stack)
          });
          return null;
        } else {
          const result = this.query(uri, astr, bstr, cstr, sig);
          createTelephonyEvent("telephony.content_resolver.query", {
            library: "android.content.ContentResolver",
            method: "query",
            uri,
            has_result: result !== null,
            stack_trace: Where(stack)
          });
          return result;
        }
      };
      secureSettings.getString.implementation = function(contentresolver, query) {
        const result = this.getString(contentresolver, query);
        const stack = threadInstance.currentThread().getStackTrace();
        createTelephonyEvent("telephony.secure_settings.get_string", {
          library: "android.provider.Settings$Secure",
          method: "getString",
          query,
          value: result,
          stack_trace: Where(stack)
        });
        return result;
      };
    } catch (error) {
      createTelephonyEvent("telephony.error", {
        error_message: error.toString(),
        error_type: "hook_device_infos"
      });
    }
  });
}
function install_telephony_manager_hooks() {
  devlog("\n");
  devlog("install telephony manager hooks");
  hook_device_infos();
  hook_sms();
}

// agent/hooking_profile_loader.ts
var show_verbose = false;
var deactivate_unlink = false;
var enable_stacktrace = false;
var hook_config = {
  // File system hooks
  "file_system_hooks": false,
  "database_hooks": false,
  // DEX and native library hooks
  "dex_unpacking_hooks": false,
  "java_dex_unpacking_hooks": false,
  "native_library_hooks": false,
  // IPC hooks
  "shared_prefs_hooks": false,
  "binder_hooks": false,
  "intent_hooks": false,
  "broadcast_hooks": false,
  // Crypto hooks
  "aes_hooks": false,
  "encodings_hooks": false,
  "keystore_hooks": false,
  // Network hooks
  "web_hooks": false,
  "socket_hooks": false,
  // Process hooks
  "process_hooks": false,
  "runtime_hooks": false,
  // Service hooks
  "bluetooth_hooks": false,
  "camera_hooks": false,
  "clipboard_hooks": false,
  "location_hooks": false,
  "telephony_hooks": false
};
send("verbose_mode");
var verbose_mode_recv_state = recv("verbose_mode", (value) => {
  show_verbose = value.payload;
});
verbose_mode_recv_state.wait();
send("deactivate_unlink");
var deactivate_unlink_recv_state = recv("deactivate_unlink", (value) => {
  deactivate_unlink = value.payload;
});
deactivate_unlink_recv_state.wait();
send("hook_config");
var hook_config_recv_state = recv("hook_config", (value) => {
  if (typeof value.payload === "object") {
    Object.assign(hook_config, value.payload);
    devlog(`[HOOK] Received hook configuration: ${JSON.stringify(value.payload)}`);
  }
});
hook_config_recv_state.wait();
send("enable_stacktrace");
var enable_stacktrace_recv_state = recv("enable_stacktrace", (value) => {
  enable_stacktrace = value.payload;
});
enable_stacktrace_recv_state.wait();
function install_hook_conditionally(hook_name, install_function) {
  if (hook_config[hook_name]) {
    try {
      install_function();
      devlog(`[HOOK] Enabled: ${hook_name}`);
    } catch (error) {
      devlog(`[HOOK] Failed to enable ${hook_name}: ${error}`);
    }
  }
}
function load_profile_hooks() {
  if (enable_stacktrace) {
    log("[Dexray] Stacktrace enabled");
  }
  log("[HOOK] Loading hooks based on configuration...");
  install_hook_conditionally("file_system_hooks", install_file_system_hooks);
  install_hook_conditionally("database_hooks", install_database_hooks);
  install_hook_conditionally("dex_unpacking_hooks", install_dex_unpacking_hooks);
  install_hook_conditionally("java_dex_unpacking_hooks", install_java_dex_unpacking_hooks);
  install_hook_conditionally("native_library_hooks", install_native_library_hooks);
  install_hook_conditionally("shared_prefs_hooks", install_shared_prefs_hooks);
  install_hook_conditionally("binder_hooks", install_binder_hooks);
  install_hook_conditionally("intent_hooks", install_intent_hooks);
  install_hook_conditionally("broadcast_hooks", install_broadcast_hooks);
  install_hook_conditionally("aes_hooks", install_aes_hooks);
  install_hook_conditionally("encodings_hooks", install_encodings_hooks);
  install_hook_conditionally("keystore_hooks", install_keystore_hooks);
  install_hook_conditionally("web_hooks", install_web_hooks);
  install_hook_conditionally("socket_hooks", install_socket_hooks);
  install_hook_conditionally("process_hooks", install_process_hooks);
  install_hook_conditionally("runtime_hooks", install_runtime_hooks);
  install_hook_conditionally("bluetooth_hooks", install_bluetooth_hooks);
  install_hook_conditionally("telephony_hooks", install_telephony_manager_hooks);
  install_hook_conditionally("camera_hooks", install_camera_hooks);
  install_hook_conditionally("clipboard_hooks", install_clipboard_hooks);
  install_hook_conditionally("location_hooks", install_location_hooks);
  const enabled_hooks = Object.entries(hook_config).filter(([_, enabled]) => enabled).map(([name, _]) => name);
  log(`[HOOK] Active hooks: ${enabled_hooks.join(", ") || "none"}`);
}
load_profile_hooks();
export {
  deactivate_unlink,
  enable_stacktrace,
  hook_config,
  show_verbose
};

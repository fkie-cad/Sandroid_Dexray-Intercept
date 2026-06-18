// agent/jni/jni_trace.ts

import {
    JNIInterceptor,
    JNILibraryWatcher,
    JNINativeReturnValue,
    JNIInvocationCallback,
    Config,
    ConfigBuilder,
    startJniEngine
} from "./jnitrace-engine/lib/index.js";

import { am_send, devlog } from "../utils/logging.js";
import { bytesToHex } from "../utils/misc.js";

const PROFILE_HOOKING_TYPE = "JNI_TRACE";

// Track which library paths were already reported
const seenLibraries = new Set<string>();

// Optional global; Frida provides Process at runtime.
declare const Process: any;
declare const DebugSymbol: any;

// Track array lengths by array handle string
const byteArrayLengths = new Map<string, number>();

// Track decoded jstring contents
const jstringValues = new Map<string, string>();

// Track object types (pointer string -> JVM descriptor, e.g. "Ljava/lang/String;")
const jobjectTypes = new Map<string, string>();

interface ArrayElementInfo {
    elemSize: number;
    elemType: string; // e.g. "jint", "jfloat"
}

const arrayElementInfo = new Map<string, ArrayElementInfo>();

interface PrimitiveArraySpec {
    lengthIndex: number;   // index of len parameter
    bufferIndex: number;   // index of buffer pointer parameter
    elemSize: number;      // bytes per element
}

interface DirectBufferInfo {
    address: string;   // pointer string
    capacity: number;  // bytes
}

const directBuffers = new Map<string, DirectBufferInfo>();       // jobject -> info
const directBufferByAddress = new Map<string, string>();         // address -> jobject handle

const arraySpecs: { [method: string]: PrimitiveArraySpec } = {
    SetBooleanArrayRegion: { lengthIndex: 3, bufferIndex: 4, elemSize: 1 },
    SetByteArrayRegion:    { lengthIndex: 3, bufferIndex: 4, elemSize: 1 },
    SetCharArrayRegion:    { lengthIndex: 3, bufferIndex: 4, elemSize: 2 },
    SetShortArrayRegion:   { lengthIndex: 3, bufferIndex: 4, elemSize: 2 },
    SetIntArrayRegion:     { lengthIndex: 3, bufferIndex: 4, elemSize: 4 },
    SetLongArrayRegion:    { lengthIndex: 3, bufferIndex: 4, elemSize: 8 },
    SetFloatArrayRegion:   { lengthIndex: 3, bufferIndex: 4, elemSize: 4 },
    SetDoubleArrayRegion:  { lengthIndex: 3, bufferIndex: 4, elemSize: 8 },

    GetBooleanArrayRegion: { lengthIndex: 3, bufferIndex: 4, elemSize: 1 },
    GetByteArrayRegion:    { lengthIndex: 3, bufferIndex: 4, elemSize: 1 },
    GetCharArrayRegion:    { lengthIndex: 3, bufferIndex: 4, elemSize: 2 },
    GetShortArrayRegion:   { lengthIndex: 3, bufferIndex: 4, elemSize: 2 },
    GetIntArrayRegion:     { lengthIndex: 3, bufferIndex: 4, elemSize: 4 },
    GetLongArrayRegion:    { lengthIndex: 3, bufferIndex: 4, elemSize: 8 },
    GetFloatArrayRegion:   { lengthIndex: 3, bufferIndex: 4, elemSize: 4 },
    GetDoubleArrayRegion:  { lengthIndex: 3, bufferIndex: 4, elemSize: 8 },
};

// For Get*/Release*ArrayElements, element size by method name
const elementSizeByElementsMethod: { [method: string]: number } = {
    GetBooleanArrayElements: 1,
    GetByteArrayElements:    1,
    GetCharArrayElements:    2,
    GetShortArrayElements:   2,
    GetIntArrayElements:     4,
    GetLongArrayElements:    8,
    GetFloatArrayElements:   4,
    GetDoubleArrayElements:  8,

    ReleaseBooleanArrayElements: 1,
    ReleaseByteArrayElements:    1,
    ReleaseCharArrayElements:    2,
    ReleaseShortArrayElements:   2,
    ReleaseIntArrayElements:     4,
    ReleaseLongArrayElements:    8,
    ReleaseFloatArrayElements:   4,
    ReleaseDoubleArrayElements:  8,
};

const primitiveElemSizeByNewMethod: { [method: string]: number } = {
    NewBooleanArray: 1,
    NewByteArray:    1,
    NewCharArray:    2,
    NewShortArray:   2,
    NewIntArray:     4,
    NewLongArray:    8,
    NewFloatArray:   4,
    NewDoubleArray:  8,
};

function handleNewPrimitiveArray(
    methodName: string,
    rawArgs: any[],
    retVal: any,
    eventData: any
): void {
    const LEN_INDEX = 1;
    const lenNum = Number(rawArgs[LEN_INDEX]);
    if (Number.isNaN(lenNum)) {
        return;
    }

    eventData.array_length = lenNum;

    const arrHandle = retVal;
    if (!arrHandle || typeof arrHandle.toString !== "function") {
        return;
    }

    const key = arrHandle.toString();
    byteArrayLengths.set(key, lenNum);

    const elemSize = primitiveElemSizeByNewMethod[methodName];
    if (elemSize) {
        arrayElementInfo.set(key, {
            elemSize,
            elemType: methodName.replace(/^New(.*)Array$/, "j$1").toLowerCase()
        });
    }
}

function handleGetPrimitiveArrayElements(
    methodName: string,
    rawArgs: any[],
    retVal: any,
    eventData: any
): void {
    const ARRAY_INDEX = 1;
    const arrHandle = rawArgs[ARRAY_INDEX];
    const len = arrHandle && typeof arrHandle.toString === "function"
        ? byteArrayLengths.get(arrHandle.toString())
        : undefined;

    if (len === undefined) {
        return;
    }

    eventData.array_length = len;

    if (jniConfig.hide_data) {
        return;
    }

    const elemSize = elementSizeByElementsMethod[methodName] || 1;

    try {
        const elemsPtr = retVal;
        const raw = elemsPtr.readByteArray(len * elemSize);
        if (raw) {
            const arr = new Uint8Array(raw);
            eventData.array_hex = bytesToHex(arr);
            maybeAttachNumericArrayValues(methodName, arr, eventData, arrHandle);
        }
    } catch (e) {
        devlog(`[JNI] Failed to read ${methodName} buffer: ${e}`);
    }
}

function preReadReleasePrimitiveElements(
    methodName: string,
    args: any[],
    self: any
): void {
    const elemSize = elementSizeByElementsMethod[methodName];
    if (!elemSize) return;

    const ARRAY_INDEX = 1;
    const ELEMS_INDEX = 2;

    const arrHandle = args[ARRAY_INDEX];
    if (!arrHandle || typeof arrHandle.toString !== "function") {
        return;
    }
    const key = arrHandle.toString();
    const len = byteArrayLengths.get(key);
    if (len === undefined) {
        return;
    }

    try {
        const elemsPtr = args[ELEMS_INDEX];
        const raw = elemsPtr.readByteArray(len * elemSize);
        if (raw) {
            const arr = new Uint8Array(raw);
            const fieldName = `_preRelease_${methodName}`; // e.g. _preRelease_ReleaseIntArrayElements
            (self as any)[fieldName] = {
                length: len,
                hex: bytesToHex(arr)
            };
        }
    } catch (e) {
        devlog(`[JNI] Failed to pre-read ${methodName} buffer: ${e}`);
    }
}

function handleReleasePrimitiveArrayElements(
    methodName: string,
    self: any,
    eventData: any
): void {
    const fieldName = `_preRelease_${methodName}`;
    const pre = (self as any)[fieldName];
    if (pre) {
        eventData.array_length = pre.length;
        if (!jniConfig.hide_data) {
            eventData.array_hex = pre.hex;
        }
        // Optionally delete the field
        delete (self as any)[fieldName];
    }
}

function enrichArrayRegion(
    methodName: string,
    rawArgs: any[],
    eventData: any
): void {
    const spec = arraySpecs[methodName];
    if (!spec) {
        return;
    }

    const lenNum = Number(rawArgs[spec.lengthIndex]);
    if (Number.isNaN(lenNum) || lenNum <= 0) {
        return;
    }

    eventData.array_length = lenNum;
    if (jniConfig.hide_data) {
        return;
    }

    const bufPtr = rawArgs[spec.bufferIndex];
    try {
        const raw = bufPtr.readByteArray(lenNum * spec.elemSize);
        if (raw) {
            const arr = new Uint8Array(raw);
            eventData.array_hex = bytesToHex(arr);
            maybeAttachNumericArrayValues(methodName, arr, eventData);
        }
    } catch (e) {
        devlog(`[JNI] Failed to read ${methodName} buffer: ${e}`);
    }
}

function safeReadCString(ptr: any): string | null {
    try {
        if (ptr && typeof ptr.readCString === "function") {
            return ptr.readCString();
        }
    } catch (e) {
        devlog(`[JNI] Failed to read CString: ${e}`);
    }
    return null;
}

function safeReadUtf8String(ptr: any): string | null {
    try {
        if (ptr && typeof ptr.readUtf8String === "function") {
            return ptr.readUtf8String();
        }
    } catch (e) {
        devlog(`[JNI] Failed to read UTF-8 string: ${e}`);
    }
    return null;
}

function buildBacktrace(bt: any): any[] | undefined {
    if (!bt || !Array.isArray(bt)) {
        return undefined;
    }

    const frames: any[] = [];

    for (const addr of bt) {
        try {
            const addressStr = addr.toString();
            const mod = Process.findModuleByAddress(addr);
            const sym = DebugSymbol.fromAddress(addr);

            frames.push({
                address: addressStr,
                module: mod
                    ? {
                        name: mod.name,
                        base: mod.base.toString(),
                        path: mod.path
                    }
                    : null,
                symbol: sym
                    ? {
                        address: sym.address.toString(),
                        name: sym.name,
                        moduleName: sym.moduleName
                    }
                    : null
            });
        } catch (e) {
            // If anything fails, at least keep the raw address
            frames.push({
                address: addr.toString(),
                module: null,
                symbol: null
            });
        }
    }

    return frames.length > 0 ? frames : undefined;
}

function isObjectLikeNativeType(nativeType: string): boolean {
    if (nativeType === "jobject" || nativeType === "jclass" || nativeType === "jstring") {
        return true;
    }
    if (nativeType.endsWith("Array")) {
        return true;
    }
    return false;
}

function decodeJavaValue(raw: any, nativeType: string): any {
    // Normalize arrays to object for now (only care about the JNI base type)
    if (nativeType.endsWith("Array")) {
        nativeType = "jobject";
    }

    switch (nativeType) {
        case "jint":
        case "jshort":
        case "jbyte":
        case "jchar":
            return Number(raw);

        case "jboolean":
            return Number(raw) !== 0;

        case "jlong":
            if (typeof raw === "number") {
                return raw;
            }
            if (raw && typeof raw.toString === "function") {
                const s = raw.toString();
                const n = parseInt(s, 10);
                return Number.isNaN(n) ? s : n;
            }
            return String(raw);

        case "jfloat":
        case "jdouble":
            return Number(raw);

        case "jstring": {
            if (raw && typeof raw.toString === "function") {
                const key = raw.toString();
                if (jstringValues.has(key)) {
                    return jstringValues.get(key);
                }
                return key;
            }
            return String(raw);
        }

        default:
            // jobject, jclass, jarray, complex object types
            if (raw && typeof raw.toString === "function") {
                const key = raw.toString();
                if (jobjectTypes.has(key)) {
                    return jobjectTypes.get(key);  // JVM descriptor
                }
                return key;
            }
            return String(raw);
    }
}

type NumericElemKind = "short" | "int" | "long" | "float" | "double";

function getNumericElemKindFromMethodName(methodName: string): NumericElemKind | null {
    if (methodName.indexOf("ShortArray") !== -1) return "short";
    if (methodName.indexOf("IntArray") !== -1)   return "int";
    if (methodName.indexOf("LongArray") !== -1)  return "long";
    if (methodName.indexOf("FloatArray") !== -1) return "float";
    if (methodName.indexOf("DoubleArray") !== -1)return "double";
    return null;
}

function getNumericElemKindFromNativeType(nativeType: string): NumericElemKind | null {
    switch (nativeType) {
        case "jshort":  return "short";
        case "jint":    return "int";
        case "jlong":   return "long";
        case "jfloat":  return "float";
        case "jdouble": return "double";
        default:        return null;
    }
}

function decodeNumericArrayBytes(bytes: Uint8Array, kind: NumericElemKind): number[] | undefined {
    const LE = true;
    let elemSize = 0;
    switch (kind) {
        case "short":  elemSize = 2; break;
        case "int":
        case "float":  elemSize = 4; break;
        case "long":
        case "double": elemSize = 8; break;
    }
    if (bytes.length % elemSize !== 0) {
        return undefined;
    }

    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const out: number[] = [];
    for (let offset = 0; offset < bytes.length; offset += elemSize) {
        let v: number;
        switch (kind) {
            case "short":
                v = dv.getInt16(offset, LE);
                break;
            case "int":
                v = dv.getInt32(offset, LE);
                break;
            case "long": {
                const big = dv.getBigInt64(offset, LE);
                const num = Number(big);
                // If outside safe range, still store the numeric approximation
                v = num;
                break;
            }
            case "float":
                v = dv.getFloat32(offset, LE);
                break;
            case "double":
                v = dv.getFloat64(offset, LE);
                break;
        }
        out.push(v);
    }
    return out;
}

/**
 * Attach array_values for numeric primitive arrays when possible.
 * @param methodName Name of the JNI method (e.g. GetIntArrayElements)
 * @param bytes      Raw element bytes (little-endian)
 * @param eventData  Event data object to augment
 * @param arrayHandle (optional) array handle to look up elemType from arrayElementInfo

 */
function maybeAttachNumericArrayValues(
    methodName: string,
    bytes: Uint8Array,
    eventData: any,
    arrayHandle?: any
): void {
    let kind = getNumericElemKindFromMethodName(methodName);

    if (!kind && arrayHandle && typeof arrayHandle.toString === "function") {
        const info = arrayElementInfo.get(arrayHandle.toString());
        if (info) {
            kind = getNumericElemKindFromNativeType(info.elemType);
        }
    }

    if (!kind) {
        return;
    }

    const values = decodeNumericArrayBytes(bytes, kind);
    if (!values) {
        return;
    }

    eventData.array_values = values;
}

interface JniConfigPayload {
    libraries: string[];
    backtrace: "fuzzy" | "accurate" | "none";
    include: string[];
    exclude: string[];
    include_export: string[];
    exclude_export: string[];
    hide_data: boolean;
    env: boolean;
    vm: boolean;
}

let jniConfig: JniConfigPayload = {
    libraries: ["*"],
    backtrace: "none",
    include: [],
    exclude: [],
    include_export: [],
    exclude_export: [],
    hide_data: false,
    env: true,
    vm: true
};

function createJniEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function initJniConfig(): Config {
    const builder = new ConfigBuilder();
    builder.libraries = jniConfig.libraries;
    builder.backtrace = jniConfig.backtrace;
    builder.includeExports = jniConfig.include_export;
    builder.excludeExports = jniConfig.exclude_export;
    builder.env = jniConfig.env;
    builder.vm = jniConfig.vm;
    return builder.build();
}

let config: Config | null = null;

function ensureConfig(): Config {
    if (config === null) {
        config = initJniConfig();
        initJniPatterns();  // compile regex filters
        devlog("[JNI] Config initialized for jnitrace-engine");
    }
    return config;
}

let jniIncludePatterns: RegExp[] = [];
let jniExcludePatterns: RegExp[] = [];

function initJniPatterns(): void {
    const toRegexes = (patterns: string[]): RegExp[] => {
        const out: RegExp[] = [];
        for (const p of patterns) {
            try {
                out.push(new RegExp(p));
            } catch (e) {
                devlog(`[JNI] Invalid regex in JNI include/exclude: ${p}`);
            }
        }
        return out;
    };

    jniIncludePatterns = toRegexes(jniConfig.include);
    jniExcludePatterns = toRegexes(jniConfig.exclude);
}

function shouldIgnoreMethod(name: string): boolean {
    if (jniIncludePatterns.length > 0) {
        let included = false;
        for (const re of jniIncludePatterns) {
            if (re.test(name)) {
                included = true;
                break;
            }
        }
        if (!included) {
            return true;
        }
    }

    if (jniExcludePatterns.length > 0) {
        for (const re of jniExcludePatterns) {
            if (re.test(name)) {
                return true;
            }
        }
    }

    return false;
}

const jniEnvCallback: JNIInvocationCallback = {
    onEnter (args): void {
        this.args = args;

        if (!jniConfig.env || jniConfig.hide_data) {
            return;
        }

        const methodName = this.methodDef.name as string;
        if (shouldIgnoreMethod(methodName)) {
            return;
        }

        switch (methodName) {

            case "ReleaseByteArrayElements":
            case "ReleaseBooleanArrayElements":
            case "ReleaseCharArrayElements":
            case "ReleaseShortArrayElements":
            case "ReleaseIntArrayElements":
            case "ReleaseLongArrayElements":
            case "ReleaseFloatArrayElements":
            case "ReleaseDoubleArrayElements":
                preReadReleasePrimitiveElements(methodName, args, this);
                break;

            case "ReleasePrimitiveArrayCritical": {
                // void ReleasePrimitiveArrayCritical(JNIEnv*, jarray, void*, jint)
                const ARRAY_INDEX = 1;
                const ELEMS_INDEX = 2;

                const arrHandle = args[ARRAY_INDEX];
                if (!arrHandle || typeof arrHandle.toString !== "function") {
                    break;
                }

                const key = arrHandle.toString();
                const len = byteArrayLengths.get(key);
                if (len === undefined) {
                    break;
                }

                try {
                    const info = arrayElementInfo.get(key);
                    const elemSize = info ? info.elemSize : 1;
                    const elemsPtr = args[ELEMS_INDEX];
                    const raw = elemsPtr.readByteArray(len * elemSize);
                    if (raw) {
                        const arr = new Uint8Array(raw);

                        let values: number[] | undefined;
                        if (info) {
                            const kind = getNumericElemKindFromNativeType(info.elemType);
                            if (kind) {
                                values = decodeNumericArrayBytes(arr, kind);
                            }
                        }

                        (this as any)._preReleasePrimitiveArray = {
                            length: len,
                            hex: bytesToHex(arr),
                            values
                        };
                    }
                } catch (e) {
                    devlog(`[JNI] Failed to pre-read ReleasePrimitiveArrayCritical buffer: ${e}`);
                }
                break;
            }

            default:
                break;
        }
    },
    onLeave (retval: JNINativeReturnValue): void {
        if (!jniConfig.env) {
            return;
        }

        const methodName = this.methodDef.name as string;
        if (shouldIgnoreMethod(methodName)) {
            return;
        }

        const rawArgs = this.args as any[];
        const retVal = retval.get();

        const ctx: any = this;
        const methodDef = ctx.methodDef;

        let cArgTypes: string[] | null = null;
        let cRetType: string | null = null;

        if (methodDef && Array.isArray(methodDef.args) && typeof methodDef.ret === "string") {
            cArgTypes = methodDef.args.slice(); // copy
            cRetType = methodDef.ret;
        } else {
            devlog(`[JNI] methodDef missing or incomplete for ${methodName}`);
        }

        const eventData: any = {
            jni_struct: "JNIEnv",
            method: methodName,
            arguments: rawArgs.map(String),
            return_value: String(retVal),
            java_method_sig: this.javaMethod ? this.javaMethod.signature : null,
            thread_id: this.threadId,
            c_arg_types: cArgTypes,   // e.g. ["JNIEnv*", "jclass", "char*", "char*"]
            c_ret_type: cRetType      // e.g. "jmethodID"
        };

        if (!jniConfig.hide_data) {
            try {
                switch (methodName) {
                    case "FindClass": {
                        const namePtr = rawArgs[1];
                        const className = safeReadCString(namePtr);
                        if (className !== null) {
                            eventData.class_name = className;
                        }
                        break;
                    }

                    case "NewStringUTF": {
                        const utfPtr = rawArgs[1];
                        const utf = safeReadUtf8String(utfPtr);
                        if (utf !== null) {
                            eventData.string_argument = utf;
                            // Map returned jstring handle -> string content
                            if (retVal && typeof retVal.toString === "function") {
                                jstringValues.set(retVal.toString(), utf);
                            }
                        }
                        break;
                    }

                    case "GetStringUTFChars": {
                        const jstr = rawArgs[1];
                        const cstrPtr = retVal;
                        const utf = safeReadUtf8String(cstrPtr);
                        if (utf !== null) {
                            eventData.string_return = utf;
                            // Map jstring handle -> string content
                            if (jstr && typeof jstr.toString === "function") {
                                jstringValues.set(jstr.toString(), utf);
                            }
                        }
                        break;
                    }

                    case "GetStringCritical": {
                        const jstr = rawArgs[1];
                        if (jstr && typeof jstr.toString === "function") {
                            const key = jstr.toString();
                            const known = jstringValues.get(key);
                            if (known !== undefined) {
                                eventData.string_return = known;
                            }
                        }
                        break;
                    }

                    case "GetMethodID":
                    case "GetStaticMethodID": {
                        const NAME_INDEX = 2;
                        const SIG_INDEX = 3;
                        const name = safeReadCString(rawArgs[NAME_INDEX]);
                        const sig = safeReadCString(rawArgs[SIG_INDEX]);
                        if (name) {
                            eventData.method_name = name;
                        }
                        if (sig) {
                            eventData.method_signature = sig;
                        }
                        if (name && sig) {
                            eventData.method_descriptor = `${name}${sig}`; // e.g. add(II)I
                        }
                        break;
                    }

                    case "GetFieldID":
                    case "GetStaticFieldID": {
                        const NAME_INDEX = 2;
                        const SIG_INDEX = 3;
                        const name = safeReadCString(rawArgs[NAME_INDEX]);
                        const sig = safeReadCString(rawArgs[SIG_INDEX]);
                        if (name) {
                            eventData.field_name = name;
                        }
                        if (sig) {
                            eventData.field_signature = sig;
                        }
                        if (name && sig) {
                            eventData.field_descriptor = `${name}:${sig}`;
                        }
                        break;
                    }

                    case "RegisterNatives": {
                        const JCLASS_INDEX = 1;
                        const METHODS_PTR_INDEX = 2;
                        const SIZE_INDEX = 3;
                        const JNI_METHOD_SIZE = 3;

                        const size = Number(rawArgs[SIZE_INDEX]);
                        const methodsPtr = rawArgs[METHODS_PTR_INDEX];
                        const natives: any[] = [];

                        let jclassName: string | null = null;
                        // Try to decode jclass name if class_name was set earlier
                        if (eventData.class_name) {
                            jclassName = eventData.class_name;
                        }

                        const ptrSize = Process ? Process.pointerSize : 8;

                        for (let i = 0; i < size; i++) {
                            const base = methodsPtr.add(i * JNI_METHOD_SIZE * ptrSize);

                            const namePtr = base.readPointer();
                            const sigPtr = base.add(ptrSize).readPointer();
                            const addrPtr = base.add(2 * ptrSize).readPointer();

                            const name = safeReadCString(namePtr);
                            const sig = safeReadCString(sigPtr);

                            natives.push({
                                name: name || null,
                                signature: sig || null,
                                address: addrPtr.toString()
                            });
                        }

                        eventData.registered_natives = natives;
                        break;
                    }
                    
                    case "ThrowNew": {
                        const CLASS_INDEX = 1;
                        const MESSAGE_INDEX = 2;

                        const message = safeReadCString(rawArgs[MESSAGE_INDEX]);
                        if (message !== null) {
                            eventData.throw_message = message;
                        }
                        break;
                    }

                    case "FatalError": {
                        const MESSAGE_INDEX = 1;
                        const message = safeReadCString(rawArgs[MESSAGE_INDEX]);
                        if (message !== null) {
                            eventData.fatal_message = message;
                        }
                        break;
                    }

                    case "GetJavaVM": {
                        const VM_PP_INDEX = 1;
                        const JNI_OK = 0;
                        const rvNum = Number(retVal);
                        if (!Number.isNaN(rvNum) && rvNum === JNI_OK) {
                            try {
                                const vmPtrPtr = rawArgs[VM_PP_INDEX];
                                const vmPtr = vmPtrPtr.readPointer();
                                eventData.java_vm_ptr = vmPtr.toString();
                            } catch (e) {
                                devlog(`[JNI] Failed to decode GetJavaVM pointer: ${e}`);
                            }
                        }
                        break;
                    }

                    case "DefineClass": {
                        const NAME_INDEX = 1;
                        const BUF_INDEX = 3;
                        const LEN_INDEX = 4;

                        const nameStr = safeReadCString(rawArgs[NAME_INDEX]);
                        if (nameStr !== null) {
                            eventData.define_class_name = nameStr;
                        }

                        try {
                            const bufPtr = rawArgs[BUF_INDEX];
                            const lenNum = Number(rawArgs[LEN_INDEX]);

                            if (!Number.isNaN(lenNum) && lenNum > 0) {
                                eventData.class_data_length = lenNum;

                                if (!jniConfig.hide_data) {
                                    const raw = bufPtr.readByteArray(lenNum);
                                    if (raw) {
                                        const MAX_BYTES = 64;
                                        const arr = new Uint8Array(raw);
                                        const slice = arr.subarray(0, Math.min(lenNum, MAX_BYTES));
                                        eventData.class_data_hex = bytesToHex(slice);
                                        if (lenNum > MAX_BYTES) {
                                            eventData.class_data_truncated = true;
                                        }
                                    }
                                }
                            }
                        } catch (e) {
                            devlog(`[JNI] Failed to read DefineClass buffer: ${e}`);
                        }

                        break;
                    }

                    case "GetArrayLength": {
                        const ARRAY_INDEX = 1;
                        const arrHandle = rawArgs[ARRAY_INDEX];
                        const lenNum = Number(retVal);
                        if (!Number.isNaN(lenNum)) {
                            byteArrayLengths.set(arrHandle.toString(), lenNum);
                            eventData.array_length = lenNum;
                        }
                        break;
                    }

                    case "NewBooleanArray":
                    case "NewByteArray":
                    case "NewCharArray":
                    case "NewShortArray":
                    case "NewIntArray":
                    case "NewLongArray":
                    case "NewFloatArray":
                    case "NewDoubleArray":
                        handleNewPrimitiveArray(methodName, rawArgs, retVal, eventData);
                        break;

                    case "GetBooleanArrayElements":
                    case "GetByteArrayElements":
                    case "GetCharArrayElements":
                    case "GetShortArrayElements":
                    case "GetIntArrayElements":
                    case "GetLongArrayElements":
                    case "GetFloatArrayElements":
                    case "GetDoubleArrayElements":
                        handleGetPrimitiveArrayElements(methodName, rawArgs, retVal, eventData);
                        break;

                    case "ReleaseBooleanArrayElements":
                    case "ReleaseByteArrayElements":
                    case "ReleaseCharArrayElements":
                    case "ReleaseShortArrayElements":
                    case "ReleaseIntArrayElements":
                    case "ReleaseLongArrayElements":
                    case "ReleaseFloatArrayElements":
                    case "ReleaseDoubleArrayElements":
                        handleReleasePrimitiveArrayElements(methodName, this, eventData);
                        break;

                    case "SetBooleanArrayRegion":
                    case "SetByteArrayRegion":
                    case "SetCharArrayRegion":
                    case "SetShortArrayRegion":
                    case "SetIntArrayRegion":
                    case "SetLongArrayRegion":
                    case "SetFloatArrayRegion":
                    case "SetDoubleArrayRegion":
                    case "GetBooleanArrayRegion":
                    case "GetByteArrayRegion":
                    case "GetCharArrayRegion":
                    case "GetShortArrayRegion":
                    case "GetIntArrayRegion":
                    case "GetLongArrayRegion":
                    case "GetFloatArrayRegion":
                    case "GetDoubleArrayRegion":
                        enrichArrayRegion(methodName, rawArgs, eventData);
                        break;

                    case "GetPrimitiveArrayCritical": {
                        // void* GetPrimitiveArrayCritical(JNIEnv*, jarray, jboolean*)
                        const ARRAY_INDEX = 1;
                        const arrHandle = rawArgs[ARRAY_INDEX];
                        const key = arrHandle && typeof arrHandle.toString === "function"
                            ? arrHandle.toString()
                            : null;

                        const len = key ? byteArrayLengths.get(key) : undefined;
                        if (len !== undefined) {
                            eventData.array_length = len;
                            if (!jniConfig.hide_data) {
                                try {
                                    const info = key ? arrayElementInfo.get(key) : undefined;
                                    const elemSize = info ? info.elemSize : 1;
                                    const bufPtr = retVal;
                                    const raw = bufPtr.readByteArray(len * elemSize);
                                    if (raw) {
                                        const arr = new Uint8Array(raw);
                                        eventData.array_hex = bytesToHex(arr);
                                    }
                                } catch (e) {
                                    devlog(`[JNI] Failed to read GetPrimitiveArrayCritical buffer: ${e}`);
                                }
                            }
                        }
                        break;
                    }

                    case "ReleasePrimitiveArrayCritical": {
                        const pre = (this as any)._preReleasePrimitiveArray;
                        if (pre) {
                            eventData.array_length = pre.length;
                            if (!jniConfig.hide_data) {
                                eventData.array_hex = pre.hex;
                                if (pre.values) {
                                    eventData.array_values = pre.values;
                                }
                            }
                            delete (this as any)._preReleasePrimitiveArray;
                        }
                        break;
                    }

                    case "NewDirectByteBuffer": {
                        // jobject NewDirectByteBuffer(JNIEnv*, void* address, jlong capacity)
                        const ADDR_INDEX = 1;
                        const CAP_INDEX = 2;

                        const addrPtr = rawArgs[ADDR_INDEX];
                        const capNum = Number(rawArgs[CAP_INDEX]);

                        if (addrPtr && typeof addrPtr.toString === "function") {
                            eventData.direct_buffer_address = addrPtr.toString();
                        }
                        if (!Number.isNaN(capNum)) {
                            eventData.direct_buffer_capacity = capNum;
                        }

                        const bufHandle = retVal;
                        if (bufHandle && typeof bufHandle.toString === "function") {
                            const key = bufHandle.toString();
                            const addrStr = addrPtr && typeof addrPtr.toString === "function"
                                ? addrPtr.toString()
                                : "";
                            directBuffers.set(key, {
                                address: addrStr,
                                capacity: Number.isNaN(capNum) ? 0 : capNum
                            });
                            if (addrStr) {
                                directBufferByAddress.set(addrStr, key);
                            }
                        }
                        break;
                    }

                    case "GetDirectBufferAddress": {
                        // void* GetDirectBufferAddress(JNIEnv*, jobject buf)
                        const BUF_INDEX = 1;
                        const bufHandle = rawArgs[BUF_INDEX];
                        const addrPtr = retVal;

                        if (addrPtr && typeof addrPtr.toString === "function") {
                            eventData.direct_buffer_address = addrPtr.toString();
                        }

                        if (bufHandle && typeof bufHandle.toString === "function") {
                            const key = bufHandle.toString();
                            const info = directBuffers.get(key);
                            if (info) {
                                eventData.direct_buffer_capacity = info.capacity;
                                if (!jniConfig.hide_data && info.capacity > 0 && addrPtr && typeof addrPtr.readByteArray === "function") {
                                    try {
                                        const MAX_BYTES = 0x400; // 1KB safety cap
                                        const toRead = Math.min(info.capacity, MAX_BYTES);
                                        const raw = addrPtr.readByteArray(toRead);
                                        if (raw) {
                                            const arr = new Uint8Array(raw);
                                            eventData.buffer_hex = bytesToHex(arr);
                                            if (info.capacity > toRead) {
                                                eventData.buffer_truncated = true;
                                            }
                                        }
                                    } catch (e) {
                                        devlog(`[JNI] Failed to read direct buffer at ${addrPtr}: ${e}`);
                                    }
                                }
                            }
                        }
                        break;
                    }

                    case "GetDirectBufferCapacity": {
                        // jlong GetDirectBufferCapacity(JNIEnv*, jobject buf)
                        const BUF_INDEX = 1;
                        const bufHandle = rawArgs[BUF_INDEX];
                        const capNum = Number(retVal);

                        if (!Number.isNaN(capNum)) {
                            eventData.direct_buffer_capacity = capNum;
                        }

                        if (bufHandle && typeof bufHandle.toString === "function") {
                            const key = bufHandle.toString();
                            const info = directBuffers.get(key) || { address: "", capacity: 0 };
                            info.capacity = Number.isNaN(capNum) ? info.capacity : capNum;
                            directBuffers.set(key, info);
                        }
                        break;
                    }

                    default:
                        break;
                }
            } catch (e) {
                devlog(`[JNI] Enrichment failed for ${methodName}: ${e}`);
            }
        }

        // Java-level argument decoding for Call*/NewObject* when javaMethod is available
        const javaMethod: any = (this as any).javaMethod;
        if (javaMethod && Array.isArray(javaMethod.nativeParams) && typeof javaMethod.ret === "string") {
            try {
                const nativeParams: string[] = javaMethod.nativeParams; // e.g. ["jstring","jstring","jstring"]
                const mArgs: string[] = Array.isArray(methodDef.args) ? methodDef.args : [];
                if (mArgs.length > 0 && nativeParams.length > 0) {
                    const lastNative = mArgs[mArgs.length - 1];
                    let javaStart = mArgs.length;

                    // For "..." methods, args[] from mainCallback = [env, obj/cls, jmethodID, javaArgs...]
                    if (lastNative === "...") {
                        javaStart = mArgs.length - 1;   // vararg Call*Method
                    } else if (lastNative === "va_list" || lastNative === "jvalue*") {
                        // For V/A methods, clonedArgs = [env, obj/cls, jmethodID, va_list/jvalue*, javaArgs...]
                        javaStart = mArgs.length;       // Call*MethodV/A
                    }

                    const javaArgs: any[] = [];
                    const jvmParams: string[] = Array.isArray(javaMethod.params)
                        ? javaMethod.params
                        : [];

                    for (let i = 0; i < nativeParams.length; i++) {
                        const idx = javaStart + i;
                        if (idx >= rawArgs.length) {
                            break;
                        }
                        const rawVal = rawArgs[idx];
                        const nativeType = nativeParams[i];

                        const decoded = decodeJavaValue(rawVal, nativeType);
                        javaArgs.push(decoded);

                        // Record object types for object-like params
                        if (rawVal && typeof rawVal.toString === "function" &&
                            isObjectLikeNativeType(nativeType)) {
                            const key = rawVal.toString();
                            const jvmDesc = jvmParams[i] || nativeType;
                            jobjectTypes.set(key, jvmDesc);
                        }
                    }

                    if (javaArgs.length > 0) {
                        eventData.java_params = nativeParams.slice(0, javaArgs.length);
                        eventData.java_args = javaArgs;
                        eventData.java_method_descriptor = javaMethod.signature;
                        eventData.java_ret_type = javaMethod.ret; // JVM descriptor, e.g. "Ljava/lang/String;"
                    }
                }

                // Decode Java-level return value (primitives + object type)
                const retDesc: string = javaMethod.ret; // JVM descriptor, e.g. "I", "Ljava/lang/String;", "[I"
                let javaRetValue: any = undefined;

                if (retDesc && retDesc !== "V") {
                    // Primitive returns
                    const rawRet = retVal;
                    switch (retDesc) {
                        case "I":
                        case "B":
                        case "S":
                        case "C":
                            javaRetValue = Number(rawRet);
                            break;
                        case "J":
                            if (typeof rawRet === "number") {
                                javaRetValue = rawRet;
                            } else if (rawRet && typeof rawRet.toString === "function") {
                                const s = rawRet.toString();
                                const n = parseInt(s, 10);
                                javaRetValue = Number.isNaN(n) ? s : n;
                            }
                            break;
                        case "F":
                        case "D":
                            javaRetValue = Number(rawRet);
                            break;
                        case "Z":
                            javaRetValue = Number(rawRet) !== 0;
                            break;
                        default:
                            // Object/array returns: record type, but don't try to decode content
                            if (rawRet && typeof rawRet.toString === "function") {
                                const key = rawRet.toString();
                                const existing = jobjectTypes.get(key) || retDesc;
                                jobjectTypes.set(key, existing);
                                javaRetValue = existing; // e.g. "Ljava/lang/String;" or "[I"
                            }
                            break;
                    }
                }

                if (javaRetValue !== undefined) {
                    eventData.java_ret_value = javaRetValue;
                }
            } catch (e) {
                devlog(`[JNI] Failed to decode Java args for ${methodName}: ${e}`);
            }
        }
        // Backtrace (if enabled)
        if (jniConfig.backtrace !== "none") {
            const bt = buildBacktrace((this as any).backtrace);
            if (bt) {
                eventData.backtrace = bt;
            }
        }

        createJniEvent("jni.env.call", eventData);
    }
};

const javaVMCallback: JNIInvocationCallback = {
    onEnter (args): void {
        this.args = args;
    },
    onLeave (retval: JNINativeReturnValue): void {
        if (!jniConfig.vm) {
            return;
        }

        const methodName = this.methodDef.name as string;
        if (shouldIgnoreMethod(methodName)) {
            return;
        }

        const rawArgs = this.args as any[];
        const retVal = retval.get();

        const ctx: any = this;
        const methodDef = ctx.methodDef;

        let cArgTypes: string[] | null = null;
        let cRetType: string | null = null;

        if (methodDef && Array.isArray(methodDef.args) && typeof methodDef.ret === "string") {
            cArgTypes = methodDef.args.slice();
            cRetType = methodDef.ret;
        }

        const eventData: any = {
            jni_struct: "JavaVM",
            method: methodName,
            arguments: rawArgs.map(String),
            return_value: String(retVal),
            thread_id: this.threadId,
            c_arg_types: cArgTypes,
            c_ret_type: cRetType
        };

        if (jniConfig.backtrace !== "none") {
            const bt = buildBacktrace((this as any).backtrace);
            if (bt) {
                eventData.backtrace = bt;
            }
        }
        
        createJniEvent("jni.vm.call", eventData);
    }
};

export function install_jni_hooks(): void {
    devlog("\n");
    devlog("[JNI] Installing JNI trace hooks");

    // Configuration is requested at hook installation time rather than at module
    // load time, ensuring the engine is only initialized when JNI tracing is
    // explicitly enabled.

    // Request JNI config from Python
    send("jni_config");
    const jniConfigRecvState = recv("jni_config", value => {
        const p = value.payload;
        if (typeof p === "object" && p !== null) {
            jniConfig = {
                ...jniConfig,
                libraries: Array.isArray(p.libraries) ? p.libraries : jniConfig.libraries,
                backtrace: (p.backtrace === "fuzzy" || p.backtrace === "accurate" || p.backtrace === "none")
                    ? p.backtrace
                    : jniConfig.backtrace,
                include: Array.isArray(p.include) ? p.include : jniConfig.include,
                exclude: Array.isArray(p.exclude) ? p.exclude : jniConfig.exclude,
                include_export: Array.isArray(p.include_export) ? p.include_export : jniConfig.include_export,
                exclude_export: Array.isArray(p.exclude_export) ? p.exclude_export : jniConfig.exclude_export,
                hide_data: typeof p.hide_data === "boolean" ? p.hide_data : jniConfig.hide_data,
                env: typeof p.env === "boolean" ? p.env : jniConfig.env,
                vm: typeof p.vm === "boolean" ? p.vm : jniConfig.vm
            };
        }
    });
    jniConfigRecvState.wait();

    // The library watcher callback is registered here for the same reason,
    // registration at module load time would arm the dynamic linker observer
    // regardless of the active hook configuration.
    JNILibraryWatcher.setCallback({
        onLoaded(path: string): void {
            ensureConfig();
            if (seenLibraries.has(path)) {
                return;
            }
            seenLibraries.add(path);
            createJniEvent("jni.library.tracked", {
                library_path: path
            });
        }
    });

    ensureConfig();

    // Engine is started after config is populated and only when this function
    // is explicitly called.
    startJniEngine();

    try {
        // JavaVM methods
        JNIInterceptor.attach("DestroyJavaVM", javaVMCallback);
        JNIInterceptor.attach("AttachCurrentThread", javaVMCallback);
        JNIInterceptor.attach("DetachCurrentThread", javaVMCallback);
        JNIInterceptor.attach("GetEnv", javaVMCallback);
        JNIInterceptor.attach("AttachCurrentThreadAsDaemon", javaVMCallback);

        // JNIEnv methods
        JNIInterceptor.attach("GetVersion", jniEnvCallback);
        JNIInterceptor.attach("DefineClass", jniEnvCallback);
        JNIInterceptor.attach("FindClass", jniEnvCallback);
        JNIInterceptor.attach("FromReflectedMethod", jniEnvCallback);
        JNIInterceptor.attach("FromReflectedField", jniEnvCallback);
        JNIInterceptor.attach("ToReflectedMethod", jniEnvCallback);
        JNIInterceptor.attach("GetSuperclass", jniEnvCallback);
        JNIInterceptor.attach("IsAssignableFrom", jniEnvCallback);
        JNIInterceptor.attach("ToReflectedField", jniEnvCallback);
        JNIInterceptor.attach("Throw", jniEnvCallback);
        JNIInterceptor.attach("ThrowNew", jniEnvCallback);
        JNIInterceptor.attach("ExceptionOccurred", jniEnvCallback);
        JNIInterceptor.attach("ExceptionDescribe", jniEnvCallback);
        JNIInterceptor.attach("ExceptionClear", jniEnvCallback);
        JNIInterceptor.attach("FatalError", jniEnvCallback);
        JNIInterceptor.attach("PushLocalFrame", jniEnvCallback);
        JNIInterceptor.attach("PopLocalFrame", jniEnvCallback);
        JNIInterceptor.attach("NewGlobalRef", jniEnvCallback);
        JNIInterceptor.attach("DeleteGlobalRef", jniEnvCallback);
        JNIInterceptor.attach("DeleteLocalRef", jniEnvCallback);
        JNIInterceptor.attach("IsSameObject", jniEnvCallback);
        JNIInterceptor.attach("NewLocalRef", jniEnvCallback);
        JNIInterceptor.attach("EnsureLocalCapacity", jniEnvCallback);
        JNIInterceptor.attach("AllocObject", jniEnvCallback);
        JNIInterceptor.attach("NewObject", jniEnvCallback);
        JNIInterceptor.attach("NewObjectV", jniEnvCallback);
        JNIInterceptor.attach("NewObjectA", jniEnvCallback);
        JNIInterceptor.attach("GetObjectClass", jniEnvCallback);
        JNIInterceptor.attach("IsInstanceOf", jniEnvCallback);
        JNIInterceptor.attach("GetMethodID", jniEnvCallback);
        JNIInterceptor.attach("CallObjectMethod", jniEnvCallback);
        JNIInterceptor.attach("CallObjectMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallObjectMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallBooleanMethod", jniEnvCallback);
        JNIInterceptor.attach("CallBooleanMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallBooleanMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallByteMethod", jniEnvCallback);
        JNIInterceptor.attach("CallByteMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallByteMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallCharMethod", jniEnvCallback);
        JNIInterceptor.attach("CallCharMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallCharMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallShortMethod", jniEnvCallback);
        JNIInterceptor.attach("CallShortMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallShortMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallIntMethod", jniEnvCallback);
        JNIInterceptor.attach("CallIntMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallIntMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallLongMethod", jniEnvCallback);
        JNIInterceptor.attach("CallLongMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallLongMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallFloatMethod", jniEnvCallback);
        JNIInterceptor.attach("CallFloatMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallFloatMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallDoubleMethod", jniEnvCallback);
        JNIInterceptor.attach("CallDoubleMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallDoubleMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallVoidMethod", jniEnvCallback);
        JNIInterceptor.attach("CallVoidMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallVoidMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualObjectMethod", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualObjectMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualObjectMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualBooleanMethod", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualBooleanMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualBooleanMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualByteMethod", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualByteMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualByteMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualCharMethod", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualCharMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualCharMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualShortMethod", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualShortMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualShortMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualIntMethod", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualIntMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualIntMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualLongMethod", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualLongMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualLongMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualFloatMethod", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualFloatMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualFloatMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualDoubleMethod", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualDoubleMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualDoubleMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualVoidMethod", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualVoidMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallNonvirtualVoidMethodA", jniEnvCallback);
        JNIInterceptor.attach("GetFieldID", jniEnvCallback);
        JNIInterceptor.attach("GetObjectField", jniEnvCallback);
        JNIInterceptor.attach("GetBooleanField", jniEnvCallback);
        JNIInterceptor.attach("GetByteField", jniEnvCallback);
        JNIInterceptor.attach("GetCharField", jniEnvCallback);
        JNIInterceptor.attach("GetShortField", jniEnvCallback);
        JNIInterceptor.attach("GetIntField", jniEnvCallback);
        JNIInterceptor.attach("GetLongField", jniEnvCallback);
        JNIInterceptor.attach("GetFloatField", jniEnvCallback);
        JNIInterceptor.attach("GetDoubleField", jniEnvCallback);
        JNIInterceptor.attach("SetObjectField", jniEnvCallback);
        JNIInterceptor.attach("SetBooleanField", jniEnvCallback);
        JNIInterceptor.attach("SetByteField", jniEnvCallback);
        JNIInterceptor.attach("SetCharField", jniEnvCallback);
        JNIInterceptor.attach("SetShortField", jniEnvCallback);
        JNIInterceptor.attach("SetIntField", jniEnvCallback);
        JNIInterceptor.attach("SetLongField", jniEnvCallback);
        JNIInterceptor.attach("SetFloatField", jniEnvCallback);
        JNIInterceptor.attach("SetDoubleField", jniEnvCallback);
        JNIInterceptor.attach("GetStaticMethodID", jniEnvCallback);
        JNIInterceptor.attach("CallStaticObjectMethod", jniEnvCallback);
        JNIInterceptor.attach("CallStaticObjectMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallStaticObjectMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallStaticBooleanMethod", jniEnvCallback);
        JNIInterceptor.attach("CallStaticBooleanMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallStaticBooleanMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallStaticByteMethod", jniEnvCallback);
        JNIInterceptor.attach("CallStaticByteMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallStaticByteMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallStaticCharMethod", jniEnvCallback);
        JNIInterceptor.attach("CallStaticCharMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallStaticCharMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallStaticShortMethod", jniEnvCallback);
        JNIInterceptor.attach("CallStaticShortMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallStaticShortMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallStaticIntMethod", jniEnvCallback);
        JNIInterceptor.attach("CallStaticIntMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallStaticIntMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallStaticLongMethod", jniEnvCallback);
        JNIInterceptor.attach("CallStaticLongMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallStaticLongMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallStaticFloatMethod", jniEnvCallback);
        JNIInterceptor.attach("CallStaticFloatMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallStaticFloatMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallStaticDoubleMethod", jniEnvCallback);
        JNIInterceptor.attach("CallStaticDoubleMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallStaticDoubleMethodA", jniEnvCallback);
        JNIInterceptor.attach("CallStaticVoidMethod", jniEnvCallback);
        JNIInterceptor.attach("CallStaticVoidMethodV", jniEnvCallback);
        JNIInterceptor.attach("CallStaticVoidMethodA", jniEnvCallback);
        JNIInterceptor.attach("GetStaticFieldID", jniEnvCallback);
        JNIInterceptor.attach("GetStaticObjectField", jniEnvCallback);
        JNIInterceptor.attach("GetStaticBooleanField", jniEnvCallback);
        JNIInterceptor.attach("GetStaticByteField", jniEnvCallback);
        JNIInterceptor.attach("GetStaticCharField", jniEnvCallback);
        JNIInterceptor.attach("GetStaticShortField", jniEnvCallback);
        JNIInterceptor.attach("GetStaticIntField", jniEnvCallback);
        JNIInterceptor.attach("GetStaticLongField", jniEnvCallback);
        JNIInterceptor.attach("GetStaticFloatField", jniEnvCallback);
        JNIInterceptor.attach("GetStaticDoubleField", jniEnvCallback);
        JNIInterceptor.attach("SetStaticObjectField", jniEnvCallback);
        JNIInterceptor.attach("SetStaticBooleanField", jniEnvCallback);
        JNIInterceptor.attach("SetStaticByteField", jniEnvCallback);
        JNIInterceptor.attach("SetStaticCharField", jniEnvCallback);
        JNIInterceptor.attach("SetStaticShortField", jniEnvCallback);
        JNIInterceptor.attach("SetStaticIntField", jniEnvCallback);
        JNIInterceptor.attach("SetStaticLongField", jniEnvCallback);
        JNIInterceptor.attach("SetStaticFloatField", jniEnvCallback);
        JNIInterceptor.attach("SetStaticDoubleField", jniEnvCallback);
        JNIInterceptor.attach("NewString", jniEnvCallback);
        JNIInterceptor.attach("GetStringLength", jniEnvCallback);
        JNIInterceptor.attach("GetStringChars", jniEnvCallback);
        JNIInterceptor.attach("ReleaseStringChars", jniEnvCallback);
        JNIInterceptor.attach("NewStringUTF", jniEnvCallback);
        JNIInterceptor.attach("GetStringUTFLength", jniEnvCallback);
        JNIInterceptor.attach("GetStringUTFChars", jniEnvCallback);
        JNIInterceptor.attach("ReleaseStringUTFChars", jniEnvCallback);
        JNIInterceptor.attach("GetArrayLength", jniEnvCallback);
        JNIInterceptor.attach("NewObjectArray", jniEnvCallback);
        JNIInterceptor.attach("GetObjectArrayElement", jniEnvCallback);
        JNIInterceptor.attach("SetObjectArrayElement", jniEnvCallback);
        JNIInterceptor.attach("NewBooleanArray", jniEnvCallback);
        JNIInterceptor.attach("NewByteArray", jniEnvCallback);
        JNIInterceptor.attach("NewCharArray", jniEnvCallback);
        JNIInterceptor.attach("NewShortArray", jniEnvCallback);
        JNIInterceptor.attach("NewIntArray", jniEnvCallback);
        JNIInterceptor.attach("NewLongArray", jniEnvCallback);
        JNIInterceptor.attach("NewFloatArray", jniEnvCallback);
        JNIInterceptor.attach("NewDoubleArray", jniEnvCallback);
        JNIInterceptor.attach("GetBooleanArrayElements", jniEnvCallback);
        JNIInterceptor.attach("GetByteArrayElements", jniEnvCallback);
        JNIInterceptor.attach("GetCharArrayElements", jniEnvCallback);
        JNIInterceptor.attach("GetShortArrayElements", jniEnvCallback);
        JNIInterceptor.attach("GetIntArrayElements", jniEnvCallback);
        JNIInterceptor.attach("GetLongArrayElements", jniEnvCallback);
        JNIInterceptor.attach("GetFloatArrayElements", jniEnvCallback);
        JNIInterceptor.attach("GetDoubleArrayElements", jniEnvCallback);
        JNIInterceptor.attach("ReleaseBooleanArrayElements", jniEnvCallback);
        JNIInterceptor.attach("ReleaseByteArrayElements", jniEnvCallback);
        JNIInterceptor.attach("ReleaseCharArrayElements", jniEnvCallback);
        JNIInterceptor.attach("ReleaseShortArrayElements", jniEnvCallback);
        JNIInterceptor.attach("ReleaseIntArrayElements", jniEnvCallback);
        JNIInterceptor.attach("ReleaseLongArrayElements", jniEnvCallback);
        JNIInterceptor.attach("ReleaseFloatArrayElements", jniEnvCallback);
        JNIInterceptor.attach("ReleaseDoubleArrayElements", jniEnvCallback);
        JNIInterceptor.attach("GetBooleanArrayRegion", jniEnvCallback);
        JNIInterceptor.attach("GetByteArrayRegion", jniEnvCallback);
        JNIInterceptor.attach("GetCharArrayRegion", jniEnvCallback);
        JNIInterceptor.attach("GetShortArrayRegion", jniEnvCallback);
        JNIInterceptor.attach("GetIntArrayRegion", jniEnvCallback);
        JNIInterceptor.attach("GetLongArrayRegion", jniEnvCallback);
        JNIInterceptor.attach("GetFloatArrayRegion", jniEnvCallback);
        JNIInterceptor.attach("GetDoubleArrayRegion", jniEnvCallback);
        JNIInterceptor.attach("SetBooleanArrayRegion", jniEnvCallback);
        JNIInterceptor.attach("SetByteArrayRegion", jniEnvCallback);
        JNIInterceptor.attach("SetCharArrayRegion", jniEnvCallback);
        JNIInterceptor.attach("SetShortArrayRegion", jniEnvCallback);
        JNIInterceptor.attach("SetIntArrayRegion", jniEnvCallback);
        JNIInterceptor.attach("SetLongArrayRegion", jniEnvCallback);
        JNIInterceptor.attach("SetFloatArrayRegion", jniEnvCallback);
        JNIInterceptor.attach("SetDoubleArrayRegion", jniEnvCallback);
        JNIInterceptor.attach("RegisterNatives", jniEnvCallback);
        JNIInterceptor.attach("UnregisterNatives", jniEnvCallback);
        JNIInterceptor.attach("MonitorEnter", jniEnvCallback);
        JNIInterceptor.attach("MonitorExit", jniEnvCallback);
        JNIInterceptor.attach("GetJavaVM", jniEnvCallback);
        JNIInterceptor.attach("GetStringRegion", jniEnvCallback);
        JNIInterceptor.attach("GetStringUTFRegion", jniEnvCallback);
        JNIInterceptor.attach("GetPrimitiveArrayCritical", jniEnvCallback);
        JNIInterceptor.attach("ReleasePrimitiveArrayCritical", jniEnvCallback);
        JNIInterceptor.attach("GetStringCritical", jniEnvCallback);
        JNIInterceptor.attach("ReleaseStringCritical", jniEnvCallback);
        JNIInterceptor.attach("NewWeakGlobalRef", jniEnvCallback);
        JNIInterceptor.attach("DeleteWeakGlobalRef", jniEnvCallback);
        JNIInterceptor.attach("ExceptionCheck", jniEnvCallback);
        JNIInterceptor.attach("NewDirectByteBuffer", jniEnvCallback);
        JNIInterceptor.attach("GetDirectBufferAddress", jniEnvCallback);
        JNIInterceptor.attach("GetDirectBufferCapacity", jniEnvCallback);
        JNIInterceptor.attach("GetObjectRefType", jniEnvCallback);

        devlog("[JNI] JNI trace hooks installed successfully");
    } catch (error) {
        devlog(`[JNI] Failed to install JNI hooks: ${error}`);
    }
}
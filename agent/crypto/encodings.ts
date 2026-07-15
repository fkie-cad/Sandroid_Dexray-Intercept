import { log, devlog, am_send } from "../utils/logging.js"
import { Where, bytesToHexSafe } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"
import { safePerform, safeUse, safeOverload, safeImplementation } from "../utils/safe_java.js"

const PROFILE_HOOKING_TYPE: string = "CRYPTO_ENCODING"

/**
 * https://github.com/dpnishant/appmon/blob/master/scripts/Android/Crypto/Hash.js
 * Some parts are taken from https://github.com/Areizen/Android-Malware-Sandbox/tree/master/plugins/base64_plugin
 */

function createEncodingEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

//function bytesToHexSafe(bytes: number[] | null): string {
//    if (!bytes || bytes.length === 0) return "";
//    return bytesToHex(new Uint8Array(bytes));
//}

function bytesToStringSafe(bytes: number[] | null): string {
    if (!bytes || bytes.length === 0) return "";
    try {
        // Array.from converts Java byte array proxies to JS arrays before filtering
        const jsBytes = Array.from(bytes) as number[];
        return String.fromCharCode(...jsBytes.filter(b => b >= 32 && b <= 126));
    } catch {
        return "";
    }
}

function install_base64_hooks(): void {
    devlog("Installing Base64 encoding/decoding hooks");

    safePerform("encodings:install_base64_hooks", () => {
        const base64 = safeUse('android.util.Base64', "encodings:install_base64_hooks");
        if (!base64) return;

        const threadDef = safeUse('java.lang.Thread', "encodings:install_base64_hooks");
        if (!threadDef) return;
        const threadInstance = threadDef.$new();

        // Method references are cached before any .implementation assignment.
        // Re-accessing the method after the first assignment replaces the overload
        // dispatcher on the wrapper, causing subsequent .overload() calls to fail.
        const decodeFn = base64.decode;
        const encodeFn = base64.encode;
        const encodeToStringFn = base64.encodeToString;

        const decodeStrInt = safeOverload(
            decodeFn, "encodings:Base64.decode", 'java.lang.String', 'int'
        );
        if (decodeStrInt) {
            decodeStrInt.implementation = safeImplementation(
                "encodings:Base64.decode[String,int]",
                decodeStrInt,
                function(original, str: string, flags: number) {
                    const result = original.call(this, str, flags);
                    if (result.length !== 0) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        createEncodingEvent("crypto.base64.decode", {
                            method: "decode(String, int)",
                            input_string: str,
                            flags: flags,
                            input_length: str.length,
                            output_length: result.length,
                            output_hex: bytesToHexSafe(result),
                            decoded_content: bytesToStringSafe(result),
                            stack_trace: Where(stack)
                        });
                    }
                    return result;
                }
            );
        }

        const decodeByteInt = safeOverload(
            decodeFn, "encodings:Base64.decode", '[B', 'int'
        );
        if (decodeByteInt) {
            decodeByteInt.implementation = safeImplementation(
                "encodings:Base64.decode[byte[],int]",
                decodeByteInt,
                function(original, input: number[], flags: number) {
                    const result = original.call(this, input, flags);
                    if (result.length !== 0) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        createEncodingEvent("crypto.base64.decode", {
                            method: "decode(byte[], int)",
                            flags: flags,
                            input_length: input.length,
                            input_hex: bytesToHexSafe(input),
                            output_length: result.length,
                            output_hex: bytesToHexSafe(result),
                            decoded_content: bytesToStringSafe(result),
                            stack_trace: Where(stack)
                        });
                    }
                    return result;
                }
            );
        }

        const decodeByteIntIntInt = safeOverload(
            decodeFn, "encodings:Base64.decode", '[B', 'int', 'int', 'int'
        );
        if (decodeByteIntIntInt) {
            decodeByteIntIntInt.implementation = safeImplementation(
                "encodings:Base64.decode[byte[],int,int,int]",
                decodeByteIntIntInt,
                function(original, input: number[], offset: number, len: number, flags: number) {
                    const result = original.call(this, input, offset, len, flags);
                    if (result.length !== 0) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        createEncodingEvent("crypto.base64.decode", {
                            method: "decode(byte[], int, int, int)",
                            offset: offset,
                            length: len,
                            flags: flags,
                            input_length: input.length,
                            input_hex: bytesToHexSafe(Array.from(input).slice(offset, offset + len) as number[]),
                            output_length: result.length,
                            output_hex: bytesToHexSafe(result),
                            decoded_content: bytesToStringSafe(result),
                            stack_trace: Where(stack)
                        });
                    }
                    return result;
                }
            );
        }

        const encodeByteInt = safeOverload(
            encodeFn, "encodings:Base64.encode", '[B', 'int'
        );
        if (encodeByteInt) {
            encodeByteInt.implementation = safeImplementation(
                "encodings:Base64.encode[byte[],int]",
                encodeByteInt,
                function(original, input: number[], flags: number) {
                    const result = original.call(this, input, flags);
                    if (input.length !== 0) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        createEncodingEvent("crypto.base64.encode", {
                            method: "encode(byte[], int)",
                            flags: flags,
                            input_length: input.length,
                            input_hex: bytesToHexSafe(input),
                            input_content: bytesToStringSafe(input),
                            output_length: result.length,
                            output_hex: bytesToHexSafe(result),
                            stack_trace: Where(stack)
                        });
                    }
                    return result;
                }
            );
        }

        const encodeByteIntIntInt = safeOverload(
            encodeFn, "encodings:Base64.encode", '[B', 'int', 'int', 'int'
        );
        if (encodeByteIntIntInt) {
            encodeByteIntIntInt.implementation = safeImplementation(
                "encodings:Base64.encode[byte[],int,int,int]",
                encodeByteIntIntInt,
                function(original, input: number[], offset: number, len: number, flags: number) {
                    const result = original.call(this, input, offset, len, flags);
                    if (input.length !== 0) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        createEncodingEvent("crypto.base64.encode", {
                            method: "encode(byte[], int, int, int)",
                            offset: offset,
                            length: len,
                            flags: flags,
                            input_length: input.length,
                            input_hex: bytesToHexSafe(Array.from(input).slice(offset, offset + len) as number[]),
                            input_content: bytesToStringSafe(Array.from(input).slice(offset, offset + len) as number[]),
                            output_length: result.length,
                            output_hex: bytesToHexSafe(result),
                            stack_trace: Where(stack)
                        });
                    }
                    return result;
                }
            );
        }

        const encodeToStringIntIntInt = safeOverload(
            encodeToStringFn, "encodings:Base64.encodeToString", '[B', 'int', 'int', 'int'
        );
        if (encodeToStringIntIntInt) {
            encodeToStringIntIntInt.implementation = safeImplementation(
                "encodings:Base64.encodeToString[byte[],int,int,int]",
                encodeToStringIntIntInt,
                function(original, input: number[], offset: number, len: number, flags: number) {
                    const result = original.call(this, input, offset, len, flags);
                    if (input.length !== 0) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        createEncodingEvent("crypto.base64.encode_to_string", {
                            method: "encodeToString(byte[], int, int, int)",
                            offset: offset,
                            length: len,
                            flags: flags,
                            input_length: input.length,
                            input_hex: bytesToHexSafe(Array.from(input).slice(offset, offset + len) as number[]),
                            input_content: bytesToStringSafe(Array.from(input).slice(offset, offset + len) as number[]),
                            output_string: result,
                            output_length: result.length,
                            stack_trace: Where(stack)
                        });
                    }
                    return result;
                }
            );
        }

        const encodeToStringByteInt = safeOverload(
            encodeToStringFn, "encodings:Base64.encodeToString", '[B', 'int'
        );
        if (encodeToStringByteInt) {
            encodeToStringByteInt.implementation = safeImplementation(
                "encodings:Base64.encodeToString[byte[],int]",
                encodeToStringByteInt,
                function(original, input: number[], flags: number) {
                    const result = original.call(this, input, flags);
                    if (input.length !== 0) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        createEncodingEvent("crypto.base64.encode_to_string", {
                            method: "encodeToString(byte[], int)",
                            flags: flags,
                            input_length: input.length,
                            input_hex: bytesToHexSafe(input),
                            input_content: bytesToStringSafe(input),
                            output_string: result,
                            output_length: result.length,
                            stack_trace: Where(stack)
                        });
                    }
                    return result;
                }
            );
        }
    });
}

export function install_encodings_hooks(): void {
    devlog("\n");
    devlog("Installing encodings hooks");

    try {
        install_base64_hooks();
    } catch (error) {
        devlog(`[HOOK] Failed to install base64 hooks: ${error}`);
    }
}
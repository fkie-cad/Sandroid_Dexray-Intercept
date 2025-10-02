import { log, devlog, am_send } from "../utils/logging.js"
import { Where, bytesToHex } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"

const PROFILE_HOOKING_TYPE: string = "CRYPTO_ENCODING"

/**
 *  https://github.com/dpnishant/appmon/blob/master/scripts/Android/Crypto/Hash.js
 * Some parts are taken from https://github.com/Areizen/Android-Malware-Sandbox/tree/master/plugins/base64_plugin
 * 
 */

function createEncodingEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function bytesToHexSafe(bytes: number[] | null): string {
    if (!bytes || bytes.length === 0) return "";
    return bytesToHex(new Uint8Array(bytes));
}

function bytesToStringSafe(bytes: number[] | null): string {
    if (!bytes || bytes.length === 0) return "";
    try {
        return String.fromCharCode(...bytes.filter(b => b >= 32 && b <= 126));
    } catch {
        return "";
    }
}

function install_base64_hooks(): void {
    devlog("Installing Base64 encoding/decoding hooks");
    
    Java.perform(() => {
        const base64 = Java.use('android.util.Base64');
        const threadDef = Java.use('java.lang.Thread');
        const threadInstance = threadDef.$new();

        base64.decode.overload('java.lang.String', 'int').implementation = function(str: string, flag: number) {
            const result = this.decode(str, flag);
            if (result.length !== 0) {
                const stack = threadInstance.currentThread().getStackTrace();
                createEncodingEvent("crypto.base64.decode", {
                    method: "decode(String, int)",
                    input_string: str,
                    flag: flag,
                    input_length: str.length,
                    output_length: result.length,
                    output_hex: bytesToHexSafe(result),
                    decoded_content: bytesToStringSafe(result),
                    stack_trace: Where(stack)
                });
            }
            return result;
        };
        base64.decode.overload('[B', 'int').implementation = function(input: number[], flag: number) {
            const result = this.decode(input, flag);
            if (result.length !== 0) {
                const stack = threadInstance.currentThread().getStackTrace();
                createEncodingEvent("crypto.base64.decode", {
                    method: "decode(byte[], int)",
                    flag: flag,
                    input_length: input.length,
                    input_hex: bytesToHexSafe(input),
                    output_length: result.length,
                    output_hex: bytesToHexSafe(result),
                    decoded_content: bytesToStringSafe(result),
                    stack_trace: Where(stack)
                });
            }
            return result;
        };
        base64.decode.overload('[B', 'int', 'int', 'int').implementation = function(input: number[], offset: number, len: number, flags: number) {
            const result = this.decode(input, offset, len, flags);
            if (result.length !== 0) {
                const stack = threadInstance.currentThread().getStackTrace();
                createEncodingEvent("crypto.base64.decode", {
                    method: "decode(byte[], int, int, int)",
                    offset: offset,
                    length: len,
                    flags: flags,
                    input_length: input.length,
                    input_hex: bytesToHexSafe(input.slice(offset, offset + len)),
                    output_length: result.length,
                    output_hex: bytesToHexSafe(result),
                    decoded_content: bytesToStringSafe(result),
                    stack_trace: Where(stack)
                });
            }
            return result;
        };
        base64.encode.overload('[B', 'int').implementation = function(input: number[], flags: number) {
            const result = this.encode(input, flags);
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
        };
        base64.encode.overload('[B', 'int', 'int', 'int').implementation = function(input: number[], offset: number, len: number, flags: number) {
            const result = this.encode(input, offset, len, flags);
            if (input.length !== 0) {
                const stack = threadInstance.currentThread().getStackTrace();
                createEncodingEvent("crypto.base64.encode", {
                    method: "encode(byte[], int, int, int)",
                    offset: offset,
                    length: len,
                    flags: flags,
                    input_length: input.length,
                    input_hex: bytesToHexSafe(input.slice(offset, offset + len)),
                    input_content: bytesToStringSafe(input.slice(offset, offset + len)),
                    output_length: result.length,
                    output_hex: bytesToHexSafe(result),
                    stack_trace: Where(stack)
                });
            }
            return result;
        };
        base64.encodeToString.overload('[B', 'int', 'int', 'int').implementation = function(input: number[], offset: number, len: number, flags: number) {
            const result = this.encodeToString(input, offset, len, flags);
            if (input.length !== 0) {
                const stack = threadInstance.currentThread().getStackTrace();
                createEncodingEvent("crypto.base64.encode_to_string", {
                    method: "encodeToString(byte[], int, int, int)",
                    offset: offset,
                    length: len,
                    flags: flags,
                    input_length: input.length,
                    input_hex: bytesToHexSafe(input.slice(offset, offset + len)),
                    input_content: bytesToStringSafe(input.slice(offset, offset + len)),
                    output_string: result,
                    output_length: result.length,
                    stack_trace: Where(stack)
                });
            }
            return result;
        };
        base64.encodeToString.overload('[B', 'int').implementation = function(input: number[], flags: number) {
            const result = this.encodeToString(input, flags);
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
        };
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
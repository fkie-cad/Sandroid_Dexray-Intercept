import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Where, bytesToHex, buffer2ArrayBuffer } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"

/**
 * 
 * Some parts are taken from https://github.com/Areizen/Android-Malware-Sandbox/tree/master/plugins/cipher_plugin
 *  and also 
 * https://trustedsec.com/blog/mobile-hacking-using-frida-to-monitor-encryption
 */
 const PROFILE_HOOKING_TYPE: string = "CRYPTO_AES"

 var cipher_id;
 var key_info;
 var opmode_info;

 function aes_info() {
    Java.perform(() => {
        let use_single_byte = false;
        let complete_bytes: number[] = [];
        let index = 0;

        const secretKeySpecDef = Java.use('javax.crypto.spec.SecretKeySpec');
        const ivParameterSpecDef = Java.use('javax.crypto.spec.IvParameterSpec');
        const cipherDef = Java.use('javax.crypto.Cipher');

        const cipherDoFinal_1 = cipherDef.doFinal.overload();
        const cipherDoFinal_2 = cipherDef.doFinal.overload('[B');
        const cipherDoFinal_3 = cipherDef.doFinal.overload('[B', 'int');
        const cipherDoFinal_4 = cipherDef.doFinal.overload('[B', 'int', 'int');
        const cipherDoFinal_5 = cipherDef.doFinal.overload('[B', 'int', 'int', '[B');
        const cipherDoFinal_6 = cipherDef.doFinal.overload('[B', 'int', 'int', '[B', 'int');

        const cipherUpdate_1 = cipherDef.update.overload('[B');
        const cipherUpdate_2 = cipherDef.update.overload('[B', 'int', 'int');
        const cipherUpdate_3 = cipherDef.update.overload('[B', 'int', 'int', '[B');
        const cipherUpdate_4 = cipherDef.update.overload('[B', 'int', 'int', '[B', 'int');

        const secretKeySpecDef_init_1 = secretKeySpecDef.$init.overload('[B', 'java.lang.String');
        const secretKeySpecDef_init_2 = secretKeySpecDef.$init.overload('[B', 'int', 'int', 'java.lang.String');

        /*
        const ivParameterSpecDef_init_1 = ivParameterSpecDef.$init.overload('[B');
        const ivParameterSpecDef_init_2 = ivParameterSpecDef.$init.overload('[B', 'int', 'int');

        secretKeySpecDef_init_1.implementation = function (arr: number[], alg: string) {
            const key = b2s(arr);
            am_send(PROFILE_HOOKING_TYPE, `Creating ${alg} secret key, ${alg}-key:\n${hexdump(key)}`);
            return secretKeySpecDef_init_1.call(this, arr, alg);
        };

        secretKeySpecDef_init_2.implementation = function (arr: number[], off: number, len: number, alg: string) {
            const key = b2s(arr);
            am_send(PROFILE_HOOKING_TYPE, `Creating ${alg} secret key, ${alg}-key:\n${hexdump(key)}`);
            return secretKeySpecDef_init_2.call(this, arr, off, len, alg);
        };
        */
        secretKeySpecDef_init_1.implementation = function (arr: number[], alg: string) {
            const key = b2s(arr);
            am_send(PROFILE_HOOKING_TYPE, `Creating ${alg} secret key, ${alg}-key:\n${hexdump_local(key)}`);
            return secretKeySpecDef_init_1.call(this, arr, alg);
        };

        secretKeySpecDef_init_2.implementation = function (arr: number[], off: number, len: number, alg: string) {
            const key = b2s(arr);
            am_send(PROFILE_HOOKING_TYPE, `Creating ${alg} secret key, ${alg}-key:\n${hexdump_local(key)}`);
            return secretKeySpecDef_init_2.call(this, arr, off, len, alg);
        };

        cipherDoFinal_1.implementation = function () {
            const ret = cipherDoFinal_1.call(this);
            info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
            return ret;
        };

        cipherDoFinal_2.implementation = function (arr: number[]) {
            addtoarray(arr);
            const ret = cipherDoFinal_2.call(this, arr);
            info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
            return ret;
        };

        cipherDoFinal_3.implementation = function (arr: number[], a: number) {
            addtoarray(arr);
            const ret = cipherDoFinal_3.call(this, arr, a);
            info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
            return ret;
        };

        cipherDoFinal_4.implementation = function (arr: number[], a: number, b: number) {
            addtoarray(arr);
            const ret = cipherDoFinal_4.call(this, arr, a, b);
            info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
            return ret;
        };

        cipherDoFinal_5.implementation = function (arr: number[], a: number, b: number, c: number[]) {
            addtoarray(arr);
            const ret = cipherDoFinal_5.call(this, arr, a, b, c);
            info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
            return ret;
        };

        cipherDoFinal_6.implementation = function (arr: number[], a: number, b: number, c: number[], d: number) {
            addtoarray(arr);
            const ret = cipherDoFinal_6.call(this, arr, a, b, c, d);
            info(this.getIV(), this.getAlgorithm(), complete_bytes, c);
            return ret;
        };

        cipherUpdate_1.implementation = function (arr: number[]) {
            addtoarray(arr);
            return cipherUpdate_1.call(this, arr);
        };

        cipherUpdate_2.implementation = function (arr: number[], a: number, b: number) {
            addtoarray(arr);
            return cipherUpdate_2.call(this, arr, a, b);
        };

        cipherUpdate_3.implementation = function (arr: number[], a: number, b: number, c: number[]) {
            addtoarray(arr);
            return cipherUpdate_3.call(this, arr, a, b, c);
        };

        cipherUpdate_4.implementation = function (arr: number[], a: number, b: number, c: number[], d: number) {
            addtoarray(arr);
            return cipherUpdate_4.call(this, arr, a, b, c, d);
        };

        function info(iv: number[], alg: string, plain: number[], encoded: number[]) {
            
            if (iv) {
                am_send(PROFILE_HOOKING_TYPE, `Initialization Vector: \n${hexdump_local(b2s(iv))}`);
            } else {
                am_send(PROFILE_HOOKING_TYPE, `Initialization Vector: ${iv}`);
            }
            var plain_as_buffer: ArrayBuffer = buffer2ArrayBuffer(plain);
            var encoded_as_buffer: ArrayBuffer = buffer2ArrayBuffer(encoded);
            am_send(PROFILE_HOOKING_TYPE, `Algorithm: ${alg}`);
            am_send(PROFILE_HOOKING_TYPE, `In: \n${hexdump_local(b2s(plain))}`); // buffer2ArrayBuffer
            console.log(hexdump(plain_as_buffer, {header: true, ansi:true}));
            am_send(PROFILE_HOOKING_TYPE, `Out: \n${hexdump_local(b2s(encoded))}`);
            console.log(hexdump(encoded_as_buffer, {header: true, ansi:true}));
            complete_bytes = [];
            index = 0;
        }

        function hexdump_local(buffer: string, blockSize: number = 16): string {
            const lines: string[] = [];
            const hex = "0123456789ABCDEF";
            for (let b = 0; b < buffer.length; b += blockSize) {
                const block = buffer.slice(b, Math.min(b + blockSize, buffer.length));
                const addr = ("0000" + b.toString(16)).slice(-4);
                let codes = Array.from(block).map(ch => {
                    const code = ch.charCodeAt(0);
                    return ` ${hex[(0xF0 & code) >> 4]}${hex[0x0F & code]}`;
                }).join("");
                codes += "   ".repeat(blockSize - block.length);
                const chars = block.replace(/[\x00-\x1F\x20]/g, '.');
                lines.push(`${addr} ${codes}  ${chars}`);
            }
            return lines.join("\n");
        }

        function b2s(array: number[]): string {
            //return String.fromCharCode(...array.map(byte => modulus(byte, 256)));
            let result = '';
            for (let i = 0; i < array.length; i++) {
                result += String.fromCharCode(modulus(array[i], 256));
            }
            return result;
        }

        function modulus(x: number, n: number): number {
            return ((x % n) + n) % n;
        }

        function addtoarray(arr: number[]) {
            for (let i = 0; i < arr.length; i++) {
                complete_bytes[index] = arr[i];
                index += 1;
            }
        }
    });
}



 function hook_secrets(){
    var secret_key_spec = Java.use("javax.crypto.spec.SecretKeySpec");
    secret_key_spec.$init.overload("[B", "java.lang.String").implementation = function (x, y) {
        var obj = {"event_type": "Javax::crypto.spec.SecretKeySpec"};
        am_send(PROFILE_HOOKING_TYPE,JSON.stringify(obj)+x.buffer);
        return this.$init(x, y);
    }

    var iv_parameter_spec = Java.use("javax.crypto.spec.IvParameterSpec");
    iv_parameter_spec.$init.overload("[B").implementation = function (x) {
        var obj = {"event_type": "Javax::crypto.spec.IvParameterSpec"};
        am_send(PROFILE_HOOKING_TYPE,JSON.stringify(obj)+ x.buffer);
        return this.$init(x);
    }
}



function hook_aes_keys(){
    var cipher = Java.use("javax.crypto.Cipher");
    var threadef = Java.use('java.lang.Thread');
    var threadinstance = threadef.$new();

    cipher.init.overload('int', 'java.security.Key').implementation = function (opmode, key) {
        cipher_id = this.hashCode();
        key_info = key.getEncoded(); 
        opmode_info = opmode;
        return this.init(opmode, key);
    }

    cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (opmode, key, params) {
        cipher_id = this.hashCode();
        key_info = key.getEncoded(); 
        opmode_info = opmode;
        return this.init(opmode, key, params);
    }

    cipher.doFinal.overload("[B").implementation = function (barr) {
        var result = this.doFinal(barr);
        if (cipher_id == this.hashCode()){
            
            //var hexKey  = Buffer.from(new Uint8Array(key_info)).toString('hex');
            var hexKey = bytesToHex(new Uint8Array(key_info));
            
            //var hexIV = Buffer.from(new Uint8Array(this.getIV())).toString('hex');
            var hexIV =  bytesToHex(new Uint8Array(this.getIV()));

            //var hexArg = Buffer.from(new Uint8Array(barr)).toString('hex');
            var hexArg =  bytesToHex(new Uint8Array(barr));
            //var hexResult = Buffer.from(new Uint8Array(result)).toString('hex');
            var hexResult =  bytesToHex(new Uint8Array(result));

            var stack = threadinstance.currentThread().getStackTrace();
            var obj = {"event_type": "Javax::crypto.Cipher.doFinal", "algo" : this.getAlgorithm(), "iv" : hexIV, "opmode" : opmode_info, "key": hexKey, "arg": hexArg, "result": hexResult, 'stack': Where(stack)};
            am_send(PROFILE_HOOKING_TYPE,JSON.stringify(obj));

            cipher_id = '';
            key_info = '';
            opmode_info = '';          
        }
        return result;
    }

}




export function install_aes_hooks(){
    devlog("\n")
    devlog("install aes hooks");
    aes_info();
    hook_secrets();
    hook_aes_keys();

}
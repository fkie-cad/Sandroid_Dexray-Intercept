import { log, devlog, am_send } from "../utils/logging.js"
import { Where, bytesToHex } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"

const PROFILE_HOOKING_TYPE: string = "CRYPTO_AES"

interface CipherSession {
    id: number;
    key: number[];
    opmode: number;
    algorithm?: string;
    iv?: number[];
}

const activeCipherSessions = new Map<number, CipherSession>();

function createAESEvent(eventType: string, data: any): void {
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

function extractPlaintext(hexData: string, opmode: number): string | null {
    if (!hexData) return null;
    try {
        const bytes = hexData.match(/.{2}/g)?.map(byte => parseInt(byte, 16)) || [];
        return String.fromCharCode(...bytes.filter(b => b >= 32 && b <= 126));
    } catch {
        return null;
    }
}

export function install_aes_secrets() {
    devlog("Installing AES secrets hooks (keys and IVs)");
    
    Java.perform(() => {
        const secretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        const ivParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");

        secretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (keyBytes: number[], algorithm: string) {
            createAESEvent("crypto.key.creation", {
                algorithm: algorithm,
                key_length: keyBytes.length,
                key_hex: bytesToHexSafe(keyBytes)
            });
            return this.$init(keyBytes, algorithm);
        };

        secretKeySpec.$init.overload("[B", "int", "int", "java.lang.String").implementation = function (keyBytes: number[], offset: number, length: number, algorithm: string) {
            createAESEvent("crypto.key.creation", {
                algorithm: algorithm,
                key_length: length,
                key_hex: bytesToHexSafe(keyBytes.slice(offset, offset + length))
            });
            return this.$init(keyBytes, offset, length, algorithm);
        };

        ivParameterSpec.$init.overload("[B").implementation = function (ivBytes: number[]) {
            createAESEvent("crypto.iv.creation", {
                iv_length: ivBytes.length,
                iv_hex: bytesToHexSafe(ivBytes)
            });
            return this.$init(ivBytes);
        };
    });
}

export function install_aes_keys() {
    devlog("Installing AES keys hooks (cipher initialization)");
    
    Java.perform(() => {
        const cipher = Java.use("javax.crypto.Cipher");

        cipher.init.overload('int', 'java.security.Key').implementation = function (opmode: number, key: any) {
            const cipherId = this.hashCode();
            const keyBytes = key.getEncoded();
            
            activeCipherSessions.set(cipherId, {
                id: cipherId,
                key: keyBytes,
                opmode: opmode
            });
            
            return this.init(opmode, key);
        };

        cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (opmode: number, key: any, params: any) {
            const cipherId = this.hashCode();
            const keyBytes = key.getEncoded();
            
            activeCipherSessions.set(cipherId, {
                id: cipherId,
                key: keyBytes,
                opmode: opmode
            });
            
            return this.init(opmode, key, params);
        };
    });
}

export function install_aes_info() {
    devlog("Installing AES info hooks (cipher operations)");
    
    Java.perform(() => {
        const cipher = Java.use("javax.crypto.Cipher");
        const threadDef = Java.use('java.lang.Thread');
        const threadInstance = threadDef.$new();

        cipher.doFinal.overload("[B").implementation = function (inputBytes: number[]) {
            const result = this.doFinal(inputBytes);
            const cipherId = this.hashCode();
            const session = activeCipherSessions.get(cipherId);
            
            if (session) {
                const algorithm = this.getAlgorithm();
                const iv = this.getIV();
                const inputHex = bytesToHexSafe(inputBytes);
                const outputHex = bytesToHexSafe(result);
                const stack = threadInstance.currentThread().getStackTrace();
                
                createAESEvent("crypto.cipher.operation", {
                    algorithm: algorithm,
                    operation_mode: session.opmode,
                    key_hex: bytesToHexSafe(session.key),
                    iv_hex: bytesToHexSafe(iv),
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
            cipher.update.overload('[B'),
            cipher.update.overload('[B', 'int', 'int'),
            cipher.update.overload('[B', 'int', 'int', '[B'),
            cipher.update.overload('[B', 'int', 'int', '[B', 'int')
        ];

        updateMethods.forEach((method, index) => {
            method.implementation = function (...args: any[]) {
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
            cipher.doFinal.overload('[B', 'int'),
            cipher.doFinal.overload('[B', 'int', 'int'),
            cipher.doFinal.overload('[B', 'int', 'int', '[B'),
            cipher.doFinal.overload('[B', 'int', 'int', '[B', 'int')
        ];

        doFinalMethods.forEach((method, index) => {
            method.implementation = function (...args: any[]) {
                const result = method.apply(this, args);
                const cipherId = this.hashCode();
                const session = activeCipherSessions.get(cipherId);
                
                if (session) {
                    const algorithm = this.getAlgorithm();
                    const iv = this.getIV();
                    const stack = threadInstance.currentThread().getStackTrace();
                    
                    createAESEvent("crypto.cipher.operation", {
                        algorithm: algorithm,
                        operation_mode: session.opmode,
                        key_hex: bytesToHexSafe(session.key),
                        iv_hex: bytesToHexSafe(iv),
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

export function install_aes_hooks() {
    devlog("\n")
    devlog("install aes hooks");
    
    install_aes_secrets();
    install_aes_keys();
    install_aes_info();
}
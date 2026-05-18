import { log, devlog, am_send } from "../utils/logging.js"
import { Where, bytesToHex } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"
import { safePerform, safeUse, safeOverload } from "../utils/safe_java.js"

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

    safePerform("aes:install_aes_secrets", () => {
        const secretKeySpec = safeUse("javax.crypto.spec.SecretKeySpec", "aes:install_aes_secrets");
        if (!secretKeySpec) return;

        const ivParameterSpec = safeUse("javax.crypto.spec.IvParameterSpec", "aes:install_aes_secrets");
        if (!ivParameterSpec) return;

        const skInit1 = safeOverload(secretKeySpec.$init, "aes:SecretKeySpec.$init", "[B", "java.lang.String");
        if (skInit1) {
            skInit1.implementation = function(keyBytes: number[], algorithm: string) {
                createAESEvent("crypto.key.creation", {
                    algorithm: algorithm,
                    key_length: keyBytes.length,
                    key_hex: bytesToHexSafe(keyBytes)
                });
                return this.$init(keyBytes, algorithm);
            };
        }

        const skInit2 = safeOverload(secretKeySpec.$init, "aes:SecretKeySpec.$init", "[B", "int", "int", "java.lang.String");
        if (skInit2) {
            skInit2.implementation = function(keyBytes: number[], offset: number, length: number, algorithm: string) {
                createAESEvent("crypto.key.creation", {
                    algorithm: algorithm,
                    key_length: length,
                    key_hex: bytesToHexSafe(keyBytes.slice(offset, offset + length))
                });
                return this.$init(keyBytes, offset, length, algorithm);
            };
        }

        const ivInit = safeOverload(ivParameterSpec.$init, "aes:IvParameterSpec.$init", "[B");
        if (ivInit) {
            ivInit.implementation = function(ivBytes: number[]) {
                createAESEvent("crypto.iv.creation", {
                    iv_length: ivBytes.length,
                    iv_hex: bytesToHexSafe(ivBytes)
                });
                return this.$init(ivBytes);
            };
        }
    });
}

export function install_aes_keys() {
    devlog("Installing AES keys hooks (cipher initialization)");

    safePerform("aes:install_aes_keys", () => {
        const cipher = safeUse("javax.crypto.Cipher", "aes:install_aes_keys");
        if (!cipher) return;

        const cipherInit1 = safeOverload(cipher.init, "aes:Cipher.init", 'int', 'java.security.Key');
        if (cipherInit1) {
            cipherInit1.implementation = function(opmode: number, key: any) {
                const cipherId = this.hashCode();
                const keyBytes = key.getEncoded();
                activeCipherSessions.set(cipherId, {
                    id: cipherId,
                    key: keyBytes,
                    opmode: opmode
                });
                return this.init(opmode, key);
            };
        }

        const cipherInit2 = safeOverload(cipher.init, "aes:Cipher.init", 'int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec');
        if (cipherInit2) {
            cipherInit2.implementation = function(opmode: number, key: any, params: any) {
                const cipherId = this.hashCode();
                const keyBytes = key.getEncoded();
                activeCipherSessions.set(cipherId, {
                    id: cipherId,
                    key: keyBytes,
                    opmode: opmode
                });
                return this.init(opmode, key, params);
            };
        }
    });
}

export function install_aes_info() {
    devlog("Installing AES info hooks (cipher operations)");

    safePerform("aes:install_aes_info", () => {
        const cipher = safeUse("javax.crypto.Cipher", "aes:install_aes_info");
        if (!cipher) return;

        const threadDef = safeUse('java.lang.Thread', "aes:install_aes_info");
        if (!threadDef) return;
        const threadInstance = threadDef.$new();

        // Single [B overload handled separately — logs more detail
        const doFinalBytes = safeOverload(cipher.doFinal, "aes:Cipher.doFinal", "[B");
        if (doFinalBytes) {
            doFinalBytes.implementation = function(inputBytes: number[]) {
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
        }

        // Specific update overloads — filter(Boolean) removes any null from failed resolution
        const updateMethods = [
            safeOverload(cipher.update, "aes:Cipher.update", '[B'),
            safeOverload(cipher.update, "aes:Cipher.update", '[B', 'int', 'int'),
            safeOverload(cipher.update, "aes:Cipher.update", '[B', 'int', 'int', '[B'),
            safeOverload(cipher.update, "aes:Cipher.update", '[B', 'int', 'int', '[B', 'int')
        ].filter(Boolean);

        updateMethods.forEach((method: any, index: number) => {
            method.implementation = function(...args: any[]) {
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

        // doFinal variants — zero-arg overload via safeOverload with no signatures
        const doFinalMethods = [
            safeOverload(cipher.doFinal, "aes:Cipher.doFinal"),
            safeOverload(cipher.doFinal, "aes:Cipher.doFinal", '[B', 'int'),
            safeOverload(cipher.doFinal, "aes:Cipher.doFinal", '[B', 'int', 'int'),
            safeOverload(cipher.doFinal, "aes:Cipher.doFinal", '[B', 'int', 'int', '[B'),
            safeOverload(cipher.doFinal, "aes:Cipher.doFinal", '[B', 'int', 'int', '[B', 'int')
        ].filter(Boolean);

        doFinalMethods.forEach((method: any, index: number) => {
            method.implementation = function(...args: any[]) {
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

export function install_aes_hooks(): void {
    devlog("\n")
    devlog("install aes hooks");

    try {
        install_aes_secrets();
    } catch (error) {
        devlog(`[HOOK] Failed to install AES secrets hooks: ${error}`);
    }

    try {
        install_aes_keys();
    } catch (error) {
        devlog(`[HOOK] Failed to install AES keys hooks: ${error}`);
    }

    try {
        install_aes_info();
    } catch (error) {
        devlog(`[HOOK] Failed to install AES info hooks: ${error}`);
    }
}
import { log, devlog, am_send } from "../utils/logging.js"
import { Java } from "../utils/javalib.js"
import { bytesToHexSafe } from "../utils/misc.js"
import { safePerform, safeUse, safeOverload, safeImplementation } from "../utils/safe_java.js"

const PROFILE_HOOKING_TYPE: string = "CRYPTO_KEYSTORE"

/**
 * https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security/blob/master/custom_scripts/Android/tracer_keystore.js
 */

interface KeystoreEntry {
    alias: string;
    type?: string;
    entry?: any;
    protection?: any;
}

const keystoreList: any[] = [];

// was initialized at module load time before, now initialized in install_keystore_hooks
let StringCls: any = null;

function createKeystoreEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function charArrayToString(charArray: any): string {
    if (charArray == null) return '(null)';
    if (!StringCls) return '(StringCls not initialized)';
    return StringCls.$new(charArray).toString();
}

// hook functions

function hookKeystoreConstructor(KeyStore: any): void {
    const ctor = safeOverload(
        KeyStore.$init,
        "keystore:KeyStore.$init",
        "java.security.KeyStoreSpi", "java.security.Provider", "java.lang.String"
    );
    if (!ctor) return;

    ctor.implementation = safeImplementation(
        "keystore:KeyStore.$init",
        ctor,
        function(original, keyStoreSpi: any, provider: any, type: string) {
            createKeystoreEvent("crypto.keystore.constructor", {
                // $className extracts the class name only - toString() includes a run-varying identity hash
                keystore_spi_class: keyStoreSpi ? keyStoreSpi.$className : null,
                provider: provider ? provider.toString() : null,
                type: type
            });
            return original.call(this, keyStoreSpi, provider, type);
        }
    );
}

function hookKeystoreGetInstance(KeyStore: any): void {
    const getInstance = safeOverload(
        KeyStore.getInstance,
        "keystore:KeyStore.getInstance",
        "java.lang.String"
    );
    if (!getInstance) return;

    getInstance.implementation = safeImplementation(
        "keystore:KeyStore.getInstance[String]",
        getInstance,
        function(original, type: string) {
            createKeystoreEvent("crypto.keystore.get_instance", {
                method: "getInstance(String)",
                type: type
            });
            const tmp = original.call(this, type);
            keystoreList.push(tmp);
            return tmp;
        }
    );
}

function hookKeystoreGetInstance_Provider(KeyStore: any): void {
    const getInstance = safeOverload(
        KeyStore.getInstance,
        "keystore:KeyStore.getInstance",
        "java.lang.String", "java.lang.String"
    );
    if (!getInstance) return;

    getInstance.implementation = safeImplementation(
        "keystore:KeyStore.getInstance[String,String]",
        getInstance,
        function(original, type: string, provider: string) {
            createKeystoreEvent("crypto.keystore.get_instance", {
                method: "getInstance(String, String)",
                type: type,
                provider: provider
            });
            const tmp = original.call(this, type, provider);
            keystoreList.push(tmp);
            return tmp;
        }
    );
}

function hookKeystoreGetInstance_Provider2(KeyStore: any): void {
    const getInstance = safeOverload(
        KeyStore.getInstance,
        "keystore:KeyStore.getInstance",
        "java.lang.String", "java.security.Provider"
    );
    if (!getInstance) return;

    getInstance.implementation = safeImplementation(
        "keystore:KeyStore.getInstance[String,Provider]",
        getInstance,
        function(original, type: string, provider: any) {
            createKeystoreEvent("crypto.keystore.get_instance", {
                method: "getInstance(String, Provider)",
                type: type,
                provider: provider ? provider.toString() : null
            });
            const tmp = original.call(this, type, provider);
            keystoreList.push(tmp);
            return tmp;
        }
    );
}

/*
 * Hook Keystore.load( ... ), set dump to true if you want to perform dump of available Aliases automatically.
 */
function hookKeystoreLoad(KeyStore: any, dump: boolean): void {
    const load = safeOverload(
        KeyStore.load,
        "keystore:KeyStore.load",
        'java.security.KeyStore$LoadStoreParameter'
    );
    if (!load) return;

    /* following function hooks to a Keystore.load(java.security.KeyStore.LoadStoreParameter) */
    load.implementation = safeImplementation(
        "keystore:KeyStore.load[LoadStoreParameter]",
        load,
        function(original, param: any) {
            createKeystoreEvent("crypto.keystore.load", {
                method: "load(LoadStoreParameter)",
                keystore_type: this.getType(),
                parameter: param ? param.toString() : null
            });
            const res = original.call(this, param);
            if (dump) {
                createKeystoreEvent("crypto.keystore.aliases", {
                    keystore_type: this.getType(),
                    aliases: ListAliasesObj(this)
                });
            }
            return res;
        }
    );
}

/*
 * Hook Keystore.load( ... ), set dump to true if you want to perform dump of available Aliases automatically.
 */
function hookKeystoreLoadStream(KeyStore: any, dump: boolean): void {
    const loadStream = safeOverload(
        KeyStore.load,
        "keystore:KeyStore.load",
        'java.io.InputStream', '[C'
    );
    if (!loadStream) return;

    /* following function hooks to a Keystore.load(InputStream stream, char[] password) */
    loadStream.implementation = safeImplementation(
        "keystore:KeyStore.load[InputStream,char[]]",
        loadStream,
        function(original, stream: any, charArray: any) {
            createKeystoreEvent("crypto.keystore.load", {
                method: "load(InputStream, char[])",
                keystore_type: this.getType(),
                password: charArrayToString(charArray),
                input_stream: stream ? stream.toString() : null
            });
            const res = original.call(this, stream, charArray);
            if (dump) {
                createKeystoreEvent("crypto.keystore.aliases", {
                    keystore_type: this.getType(),
                    aliases: ListAliasesObj(this)
                });
            }
            return res;
        }
    );
}

function hookKeystoreStore(KeyStore: any): void {
    // fix: was raw am_send with string concatenation
    const store = safeOverload(
        KeyStore.store,
        "keystore:KeyStore.store",
        'java.security.KeyStore$LoadStoreParameter'
    );
    if (!store) return;

    /* following function hooks to a Keystore.store(java.security.KeyStore$LoadStoreParameter) */
    store.implementation = safeImplementation(
        "keystore:KeyStore.store[LoadStoreParameter]",
        store,
        function(original, param) {
            createKeystoreEvent("crypto.keystore.store", {
                method: "store(LoadStoreParameter)",
                keystore_type: this.getType(),
                parameter: param ? param.toString() : null
            });
            return original.call(this, param);
        }
    );
}

function hookKeystoreStoreStream(KeyStore: any): void {
    // fix: was raw am_send with string concatenation
    const storeStream = safeOverload(
        KeyStore.store,
        "keystore:KeyStore.store",
        'java.io.OutputStream', '[C'
    );
    if (!storeStream) return;

    /* following function hooks to a Keystore.store(OutputStream stream, char[] password) */
    storeStream.implementation = safeImplementation(
        "keystore:KeyStore.store[OutputStream,char[]]",
        storeStream,
        function(original, stream, charArray) {
            createKeystoreEvent("crypto.keystore.store", {
                method: "store(OutputStream, char[])",
                keystore_type: this.getType(),
                password: charArrayToString(charArray),
                output_stream: stream ? stream.toString() : null
            });
            return original.call(this, stream, charArray);
        }
    );
}

function hookKeystoreGetKey(KeyStore: any): void {
    const getKey = safeOverload(
        KeyStore.getKey,
        "keystore:KeyStore.getKey",
        "java.lang.String", "[C"
    );
    if (!getKey) return;

    getKey.implementation = safeImplementation(
        "keystore:KeyStore.getKey",
        getKey,
        function(original, alias: string, charArray: any) {
            createKeystoreEvent("crypto.keystore.get_key", {
                alias: alias,
                password: charArrayToString(charArray)
            });
            return original.call(this, alias, charArray);
        }
    );
}

function hookKeystoreSetEntry(KeyStore: any): void {
    // fix: was raw am_send with string concatenation
    const setEntry = safeOverload(
        KeyStore.setEntry,
        "keystore:KeyStore.setEntry",
        "java.lang.String",
        "java.security.KeyStore$Entry",
        "java.security.KeyStore$ProtectionParameter"
    );
    if (!setEntry) return;

    setEntry.implementation = safeImplementation(
        "keystore:KeyStore.setEntry",
        setEntry,
        function(original, alias, entry, protection) {
            createKeystoreEvent("crypto.keystore.set_entry", {
                method: "setEntry(String, KeyStore$Entry, KeyStore$ProtectionParameter)",
                alias: alias,
                entry: dumpKeyStoreEntry(entry),
                protection: dumpProtectionParameter(protection)
            });
            return original.call(this, alias, entry, protection);
        }
    );
}

// function hookKeystoreSetEntry() {
// 	var keyStoreSetKeyEntry = Java.use('java.security.KeyStore')['setEntry'].overload("java.lang.String", "java.security.KeyStore$Entry", "java.security.KeyStore$ProtectionParameter");
// 	keyStoreSetKeyEntry.implementation = function (alias, entry, protection) {
// 		//am_send(PROFILE_HOOKING_TYPE,"[Call] Keystore.setEntry(java.lang.String, java.security.KeyStore$Entry, java.security.KeyStore$ProtectionParameter )")
// 		am_send(PROFILE_HOOKING_TYPE,"[Keystore.setEntry()]: alias: " + alias + ", entry: " + dumpKeyStoreEntry(entry) + "', protection: " + dumpProtectionParameter(protection));
// 		return this.setEntry(alias, entry, protection);
// 	}
// }

// function hookKeystoreSetKeyEntry() {
// 	var keyStoreSetKeyEntry = Java.use('java.security.KeyStore')['setKeyEntry'].overload("java.lang.String", "java.security.Key", "[C", "[Ljava.security.cert.Certificate;");
// 	keyStoreSetKeyEntry.implementation = function (alias, key, charArray, certs) {
// 		//am_send(PROFILE_HOOKING_TYPE,"[Call] Keystore.setKeyEntry(java.lang.String, java.security.Key, [C, [Ljava.security.cert.Certificate; )
// 		am_send(PROFILE_HOOKING_TYPE,"[Keystore.setKeyEntry()]: alias: " + alias + ", key: " + key + ", password: '" + charArrayToString(charArray) + "', certs: " + certs);
// 		return this.setKeyEntry(alias, key, charArray, certs);
// 	}
// }

// function hookKeystoreSetKeyEntry2() {
// 	var keyStoreSetKeyEntry = Java.use('java.security.KeyStore')['setKeyEntry'].overload("java.lang.String", "[B", "[Ljava.security.cert.Certificate;");
// 	keyStoreSetKeyEntry.implementation = function (alias, key, certs) {
// 		//am_send(PROFILE_HOOKING_TYPE,"[Call] Keystore.setKeyEntry(java.lang.String, [B, [Ljava.security.cert.Certificate; )")
// 		am_send(PROFILE_HOOKING_TYPE,"[Keystore.setKeyEntry2()]: alias: " + alias + ", key: " + key + "', certs: " + certs);
// 		return this.setKeyEntry(alias, key, certs);
// 	}
//}

function hookKeystoreSetKeyEntry(KeyStore: any): void {
    // fix: was raw am_send with string concatenation
    const setKeyEntry = safeOverload(
        KeyStore.setKeyEntry,
        "keystore:KeyStore.setKeyEntry",
        "java.lang.String", "java.security.Key", "[C", "[Ljava.security.cert.Certificate;"
    );
    if (!setKeyEntry) return;

    setKeyEntry.implementation = safeImplementation(
        "keystore:KeyStore.setKeyEntry[String,Key,char[],Certificate[]]",
        setKeyEntry,
        function(original, alias, key, charArray, certs) {
            let keyHex: string | null = null;
            if (key) {
                try {
                    // getEncoded() returns null for hardware-backed keys - caught silently
                    const encoded = key.getEncoded();
                    keyHex = encoded
                        ? bytesToHexSafe(Array.from(encoded) as number[])
                        : null;
                } catch (_) {}
            }
            createKeystoreEvent("crypto.keystore.set_key_entry", {
                method: "setKeyEntry(String, Key, char[], Certificate[])",
                alias: alias,
                key_class: key ? key.$className : null,
                key_algorithm: key ? key.getAlgorithm() : null,
                key_format: key ? key.getFormat() : null,
                key_hex: keyHex,
                password: charArrayToString(charArray),
                cert_count: certs ? certs.length : null
            });
            return original.call(this, alias, key, charArray, certs);
        }
    );
}

function hookKeystoreSetKeyEntry2(KeyStore: any): void {
    // fix: was raw am_send with string concatenation
    const setKeyEntry2 = safeOverload(
        KeyStore.setKeyEntry,
        "keystore:KeyStore.setKeyEntry2",
        "java.lang.String", "[B", "[Ljava.security.cert.Certificate;"
    );
    if (!setKeyEntry2) return;

    setKeyEntry2.implementation = safeImplementation(
        "keystore:KeyStore.setKeyEntry[String,byte[],Certificate[]]",
        setKeyEntry2,
        function(original, alias, key, certs) {
            createKeystoreEvent("crypto.keystore.set_key_entry", {
                method: "setKeyEntry(String, byte[], Certificate[])",
                alias: alias,
                // Array.from converts the Java byte array proxy for hex encoding
                key_hex: key ? bytesToHexSafe(Array.from(key) as number[]) : null,
                cert_count: certs ? certs.length : null
            });
            return original.call(this, alias, key, certs);
        }
    );
}

/*
 * Usually used to load certs for cert pinning.
 */
function hookKeystoreGetCertificate(KeyStore: any): void {
    // fix: was raw am_send with string concatenation
    const getCertificate = safeOverload(
        KeyStore.getCertificate,
        "keystore:KeyStore.getCertificate",
        "java.lang.String"
    );
    if (!getCertificate) return;

    getCertificate.implementation = safeImplementation(
        "keystore:KeyStore.getCertificate",
        getCertificate,
        function(original, alias: string) {
            createKeystoreEvent("crypto.keystore.get_certificate", {
                alias: alias
            });
            return original.call(this, alias);
        }
    );
}

/*
 * Usually used to load certs for cert pinning.
 */
function hookKeystoreGetCertificateChain(KeyStore: any): void {
    // fix: was raw am_send with string concatenation
    const getCertificateChain = safeOverload(
        KeyStore.getCertificateChain,
        "keystore:KeyStore.getCertificateChain",
        "java.lang.String"
    );
    if (!getCertificateChain) return;

    getCertificateChain.implementation = safeImplementation(
        "keystore:KeyStore.getCertificateChain",
        getCertificateChain,
        function(original, alias) {
            createKeystoreEvent("crypto.keystore.get_certificate_chain", {
                method: "getCertificateChain(String)",
                alias: alias
            });
            return original.call(this, alias);
        }
    );
}

function hookKeystoreGetEntry(KeyStore: any): void {
    // fix: was raw am_send with string concatenation
    const getEntry = safeOverload(
        KeyStore.getEntry,
        "keystore:KeyStore.getEntry",
        "java.lang.String", "java.security.KeyStore$ProtectionParameter"
    );
    if (!getEntry) return;

    getEntry.implementation = safeImplementation(
        "keystore:KeyStore.getEntry",
        getEntry,
        function(original, alias, protection) {
            createKeystoreEvent("crypto.keystore.get_entry", {
                method: "getEntry(String, KeyStore$ProtectionParameter)",
                alias: alias,
                protection: dumpProtectionParameter(protection)
            });
            const entry = original.call(this, alias, protection);
            createKeystoreEvent("crypto.keystore.get_entry_result", {
                alias: alias,
                entry: dumpKeyStoreEntry(entry)
            });
            return entry;
        }
    );
}

// --- Helper / dump functions --------------------------------------------------

// helper / dump functions

function dumpProtectionParameter(protection: any): any {
    if (protection == null) return null;
    const protectionCls = protection.$className;
    // Frida $className uses $ for inner classes - comparisons must match
    if (protectionCls.localeCompare("android.security.keystore.KeyProtection") == 0) {
        return { protection_class: protectionCls };
    } else if (protectionCls.localeCompare("java.security.KeyStore$CallbackHandlerProtection") == 0) {
        return { protection_class: protectionCls };
    } else if (protectionCls.localeCompare("java.security.KeyStore$PasswordProtection") == 0) {
        const getPasswordMethod = Java.use('java.security.KeyStore$PasswordProtection')['getPassword'];
        const password = getPasswordMethod.call(protection);
        return {
            protection_class: protectionCls,
            password: charArrayToString(password)
        };
    } else if (protectionCls.localeCompare("android.security.KeyStoreParameter") == 0) {
        const isEncryptionRequiredMethod = Java.use('android.security.KeyStoreParameter')['isEncryptionRequired'];
        const encryptionRequired = isEncryptionRequiredMethod.call(protection);
        return {
            protection_class: protectionCls,
            encryption_required: encryptionRequired
        };
    } else {
        return { protection_class: protectionCls };
    }
}

function dumpKeyStoreEntry(entry: any): any {
    if (entry == null) return null;
    const entryCls = entry.$className;
    const castedEntry = Java.cast(entry, Java.use(entryCls));
    if (entryCls.localeCompare("java.security.KeyStore$PrivateKeyEntry") == 0) {
        const key = Java.use('java.security.KeyStore$PrivateKeyEntry')['getPrivateKey'].call(castedEntry);
        return {
            entry_class: entryCls,
            key_class: key ? key.$className : null
        };
    } else if (entryCls.localeCompare("java.security.KeyStore$SecretKeyEntry") == 0) {
        const key = Java.use('java.security.KeyStore$SecretKeyEntry')['getSecretKey'].call(castedEntry);
        // hardware-backed AndroidKeyStore keys do not expose encoded bytes
        if (key.$className.localeCompare("android.security.keystore.AndroidKeyStoreSecretKey") == 0) {
            return {
                entry_class: entryCls,
                key_class: key.$className,
                key_hex: null
            };
        }
        const keyFormat = Java.use(key.$className)['getFormat'].call(key);
        const encodedBytes = Java.use(key.$className)['getEncoded'].call(key);
        return {
            entry_class: entryCls,
            key_class: key.$className,
            key_format: keyFormat ? keyFormat.toString() : null,
            key_hex: encodedBytes
                ? bytesToHexSafe(Array.from(encodedBytes) as number[])
                : null
        };
    } else if (entryCls.localeCompare("java.security.KeyStore$TrustedCertificateEntry") == 0) {
        return { entry_class: entryCls };
    } else if (entryCls.localeCompare("android.security.WrappedKeyEntry") == 0) {
        return { entry_class: entryCls };
    } else {
        return { entry_class: entryCls };
    }
}

// --- List of utility functions ---------------------------------------------------

/*
 * Dump all aliases in keystores of all types (predefined in keystoreTypes)
 */
function ListAliasesStatic() {
    const keystoreTypes = ["AndroidKeyStore", "AndroidCAStore", "BKS", "BouncyCastle", "PKCS12"];
    keystoreTypes.forEach(function(entry) {
        createKeystoreEvent("crypto.keystore.aliases_static", {
            keystore_type: entry,
            aliases: ListAliasesType(entry)
        });
    });
    return "[done]";
}

/*
 * Dump all aliases in keystores of all instances obtained during app runtime.
 * Instances that will be dumped are collected via hijacking Keystore.getInstance()
 */
function ListAliasesRuntime() {
    safePerform("keystore:ListAliasesRuntime", () => {
        devlog("[ListAliasesRuntime] Instances: " + keystoreList);
        keystoreList.forEach(function(entry) {
            createKeystoreEvent("crypto.keystore.aliases_runtime", {
                keystore_obj: entry.toString(),
                keystore_type: entry.getType(),
                aliases: ListAliasesObj(entry)
            });
        });
    });
    return "[done]";
}

/*
 * Dump all aliases in AndroidKey keystore.
 */
function ListAliasesAndroid() {
    return ListAliasesType("AndroidKeyStore");
}

/*
 * Dump all aliases in keystore of given 'type'.
 * Example: ListAliasesType('AndroidKeyStore');
 */
function ListAliasesType(type) {
    const result: any[] = [];
    safePerform("keystore:ListAliasesType", () => {
        const keyStoreCls = safeUse('java.security.KeyStore', "keystore:ListAliasesType");
        if (!keyStoreCls) return;
        const keyStoreObj = keyStoreCls.getInstance(type);
        keyStoreObj.load(null);
        var aliases = keyStoreObj.aliases();
        while (aliases.hasMoreElements()) {
            result.push("'" + aliases.nextElement() + "'");
        }
    });
    return result;
}

/*
 * Dump all aliases for a given keystore object.
 * Example: ListAliasesObj(keystoreObj);
 */
function ListAliasesObj(obj) {
    const result: any[] = [];
    try {
        var aliases = obj.aliases();
        while (aliases.hasMoreElements()) {
            result.push(aliases.nextElement() + "");
        }
    } catch (e) {
        devlog(`[HOOK ERROR] keystore:ListAliasesObj: ${e}`);
    }
    return result;
}

/*
 * Retrieve keystore instance from keystoreList
 * Example: GetKeyStore("KeyStore...@af102a");
 */
function GetKeyStore(keystoreName) {
    var result = null;
    for (var i = 0; i < keystoreList.length; i++) {
        if (keystoreName.localeCompare("" + keystoreList[i]) == 0)
            result = keystoreList[i];
    }
    return result;
}

/* TAG: tagged for removal or relocation to dedicated general helpers/utils after re-evaluation */
/* following function reads an InputStream and returns an ASCII char representation of it */
function readStreamToHex(stream) {
    var data = [];
    var byteRead = stream.read();
    while (byteRead != -1) {
        data.push(('0' + (byteRead & 0xFF).toString(16)).slice(-2));
        byteRead = stream.read();
    }
    stream.close();
    return data.join('');
}

/*  needs to be fixed

/*
* Dump keystore key properties in JSON object
* Example: AliasInfo('secret');
*
function AliasInfo(keyAlias) {
	var result = {};
	Java.perform(function () {
		var keyStoreCls = Java.use('java.security.KeyStore');
		var keyFactoryCls = Java.use('java.security.KeyFactory');
		var keyInfoCls = Java.use('android.security.keystore.KeyInfo');
		var keySecretKeyFactoryCls = Java.use('javax.crypto.SecretKeyFactory');
		var keyFactoryObj = null;

		var keyStoreObj = keyStoreCls.getInstance('AndroidKeyStore');
		keyStoreObj.load(null);
		var key = keyStoreObj.getKey(keyAlias, null);
		if (key == null) {
			am_send(PROFILE_HOOKING_TYPE,'key does not exist');
			return null;
		}
		try {
			keyFactoryObj = keyFactoryCls.getInstance(key.getAlgorithm(), 'AndroidKeyStore');
		} catch (err) {
			keyFactoryObj = keySecretKeyFactoryCls.getInstance(key.getAlgorithm(), 'AndroidKeyStore');
		}
		var keyInfo = keyFactoryObj.getKeySpec(key, keyInfoCls.class);
		result.keyAlgorithm = key.getAlgorithm();
		result.keySize = keyInfoCls['getKeySize'].call(keyInfo);
		result.blockModes = keyInfoCls['getBlockModes'].call(keyInfo);
		result.digests = keyInfoCls['getDigests'].call(keyInfo);
		result.encryptionPaddings = keyInfoCls['getEncryptionPaddings'].call(keyInfo);
		result.keyValidityForConsumptionEnd = keyInfoCls['getKeyValidityForConsumptionEnd'].call(keyInfo);
		if (result.keyValidityForConsumptionEnd != null) result.keyValidityForConsumptionEnd = result.keyValidityForConsumptionEnd.toString();
		result.keyValidityForOriginationEnd = keyInfoCls['getKeyValidityForOriginationEnd'].call(keyInfo);
		if (result.keyValidityForOriginationEnd != null) result.keyValidityForOriginationEnd = result.keyValidityForOriginationEnd.toString();
		result.keyValidityStart = keyInfoCls['getKeyValidityStart'].call(keyInfo);
		if (result.keyValidityStart != null) result.keyValidityStart = result.keyValidityStart.toString();
		result.keystoreAlias = keyInfoCls['getKeystoreAlias'].call(keyInfo);
		result.origin = keyInfoCls['getOrigin'].call(keyInfo);
		result.purposes = keyInfoCls['getPurposes'].call(keyInfo);
		result.signaturePaddings = keyInfoCls['getSignaturePaddings'].call(keyInfo);
		result.userAuthenticationValidityDurationSeconds = keyInfoCls['getUserAuthenticationValidityDurationSeconds'].call(keyInfo);
		result.isInsideSecureHardware = keyInfoCls['isInsideSecureHardware'].call(keyInfo);
		result.isInvalidatedByBiometricEnrollment = keyInfoCls['isInvalidatedByBiometricEnrollment'].call(keyInfo);
		try { result.isTrustedUserPresenceRequired = keyInfoCls['isTrustedUserPresenceRequired'].call(keyInfo); } catch (err) { }
		result.isUserAuthenticationRequired = keyInfoCls['isUserAuthenticationRequired'].call(keyInfo);
		result.isUserAuthenticationRequirementEnforcedBySecureHardware = keyInfoCls['isUserAuthenticationRequirementEnforcedBySecureHardware'].call(keyInfo);
		result.isUserAuthenticationValidWhileOnBody = keyInfoCls['isUserAuthenticationValidWhileOnBody'].call(keyInfo);
		try { result.isUserConfirmationRequired = keyInfoCls['isUserConfirmationRequired'].call(keyInfo); } catch (err) { }
		//am_send(PROFILE_HOOKING_TYPE," result: " + JSON.stringify(result));

		//am_send(PROFILE_HOOKING_TYPE,"aliases: " + aliases.getClass());


	});
	return result;
} */

// --- Install functions --------------------------------------------------------

function install_keystore_constructor_hooks(): void {
    devlog("Installing keystore constructor hooks");
    safePerform("keystore:install_keystore_constructor_hooks", () => {
        const KeyStore = safeUse('java.security.KeyStore', "keystore:install_keystore_constructor_hooks");
        if (!KeyStore) return;
        hookKeystoreConstructor(KeyStore);
        hookKeystoreGetInstance(KeyStore);
        hookKeystoreGetInstance_Provider(KeyStore);
        hookKeystoreGetInstance_Provider2(KeyStore);
    });
}

function install_keystore_load_hooks(): void {
    devlog("Installing keystore load/store hooks");
    safePerform("keystore:install_keystore_load_hooks", () => {
        const KeyStore = safeUse('java.security.KeyStore', "keystore:install_keystore_load_hooks");
        if (!KeyStore) return;
        hookKeystoreLoad(KeyStore, false);
        hookKeystoreLoadStream(KeyStore, false);
        hookKeystoreStore(KeyStore);
        hookKeystoreStoreStream(KeyStore);
    });
}

function install_keystore_access_hooks(): void {
    devlog("Installing keystore access hooks");
    safePerform("keystore:install_keystore_access_hooks", () => {
        const KeyStore = safeUse('java.security.KeyStore', "keystore:install_keystore_access_hooks");
        if (!KeyStore) return;
        hookKeystoreGetKey(KeyStore);
        hookKeystoreGetCertificate(KeyStore);
        hookKeystoreGetCertificateChain(KeyStore);
        hookKeystoreGetEntry(KeyStore);
        hookKeystoreSetEntry(KeyStore);
        hookKeystoreSetKeyEntry(KeyStore);
        hookKeystoreSetKeyEntry2(KeyStore);
    });
}

export function install_keystore_hooks(): void {
    devlog("\n");
    devlog("Installing keystore hooks");

    safePerform("keystore:init", () => {
        StringCls = safeUse('java.lang.String', "keystore:init");
    });

    try {
        install_keystore_constructor_hooks();
    } catch (error) {
        devlog(`[HOOK] Failed to install keystore constructor hooks: ${error}`);
    }

    try {
        install_keystore_load_hooks();
    } catch (error) {
        devlog(`[HOOK] Failed to install keystore load hooks: ${error}`);
    }

    try {
        install_keystore_access_hooks();
    } catch (error) {
        devlog(`[HOOK] Failed to install keystore access hooks: ${error}`);
    }
}

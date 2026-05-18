import { log, devlog, am_send } from "../utils/logging.js"
import { Where } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"
import { safePerform, safeUse, safeOverload } from "../utils/safe_java.js"

/**
 * https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security/blob/master/custom_scripts/Android/tracer_keystore.js
 */

const PROFILE_HOOKING_TYPE: string = "CRYPTO_KEYSTORE"

interface KeystoreEntry {
    alias: string;
    type?: string;
    entry?: any;
    protection?: any;
}

const keystoreList: any[] = [];
// was initialized at module load time via bare Java.perform
// now initialized inside install_keystore_hooks via safePerform
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
    return StringCls.$new(charArray);
}

function hookKeystoreConstructor(KeyStore: any): void {
    const ctor = safeOverload(
        KeyStore.$init,
        "keystore:KeyStore.$init",
        "java.security.KeyStoreSpi", "java.security.Provider", "java.lang.String"
    );
    if (!ctor) return;
    ctor.implementation = function(keyStoreSpi: any, provider: any, type: string) {
        createKeystoreEvent("crypto.keystore.constructor", {
            keystore_spi: keyStoreSpi ? keyStoreSpi.toString() : null,
            provider: provider ? provider.toString() : null,
            type: type
        });
        return this.$init(keyStoreSpi, provider, type);
    };
}

function hookKeystoreGetInstance(KeyStore: any): void {
    const getInstance = safeOverload(
        KeyStore.getInstance,
        "keystore:KeyStore.getInstance",
        "java.lang.String"
    );
    if (!getInstance) return;
    getInstance.implementation = function(type: string) {
        createKeystoreEvent("crypto.keystore.get_instance", {
            method: "getInstance(String)",
            type: type
        });
        const tmp = this.getInstance(type);
        keystoreList.push(tmp); // Collect keystore objects to allow dump them later using ListAliasesRuntime()
        return tmp;
    };
}

function hookKeystoreGetInstance_Provider(KeyStore: any): void {
    const getInstance = safeOverload(
        KeyStore.getInstance,
        "keystore:KeyStore.getInstance",
        "java.lang.String", "java.lang.String"
    );
    if (!getInstance) return;
    getInstance.implementation = function(type: string, provider: string) {
        createKeystoreEvent("crypto.keystore.get_instance", {
            method: "getInstance(String, String)",
            type: type,
            provider: provider
        });
        const tmp = this.getInstance(type, provider);
        keystoreList.push(tmp); // Collect keystore objects to allow dump them later using ListAliasesRuntime()
        return tmp;
    };
}

function hookKeystoreGetInstance_Provider2(KeyStore: any): void {
    const getInstance = safeOverload(
        KeyStore.getInstance,
        "keystore:KeyStore.getInstance",
        "java.lang.String", "java.security.Provider"
    );
    if (!getInstance) return;
    getInstance.implementation = function(type: string, provider: any) {
        createKeystoreEvent("crypto.keystore.get_instance", {
            method: "getInstance(String, Provider)",
            type: type,
            provider: provider ? provider.toString() : null
        });
        const tmp = this.getInstance(type, provider);
        keystoreList.push(tmp);
        return tmp;
    };
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
    load.implementation = function(param: any) {
        createKeystoreEvent("crypto.keystore.load", {
            method: "load(LoadStoreParameter)",
            keystore_type: this.getType(),
            parameter: param ? param.toString() : null
        });
        this.load(param);
        if (dump) {
            createKeystoreEvent("crypto.keystore.aliases", {
                keystore_type: this.getType(),
                aliases: ListAliasesObj(this)
            });
        }
    };
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
    loadStream.implementation = function(stream: any, charArray: any) {
        createKeystoreEvent("crypto.keystore.load", {
            method: "load(InputStream, char[])",
            keystore_type: this.getType(),
            password: charArrayToString(charArray),
            input_stream: stream ? stream.toString() : null
        });
        this.load(stream, charArray);
        if (dump) {
            createKeystoreEvent("crypto.keystore.aliases", {
                keystore_type: this.getType(),
                aliases: ListAliasesObj(this)
            });
        }
    };
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
    store.implementation = function(param) {
        createKeystoreEvent("crypto.keystore.store", {
            method: "store(LoadStoreParameter)",
            keystore_type: this.getType(),
            parameter: param ? param.toString() : null
        });
        this.store(param);
    };
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
    storeStream.implementation = function(stream, charArray) {
        createKeystoreEvent("crypto.keystore.store", {
            method: "store(OutputStream, char[])",
            keystore_type: this.getType(),
            password: charArrayToString(charArray),
            output_stream: stream ? stream.toString() : null
        });
        this.store(stream, charArray);
    };
}

function hookKeystoreGetKey(KeyStore: any): void {
    const getKey = safeOverload(
        KeyStore.getKey,
        "keystore:KeyStore.getKey",
        "java.lang.String", "[C"
    );
    if (!getKey) return;
    getKey.implementation = function(alias: string, charArray: any) {
        createKeystoreEvent("crypto.keystore.get_key", {
            alias: alias,
            password: charArrayToString(charArray)
        });
        return this.getKey(alias, charArray);
    };
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
    setEntry.implementation = function(alias, entry, protection) {
        createKeystoreEvent("crypto.keystore.set_entry", {
            method: "setEntry(String, KeyStore$Entry, KeyStore$ProtectionParameter)",
            alias: alias,
            entry: dumpKeyStoreEntry(entry),
            protection: dumpProtectionParameter(protection)
        });
        return this.setEntry(alias, entry, protection);
    };
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
    setKeyEntry.implementation = function(alias, key, charArray, certs) {
        createKeystoreEvent("crypto.keystore.set_key_entry", {
            method: "setKeyEntry(String, Key, char[], Certificate[])",
            alias: alias,
            key: key ? key.toString() : null,
            password: charArrayToString(charArray),
            certs: certs ? certs.toString() : null
        });
        return this.setKeyEntry(alias, key, charArray, certs);
    };
}

function hookKeystoreSetKeyEntry2(KeyStore: any): void {
    // fix: was raw am_send with string concatenation
    const setKeyEntry2 = safeOverload(
        KeyStore.setKeyEntry,
        "keystore:KeyStore.setKeyEntry2",
        "java.lang.String", "[B", "[Ljava.security.cert.Certificate;"
    );
    if (!setKeyEntry2) return;
    setKeyEntry2.implementation = function(alias, key, certs) {
        createKeystoreEvent("crypto.keystore.set_key_entry", {
            method: "setKeyEntry(String, byte[], Certificate[])",
            alias: alias,
            key: key ? key.toString() : null,
            certs: certs ? certs.toString() : null
        });
        return this.setKeyEntry(alias, key, certs);
    };
}

/*
* Usually used to load certs for cert pinning.
*/
function hookKeystoreGetCertificate(KeyStore: any): void {
    const getCertificate = safeOverload(
        KeyStore.getCertificate,
        "keystore:KeyStore.getCertificate",
        "java.lang.String"
    );
    if (!getCertificate) return;
    getCertificate.implementation = function(alias: string) {
        createKeystoreEvent("crypto.keystore.get_certificate", {
            alias: alias
        });
        return this.getCertificate(alias);
    };
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
    getCertificateChain.implementation = function(alias) {
        createKeystoreEvent("crypto.keystore.get_certificate_chain", {
            method: "getCertificateChain(String)",
            alias: alias
        });
        return this.getCertificateChain(alias);
    };
}

function hookKeystoreGetEntry(KeyStore: any): void {
    // fix: was raw am_send with string concatenation
    const getEntry = safeOverload(
        KeyStore.getEntry,
        "keystore:KeyStore.getEntry",
        "java.lang.String", "java.security.KeyStore$ProtectionParameter"
    );
    if (!getEntry) return;
    getEntry.implementation = function(alias, protection) {
        createKeystoreEvent("crypto.keystore.get_entry", {
            method: "getEntry(String, KeyStore$ProtectionParameter)",
            alias: alias,
            protection: dumpProtectionParameter(protection)
        });
        const entry = this.getEntry(alias, protection);
        createKeystoreEvent("crypto.keystore.get_entry_result", {
            alias: alias,
            entry: dumpKeyStoreEntry(entry)
        });
        return entry;
    };
}

// --- Helper / dump functions --------------------------------------------------
// These call Java.use directly — valid here because they are only called
// from within .implementation callbacks (already in Java.perform context).

function dumpProtectionParameter(protection) {
    if (protection != null) {
        var protectionCls = protection.$className;
        if (protectionCls.localeCompare("android.security.keystore.KeyProtection") == 0) {
            return "" + protectionCls + " [implement dumping if needed]";
        }
        else if (protectionCls.localeCompare("java.security.KeyStore.CallbackHandlerProtection") == 0) {
            return "" + protectionCls + " [implement dumping if needed]";
        }
        else if (protectionCls.localeCompare("java.security.KeyStore.PasswordProtection") == 0) {
            var getPasswordMethod = Java.use('java.security.KeyStore.PasswordProtection')['getPassword'];
            var password = getPasswordMethod.call(protection);
            return "password: " + charArrayToString(password);
        }
        else if (protectionCls.localeCompare("android.security.KeyStoreParameter") == 0) {
            var isEncryptionRequiredMethod = Java.use('android.security.KeyStoreParameter')['isEncryptionRequired'];
            var result = isEncryptionRequiredMethod.call(protection);
            return "isEncryptionRequired: " + result;
        }
        else
            return "Unknown protection parameter type: " + protectionCls;
    }
    else
        return "null";
}

function dumpKeyStoreEntry(entry) {
	// java.security.KeyStore$PrivateKeyEntry, java.security.KeyStore$SecretKeyEntry, java.security.KeyStore$TrustedCertificateEntry, android.security.WrappedKeyEntry 
    if (entry != null) {
        var entryCls = entry.$className;
        var castedEntry = Java.cast(entry, Java.use(entryCls));
        if (entryCls.localeCompare("java.security.KeyStore$PrivateKeyEntry") == 0) {
            var getPrivateKeyEntryMethod = Java.use('java.security.KeyStore$PrivateKeyEntry')['getPrivateKey'];
            var key = getPrivateKeyEntryMethod.call(castedEntry);
            return "" + entryCls + " [implement key dumping if needed] " + key.$className;
        }
        else if (entryCls.localeCompare("java.security.KeyStore$SecretKeyEntry") == 0) {
            var getSecretKeyMethod = Java.use('java.security.KeyStore$SecretKeyEntry')['getSecretKey'];
            var key = getSecretKeyMethod.call(castedEntry);
            var keyGetFormatMethod = Java.use(key.$className)['getFormat'];
            var keyGetEncodedMethod = Java.use(key.$className)['getEncoded'];
            if (key.$className.localeCompare("android.security.keystore.AndroidKeyStoreSecretKey") == 0)
                return "keyClass: android.security.keystore.AndroidKeyStoreSecretKey can't dump";
            return "keyFormat: " + keyGetFormatMethod.call(key) + ", encodedKey: '" + keyGetEncodedMethod.call(key) + "', key: " + key;
        }
        else if (entryCls.localeCompare("java.security.KeyStore$TrustedCertificateEntry") == 0) {
            return "" + entryCls + " [implement key dumping if needed]";
        }
        else if (entryCls.localeCompare("android.security.WrappedKeyEntry") == 0) {
            return "" + entryCls + " [implement key dumping if needed]";
        }
        else
            return "Unknown key entry type: " + entryCls;
    }
    else
        return "null";
}


// --- List utility functions ---------------------------------------------------

/*
* Dump all aliases in keystores of all types(predefined in keystoreTypes)	
*/
function ListAliasesStatic() {
	// BCPKCS12/PKCS12-DEF - exceptions: /*[]..., "BCPKCS12", "PKCS12-DEF", ...]*/
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
* Instances that will be dumped are collected via hijacking Keystre.getInstance() -> hookKeystoreGetInstance()
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
        // called from within .implementation callbacks => already in Java context
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

/* TAG: tagged for removal or relocation to dedicated general helpers/utils after reevaluation */
/* following function reads an InputStream and returns an ASCII char representation of it */
function readStreamToHex(stream) {
    var data = [];
    var byteRead = stream.read();
    while (byteRead != -1) {
        data.push(('0' + (byteRead & 0xFF).toString(16)).slice(-2));
		/* <---------------- binary to hex ---------------> */
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

    // fix: StringCls was initialized at module load time via bare Java.perform
    // now initialized here before any hook callbacks that depend on it
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

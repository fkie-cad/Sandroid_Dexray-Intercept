import { log, devlog, am_send } from "../utils/logging.js"
import { Where } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"
import { hook_config } from "../hooking_profile_loader.js"

const PROFILE_HOOKING_TYPE: string = "CRYPTO_KEYSTORE"
const HOOK_NAME = 'keystore_hooks'

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
let StringCls: any = null;

function createKeystoreEvent(eventType: string, data: any): void {
    // Check if hook is enabled at runtime
    if (!hook_config[HOOK_NAME]) {
        return;
    }
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

// Helper function to send messages with runtime check
function sendKeystoreMessage(message: string): void {
    if (!hook_config[HOOK_NAME]) {
        return;
    }
    am_send(PROFILE_HOOKING_TYPE, message);
}

Java.perform(() => {
    StringCls = Java.use('java.lang.String');
});

function hookKeystoreConstructor(): void {
    const keyStoreConstructor = Java.use('java.security.KeyStore').$init.overload("java.security.KeyStoreSpi", "java.security.Provider", "java.lang.String");
    keyStoreConstructor.implementation = function (keyStoreSpi: any, provider: any, type: string) {
        createKeystoreEvent("crypto.keystore.constructor", {
            keystore_spi: keyStoreSpi ? keyStoreSpi.toString() : null,
            provider: provider ? provider.toString() : null,
            type: type
        });
        return this.$init(keyStoreSpi, provider, type);
    };
}

function hookKeystoreGetInstance(): void {
    const keyStoreGetInstance = Java.use('java.security.KeyStore')['getInstance'].overload("java.lang.String");
    keyStoreGetInstance.implementation = function (type: string) {
        createKeystoreEvent("crypto.keystore.get_instance", {
            method: "getInstance(String)",
            type: type
        });
        const tmp = this.getInstance(type);
        keystoreList.push(tmp); // Collect keystore objects to allow dump them later using ListAliasesRuntime()
        return tmp;
    };
}

function hookKeystoreGetInstance_Provider(): void {
    const keyStoreGetInstance = Java.use('java.security.KeyStore')['getInstance'].overload("java.lang.String", "java.lang.String");
    keyStoreGetInstance.implementation = function (type: string, provider: string) {
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

function hookKeystoreGetInstance_Provider2(): void {
    const keyStoreGetInstance = Java.use('java.security.KeyStore')['getInstance'].overload("java.lang.String", "java.security.Provider");
    keyStoreGetInstance.implementation = function (type: string, provider: any) {
        createKeystoreEvent("crypto.keystore.get_instance", {
            method: "getInstance(String, Provider)",
            type: type,
            provider: provider ? provider.toString() : null
        });
        const tmp = this.getInstance(type, provider);
        keystoreList.push(tmp); // Collect keystore objects to allow dump them later using ListAliasesRuntime()
        return tmp;
    };
}

/*
* Hook Keystore.load( ... ), set dump to true if you want to perform dump of available Aliases automatically.	
*/
function hookKeystoreLoad(dump: boolean): void {
    const keyStoreLoad = Java.use('java.security.KeyStore')['load'].overload('java.security.KeyStore$LoadStoreParameter');
    /* following function hooks to a Keystore.load(java.security.KeyStore.LoadStoreParameter) */
    keyStoreLoad.implementation = function (param: any) {
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
function hookKeystoreLoadStream(dump: boolean): void {
    const keyStoreLoadStream = Java.use('java.security.KeyStore')['load'].overload('java.io.InputStream', '[C');
    /* following function hooks to a Keystore.load(InputStream stream, char[] password) */
    keyStoreLoadStream.implementation = function (stream: any, charArray: any) {
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

function hookKeystoreStore() {
	var keyStoreStoreStream = Java.use('java.security.KeyStore')['store'].overload('java.security.KeyStore$LoadStoreParameter');
	/* following function hooks to a Keystore.store(java.security.KeyStore$LoadStoreParameter) */
	keyStoreStoreStream.implementation = function (param) {
		sendKeystoreMessage("[Keystore.store()]: keystoreType: " + this.getType() + ", param: '" + param);
		this.store(param);
	}
}

function hookKeystoreStoreStream() {
	var keyStoreStoreStream = Java.use('java.security.KeyStore')['store'].overload('java.io.OutputStream', '[C');
	/* following function hooks to a Keystore.store(OutputStream stream, char[] password) */
	keyStoreStoreStream.implementation = function (stream, charArray) {
		sendKeystoreMessage("[Keystore.store(OutputStream, char[])]: keystoreType: " + this.getType() + ", password: '" + charArrayToString(charArray) + "', outputSteam: " + stream);
		this.store(stream, charArray);
	}
}

function hookKeystoreGetKey(): void {
    const keyStoreGetKey = Java.use('java.security.KeyStore')['getKey'].overload("java.lang.String", "[C");
    keyStoreGetKey.implementation = function (alias: string, charArray: any) {
        createKeystoreEvent("crypto.keystore.get_key", {
            alias: alias,
            password: charArrayToString(charArray)
        });
        return this.getKey(alias, charArray);
    };
}

function hookKeystoreSetEntry() {
	var keyStoreSetKeyEntry = Java.use('java.security.KeyStore')['setEntry'].overload("java.lang.String", "java.security.KeyStore$Entry", "java.security.KeyStore$ProtectionParameter");
	keyStoreSetKeyEntry.implementation = function (alias, entry, protection) {
		sendKeystoreMessage("[Keystore.setEntry()]: alias: " + alias + ", entry: " + dumpKeyStoreEntry(entry) + "', protection: " + dumpProtectionParameter(protection));
		return this.setEntry(alias, entry, protection);
	}
}

function hookKeystoreSetKeyEntry() {
	var keyStoreSetKeyEntry = Java.use('java.security.KeyStore')['setKeyEntry'].overload("java.lang.String", "java.security.Key", "[C", "[Ljava.security.cert.Certificate;");
	keyStoreSetKeyEntry.implementation = function (alias, key, charArray, certs) {
		sendKeystoreMessage("[Keystore.setKeyEntry()]: alias: " + alias + ", key: " + key + ", password: '" + charArrayToString(charArray) + "', certs: " + certs);
		return this.setKeyEntry(alias, key, charArray, certs);
	}
}

function hookKeystoreSetKeyEntry2() {
	var keyStoreSetKeyEntry = Java.use('java.security.KeyStore')['setKeyEntry'].overload("java.lang.String", "[B", "[Ljava.security.cert.Certificate;");
	keyStoreSetKeyEntry.implementation = function (alias, key, certs) {
		sendKeystoreMessage("[Keystore.setKeyEntry2()]: alias: " + alias + ", key: " + key + "', certs: " + certs);
		return this.setKeyEntry(alias, key, certs);
	}
}

/*
* Usually used to load certs for cert pinning.
*/
function hookKeystoreGetCertificate(): void {
    const keyStoreGetCertificate = Java.use('java.security.KeyStore')['getCertificate'].overload("java.lang.String");
    keyStoreGetCertificate.implementation = function (alias: string) {
        createKeystoreEvent("crypto.keystore.get_certificate", {
            alias: alias
        });
        return this.getCertificate(alias);
    };
}

/*
* Usually used to load certs for cert pinning.
*/
function hookKeystoreGetCertificateChain() {
	var keyStoreGetCertificate = Java.use('java.security.KeyStore')['getCertificateChain'].overload("java.lang.String");
	keyStoreGetCertificate.implementation = function (alias) {
		sendKeystoreMessage("[Keystore.getCertificateChain()]: alias: " + alias);
		return this.getCertificateChain(alias);
	}
}

function hookKeystoreGetEntry() {
	var keyStoreGetEntry = Java.use('java.security.KeyStore')['getEntry'].overload("java.lang.String", "java.security.KeyStore$ProtectionParameter");
	keyStoreGetEntry.implementation = function (alias, protection) {
		sendKeystoreMessage("[Keystore.getEntry()]: alias: " + alias + ", protection: '" + dumpProtectionParameter(protection) + "'");
		var entry = this.getEntry(alias, protection);
		sendKeystoreMessage("[getEntry()]: Entry: " + dumpKeyStoreEntry(entry));
		return entry;
	}
}

function dumpProtectionParameter(protection) {
	if (protection != null) {
		// android.security.keystore.KeyProtection, java.security.KeyStore.CallbackHandlerProtection, java.security.KeyStore.PasswordProtection, android.security.KeyStoreParameter 
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
			//am_send(PROFILE_HOOKING_TYPE,""+key.$className);
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

/*
* Dump all aliasses in keystores of all types(predefined in keystoreTypes)
*/
function ListAliasesStatic() {
	// BCPKCS12/PKCS12-DEF - exceptions
	var keystoreTypes = ["AndroidKeyStore", "AndroidCAStore", /*"BCPKCS12",*/ "BKS", "BouncyCastle", "PKCS12", /*"PKCS12-DEF"*/];
	keystoreTypes.forEach(function (entry) {
		sendKeystoreMessage("[ListAliasesStatic] keystoreType: " + entry + " \nAliases: " + ListAliasesType(entry));
	});
	return "[done]";
}

/*
* Dump all aliasses in keystores of all instances obtained during app runtime.
* Instances that will be dumped are collected via hijacking Keystre.getInstance() -> hookKeystoreGetInstance()
*/
function ListAliasesRuntime() {
	Java.perform(function () {
		sendKeystoreMessage("[ListAliasesRuntime] Instances: " + keystoreList);
		keystoreList.forEach(function (entry) {
			sendKeystoreMessage("[ListAliasesRuntime] keystoreObj: " + entry + " type: " + entry.getType() + " \n" + ListAliasesObj(entry));
		});
	});
	return "[done]";
}

/*
* Dump all aliasses in AndroidKey keystore. 
*/
function ListAliasesAndroid() {
	return ListAliasesType("AndroidKeyStore");
}     

/*
* Dump all aliasses in keystore of given 'type'. 
* Example: ListAliasesType('AndroidKeyStore');
*/
function ListAliasesType(type) {
	var result = [];
	Java.perform(function () {
		var keyStoreCls = Java.use('java.security.KeyStore');
		var keyStoreObj = keyStoreCls.getInstance(type);
		keyStoreObj.load(null);
		var aliases = keyStoreObj.aliases();
		//am_send(PROFILE_HOOKING_TYPE,"aliases: " + aliases.getClass());
		while (aliases.hasMoreElements()) {
			result.push("'" + aliases.nextElement() + "'");
		}
	});
	return result;
}

/*
* Dump all aliasses for a given keystore object. 
* Example: ListAliasesObj(keystoreObj);
*/
function ListAliasesObj(obj) {
	var result = [];
	Java.perform(function () {
		var aliases = obj.aliases();
		while (aliases.hasMoreElements()) {
			result.push(aliases.nextElement() + "");
		}
	});
	return result;
}

/*
* Retrieve keystore instance from keystoreList
* Example: GetKeyStore("KeyStore...@af102a");
*/
function GetKeyStore(keystoreName) {
	var result = null;
	Java.perform(function () {
		for (var i = 0; i < keystoreList.length; i++) {
			if (keystoreName.localeCompare("" + keystoreList[i]) == 0)
				result = keystoreList[i];
		}
	});
	return result;
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

function charArrayToString(charArray: any): string {
    if (charArray == null)
        return '(null)';
    else
        return StringCls.$new(charArray);
}

function install_keystore_constructor_hooks(): void {
    devlog("Installing keystore constructor hooks");
    Java.perform(() => {
        hookKeystoreConstructor();
        hookKeystoreGetInstance();
        hookKeystoreGetInstance_Provider();
        hookKeystoreGetInstance_Provider2();
    });
}

function install_keystore_load_hooks(): void {
    devlog("Installing keystore load/store hooks");
    Java.perform(() => {
        hookKeystoreLoad(false);
        hookKeystoreLoadStream(false);
        hookKeystoreStore();
        hookKeystoreStoreStream();
    });
}

function install_keystore_access_hooks(): void {
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




export function install_keystore_hooks(): void {
    devlog("\n");
    devlog("Installing keystore hooks");

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


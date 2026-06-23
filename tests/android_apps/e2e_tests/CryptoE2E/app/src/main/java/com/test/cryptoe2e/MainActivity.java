package com.test.cryptoe2e;

import android.app.Activity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreSpi;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends Activity {

    private static final String TAG = "CRYPTO_E2E";

    private static class SimpleLoadStoreParameter implements LoadStoreParameter {
        private final ProtectionParameter protection;

        SimpleLoadStoreParameter(char[] password) {
            this.protection = new PasswordProtection(password);
        }

        @Override
        public ProtectionParameter getProtectionParameter() {
            return protection;
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.i(TAG, "CryptoE2E started");

        try {
            try {
                runAesTests();
            } catch (Throwable t) {
                Log.e(TAG, "runAesTests failed", t);
            }

            try {
                runBase64Tests();
            } catch (Throwable t) {
                Log.e(TAG, "runBase64Tests failed", t);
            }

            try {
                runKeystoreTests();
            } catch (Throwable t) {
                Log.e(TAG, "runKeystoreTests failed", t);
            }

        } catch (Throwable t) {
            Log.e(TAG, "Error in CryptoE2E", t);
        } finally {
            Log.i(TAG, "CryptoE2E finished");
            finish();
        }
    }

    // ------------------------------------------------------------
    // 1) AES tests (AesE2E)  -> aes.ts
    // ------------------------------------------------------------

    private void runAesTests() {
        Log.i(TAG, "runAesTests started");

        try {
            // Base key material
            byte[] fullKey = new byte[16];
            new SecureRandom().nextBytes(fullKey);

            // 1) SecretKeySpec(byte[], String) ->
            //    aes.ts: SecretKeySpec.$init[byte[],String]
            //    -> PROFILE_HOOKING_TYPE="CRYPTO_AES", event_type="crypto.key.creation"
            SecretKeySpec keyFull = new SecretKeySpec(fullKey, "AES");

            // 2) SecretKeySpec(byte[], int, int, String) ->
            //    aes.ts: SecretKeySpec.$init[byte[],int,int,String]
            //    -> event_type="crypto.key.creation"
            //    (hook currently logs "not a function"; constructor is still executed)
            SecretKeySpec keyPartial = new SecretKeySpec(fullKey, 0, 16, "AES");

            // 3) IvParameterSpec(byte[]) ->
            //    aes.ts: IvParameterSpec.$init[byte[]]
            //    -> event_type="crypto.iv.creation"
            byte[] ivBytes = new byte[16];
            new SecureRandom().nextBytes(ivBytes);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

            String plaintext = "Hello AES E2E!";
            byte[] plainBytes = plaintext.getBytes("UTF-8");

            // ---------- AES/CBC: update + doFinal() ----------

            // 4) Cipher.getInstance("AES/CBC/PKCS5Padding") + init(ENCRYPT_MODE, Key, AlgorithmParameterSpec) ->
            //    aes.ts: Cipher.init[int,Key,AlgorithmParameterSpec]
            //    -> registers cipher session with key + opmode
            Cipher cipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipherEnc.init(Cipher.ENCRYPT_MODE, keyFull, ivSpec);

            // 5) update(byte[], int, int) ->
            //    aes.ts: Cipher.update[1] (overload with [B,int,int)
            //    -> event_type="crypto.cipher.update"
            byte[] encPart = cipherEnc.update(plainBytes, 0, plainBytes.length);

            // 6) doFinal() (no-arg) ->
            //    aes.ts: Cipher.doFinal[0] (no-arg overload)
            //    -> event_type="crypto.cipher.operation" (CBC encrypt)
            byte[] encFinal = cipherEnc.doFinal();
            Log.i(TAG, "CBC encrypt: part=" + (encPart != null ? encPart.length : 0)
                    + ", final=" + encFinal.length);

            // Reassemble ciphertext
            byte[] ciphertext;
            if (encPart != null && encPart.length > 0) {
                ciphertext = new byte[encPart.length + encFinal.length];
                System.arraycopy(encPart, 0, ciphertext, 0, encPart.length);
                System.arraycopy(encFinal, 0, ciphertext, encPart.length, encFinal.length);
            } else {
                ciphertext = encFinal;
            }

            // 7) Cipher.getInstance("AES/CBC/PKCS5Padding") + init(DECRYPT_MODE, Key, AlgorithmParameterSpec)
            //    + doFinal(byte[]) ->
            //    aes.ts: Cipher.init[int,Key,AlgorithmParameterSpec] + Cipher.doFinal[byte[]]
            //    -> event_type="crypto.cipher.operation" with plaintext derived from output_hex
            Cipher cipherDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipherDec.init(Cipher.DECRYPT_MODE, keyPartial, ivSpec);
            byte[] decBytes = cipherDec.doFinal(ciphertext);
            String recovered = new String(decBytes, "UTF-8");
            Log.i(TAG, "CBC recovered: " + recovered);

            // ---------- AES/ECB: init(int, Key) + all update variants ----------

            // 8) init(ENCRYPT_MODE, Key) (no params) ->
            //    aes.ts: Cipher.init[int,Key]
            //    -> session registration for AES/ECB
            Cipher cipherECB = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipherECB.init(Cipher.ENCRYPT_MODE, keyFull);

            // 9) update(byte[]) ->
            //    aes.ts: Cipher.update[0] (overload with [B)
            //    -> event_type="crypto.cipher.update"
            byte[] ecbUpdate1 = cipherECB.update(plainBytes);
            Log.i(TAG, "ECB update(byte[]): " + (ecbUpdate1 != null ? ecbUpdate1.length : 0));

            // 10) update(byte[], int, int, byte[]) ->
            //     aes.ts: Cipher.update[2] (overload with [B,int,int,[B)
            //     -> event_type="crypto.cipher.update"
            byte[] outBuf1 = new byte[64];
            int outLen1 = cipherECB.update(plainBytes, 0, plainBytes.length, outBuf1);
            Log.i(TAG, "ECB update(byte[],int,int,byte[]): " + outLen1);

            // 11) update(byte[], int, int, byte[], int) ->
            //     aes.ts: Cipher.update[3] (overload with [B,int,int,[B,int)
            //     -> event_type="crypto.cipher.update"
            byte[] outBuf2 = new byte[64];
            int outLen2 = cipherECB.update(plainBytes, 0, plainBytes.length, outBuf2, 0);
            Log.i(TAG, "ECB update(byte[],int,int,byte[],int): " + outLen2);

            // ---------- Additional doFinal variants (AES/ECB) ----------

            Cipher cipherVar = Cipher.getInstance("AES/ECB/PKCS5Padding");

            // 12) doFinal(byte[], int, int) ->
            //     aes.ts: Cipher.doFinal[2] (overload with [B,int,int)
            //     -> event_type="crypto.cipher.operation"
            cipherVar.init(Cipher.ENCRYPT_MODE, keyFull);
            byte[] outA = cipherVar.doFinal(plainBytes, 0, plainBytes.length);
            Log.i(TAG, "doFinal(byte[],int,int): " + outA.length);

            // 13) doFinal(byte[], int, int, byte[]) ->
            //     aes.ts: Cipher.doFinal[3] (overload with [B,int,int,[B)
            //     -> event_type="crypto.cipher.operation"
            cipherVar.init(Cipher.ENCRYPT_MODE, keyFull);
            byte[] outBuf3 = new byte[64];
            int outLen3 = cipherVar.doFinal(plainBytes, 0, plainBytes.length, outBuf3);
            Log.i(TAG, "doFinal(byte[],int,int,byte[]): " + outLen3);

            // 14) doFinal(byte[], int, int, byte[], int) ->
            //     aes.ts: Cipher.doFinal[4] (overload with [B,int,int,[B,int)
            //     -> event_type="crypto.cipher.operation"
            cipherVar.init(Cipher.ENCRYPT_MODE, keyFull);
            byte[] outBuf4 = new byte[64];
            int outLen4 = cipherVar.doFinal(plainBytes, 0, plainBytes.length, outBuf4, 0);
            Log.i(TAG, "doFinal(byte[],int,int,byte[],int): " + outLen4);

            Log.i(TAG, "runAesTests completed");

        } catch (Throwable t) {
            Log.e(TAG, "Error in runAesTests", t);
        }
    }

    // ------------------------------------------------------------
    // 2) Base64 tests (CryptoBase64E2E) -> encodings.ts
    // ------------------------------------------------------------

    private void runBase64Tests() {
        Log.i(TAG, "runBase64Tests started");

        try {
            String inputString = "Hello Base64 E2E!";
            byte[] inputBytes = inputString.getBytes("UTF-8");

            // 1) decode(String, int) ->
            //    encodings.ts: Base64.decode(String,int)
            //    -> PROFILE_HOOKING_TYPE="CRYPTO_ENCODING", event_type="crypto.base64.decode"
            String encoded = Base64.encodeToString(inputBytes, Base64.NO_WRAP);
            byte[] decoded1 = Base64.decode(encoded, Base64.NO_WRAP);
            Log.i(TAG, "decode(String,int) -> " + new String(decoded1, "UTF-8"));

            // 2) decode(byte[], int) ->
            //    encodings.ts: Base64.decode(byte[],int)
            //    -> event_type="crypto.base64.decode"
            byte[] encodedBytes = Base64.encode(inputBytes, Base64.NO_WRAP);
            byte[] decoded2 = Base64.decode(encodedBytes, Base64.NO_WRAP);
            Log.i(TAG, "decode(byte[],int) -> " + new String(decoded2, "UTF-8"));

            // 3) decode(byte[], int, int, int) ->
            //    encodings.ts: Base64.decode(byte[],int,int,int)
            //    -> event_type="crypto.base64.decode"
            //    (hook currently logs "not a function"; call is still executed)
            byte[] encodedBytes2 = Base64.encode(inputBytes, Base64.NO_WRAP);
            byte[] decoded3 = Base64.decode(encodedBytes2, 0, encodedBytes2.length, Base64.NO_WRAP);
            Log.i(TAG, "decode(byte[],int,int,int) -> " + new String(decoded3, "UTF-8"));

            // 4) encode(byte[], int) ->
            //    encodings.ts: Base64.encode(byte[],int)
            //    -> event_type="crypto.base64.encode"
            byte[] enc1 = Base64.encode(inputBytes, Base64.NO_WRAP);
            Log.i(TAG, "encode(byte[],int) length: " + enc1.length);

            // 5) encode(byte[], int, int, int) ->
            //    encodings.ts: Base64.encode(byte[],int,int,int)
            //    -> event_type="crypto.base64.encode"
            //    (hook currently logs "not a function"; call is still executed)
            byte[] enc2 = Base64.encode(inputBytes, 0, inputBytes.length, Base64.NO_WRAP);
            Log.i(TAG, "encode(byte[],int,int,int) length: " + enc2.length);

            // 6) encodeToString(byte[], int) ->
            //    encodings.ts: Base64.encodeToString(byte[],int)
            //    -> event_type="crypto.base64.encode_to_string"
            String encStr1 = Base64.encodeToString(inputBytes, Base64.NO_WRAP);
            Log.i(TAG, "encodeToString(byte[],int): " + encStr1);

            // 7) encodeToString(byte[], int, int, int) ->
            //    encodings.ts: Base64.encodeToString(byte[],int,int,int)
            //    -> event_type="crypto.base64.encode_to_string"
            //    (hook currently logs "not a function"; call is still executed)
            String encStr2 = Base64.encodeToString(inputBytes, 0, inputBytes.length, Base64.NO_WRAP);
            Log.i(TAG, "encodeToString(byte[],int,int,int): " + encStr2);

            Log.i(TAG, "runBase64Tests completed");

        } catch (Throwable t) {
            Log.e(TAG, "Error in runBase64Tests", t);
        }
    }

    // ------------------------------------------------------------
    // 3) Keystore tests (KeystoreE2E) -> keystore.ts
    // ------------------------------------------------------------

    private void runKeystoreTests() {
        Log.i(TAG, "runKeystoreTests started");

        try {
            // -------- Legacy / JCA BKS keystore tests (exercise current hooks) --------

            // 1) Select a keystore type
            String defaultType = KeyStore.getDefaultType(); // often "BKS"
            Log.i(TAG, "Default KeyStore type: " + defaultType);

            // 2) Select a provider that supports this type (e.g., BC for BKS on this runtime)
            Provider[] providers = Security.getProviders();
            Provider providerForType = null;
            if (providers != null) {
                for (Provider p : providers) {
                    if (p.getService("KeyStore", defaultType) != null) {
                        providerForType = p;
                        break;
                    }
                }
            }
            Provider provider = providerForType;
            String providerName = provider != null ? provider.getName() : null;
            Log.i(TAG, "Provider for type " + defaultType + ": " + providerName);

            // 3) getInstance(String) ->
            //    keystore.ts: KeyStore.getInstance[String]
            //    -> event_type="crypto.keystore.get_instance" + "crypto.keystore.constructor"
            KeyStore ksTypeOnly = null;
            try {
                ksTypeOnly = KeyStore.getInstance(defaultType);
                Log.i(TAG, "KeyStore.getInstance(String) OK: " + ksTypeOnly.getType());
            } catch (Throwable t) {
                Log.e(TAG, "getInstance(String) failed", t);
            }

            // 4) getInstance(String, String) with a matching provider ->
            //    keystore.ts: KeyStore.getInstance[String,String]
            //    -> event_type="crypto.keystore.get_instance"
            KeyStore ksTypeProvName = null;
            if (providerName != null) {
                try {
                    ksTypeProvName = KeyStore.getInstance(defaultType, providerName);
                    Log.i(TAG, "KeyStore.getInstance(String,String) OK: " + ksTypeProvName.getType());
                } catch (Throwable t) {
                    Log.e(TAG, "getInstance(String,String) failed", t);
                }
            }

            // 5) getInstance(String, Provider) with a matching provider ->
            //    keystore.ts: KeyStore.getInstance[String,Provider]
            //    -> event_type="crypto.keystore.get_instance"
            KeyStore ksTypeProv = null;
            if (provider != null) {
                try {
                    ksTypeProv = KeyStore.getInstance(defaultType, provider);
                    Log.i(TAG, "KeyStore.getInstance(String,Provider) OK: " + ksTypeProv.getType());
                } catch (Throwable t) {
                    Log.e(TAG, "getInstance(String,Provider) failed", t);
                }
            }

            // Choose one instance for BKS-style operations; prefer ksTypeOnly
            KeyStore ks = ksTypeOnly != null ? ksTypeOnly :
                          (ksTypeProvName != null ? ksTypeProvName : ksTypeProv);
            if (ks == null) {
                Log.e(TAG, "No usable BKS KeyStore instance, aborting BKS tests");
            } else {
                // 6) load(InputStream, char[]) ->
                //    keystore.ts: KeyStore.load[InputStream,char[]]
                //    -> event_type="crypto.keystore.load"
                try {
                    char[] storePassword = "storepass".toCharArray();
                    InputStream is = null; // null -> initialize empty keystore
                    ks.load(is, storePassword);
                    Log.i(TAG, "load(InputStream,char[]) OK");
                } catch (Throwable t) {
                    Log.e(TAG, "load(InputStream,char[]) failed", t);
                }

                // 7) load(LoadStoreParameter) ->
                //    keystore.ts: KeyStore.load[LoadStoreParameter]
                //    -> event_type="crypto.keystore.load"
                //    (may throw UnsupportedOperationException on this runtime)
                try {
                    char[] lspPassword = "lspass".toCharArray();
                    LoadStoreParameter lsp = new SimpleLoadStoreParameter(lspPassword);
                    ks.load(lsp);
                    Log.i(TAG, "load(LoadStoreParameter) OK");
                } catch (UnsupportedOperationException uoe) {
                    Log.w(TAG, "load(LoadStoreParameter) unsupported for keystore type " + ks.getType());
                } catch (Throwable t) {
                    Log.e(TAG, "load(LoadStoreParameter) failed", t);
                }

                // 8) Generate a SecretKey for entries
                SecretKey secretKey = null;
                try {
                    KeyGenerator kg = KeyGenerator.getInstance("AES");
                    kg.init(128);
                    secretKey = kg.generateKey();
                    Log.i(TAG, "Generated SecretKey: " + (secretKey != null ? secretKey.getAlgorithm() : "null"));
                } catch (Throwable t) {
                    Log.e(TAG, "SecretKey generation failed", t);
                }

                // 9) setEntry(String, Entry, ProtectionParameter) ->
                //    keystore.ts: KeyStore.setEntry
                //    -> event_type="crypto.keystore.set_entry"
                PasswordProtection entryProt = new PasswordProtection("entrypass".toCharArray());
                try {
                    if (secretKey != null) {
                        SecretKeyEntry skEntry = new SecretKeyEntry(secretKey);
                        ks.setEntry("alias_entry", skEntry, entryProt);
                        Log.i(TAG, "setEntry(...) OK");
                    }
                } catch (Throwable t) {
                    Log.e(TAG, "setEntry(...) failed", t);
                }

                // 10) getEntry(String, ProtectionParameter) ->
                //     keystore.ts: KeyStore.getEntry
                //     -> event_type="crypto.keystore.get_entry" + "crypto.keystore.get_entry_result"
                try {
                    KeyStore.Entry entry = ks.getEntry("alias_entry", entryProt);
                    Log.i(TAG, "getEntry(...) result: " +
                            (entry != null ? entry.getClass().getName() : "null"));
                } catch (Throwable t) {
                    Log.e(TAG, "getEntry(...) failed", t);
                }

                // 11) getKey(String, char[]) ->
                //     keystore.ts: KeyStore.getKey
                //     -> event_type="crypto.keystore.get_key"
                try {
                    java.security.Key key = ks.getKey("alias_entry", "entrypass".toCharArray());
                    Log.i(TAG, "getKey(...) result: " +
                            (key != null ? key.getAlgorithm() : "null"));
                } catch (Throwable t) {
                    Log.e(TAG, "getKey(...) failed", t);
                }

                // 12) getCertificate(String) and getCertificateChain(String) ->
                //     keystore.ts: getCertificate / getCertificateChain
                try {
                    java.security.cert.Certificate cert = ks.getCertificate("alias_entry");
                    Log.i(TAG, "getCertificate(...) result: " +
                            (cert != null ? cert.getType() : "null"));
                } catch (Throwable t) {
                    Log.e(TAG, "getCertificate(...) failed", t);
                }

                try {
                    java.security.cert.Certificate[] chain =
                            ks.getCertificateChain("alias_entry");
                    Log.i(TAG, "getCertificateChain(...) result: " +
                            (chain != null ? chain.length : 0));
                } catch (Throwable t) {
                    Log.e(TAG, "getCertificateChain(...) failed", t);
                }

                // 13) setKeyEntry(String, Key, char[], Certificate[]) ->
                //     keystore.ts: KeyStore.setKeyEntry[String,Key,char[],Certificate[]]
                //     -> event_type="crypto.keystore.set_key_entry"
                try {
                    if (secretKey != null) {
                        ks.setKeyEntry("alias_key", secretKey, "entrypass".toCharArray(), null);
                        Log.i(TAG, "setKeyEntry(String,Key,char[],Certificate[]) OK");
                    }
                } catch (Throwable t) {
                    Log.e(TAG, "setKeyEntry(String,Key,...) failed", t);
                }

                // 14) setKeyEntry(String, byte[], Certificate[]) ->
                //     keystore.ts: KeyStore.setKeyEntry[String,byte[],Certificate[]]
                //     -> event_type="crypto.keystore.set_key_entry"
                try {
                    if (secretKey != null && secretKey.getEncoded() != null) {
                        byte[] encodedKey = secretKey.getEncoded();
                        ks.setKeyEntry("alias_key_bytes", encodedKey, null);
                        Log.i(TAG, "setKeyEntry(String,byte[],Certificate[]) OK");
                    }
                } catch (Throwable t) {
                    Log.e(TAG, "setKeyEntry(String,byte[],...) failed", t);
                }

                // 15) store(OutputStream, char[]) ->
                //     keystore.ts: KeyStore.store[OutputStream,char[]]
                //     -> event_type="crypto.keystore.store"
                try {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    ks.store(baos, "storepass".toCharArray());
                    Log.i(TAG, "store(OutputStream,char[]) OK, size=" + baos.toByteArray().length);
                } catch (Throwable t) {
                    Log.e(TAG, "store(OutputStream,char[]) failed", t);
                }

                // 16) store(LoadStoreParameter) ->
                //     keystore.ts: KeyStore.store[LoadStoreParameter]
                //     -> event_type="crypto.keystore.store"
                //     (may throw UnsupportedOperationException on this runtime)
                try {
                    LoadStoreParameter lspStore =
                            new SimpleLoadStoreParameter("storepass".toCharArray());
                    ks.store(lspStore);
                    Log.i(TAG, "store(LoadStoreParameter) OK");
                } catch (UnsupportedOperationException uoe) {
                    Log.w(TAG, "store(LoadStoreParameter) unsupported for keystore type " + ks.getType());
                } catch (Throwable t) {
                    Log.e(TAG, "store(LoadStoreParameter) failed", t);
                }
            }

            // -------- Additional AndroidKeyStore tests (future hook development) --------

            try {
                runAndroidKeyStoreTests();
            } catch (Throwable t) {
                Log.e(TAG, "runAndroidKeyStoreTests failed", t);
            }

            try {
                runLoadStoreParameterSupportSurvey();
            } catch (Throwable t) {
                Log.e(TAG, "runLoadStoreParameterSupportSurvey failed", t);
            }

            Log.i(TAG, "runKeystoreTests completed");

        } catch (Throwable t) {
            Log.e(TAG, "Error in runKeystoreTests", t);
        }
    }

    // Additional AndroidKeyStore tests
    // These use correct types/provider combinations on this runtime and are intended
    // as future hook targets (AndroidKeyStore + KeyGenParameterSpec).
    private void runAndroidKeyStoreTests() {
        Log.i(TAG, "runAndroidKeyStoreTests (AndroidKeyStore) started");

        try {
            // 1) KeyStore.getInstance("AndroidKeyStore") ->
            //    keystore.ts: KeyStore.getInstance[String]
            //    -> event_type="crypto.keystore.get_instance" (type="AndroidKeyStore")
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            Log.i(TAG, "AndroidKeyStore.getInstance(String) OK: " + ks.getType());

            // 2) Provider-based getInstance for AndroidKeyStore (if provider is available) ->
            //    keystore.ts: KeyStore.getInstance[String,String] and [String,Provider]
            Provider androidKsProv = Security.getProvider("AndroidKeyStore");
            if (androidKsProv != null) {
                try {
                    KeyStore ksByName =
                            KeyStore.getInstance("AndroidKeyStore", "AndroidKeyStore");
                    Log.i(TAG, "AndroidKeyStore.getInstance(String,String) OK: " +
                            ksByName.getType());
                } catch (Throwable t) {
                    Log.e(TAG, "AndroidKeyStore getInstance(String,String) failed", t);
                }

                try {
                    KeyStore ksByProv =
                            KeyStore.getInstance("AndroidKeyStore", androidKsProv);
                    Log.i(TAG, "AndroidKeyStore.getInstance(String,Provider) OK: " +
                            ksByProv.getType());
                } catch (Throwable t) {
                    Log.e(TAG, "AndroidKeyStore getInstance(String,Provider) failed", t);
                }
            }

            // 3) load(null) – correct AndroidKeyStore pattern (not currently hooked explicitly)
            ks.load(null);
            Log.i(TAG, "AndroidKeyStore.load(null) OK");

            // 4) Generate an AES key inside AndroidKeyStore ->
            //    future hooks may instrument KeyGenParameterSpec / AndroidKeyStoreSecretKey
            KeyGenerator kg = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    "alias_android_aes",
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build();
            kg.init(spec);
            SecretKey androidKey = kg.generateKey();
            Log.i(TAG, "AndroidKeyStore SecretKey generated: " +
                    (androidKey != null ? androidKey.getAlgorithm() : "null"));

            // 5) getKey on AndroidKeyStore alias ->
            //    keystore.ts: KeyStore.getKey (future hook coverage for AndroidKeyStore)
            try {
                java.security.Key key = ks.getKey("alias_android_aes", null);
                Log.i(TAG, "AndroidKeyStore.getKey(...) result: " +
                        (key != null ? key.getAlgorithm() : "null"));
            } catch (Throwable t) {
                Log.e(TAG, "AndroidKeyStore.getKey(...) failed", t);
            }

            // 6) getCertificate / getCertificateChain on AndroidKeyStore alias
            //    (usually null/empty for symmetric keys, but useful for future hooks)
            try {
                java.security.cert.Certificate cert =
                        ks.getCertificate("alias_android_aes");
                Log.i(TAG, "AndroidKeyStore.getCertificate(...) result: " +
                        (cert != null ? cert.getType() : "null"));
            } catch (Throwable t) {
                Log.e(TAG, "AndroidKeyStore.getCertificate(...) failed", t);
            }

            try {
                java.security.cert.Certificate[] chain =
                        ks.getCertificateChain("alias_android_aes");
                Log.i(TAG, "AndroidKeyStore.getCertificateChain(...) result: " +
                        (chain != null ? chain.length : 0));
            } catch (Throwable t) {
                Log.e(TAG, "AndroidKeyStore.getCertificateChain(...) failed", t);
            }

            Log.i(TAG, "runAndroidKeyStoreTests completed");

        } catch (Throwable t) {
            Log.e(TAG, "Error in runAndroidKeyStoreTests", t);
        }
    }

    private void runLoadStoreParameterSupportSurvey() {
        Log.i(TAG, "runLoadStoreParameterSupportSurvey");
        try {
            Provider[] providers = Security.getProviders();
            if (providers == null || providers.length == 0) {
                Log.w(TAG, "No security providers available for survey");
                return;
            }

            for (Provider provider : providers) {
                for (Provider.Service service : provider.getServices()) {
                    if (!"KeyStore".equalsIgnoreCase(service.getType())) {
                        continue;
                    }
                    String type = service.getAlgorithm();
                    try {
                        KeyStore ks = KeyStore.getInstance(type, provider);
                        KeyStoreSpi spi = extractKeyStoreSpi(ks);
                        if (spi == null) {
                            Log.i(TAG, "Survey: type=" + type + " provider=" + provider.getName()
                                    + " spi not accessible");
                            continue;
                        }
                        Class<?> spiClass = spi.getClass();
                        boolean loadSupported = overridesEngineLoadStoreParameter(spiClass);
                        boolean storeSupported = overridesEngineStoreStoreParameter(spiClass);
                        if (loadSupported || storeSupported) {
                            Log.i(TAG, "Survey: type=" + type + " provider=" + provider.getName()
                                    + " LoadStoreParameter override load=" + loadSupported
                                    + " store=" + storeSupported);
                        }
                    } catch (Throwable t) {
                        Log.w(TAG, "Survey error for type=" + type + " provider=" + provider.getName(), t);
                    }
                }
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runLoadStoreParameterSupportSurvey", t);
        }
    }

    private KeyStoreSpi extractKeyStoreSpi(KeyStore ks) {
        if (ks == null) {
            return null;
        }
        try {
            Class<?> cls = ks.getClass();
            while (cls != null && cls != Object.class) {
                Field[] fields = cls.getDeclaredFields();
                for (Field field : fields) {
                    field.setAccessible(true);
                    Object value = field.get(ks);
                    if (value instanceof KeyStoreSpi) {
                        return (KeyStoreSpi) value;
                    }
                }
                cls = cls.getSuperclass();
            }
        } catch (Throwable t) {
            Log.w(TAG, "extractKeyStoreSpi failed", t);
        }
        return null;
    }

    private boolean overridesEngineLoadStoreParameter(Class<?> spiClass) {
        try {
            Method m = spiClass.getMethod("engineLoad", LoadStoreParameter.class);
            return m.getDeclaringClass() != KeyStoreSpi.class;
        } catch (NoSuchMethodException e) {
            return false;
        }
    }

    private boolean overridesEngineStoreStoreParameter(Class<?> spiClass) {
        try {
            Method m = spiClass.getMethod("engineStore", LoadStoreParameter.class);
            return m.getDeclaringClass() != KeyStoreSpi.class;
        } catch (NoSuchMethodException e) {
            return false;
        }
    }

}
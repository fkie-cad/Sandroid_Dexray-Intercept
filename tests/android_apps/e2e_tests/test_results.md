# Coverage tests for current hooks

## Introduction and Setup

1. This document contains a summary of the current test results after testing the current state of hooks in `agent/*`
against the test app corpus `tests/android_apps/e2e_tests/*`

2. Each category of hooks was tested against:
    * an app containing triggers for each possible hook across the category, e.g. `agents/network/*` hooks were tested against
    `tests/android_apps/e2e_tests/NetworkE2E`, which is the source for the test app `com.test.networke2e`
    * in general: test hooks from category `<category>` against app `com.test.categorye2e` from `tests/android_apps/e2e_tests/CategoryE2E`
    * to repeat test:
      1. build app: `./gradlew assembleDebug`
      2. install app: `adb install -r app/build/outputs/apk/debug/app-debug.apk`
      3. optionally check if the app runs as intended unhooked:
      ```
      adb shell am start -n com.test.category/.MainActivity
      adb logcat -v color threadtime -s CATEGORY_TAG1:'*' -s CATEGORY_TAG2:'*' -s CATEGORY_TAG3:'*' 
      ```
      where `CATEGORY_TAGn` are the tags defined in the Java / native code for the app and used for filtering the logs
      
      4. run app with hooks activated: `dexray-intercept -s -v --enable-catory com.test.categorye2e`
      5. check adb logs, cli output and the generated `profile_com.test.categorye2e_YYYY-MM-DD_hh-mm-ss.json`


## Services Hooks - E2E Test Results

### Test app
`tests/android_apps/e2e_tests/ServicesE2E`

### Hook files
- `agent/services/bluetooth.ts`
- `agent/services/camera.ts`
- `agent/services/clipboard.ts`
- `agent/services/location.ts`
- `agent/services/telephony.ts`

### Logcat tags
- `SERVICES_E2E` - MainActivity and all non-clipboard tests
- `SERVICES_CLIPBOARD` - ClipboardTestActivity

---

### Test environment

#### Recommended emulator
AVD (API 30 / 34, Google APIs x86_64) with netsim enabled

#### Launch command
- `nohup emulator -avd <avd_name> -packet-streamer-endpoint default -no-snapshot > /dev/null 2>&1 &`
- `adb shell cmd bluetooth_manager enable && adb shell settings get global bluetooth_on`

#### Required permissions (grant after every fresh install)
```
adb shell pm grant com.test.servicese2e android.permission.ACCESS_FINE_LOCATION 
adb shell pm grant com.test.servicese2e android.permission.ACCESS_COARSE_LOCATION
adb shell pm grant com.test.servicese2e android.permission.CAMERA
adb shell pm grant com.test.servicese2e android.permission.SEND_SMS
adb shell pm grant com.test.servicese2e android.permission.READ_PHONE_STATE
adb shell pm grant com.test.servicese2e android.permission.READ_SMS
adb shell pm grant com.test.servicese2e android.permission.READ_PHONE_NUMBERS
adb shell appops set com.test.servicese2e READ_PHONE_STATE allow
adb shell pm grant com.test.servicese2e android.permission.BLUETOOTH_CONNECT
adb shell pm grant com.test.servicese2e android.permission.BLUETOOTH_SCAN
```

#### BT-1 prerequisite - Bumble GATT server
BT-1 (`BluetoothGatt.readCharacteristic`) requires a virtual BLE peer. Start before running the app:
`python3 tests/android_apps/e2e_tests/ServicesE2E/bumble_gatt_server.py`

Expected output: `GATT server advertising at F0:F1:F2:F3:F4:F5`

#### Hook run command
`dexray-intercept -s -v --hooks-services com.test.servicese2e`

#### Baseline run command
```
adb shell am start -n com.test.servicese2e/.MainActivity
adb logcat -v threadtime -s SERVICES_E2E:'*' -s SERVICES_CLIPBOARD:'*'
```

---

### Baseline results (no hooks)

All sections run to completion. Expected warnings documented below.

| Section | Result | Notes |
|---------|--------|-------|
| runBluetoothTests | pass | connectGatt requires bumble server; times out without it |
| runClipboardTests | pass | getPrimaryClip returns null without window focus; handled by ClipboardTestActivity |
| runLocationTests | pass | |
| runSmsTests | pass | |
| runDeviceInfoTests | partial | getSubscriberId/getDeviceId/getImei blocked by carrier privilege on API 29+; expected |
| runWifiAndBluetoothInfoTests | pass | |
| runSystemPropertiesTests | pass | |
| runContentResolverTests | pass | |
| runSettingsSecureTests | pass | |
| runCameraTests | pass | Legacy Camera.open() skipped on emulator; Camera2 tested |
| ClipboardTestActivity | pass | getPrimaryClip item count 1 confirmed |

---

### Hook coverage matrix

#### bluetooth.ts

| Hook ID | Hook site | Event type | Observed | Key fields | Notes |
|---------|-----------|-----------|----------|-----------|-------|
| BT-1 | BluetoothGatt.readCharacteristic | bluetooth.gatt.read_characteristic | yes | characteristic_uuid | Requires bumble GATT server via netsim; returns false without real peer; confirmed on test_API34 |
| BT-2 | BluetoothGattCharacteristic.setValue([B) | bluetooth.gatt.set_characteristic_value | yes | characteristic_uuid, value_hex | Correct |
| BT-3 | BluetoothAdapter.getDefaultAdapter | bluetooth.adapter.get_default | yes | adapter_available missing | adapter_available field emitted by hook but not in ServiceEvent model - dropped by parser |
| BT-4 | BluetoothAdapter.enable | bluetooth.adapter.enable | yes | success: true | Correct |
| BT-5 | BluetoothAdapter.disable | bluetooth.adapter.disable | no | - | Hook install error: direct .implementation on ambiguous overload; disable() gained .overload('boolean') on API 33+; aborts hook_bluetooth() at this line, preventing BT-6 and BT-7 installation |
| BT-6 | BluetoothAdapter.startDiscovery | bluetooth.adapter.start_discovery | no | - | Hook never installed - execution aborted at BT-5 |
| BT-7 | BluetoothDevice.createBond | bluetooth.device.create_bond | no | - | Hook never installed - execution aborted at BT-5 |

#### camera.ts

| Hook ID | Hook site | Event type | Observed | Key fields | Notes |
|---------|-----------|-----------|----------|-----------|-------|
| CAM-1 | Camera.open() | camera.legacy.open | yes (real hardware / rooted emulator only) | camera_id: "default", success: true | Skipped on standard emulator due to native HAL crash; testable on real hardware or rooted API 30 emulator |
| CAM-2 | Camera.open(int) | camera.legacy.open | yes (real hardware / rooted emulator only) | camera_id: 0, success: true | Same as CAM-1 |
| CAM-3 | CameraManager.openCamera | camera.camera2.open | yes | camera_id | has_callback and has_handler fields emitted by hook but not in ServiceEvent model - dropped |
| CAM-4 | CameraManager.getCameraIdList | camera.camera2.get_camera_list | yes | camera_count | camera_ids array emitted by hook but not in ServiceEvent model - dropped |

#### clipboard.ts

| Hook ID | Hook site | Event type | Observed | Key fields | Notes |
|---------|-----------|-----------|----------|-----------|-------|
| CL-1 | ClipboardManager.setPrimaryClip | clipboard.set_primary_clip | yes | content_type, content | Correct |
| CL-2 | ClipboardManager.getPrimaryClip | clipboard.get_primary_clip | yes | item_count: 1 | Requires ClipboardTestActivity with window focus; item_count 0 without focus under Theme.NoDisplay |

#### location.ts

| Hook ID | Hook site | Event type | Observed | Key fields | Notes |
|---------|-----------|-----------|----------|-----------|-------|
| LOC-1 | LocationManager.getLastKnownLocation(String) | location.last_known_location | yes (x2) | provider, latitude, longitude, accuracy, has_location | GPS returns location; NETWORK returns has_location: false on emulator |
| LOC-2 | LocationManager.requestLocationUpdates (4-arg) | location.request_updates | yes | provider: gps | min_time_ms, min_distance_m, has_listener emitted by hook but not in ServiceEvent model - dropped |
| LOC-3 | LocationManager.requestLocationUpdates (5-arg with Looper) | location.request_updates | yes | provider: network | has_looper also dropped by parser |
| LOC-4 | Location.getLatitude | location.get_latitude | yes (x2) | latitude | Fires on getLastKnownLocation result and on direct Location object call |
| LOC-5 | Location.getLongitude | location.get_longitude | yes (x2) | longitude | Same as LOC-4 |
| LOC-6 | FusedLocationProviderClient.getLastLocation | location.fused_provider.get_last_location | no | - | No HOOK ERROR; GMS class resolution silently fails on test_API34; hook target may differ by GMS build |

#### telephony.ts

| Hook ID | Hook site | Event type | Observed | Key fields | Notes |
|---------|-----------|-----------|----------|-----------|-------|
| TEL-1 | SmsManager.sendTextMessage | telephony.sms.send_text | yes | destination_address, message_text | Correct |
| TEL-2 | SmsManager.sendMultipartTextMessage | telephony.sms.send_multipart | yes | destination_address | message_parts array emitted but not in ServiceEvent model - dropped |
| TEL-3 | SystemProperties.get(String) | telephony.system_properties.get | yes | property_key, property_value | Also fires on system init properties; test-triggered ro.build.version.release confirmed |
| TEL-4 | Build.* via Object.defineProperty | telephony.build.get_property | no | - | Hook is non-functional: Object.defineProperty on Frida JS wrapper does not intercept JVM getstatic bytecode; test app reads Build.MODEL/DEVICE/PRODUCT correctly but hook never fires |
| TEL-5 | TelephonyManager.getLine1Number | telephony.manager.get_phone_number | yes | phone_number | Correct; requires READ_SMS or READ_PHONE_NUMBERS on API 30+ |
| TEL-6 | TelephonyManager.getSubscriberId | telephony.manager.get_imsi | no | - | HOOK ERROR: SecurityException; hook calls original before emitting event so exception prevents emission; carrier privilege required on API 29+; hooks functional on real hardware with carrier apps |
| TEL-7 | TelephonyManager.getDeviceId | telephony.manager.get_device_id | no | - | Same as TEL-6 |
| TEL-8 | TelephonyManager.getImei | telephony.manager.get_imei | no | - | Same as TEL-6 |
| TEL-9 | TelephonyManager.getSimOperator | telephony.manager.get_sim_operator | yes | event_type only | sim_operator field emitted by hook but not in ServiceEvent model - dropped |
| TEL-10 | BluetoothAdapter.getAddress | telephony.bluetooth.get_address | yes | event_type only | mac_address field emitted but not mapped in ServiceParser - dropped; hook is in telephony.ts not bluetooth.ts - only captured when telephony_hooks enabled |
| TEL-11 | WifiInfo.getMacAddress | telephony.wifi.get_mac_address | yes | event_type only | mac_address field dropped by parser |
| TEL-12 | WifiInfo.getSSID | telephony.wifi.get_ssid | yes | event_type only | ssid field dropped by parser |
| TEL-13 | WifiInfo.getBSSID | telephony.wifi.get_bssid | yes | event_type only | bssid field dropped by parser |
| TEL-14 | ContentResolver.query (Bundle overload) | telephony.content_resolver.query_gsf | yes | event_type only | uri and action fields dropped by parser |
| TEL-15 | ContentResolver.query (5-arg String overload) | telephony.content_resolver.query | yes | event_type only | Re-entrancy: hook calls Java.use(...).getContentResolver().query() instead of original.call(); re-enters the hooked method; generates duplicate events; uri, has_result dropped |
| TEL-16 | ContentResolver.query (6-arg + CancellationSignal) | telephony.content_resolver.query | yes | event_type only | uri field dropped |
| TEL-17 | Settings$Secure.getString | telephony.secure_settings.get_string | yes | event_type only | query and value fields emitted but not in ServiceEvent model - dropped |

---

### Known issues

#### Hook-side bugs

| ID | File | Description | Impact |
|----|------|-------------|--------|
| S-2 | telephony.ts | Object.defineProperty on Frida JS wrapper does not intercept JVM getstatic; telephony.build.get_property events never emitted | TEL-4 completely non-functional |
| S-3 | telephony.ts | 5-arg ContentResolver.query hook body calls Java.use(...).getContentResolver().query() instead of original.call(); re-enters the hooked method; produces duplicate events | Noise in results; potential stack overflow risk on recursive content providers |
| S-5 | telephony.ts | BluetoothAdapter.getAddress hooked in telephony.ts under hook_device_infos(); event emitted as telephony.bluetooth.get_address; only captured when telephony_hooks enabled; missing from bluetooth category | Wrong category; users enabling only bluetooth_hooks will not see address reads |
| S-6 | camera.ts | CameraManager.openCamera only hooks (String, StateCallback, Handler) overload; API 28+ executor overload (String, Executor, StateCallback) not covered | Partial coverage on API 28+ |
| S-10 | bluetooth.ts | BluetoothAdapter.disable uses direct .implementation on ambiguous overload; fails on API 33+ where disable() has two overloads; aborts hook_bluetooth() body, preventing startDiscovery and createBond from being installed | BT-5, BT-6, BT-7 never installed on API 33+ |
| S-11 | all services hooks | Multiple direct .implementation assignments without safeOverload guard; fragile when methods gain overloads in newer API levels; affects enable, startDiscovery, createBond, ClipboardManager methods, Location methods, CameraManager.getCameraIdList, WifiInfo methods, TelephonyManager no-arg methods, Settings$Secure.getString | Latent fragility across all services hooks |
| S-12 | telephony.ts | getSubscriberId, getDeviceId, getImei hooks call original before emitting event; SecurityException from original prevents event emission; the attempt is not recorded | No event emitted on permission-denied calls; forensic gap for apps that attempt restricted identifier access |

#### Parser and model issues

| ID | Location | Description |
|----|---------|-------------|
| S-8 | ServiceParser, ServiceEvent | mac_address field from telephony.bluetooth.get_address and WifiInfo hooks not mapped; silently dropped |
| S-9 | ServiceParser, ServiceEvent | adapter_available from bluetooth.adapter.get_default not in ServiceEvent model; dropped |
| Parser-1 | ServiceParser | No catch-all metadata mapping; fields not explicitly listed in field_mapping are silently dropped; affected fields: ssid, bssid, sim_operator, query, value, message_parts, min_time_ms, min_distance_m, has_listener, has_looper, uri, has_result, action, camera_ids, has_callback, has_handler, kill_apps |
| Parser-2 | ServiceParser, ServiceEvent | API 33+ disable(boolean) emits kill_apps field; not mapped in ServiceParser or ServiceEvent |
| Parser-3 | ServiceParser | telephony.build.* event types have no parser branch; moot until S-2 is fixed |

#### Test environment limitations

| Note | Detail |
|------|--------|
| BT-1 emulator | Requires netsim + bumble GATT server on test_API34 or higher; connectGatt returns null on non-rooted emulators without netsim |
| BT-1 hooks under Frida | connectGatt returns null on rooted API 30 emulator when Frida is attached; Frida instrumentation affects BT stack timing; use test_API34 with netsim for BT-1 hook testing |
| TEL-6/7/8 emulator | getSubscriberId, getDeviceId, getImei require carrier privilege; blocked on all standard emulators regardless of root; hooks functional on real hardware with carrier-privileged apps or on Android API 28 and below where READ_PHONE_STATE alone is sufficient |
| TEL-6/7/8 API 28 | On API 28 emulator (google_apis image) READ_PHONE_STATE alone is sufficient; creating test_API28 AVD will confirm hooks emit correctly |
| LOC-6 emulator | FusedLocationProviderClient.getLastLocation hook not firing on test_API34; GMS class may differ from hook target class; requires investigation |
| CAM-1/2 emulator | Legacy Camera.open() causes native HAL SIGSEGV on standard emulators; test app skips on emulator detection; testable on real hardware; on rooted API 30 emulator Camera.open() works but Frida hook fires before native crash |
| Clipboard | getPrimaryClip returns null from non-focused windows on API 29+; resolved by ClipboardTestActivity with Theme.Translucent.NoTitleBar |
| Native HAL | Frida JNI tracing agent could intercept Camera.open() at native HAL level as an alternative to hardware testing; not yet implemented; see also Interceptor.attach / safeReplace options on HAL .so symbols |

---

### Summary

| Category | Total hooks | Observed and emitting | Hook errors | Not emitting (environment) | Non-functional hook |
|----------|-------------|----------------------|-------------|---------------------------|-------------------|
| Bluetooth | 7 | 3 (BT-1 to BT-4 minus BT-3 adapter_available) | 1 (BT-5 aborts chain) | 0 | 3 (BT-5/6/7) |
| Camera | 4 | 4 (CAM-1/2 on real hardware only) | 0 | 0 | 0 |
| Clipboard | 2 | 2 | 0 | 0 | 0 |
| Location | 6 | 5 | 0 | 1 (LOC-6 GMS) | 0 |
| Telephony | 17 | 10 | 3 (TEL-6/7/8 carrier privilege) | 0 | 1 (TEL-4 Build.*) |
| **Total** | **36** | **24** | **4** | **1** | **4** |


## Crypto Hooks - E2E Test Results

### Test app
`tests/android_apps/e2e_tests/CryptoE2E`  
Package: `com.test.cryptoe2e`  
Logcat tag: `CRYPTO_E2E`

### Hook files
- `agent/crypto/aes.ts`
- `agent/crypto/encodings.ts`
- `agent/crypto/keystore.ts`

### Hook groups and profile types
- AES hooks -> `CRYPTO_AES`
- Encodings (Base64) hooks -> `CRYPTO_ENCODING`
- Keystore hooks -> `CRYPTO_KEYSTORE`

### Run commands

#### Baseline (no hooks)

```bash
cd tests/android_apps/e2e_tests/CryptoE2E
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk

adb shell am force-stop com.test.cryptoe2e
adb shell am start -n com.test.cryptoe2e/.MainActivity

adb logcat -v threadtime -s CRYPTO_E2E:'*'
```

#### With hooks
```
dexray-intercept -s -v --hooks-crypto com.test.cryptoe2e
adb logcat -v threadtime -s CRYPTO_E2E:'*'
```

#### Runtime results (with hooks)

- App behavior
  - CryptoE2E completes all sections as in baseline; no crashes or behavioral changes.

- AES (`CRYPTO_AES`)
  - Events observed: `crypto.key.creation`, `crypto.iv.creation`, `crypto.cipher.update`, `crypto.cipher.operation` for AES/CBC, AES/ECB, and keystore-internal PBE operations.
  - Hook issues:
    - `SecretKeySpec(byte[], int, int, String)` hook fails to install (`[HOOK ERROR] ... not a function`).
    - A dead hook entry targets non-existent `Cipher.doFinal(byte[], int)` (never installs, no events).

- Base64 (`CRYPTO_ENCODING`)
  - Events observed: `crypto.base64.encode`, `crypto.base64.encode_to_string`, `crypto.base64.decode` for 2-argument encode/decode overloads.
  - Hook issues:
    - 4-argument overload hooks (`encode/decode/encodeToString(byte[], int, int, int)`) fail to install (`[HOOK ERROR] ... not a function`), so those sites have no events.
    - Flags schema is inconsistent: encode uses `flags`, decode uses `flag` (values still present in metadata).

- Keystore (`CRYPTO_KEYSTORE`)
  - Events observed: `crypto.keystore.get_instance`, `crypto.keystore.constructor`, `crypto.keystore.load`, `crypto.keystore.store`, `crypto.keystore.set_entry`, `crypto.keystore.get_entry`, `crypto.keystore.get_entry_result`, `crypto.keystore.get_key`, `crypto.keystore.get_certificate`, `crypto.keystore.get_certificate_chain`, `crypto.keystore.set_key_entry` for BKS and AndroidKeyStore.
  - Hook issues:
    - `load/store(LoadStoreParameter)` on BKS always throw `UnsupportedOperationException`; hooks emit events and log `[HOOK ERROR]`, app logs these as “unsupported”.
    - Several metadata fields (`password`, `key`, `parameter`) are emitted as unstructured stringified Java objects rather than normalized values.


### Hook coverage matrix

#### AES hooks (`aes.ts`)

| Hook ID | Hook site                                       | Event type(s)             | Exercised by app | Emitting events     | Notes                                                                 |
|--------:|-------------------------------------------------|---------------------------|------------------|---------------------|-----------------------------------------------------------------------|
| AES-1   | `SecretKeySpec.<init>(byte[], String)`          | `crypto.key.creation`     | yes              | yes                 | AES key creation for AES/CBC and AES/ECB                              |
| AES-2   | `SecretKeySpec.<init>(byte[], int, int, String)`| `crypto.key.creation`     | yes              | no (hook ERROR)     | Overload exists and is called; hook fails to install (`not a function`) |
| AES-3   | `IvParameterSpec.<init>(byte[])`                | `crypto.iv.creation`      | yes              | yes                 | IV creation for AES/CBC                                               |
| AES-4   | `Cipher.init(int, Key)`                         | via cipher events         | yes              | yes                 | AES/ECB and generic AES                                               |
| AES-5   | `Cipher.init(int, Key, AlgorithmParameterSpec)` | via cipher events         | yes              | yes                 | AES/CBC encrypt/decrypt                                               |
| AES-6   | `Cipher.update(byte[])`                         | `crypto.cipher.update`    | yes              | yes                 | AES/ECB updates; length fields left at 0                              |
| AES-7   | `Cipher.update(byte[], int, int)`               | `crypto.cipher.update`    | yes              | yes                 | AES/CBC update; lengths not recorded                                  |
| AES-8   | `Cipher.update(byte[], int, int, byte[])`       | `crypto.cipher.update`    | yes              | yes                 | AES/ECB variant                                                       |
| AES-9   | `Cipher.update(byte[], int, int, byte[], int)`  | `crypto.cipher.update`    | yes              | yes                 | AES/ECB variant                                                       |
| AES-10  | `Cipher.doFinal()`                              | `crypto.cipher.operation` | yes              | yes                 | AES/CBC encrypt and internal uses                                     |
| AES-11  | `Cipher.doFinal(byte[])`                        | `crypto.cipher.operation` | yes              | yes                 | AES/CBC decrypt                                                       |
| AES-12  | `Cipher.doFinal(byte[], int, int)`              | `crypto.cipher.operation` | yes              | yes                 | AES/ECB path                                                          |
| AES-13  | `Cipher.doFinal(byte[], int, int, byte[])`      | `crypto.cipher.operation` | yes              | yes                 | AES/ECB path                                                          |
| AES-14  | `Cipher.doFinal(byte[], int, int, byte[], int)` | `crypto.cipher.operation` | yes              | yes                 | AES/ECB path                                                          |
| AES-15  | `Cipher.doFinal(byte[], int)`                   | none                      | no (no such API) | no                  | Hook entry exists but Java API lacks this overload; safeOverload returns null |

---

#### Base64 hooks (`encodings.ts`)

| Hook ID | Hook site                                            | Event type(s)                   | Exercised by app | Emitting events     | Notes                                                                 |
|--------:|------------------------------------------------------|---------------------------------|------------------|---------------------|-----------------------------------------------------------------------|
| ENC-1   | `Base64.decode(String, int)`                         | `crypto.base64.decode`         | yes              | yes                 | Uses `metadata.flag`                                                  |
| ENC-2   | `Base64.decode(byte[], int)`                         | `crypto.base64.decode`         | yes              | yes                 | Uses `metadata.flag`                                                  |
| ENC-3   | `Base64.decode(byte[], int, int, int)`               | `crypto.base64.decode`         | yes              | no (hook ERROR)     | `[HOOK ERROR] not a function`; app calls this overload                |
| ENC-4   | `Base64.encode(byte[], int)`                         | `crypto.base64.encode`         | yes              | yes                 | Uses `metadata.flags`                                                 |
| ENC-5   | `Base64.encode(byte[], int, int, int)`               | `crypto.base64.encode`         | yes              | no (hook ERROR)     | `[HOOK ERROR] not a function`; app calls this overload                |
| ENC-6   | `Base64.encodeToString(byte[], int)`                 | `crypto.base64.encode_to_string` | yes            | yes                 | Uses `metadata.flags`                                                 |
| ENC-7   | `Base64.encodeToString(byte[], int, int, int)`       | `crypto.base64.encode_to_string` | yes            | no (hook ERROR)     | `[HOOK ERROR] not a function`; app calls this overload                |

---

#### Keystore hooks (`keystore.ts`)

| Hook ID | Hook site                                                        | Event type(s)                                            | Exercised by app | Emitting events     | Notes                                                                                      |
|--------:|------------------------------------------------------------------|----------------------------------------------------------|------------------|---------------------|--------------------------------------------------------------------------------------------|
| KS-1    | `KeyStore.<init>(KeyStoreSpi, Provider, String)`                 | `crypto.keystore.constructor`                            | yes              | yes                 | Seen for BKS, BouncyCastle, PKCS12, AndroidCAStore, AndroidKeyStore                        |
| KS-2    | `KeyStore.getInstance(String)`                                   | `crypto.keystore.get_instance`                           | yes              | yes                 | BKS and AndroidKeyStore                                                                    |
| KS-3    | `KeyStore.getInstance(String, String)`                           | `crypto.keystore.get_instance`                           | yes              | yes                 | BKS and AndroidKeyStore                                                                    |
| KS-4    | `KeyStore.getInstance(String, Provider)`                         | `crypto.keystore.get_instance`                           | yes              | yes                 | BKS, BouncyCastle, PKCS12, AndroidCAStore, AndroidKeyStore                                 |
| KS-5    | `KeyStore.load(LoadStoreParameter)`                              | `crypto.keystore.load`                                   | yes              | yes                 | BKS and AndroidKeyStore; BKS always throws `UnsupportedOperationException`                 |
| KS-6    | `KeyStore.load(InputStream, char[])`                             | `crypto.keystore.load`                                   | yes (BKS)        | yes                 | Standard BKS load path                                                                     |
| KS-7    | `KeyStore.store(LoadStoreParameter)`                             | `crypto.keystore.store`                                  | yes (BKS)        | yes                 | BKS always throws `UnsupportedOperationException`                                          |
| KS-8    | `KeyStore.store(OutputStream, char[])`                           | `crypto.keystore.store`                                  | yes (BKS)        | yes                 | BKS keystore written to memory                                                             |
| KS-9    | `KeyStore.getKey(String, char[])`                                | `crypto.keystore.get_key`                                | yes              | yes                 | BKS alias and AndroidKeyStore alias                                                        |
| KS-10   | `KeyStore.setEntry(String, KeyStore.Entry, ProtectionParameter)` | `crypto.keystore.set_entry`                              | yes              | yes                 | Entry/protection emitted as ad-hoc strings                                                 |
| KS-11   | `KeyStore.getEntry(String, ProtectionParameter)`                 | `crypto.keystore.get_entry`, `crypto.keystore.get_entry_result` | yes      | yes                 | BKS secret key entry                                                                       |
| KS-12   | `KeyStore.setKeyEntry(String, Key, char[], Certificate[])`       | `crypto.keystore.set_key_entry`                          | yes              | yes                 | AES `SecretKey` with password                                                              |
| KS-13   | `KeyStore.setKeyEntry(String, byte[], Certificate[])`            | `crypto.keystore.set_key_entry`                          | yes              | yes                 | Encoded key path                                                                           |
| KS-14   | `KeyStore.getCertificate(String)`                                | `crypto.keystore.get_certificate`                        | yes              | yes                 | BKS and AndroidKeyStore aliases                                                            |
| KS-15   | `KeyStore.getCertificateChain(String)`                           | `crypto.keystore.get_certificate_chain`                  | yes              | yes                 | BKS and AndroidKeyStore aliases                                                            |

---

### Known issues

#### Hook-side bugs and conceptual problems

| ID      | File           | Description                                                                                              | Impact                                                                                          |
|---------|----------------|----------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------|
| C-AES-1 | `aes.ts`       | Hook for `SecretKeySpec.<init>(byte[], int, int, String)` fails to install (`not a function`).          | No `crypto.key.creation` event for this overload; constructor still executes.                  |
| C-AES-2 | `aes.ts`       | Hook targets `Cipher.doFinal(byte[], int)` which does not exist in `javax.crypto.Cipher`.               | Dead hook entry; safeOverload returns null; no events, no runtime error.                       |
| C-AES-3 | `aes.ts`       | `crypto.cipher.update` events do not populate `input_length` / `output_length`.                        | AES update events have size fields fixed at 0.                                                 |
| C-AES-4 | `safe_java.ts` | `safeImplementation` re-calls `original` after logging an error; exceptions can cause double invocation. | Generic limitation affecting all Java hooks on exceptional paths.                              |
| C-ENC-1 | `encodings.ts` | Hooks for 4-arg Base64 overloads fail to install (`encode/decode/encodeToString(byte[],int,int,int)`).  | App exercises these overloads; no `crypto.base64.*` events for them.                           |
| C-ENC-2 | `encodings.ts` | Encode events use `metadata.flags`, decode events use `metadata.flag`.                                  | Parser only treats `flags` specially; decode flags remain generic metadata.                    |
| C-KS-1  | `keystore.ts`  | LSP-based hooks (`load/store(LoadStoreParameter)`) are copied from general JCA patterns, not Android-specific. | On Android BKS/BC, LSP load/store always throw; events emitted but design does not match real flows. |
| C-KS-2  | `keystore.ts`  | Keystore metadata fields like `password`, `key`, `parameter` emitted as stringified Java proxies.       | Data is noisy and not immediately useful for structured analysis.                              |

#### Parser and model issues

| ID     | Location                    | Description                                                                                  |
|--------|-----------------------------|----------------------------------------------------------------------------------------------|
| C-P-1  | `CryptoParser`, `CryptoEvent` | Base64 `decoded_content` / `input_content` stay in metadata; `plaintext` not derived from them. |
| C-P-2  | `CryptoParser`             | Only `flags` treated as structured; `flag` (decode) remains generic metadata.               |

#### Test-app limitations and future extensions

| Note                       | Detail                                                                                           |
|----------------------------|--------------------------------------------------------------------------------------------------|
| AES modes                  | Only CBC and ECB are covered; hooks are generic and will see other modes when tests are added. |
| Keystore LSP success paths | No keystore type on this runtime supports both LSP load and store; tests document partial support only. |

---

### Summary

| Category | Total hook sites (TS) | Exercised by app      | Emitting events correctly                | Hook errors / conceptual issues                                                                 |
|----------|-----------------------|------------------------|------------------------------------------|-------------------------------------------------------------------------------------------------|
| AES      | 14 defined (13 real)  | 13 real + 1 invalid   | Most, except AES-2, AES-15               | AES-2 fails to install; AES-15 targets non-existent overload; update events lack size fields.  |
| Base64   | 7                     | 7                      | 4 (encode/encode_to_string/decode)       | 4-arg overload hooks fail to install; encode/decode flag schema inconsistent.                  |
| Keystore | 15                    | 15                     | All emit events (with caveats)           | LSP hooks do not match Android BKS/BC; several metadata fields emitted as unstructured strings. |


#### 2. Potential future crypto hooks (for later test and hook design)

List of additional, Android-relevant crypto hooks that would be sensible candidates for future work. These are not implemented yet; they can guide future hook design and future extensions of CryptoE2E.

##### 2.1 Java symmetric and asymmetric primitives

- `javax.crypto.Cipher.getInstance(String transformation)`
  - Record algorithm/mode/padding usage across the app.

  - Useful for identifying weak modes (ECB), no-padding usage, or unusual provider-specific transformations.
- `javax.crypto.Mac.getInstance(String algorithm)` and `Mac.doFinal(...)`

  - Capture HMAC and MAC algorithms and key sizes.
  - For integrity/authentication analysis and key reuse detection.

- `java.security.MessageDigest.getInstance(String algorithm)` and `digest(...)`
  - Observe hash algorithm usage (MD5, SHA-1, SHA-256, etc).

  - Spot weak hashes and potential fingerprinting of secrets.
- `javax.crypto.KeyGenerator.getInstance(...)` and `init(int keysize, SecureRandom)`

  - Record generated key algorithms and key lengths.
  - Useful for verifying minimum key sizes.

- `java.security.KeyAgreement.getInstance("ECDH")` and `doPhase` / `generateSecret`
  - Observe ECDH key agreement parameters.

- `java.security.Signature.getInstance(...)` and `sign` / `verify`
  - Capture signature algorithms and key lengths.

##### 2.2 SecureRandom and entropy


- `java.security.SecureRandom.getInstance(...)` and `nextBytes(byte[])`
  - Record source of randomness (e.g. `SHA1PRNG`, `AndroidOpenSSL`).

  - Optionally sample limited output lengths to detect fixed seeds or misuse.
- `SecureRandom.setSeed(byte[]/long)`

  - Capture explicit seeding events which may reduce entropy.

##### 2.3 AndroidKeyStore–specific hooks


- `android.security.keystore.KeyGenParameterSpec.Builder` methods:
  - `setBlockModes`, `setEncryptionPaddings`, `setKeySize`, `setUserAuthenticationRequired`, etc.

  - Record configuration of generated keys in AndroidKeyStore.
- `android.security.keystore.KeyInfo` introspection:

  - Hook retrieval and extraction of:
    - keyAlgorithm, keySize, blockModes, digests, encryptionPaddings,

    - isInsideSecureHardware, isUserAuthenticationRequired,
    - keyValidityStart / keyValidityForOriginationEnd / keyValidityForConsumptionEnd.


- `android.security.KeyStoreParameter` and `android.security.keystore.KeyProtection`:
  - Observe parameters for imported keys and key usage constraints.


- `javax.crypto.SecretKeyFactory` / `KeyFactory` for AndroidKeyStore keys:
  - Capture usage of `KeyFactory.getInstance(..., "AndroidKeyStore")` and associated `KeySpec`s.

##### 2.4 Additional encoding/decoding and string transformations


- `java.util.Base64` (for newer Android runtimes where it is used instead of `android.util.Base64`):
  - Same encode/decode coverage as for `android.util.Base64`.


- Other common encodings:
  - `org.bouncycastle.util.encoders.Hex` and Base64 equivalents if present in apps.

  - Frequently used proprietary encoders in known SDKs.
- Simple string decryption patterns:

  - Hooks around `CipherInputStream` / `CipherOutputStream`.
  - Common obfuscation helpers in known libraries (for example, static methods that decrypt resources or strings).

##### 2.5 Native crypto (for future native hook layer)

If a native crypto layer is added in the future (outside current TS scope), typical hook sites could include:


- OpenSSL/BoringSSL/Conscrypt:
  - `EVP_EncryptInit_ex`, `EVP_EncryptUpdate`, `EVP_EncryptFinal_ex`.

  - `EVP_DecryptInit_ex`, `EVP_DecryptUpdate`, `EVP_DecryptFinal_ex`.
  - `EVP_DigestInit_ex`, `EVP_DigestUpdate`, `EVP_DigestFinal_ex`.

  - `RSA_*`, `ECDSA_*`, `EC_KEY_*`.
- Android system libraries:

  - `libcrypto.so`, `libssl.so`, `libboringssl.so` exports as resolved via `safeEnumerateMatches` / `safeAttachExport`.

These would require a separate native test app or a native component inside CryptoE2E.

---

## IPC Hooks - E2E Test Results

### Test app
`tests/android_apps/e2e_tests/IpcE2E`  
Package: `com.test.ipce2e`  
Logcat tag: `IPC_E2E`

### Hook files
- `agent/ipc/binder.ts`
- `agent/ipc/broadcast.ts`
- `agent/ipc/intents.ts`
- `agent/ipc/shared_prefs.ts`

### Hook groups and profile types
- Binder hooks -> `IPC_BINDER`
- Broadcast hooks -> `IPC_BROADCAST`
- Intent hooks -> `IPC_INTENT`
- SharedPreferences/DataStore hooks -> `IPC_SHARED-PREF`

---

### Test environment

#### Required permissions
All permissions are normal permissions, granted automatically at install from the manifest.
No `adb shell pm grant` needed.

```xml
<uses-permission android:name="android.permission.BROADCAST_STICKY" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
```

#### Hook run command
`dexray-intercept -s -v --hooks-ipc com.test.ipce2e`

#### Baseline run command
```
adb shell am force-stop com.test.ipce2e
adb shell am start -n com.test.ipce2e/.MainActivity
adb logcat -v threadtime -s IPC_E2E:'*'
```

#### Event type summary from profile JSON
```
FILE=$(ls profile_com.test.ipce2e_*.json | tail -1)
jq '.IPC_BINDER[].event_type, .IPC_BROADCAST[].event_type, .IPC_INTENT[].event_type, .["IPC_SHARED-PREF"][].event_type' "$FILE" | sort | uniq -c
```

#### Baseline results (no hooks)

All sections run to completion.

| Section | Result | Notes |
|---------|--------|-------|
| runBinderTests | pass | ANDROID_ID and DEVICE_NAME retrieved via Binder IPC |
| runBroadcastTests | pass | sendStickyBroadcast OK; startForegroundService OK |
| runIntentTests | pass | Both getData() calls return expected URIs |
| runSharedPrefsTests | pass | All SP values round-trip correctly; DataStore values correct |
| IpcE2E finished | logged | App exits cleanly |
| MyTestService started x2 | logged (async) | One from startService, one from startForegroundService |
| MyTestService: startActivity from background Service OK | logged | BAL restriction behavior is environment-dependent on API 29+; succeeded on API 30 x86_64 emulator |
| MyTestService: startActivity from foreground Service OK | logged | Foreground service is BAL-exempt; reliable across environments |
| MyTestService: startActivity(Intent,Bundle) from foreground Service OK | logged | Foreground service BAL-exempt; reliable trigger for BC-5 |
| SecondActivity started x5 | logged (async) | 2 from MainActivity.startActivity, 1 from background service, 1 from foreground service (Intent), 1 from foreground service (Intent+Bundle) |

---

#### Hook coverage matrix

##### binder.ts

| Hook ID | Hook site | Event type | Observed | Key fields | Notes |
|---------|-----------|------------|----------|------------|-------|
| BND-1 | libbinder.so ioctl (BINDER_WRITE_READ, cmd 0xc0306201) | binder.transaction | yes (10 events) | transaction_type, code, data_size, payload_hex | Original comparison `cmd != ptr(0xc0306201)` used JavaScript object identity and was always true; fixed to `cmd.toUInt32() !== 0xc0306201`; magic value 0xc0306201 is identical for arm64 and x86_64 64-bit Android |

##### broadcast.ts

| Hook ID | Hook site | Event type | Observed | Key fields | Notes |
|---------|-----------|------------|----------|------------|-------|
| BC-1 | ContextWrapper.sendBroadcast(Intent) | broadcast.sent | yes | intent action, extras | Correct |
| BC-2 | ContextWrapper.sendBroadcast(Intent, String) | broadcast.sent | yes | intent action | receiver_permission not in IPCEvent; silently dropped by parser |
| BC-3 | ContextWrapper.sendStickyBroadcast(Intent) | broadcast.sticky_sent | yes | intent action | Deprecated API 21+; functional; requires BROADCAST_STICKY permission |
| BC-4 | ContextWrapper.startActivity(Intent) | activity.started | yes (service context only) | intent component | Fires from MyTestService (background and foreground paths); calls from Activity subclasses dispatch to Activity.startActivity override and never reach ContextWrapper; hook misses the most common Android case |
| BC-5 | ContextWrapper.startActivity(Intent, Bundle) | activity.started | yes (foreground service context) | intent component | Triggered from MyTestService foreground path; calls from Activity subclasses still miss this hook for the same reason as BC-4 |
| BC-5 | ContextWrapper.startActivity(Intent, Bundle) | activity.started | no | - | No trigger from a non-Activity context with Bundle currently in app; to be added when BC-4/BC-5 are fixed to also hook Activity.startActivity |
| BC-6 | ContextWrapper.startService(Intent) | service.started | yes | method only | Intent details emitted under field `service`; not mapped in IPCEvent/IPCParser; intent content silently dropped |
| BC-7 | ContextWrapper.stopService(Intent) | service.stopped | yes | method only | Same field mapping issue as BC-6 |
| BC-8 | ContextWrapper.registerReceiver(BroadcastReceiver, IntentFilter) | none | hook installed | - | Pass-through only; no event emitted; purpose undocumented in hook file |
| BC-9 | ContextWrapper.registerReceiver(BroadcastReceiver, IntentFilter, String, Handler) | none | hook installed | - | Same as BC-8 |
| BC-10 | ContextWrapper.startForegroundService(Intent) | none | no hook | - | No hook implemented; trigger present in app for future hook |

##### intents.ts

| Hook ID | Hook site | Event type | Observed | Key fields | Notes |
|---------|-----------|------------|----------|------------|-------|
| INT-1 | Intent.getData() | intent.data_accessed | yes (19 events, 2 genuine) | intent action, data_uri, extras, mime_type | 17 of 19 events are cross-hook artifacts: broadcast.ts calls getIntentInfo(intent) inside every broadcast/service hook, which internally calls getData() and triggers this hook; genuine events are android.intent.action.VIEW and com.test.ipce2e.CUSTOM_ACTION |
| INT-2 | Activity.getIntent() | intent.accessed | yes (5 events) | intent action, component, extras | 1 from MainActivity; 2 from each SecondActivity instance (from MainActivity, from background service, from foreground service) |

##### shared_prefs.ts

| Hook ID | Hook site | Event type | Observed | Key fields | Notes |
|---------|-----------|------------|----------|------------|-------|
| SP-1 | SharedPreferencesImpl.$init(File, int) | shared_prefs.init | yes | file, method | Full path: /data/user/0/com.test.ipce2e/shared_prefs/ipc_e2e_prefs.xml |
| SP-2 | SharedPreferencesImpl$EditorImpl.putString(String, String) | shared_prefs.put_string | yes | key, value | Correct |
| SP-3 | SharedPreferencesImpl$EditorImpl.putInt(String, int) | shared_prefs.putint | yes | key, value | Correct |
| SP-4 | SharedPreferencesImpl$EditorImpl.putLong(String, long) | shared_prefs.putlong | yes | key, value | Correct |
| SP-5 | SharedPreferencesImpl$EditorImpl.putFloat(String, float) | shared_prefs.putfloat | yes | key, value | IEEE 754 float-to-string artifact: 3.140000104904175 for 3.14f; expected |
| SP-6 | SharedPreferencesImpl$EditorImpl.putBoolean(String, boolean) | shared_prefs.putboolean | yes | key, value | Correct |
| DS-1 | DataStore.updateData (all overloads) | datastore.update | no | - | Kotlin coroutine suspend function; JVM bytecode has hidden Continuation parameter; Java.use overload matching does not intercept suspend call sites |
| DS-2 | DataStore.getData | datastore.get | no | - | Kotlin Flow property backed by coroutine machinery; same non-interception issue as DS-1 |
| DS-3 | Preferences.get(Preferences$Key) | datastore_prefs.get | yes | key, value | Concrete Kotlin class; fires on prefs[key] reads |
| DS-4 | MutablePreferences.get(Preferences$Key) | datastore_prefs.get | yes | key, value | Fires on prefs[key] = value writes inside edit {} |
| DS-5 | Preferences$Key.$init(String) | datastore_prefs.key_init | yes | key | 6 events for 3 keys; each key constructed twice (edit{} path and data.first() path) |

---

#### Known issues

##### Hook-side bugs

| ID | File | Description | Impact |
|----|------|-------------|--------|
| IPC-BND-1 | binder.ts | `cmd != ptr(0xc0306201)` used JavaScript object identity comparison; always evaluated true; fixed to `cmd.toUInt32() !== 0xc0306201` | Was: no binder.transaction events ever emitted. Fixed and confirmed emitting. |
| IPC-BND-2 | binder.ts | `hexdump(buffer, { length: data_size })` passes a UInt64 as length; Frida hexdump expects a JS Number; payload preview truncates to 7 bytes regardless of actual data_size | Binder payload content is unreadable; fix: `Number(binder_transaction_data.data_size)` |
| IPC-BND-3 | binder.ts | hook_binder() wraps safeAttachExport inside Java.perform; native symbol attachment requires no Java runtime context | Harmless but incorrect; unnecessary Java.perform overhead for a native-only operation |
| IPC-BC-1 | broadcast.ts | BC-4/BC-5 hook ContextWrapper.startActivity; calls from Activity subclasses dispatch through Activity.startActivity override and never reach ContextWrapper; hook only fires when caller is a Service or Application context | activity.started events missed for the most common case; hook must additionally target Activity.startActivity for both overloads |
| IPC-BC-2 | broadcast.ts | BC-6/BC-7 (startService/stopService) use direct .implementation without safeOverload guard; fragile if these methods gain additional overloads in future API levels | Latent fragility; currently functional |
| IPC-BC-3 | broadcast.ts | service.started/service.stopped events store intent details under field `service`; IPCEvent and IPCParser do not map this field; content silently dropped | Service hook events carry only `method`; all intent details for service operations unavailable |
| IPC-BC-4 | broadcast.ts | BC-8/BC-9 (registerReceiver overloads) are hooked as pass-throughs emitting no events; purpose undocumented | No data captured for receiver registrations; unclear if intended as stub or oversight |
| IPC-INT-1 | intents.ts, broadcast.ts | broadcast.ts calls getIntentInfo(intent) inside every broadcast and service hook body; getIntentInfo calls intent.getData(), triggering INT-1; produces spurious intent.data_accessed events for every broadcast and service operation | 17 of 19 intent.data_accessed events are cross-hook artifacts unrelated to explicit getData() calls |
| IPC-INT-2 | intents.ts | data_size field always emitted as 0 on all IPC_INTENT events; field is never populated | Unused field; adds noise to all intent events |
| IPC-SP-1 | shared_prefs.ts | DS-1/DS-2 target Kotlin coroutine suspend functions (DataStore.updateData, DataStore.getData); not interceptable via Java.use overload matching due to hidden Continuation parameter | No datastore.update or datastore.get events ever emitted; DataStore write and read flow monitoring non-functional |

##### Parser and model issues

| ID | Location | Description |
|----|----------|-------------|
| IPC-P-1 | IPCParser, IPCEvent | `service` field emitted by BC-6/BC-7 hooks not mapped in IPCEvent; intent details for service operations silently dropped |
| IPC-P-2 | BroadcastParser | receiver_permission from BC-2 not in IPCEvent; stored only as generic metadata |
| IPC-P-3 | CLI display | sender_pid from binder.transaction events displays as `unknown`; field present in JSON but not surfaced in CLI event summary |

##### Test environment limitations

| Note | Detail |
|------|--------|
| Background startActivity from Service | Succeeded on API 30 x86_64 emulator; Background Activity Launch restrictions introduced in API 29 are environment-dependent; may be blocked on stricter devices or API levels |
| Foreground startActivity from Service | Reliable across environments; foreground services are BAL-exempt; this is the authoritative ContextWrapper.startActivity trigger |
| sendStickyBroadcast | Requires BROADCAST_STICKY normal permission in manifest; no runtime grant needed |
| startForegroundService | Requires FOREGROUND_SERVICE normal permission; MyTestService must call startForeground() within 5 seconds; handled via EXTRA_START_FOREGROUND flag in onStartCommand |

---

#### Summary

| Category | Total hooks | Observed and emitting | Hook errors | Not emitting (environment) | Non-functional hook |
|----------|-------------|----------------------|-------------|---------------------------|---------------------|
| Binder | 1 | 1 (after IPC-BND-1 fix) | 0 | 0 | 0 |
| Broadcast | 10 | 8 (BC-1/2/3/4/5/6/7; BC-8/9 pass-through) | 0 | 0 | 1 (BC-10 no hook) |
| Intents | 2 | 2 (with cross-hook noise) | 0 | 0 | 0 |
| SharedPreferences | 6 | 6 | 0 | 0 | 0 |
| DataStore | 5 | 3 (DS-3/4/5) | 0 | 0 | 2 (DS-1/DS-2 coroutine suspend) |
| **Total** | **24** | **20** | **0** | **0** | **3** |



## Database hooks (agent/database/sql.ts -> DATABASE)

### Test app
`tests/android_apps/e2e_tests/DatabaseE2E`
- package `com.test.databasee2e`
- Min SDK: 24

### Run command
`dexray-intercept -s -v --enable-database com.test.databasee2e`

#### Logcat filter
`adb logcat -v color time -s DATABASE_E2E:'' SQLCIPHER_E2E_HELPER:'' ROOM_SQLCIPHER_E2E:'*' -s SQLITE_NATIVE_E2E:'*' AndroidRuntime:E`

#### Profile event type summary (jq)
```
FILE=(lsprofilecom.test.databasee2e∗.json∣tail−1)jq′.DATABASE[].eventtype′"(lsprofilec​om.test.databasee2e∗​.json∣tail−1)jq′.DATABASE[].eventt​ype′"FILE" | sort | uniq -c | sort -rn
```

#### Baseline (app without hooks)

All 7 test sections complete with 0 failures:

- `runSqliteJavaTests` completed
- `runNativeBindTypeTests` completed
- `SqliteNativeTests` completed (5 passed, 0 failed)
- `runRoomTests` completed
- `runSqlCipherTests` completed
- `RoomSqlCipherTests` completed
- `runWcdbTests` completed

Note: `PRAGMA key execSQL` in `runSqlCipherTests` intentionally throws
`SQLiteException: Queries cannot be performed using execSQL()` in SQLCipher 4.x.
This is expected - the hook fires before the exception propagates.

---

#### Static coverage - hook sites vs app

##### `hook_java_sql()` - `android.database.sqlite.SQLiteDatabase`

| ## | Hook site | Event type emitted | Format | App trigger | Result |
|---|-----------|-------------------|--------|-------------|--------|
| 1 | `execSQL(String)` | `database.sqlite.exec` | JSON | `runSqliteJavaTests` DROP/CREATE calls | FIRES - correct |
| 2 | `execSQL(String, Object[])` | `database.sqlite.exec` | JSON | `runSqliteJavaTests` INSERT with Object[] | FIRES - correct |
| 3 | `query(boolean,String,String[],String,String[],String,String,String,String)` | `database.legacy` | raw string | `runSqliteJavaTests` `query(true,...)` | FIRES - format inconsistency: emits raw string, not JSON |
| 4 | `query(String,String[],String,String[],String,String,String,String)` | `database.sqlite.query` | JSON | `runSqliteJavaTests` `query(table,...,"5")` | FIRES - correct |
| 5 | `query(boolean,...,CancellationSignal)` | `database.legacy` | raw string | `runSqliteJavaTests` `query(true,...,CancellationSignal)` | FIRES - format inconsistency |
| 6 | `query(String,String[],String,String[],String,String,String)` | `database.legacy` | raw string | `runSqliteJavaTests` `query(table,...,"id ASC")` | FIRES - format inconsistency |
| 7 | `queryWithFactory(CursorFactory,boolean,...,String,String)` | `database.legacy` + `database.sqlite.query_legacy` | dual raw strings | `runSqliteJavaTests` `queryWithFactory(null,false,...)` | FIRES - dual emission: queryWithFactory fires its own hook then internally calls rawQueryWithFactory which fires again |
| 8 | `queryWithFactory(CursorFactory,boolean,...,CancellationSignal)` | `database.legacy` + `database.sqlite.query_legacy` | dual raw strings | `runSqliteJavaTests` `queryWithFactory(null,false,...,CancellationSignal)` | FIRES - same dual emission issue as #7 |
| 9 | `rawQuery(String,String[])` | `database.sqlite.query` | JSON | `runSqliteJavaTests` `rawQuery("SELECT...",{"A%"})` | FIRES - correct |
| 10 | `rawQuery(String,String[],CancellationSignal)` | `database.sqlite.query` | JSON | `runSqliteJavaTests` `rawQuery("SELECT...",{"10"},signal)` | FIRES - correct |
| 11 | `rawQueryWithFactory(CursorFactory,String,String[],String,CancellationSignal)` | `database.sqlite.query_legacy` | raw ANSI string | `runSqliteJavaTests` `rawQueryWithFactory(null,sql,args,table,signal)` | FIRES - format inconsistency |
| 12 | `rawQueryWithFactory(CursorFactory,String,String[],String)` | `database.sqlite.query_legacy` | raw ANSI string | `runSqliteJavaTests` `rawQueryWithFactory(null,sql,args,table)` | FIRES - format inconsistency |
| 13 | `insert(String,String,ContentValues)` | `database.sqlite.insert` + `database.sqlite.insert_legacy` | JSON + raw string | `runSqliteJavaTests` `insert(table,null,cv)` | FIRES - dual emission: insert() calls insertWithOnConflict() internally, both hooks fire; content_values shows Java class description instead of actual values |
| 14 | `insertOrThrow(String,String,ContentValues)` | `database.sqlite.insert` + `database.sqlite.insert_legacy` | JSON + raw string | `runSqliteJavaTests` `insertOrThrow(table,null,cv2)` | FIRES - same dual emission as #13 |
| 15 | `insertWithOnConflict(String,String,ContentValues,int)` | `database.sqlite.insert_legacy` | raw ANSI string | `runSqliteJavaTests` `insertWithOnConflict(...,CONFLICT_REPLACE)` | FIRES - format inconsistency; also fires spuriously from insert/insertOrThrow |
| 16 | `openDatabase(String,CursorFactory,int)` | `database.sqlite.open` | JSON | `runSqliteJavaTests` `openDatabase(path,null,flags)` | FIRES - correct |
| 17 | `openDatabase(String,CursorFactory,int,DatabaseErrorHandler)` | `database.sqlite.open_legacy` | raw ANSI string | `runSqliteJavaTests` `openDatabase(path,null,flags,errorHandler)` | FIRES - format inconsistency |
| 18 | `openOrCreateDatabase(String,CursorFactory)` | `database.sqlite.open` | JSON | `runSqliteJavaTests` `Context.openOrCreateDatabase()` | FIRES - but note: Context.openOrCreateDatabase() routes through the 4-arg openDatabase internally; the 2-arg hook fires via static dispatch at the Java level |
| 19 | `openOrCreateDatabase(String,CursorFactory,DatabaseErrorHandler)` | `database.sqlite.open_legacy` | raw ANSI string | `runSqliteJavaTests` `openOrCreateDatabase(path,null,errorHandler)` | FIRES - format inconsistency |
| 20 | `update(String,ContentValues,String,String[])` | `database.sqlite.update` | JSON | `runSqliteJavaTests` `update(table,upd,"name=?",args)` | FIRES - correct; content_values shows Java class description instead of actual values |
| 21 | `updateWithOnConflict(String,ContentValues,String,String[],int)` | `database.sqlite.update_legacy` | raw ANSI string | `runSqliteJavaTests` `updateWithOnConflict(...,CONFLICT_IGNORE)` | FIRES - format inconsistency |
| 22 | `delete(String,String,String[])` + result | `database.sqlite.delete` + `database.sqlite.delete_result` | JSON x2 | `runSqliteJavaTests` `delete(table,"name=?",args)` | FIRES - correct; emits pre-call event and post-call event with rows_affected |

##### `hook_SQLCipher()` - `net.sqlcipher.database.*`

| ## | Hook site | Event type emitted | Format | App trigger | Result |
|---|-----------|-------------------|--------|-------------|--------|
| 1 | `SQLiteOpenHelper.getWritableDatabase(String)` | `database.sqlcipher.open` | JSON | `runSqlCipherTests` `helper.getWritableDatabase(pw)` | FIRES - correct |
| 2 | `SQLiteDatabase.openOrCreateDatabase(File,String)` | - | - | `runSqlCipherTests` `openOrCreateDatabase(file,pw,null)` | HOOK ERROR - wrong overload signature: 2-arg does not exist in SQLCipher 4.5.0; minimum is 3-arg `(File,String,CursorFactory)` |
| 3 | `SQLiteDatabase.openOrCreateDatabase(File,String)` duplicate | - | - | same | HOOK ERROR - same broken overload registered twice; second assignment would overwrite first even if the overload existed |
| 4 | `SQLiteDatabase.openOrCreateDatabase(String,char[])` | - | - | `runSqlCipherTests` `openOrCreateDatabase(path,pw.toCharArray(),null,null)` | HOOK ERROR - wrong overload signature: app calls 4-arg `(String,char[],CursorFactory,DatabaseErrorHandler)` |
| 5 | `SQLiteDatabase.rawExecSQL(String)` | `database.sqlcipher.legacy` | raw sendLog string | `runSqlCipherTests` `dbPragma.rawExecSQL("PRAGMA cipher_memory_security = OFF")` | FIRES - format inconsistency: raw string not JSON |
| 6 | `SQLiteDatabase.execSQL(String)` | `database.sqlcipher.exec` | JSON | `runSqlCipherTests` multiple `execSQL` calls | FIRES BUT ZERO EVENTS: hook installs without error; despite multiple execSQL calls on net.sqlcipher.database.SQLiteDatabase, zero `database.sqlcipher.exec` events appear in profile; likely SQLCipher routes internally differently than standard SQLiteDatabase |
| 7 | `SQLiteDatabase.getWritableDatabase(String)` | - | - | - | HOOK ERROR - Method is null or undefined: these are SQLiteOpenHelper instance methods, not SQLiteDatabase methods |
| 8 | `SQLiteDatabase.getReadableDatabase(String)` | - | - | - | HOOK ERROR - same architectural error as #7 |
| 9 | `SQLiteDatabase.close()` | `database.sqlcipher.legacy` | raw sendLog string | `runSqlCipherTests` `db.close()` calls | FIRES - format inconsistency |
| 10 | `SQLiteDatabase.beginTransaction()` | `database.sqlcipher.transaction` | JSON | `runSqlCipherTests` `db.beginTransaction()` | FIRES - correct |
| 11 | `SQLiteDatabase.endTransaction()` | `database.sqlcipher.transaction` | JSON | `runSqlCipherTests` `db.endTransaction()` | FIRES - correct |
| - | `SQLiteDatabase.setTransactionSuccessful()` | - | - | `runSqlCipherTests` `db.setTransactionSuccessful()` | NOT HOOKED - no hook defined in hook_SQLCipher(); method is called but produces no event |

##### `hook_room_library()` - `androidx.room.*`

| # | Hook site | Event type emitted | Format | App trigger | Result |
|---|-----------|-------------------|--------|-------------|--------|
| 1 | `Room.databaseBuilder(Context,Class,String)` | `database.room.builder` | JSON | `runRoomTests` + `RoomSqlCipherTests` | FIRES - correct; 2 events observed (plain DB + encrypted DB) |
| 2 | `SQLiteDatabase.openOrCreateDatabase(File,String)` in Room block | - | - | `RoomSqlCipherTests` via SupportFactory | HOOK ERROR - same broken 2-arg overload as hook_SQLCipher(); SQLCipher 4.5.0 minimum is 3-arg |
| 3 | `SQLiteDatabase.openOrCreateDatabase(String,String)` in Room block | - | - | - | HOOK ERROR - 2-arg `(String,String)` overload does not exist in SQLCipher 4.5.0 |
| 4 | `SQLiteDatabase.execSQL(String)` PRAGMA key in Room block | `database.sqlcipher.pragma` | JSON | `runSqlCipherTests` explicit `execSQL("PRAGMA key=...")` | FIRES - hook fires before the SQLCipher exception is thrown; event captured correctly; note: SupportFactory+byte[] path bypasses Java execSQL entirely and cannot trigger this hook |
| 5 | `SupportSQLiteOpenHelper.Callback.onCreate` | `database.room.callback` | JSON | first DB creation only | FIRES on first run after `deleteDatabase()` call; `deleteDatabase()` added to test to ensure onCreate fires on every run |
| 6 | `SupportSQLiteOpenHelper.Callback.onOpen` | `database.room.callback` | JSON | `runRoomTests` + `RoomSqlCipherTests` every DB open | FIRES - correct; 2 events observed |
| 7 | `RoomDatabase.insert(Object)` | - | - | `runRoomTests` `dao.insert(alice)` | HOOK ERROR - Method is null or undefined: RoomDatabase has no such method; Room-generated DAO uses EntityInsertionAdapter internally |
| 8 | `RoomDatabase.update(Object)` | - | - | `runRoomTests` `dao.update(alice)` | HOOK ERROR - same architectural error |
| 9 | `RoomDatabase.delete(Object)` | - | - | `runRoomTests` `dao.delete(bob)` | HOOK ERROR - same architectural error |
| 10 | `RoomDatabase.query(SupportSQLiteQuery)` | `database.room.legacy` | raw am_send string | `runRoomTests` `dao.rawSelect(rawQuery)` | FIRES - format inconsistency: emits as raw string labeled `event_type: Room.Database` |
| 11 | `SupportSQLiteDatabase.execSQL(String)` | `database.sqlite.exec` | JSON | Room internal schema creation | FIRES - routes through SQLiteDatabase.execSQL hook; observed for Room PRAGMA and trigger setup statements |
| 12 | `LiveData.observe(LifecycleOwner,Observer)` | `database.room.legacy` | raw am_send string | `runRoomTests` `dao.selectAllLive().observe(ProcessLifecycleOwner.get(),...)` | FIRES - format inconsistency: emits as raw string labeled `event_type: Room.LiveData` |
| 13 | `FlowCollector.emit(Object)` | - | - | `runRoomTests` `FlowTestHelper.collectFirst(db.flowUserDao())` | HOOK ERROR - wrong overload: Kotlin suspend functions require `(Object,Continuation)` not `(Object)` |

##### `hook_wcdb()` - `com.tencent.wcdb.database.SQLiteDatabase`

| # | Hook site | Event type emitted | Format | App trigger | Result |
|---|-----------|-------------------|--------|-------------|--------|
| 1 | `openDatabase(String,CursorFactory,int)` | `database.wcdb.legacy` | raw ANSI string | `runWcdbTests` `WCDB.openDatabase(path,null,flags)` | FIRES - format inconsistency |
| 2 | `openOrCreateDatabase(String,CursorFactory)` | `database.wcdb.legacy` | raw ANSI string | `runWcdbTests` `WCDB.openOrCreateDatabase(path,null)` | FIRES - format inconsistency |
| 3 | `execSQL(String)` | `database.wcdb.legacy` | raw ANSI string | `runWcdbTests` DROP/CREATE/INSERT calls | FIRES - format inconsistency |
| 4 | `execSQL(String,Object[])` | `database.wcdb.legacy` | raw ANSI string | `runWcdbTests` `execSQL("INSERT...",Object[])` | FIRES - format inconsistency |
| 5 | `rawQuery(String,String[])` | - | - | `runWcdbTests` `db.rawQuery(...)` | HOOK ERROR - wrong overload signature: WCDB rawQuery takes `Object[]` not `String[]`; actual overloads are `(String,Object[])` and `(String,Object[],CancellationSignal)` |
| 6 | `insert(String,String,ContentValues)` | `database.wcdb.legacy` | raw ANSI string | `runWcdbTests` `WCDB.insert(table,null,cv)` | FIRES - format inconsistency |
| 7 | `update(String,ContentValues,String,String[])` | `database.wcdb.legacy` | raw ANSI string | `runWcdbTests` `WCDB.update(...)` | FIRES - format inconsistency |
| 8 | `delete(String,String,String[])` | `database.wcdb.legacy` | raw ANSI string | `runWcdbTests` `WCDB.delete(...)` | FIRES - emits two raw events: pre-call + rows-affected post-call |
| 9 | `beginTransaction()` | - | - | `runWcdbTests` `db.beginTransaction()` | FATAL ERROR - `.implementation` assigned directly on ambiguous method with multiple overloads; throws `Error: beginTransaction(): has more than one overload` at hook install time; crashes entire WCDB hook block |
| 10 | `endTransaction()` | - | - | `runWcdbTests` `db.endTransaction()` | NOT REACHED - not installed due to beginTransaction fatal error |
| 11 | `setTransactionSuccessful()` | - | - | `runWcdbTests` `db.setTransactionSuccessful()` | NOT REACHED - not installed due to beginTransaction fatal error |

##### `hook_native_sqlite()` - `libsqlite.so`

| # | Hook site | Event type emitted | Format | Triggered | Notes |
|---|-----------|-------------------|--------|-----------|-------|
| 1 | `sqlite3_open` | `database.native.open` | JSON | Indirectly via Java opens | Installs on libsqlite.so; android uses sqlite3_open_v2 predominantly; sqlite3_open not directly observed |
| 2 | `sqlite3_open_v2` | `database.native.open` | JSON | Every DB open (all Java paths) | FIRES - correct; confirmed as method field in profile |
| 3 | `sqlite3_open16` | `database.native.open` | JSON | `SqliteNativeTests` native component | INSTALLS on libsqlite.so but DOES NOT FIRE: native component uses a statically compiled SQLite amalgamation in libsqlite_native_tests.so, not libsqlite.so; on API 24+ linker namespace isolation prevents app-side dlopen("libsqlite.so"); hook would fire on API < 24 where namespace isolation does not exist |
| 4 | `sqlite3_exec` | `database.native.exec` | JSON | Internal schema validation queries | FIRES - correct |
| 5-10 | `sqlite3_prepare` (6 variants) | `database.native.legacy` | raw multiline string | All queries | FIRES at high volume; sql field captures only first character for sqlite3_prepare16_v2 because args[1].readUtf8String() is called on a UTF-16 pointer |
| 11 | `sqlite3_step` | `database.native.legacy` | raw multiline string | Every statement execution | FIRES at very high volume |
| 12 | `sqlite3_close` | `database.native.legacy` | raw multiline string | db.close() calls | FIRES |
| 13 | `sqlite3_close_v2` | `database.native.legacy` | raw multiline string | db.close() calls | FIRES |
| 14 | `sqlite3_bind_text` | `database.native.legacy` | raw multiline string | String bind args | INSTALLS but DOES NOT FIRE: Android JNI bridge uses sqlite3_bind_text16 for Java String values, not sqlite3_bind_text; sqlite3_bind_text16 is not hooked |
| 15 | `sqlite3_bind_blob` | `database.native.legacy` | raw multiline string | `runNativeBindTypeTests` ContentValues BLOB column | FIRES - but value field reads as "Error reading value": args[2].readUtf8String() fails on raw binary blob pointer |
| 16 | `sqlite3_bind_int` | `database.native.legacy` | raw multiline string | `SqliteNativeTests` native component | INSTALLS on libsqlite.so but DOES NOT FIRE: same linker namespace isolation issue as sqlite3_open16; Android JNI bridge always uses sqlite3_bind_int64; hook would fire on API < 24 |
| 17 | `sqlite3_bind_int64` | `database.native.legacy` | raw multiline string | All Java integer bindings | FIRES - correct; observed for all integer/long value bindings from Java |
| 18 | `sqlite3_bind_double` | `database.native.legacy` | raw multiline string | `runNativeBindTypeTests` ContentValues REAL column | FIRES - but value is incorrect: ARM64 passes float arguments in FP registers (d0-d7), not general-purpose registers; args[2].readDouble() reads from wrong register |
| 19 | `sqlite3_bind_null` | `database.native.legacy` | raw multiline string | `runNativeBindTypeTests` ContentValues putNull() | FIRES - correct |

---

#### Runtime results (with hooks)

##### App stability

All 7 test sections complete with 0 failures under hooks - identical to baseline.

##### Observed event types in profile

| event_type | Count (observed) | Source |
|-----------|-----------------|--------|
| `database.native.legacy` | ~524 | sqlite3_prepare*, sqlite3_step, sqlite3_close*, sqlite3_bind_* |
| `database.sqlite.query_legacy` | ~32 | query overloads, queryWithFactory, rawQueryWithFactory |
| `database.native.exec` | ~24 | sqlite3_exec internal schema queries |
| `database.sqlite.exec` | ~22 | execSQL(String) and execSQL(String,Object[]) |
| `database.legacy` | ~12 | query 7/9/10-arg, queryWithFactory |
| `database.sqlcipher.legacy` | ~11 | close() x5, rawExecSQL x2, rawExecSQL pragma x2 |
| `database.wcdb.legacy` | ~10 | all WCDB hooks |
| `database.native.open` | ~10 | sqlite3_open_v2 for each DB open |
| `database.sqlcipher.transaction` | ~8 | beginTransaction/endTransaction |
| `database.sqlite.open_legacy` | ~6 | openDatabase 4-arg, openOrCreateDatabase 3-arg |
| `database.sqlite.query` | ~4 | rawQuery x2, query 8-arg |
| `database.sqlite.insert_legacy` | ~4 | insertWithOnConflict + spurious from insert/insertOrThrow |
| `database.sqlite.insert` | ~3 | insert, insertOrThrow |
| `database.sqlcipher.open` | ~3 | SQLiteOpenHelper.getWritableDatabase |
| `database.sqlite.update_legacy` | ~2 | updateWithOnConflict + spurious from update |
| `database.room.callback` | ~2 | onOpen x2 |
| `database.room.builder` | ~2 | Room.databaseBuilder x2 |
| `database.sqlite.update` | 1 | update |
| `database.sqlite.open` | 1 | openDatabase 3-arg |
| `database.sqlite.delete_result` | 1 | delete post-call |
| `database.sqlite.delete` | 1 | delete |
| `database.sqlcipher.pragma` | 1 | PRAGMA key via execSQL |
| `database.room.legacy` | 1 | LiveData.observe |

---

#### Known issues and gaps

##### Hook-side bugs requiring fixes in `sql.ts`

**B1 - SQLCipher openOrCreateDatabase wrong signatures (4 hook registrations)**
- Affects: `hook_SQLCipher()` x2, `hook_room_library()` x2
- `(File,String)` and `(String,char[])` do not exist in SQLCipher 4.5.0
- Correct signatures from runtime: `(File,String,CursorFactory)`, `(File,String,CursorFactory,SQLiteDatabaseHook)`, `(File,String,CursorFactory,SQLiteDatabaseHook,DatabaseErrorHandler)` and String-path equivalents

**B2 - SQLCipher getWritableDatabase/getReadableDatabase hooked on wrong class**
- Affects: `hook_SQLCipher()`
- These methods belong to `SQLiteOpenHelper`, not `SQLiteDatabase`
- SQLiteOpenHelper variant at the top of hook_SQLCipher() works correctly; the SQLiteDatabase attempts should be removed

**B3 - SQLCipher execSQL(String) installs but fires zero events**
- Affects: `hook_SQLCipher()`
- Hook installs without error; multiple execSQL calls on net.sqlcipher.database.SQLiteDatabase produce zero database.sqlcipher.exec events
- Cause unclear; possible SQLCipher internal routing or class loading issue; requires further investigation

**B4 - SQLCipher duplicate hook on same overload**
- Affects: `hook_SQLCipher()`
- `openOrCreateDatabase(File,String)` registered twice; second assignment silently overwrites first

**B5 - WCDB beginTransaction fatal Frida script error**
- Affects: `hook_wcdb()`
- `.implementation` assigned directly on ambiguous method with multiple overloads: `()` and `(SQLiteTransactionListener,boolean)`
- Throws `Error: beginTransaction(): has more than one overload` at hook install time
- Prevents installation of beginTransaction, endTransaction, and setTransactionSuccessful hooks entirely
- Fix: use `safeOverload(wcdbDatabase.beginTransaction, context, "")` to select no-arg overload

**B6 - WCDB rawQuery wrong overload signature**
- Affects: `hook_wcdb()`
- Hooked as `(String,String[])` but WCDB rawQuery takes `(String,Object[])` and `(String,Object[],CancellationSignal)`

**B7 - RoomDatabase.insert/update/delete architectural error**
- Affects: `hook_room_library()`
- `RoomDatabase.insert(Object)`, `RoomDatabase.update(Object)`, `RoomDatabase.delete(Object)` do not exist on RoomDatabase
- Room-generated DAO uses EntityInsertionAdapter and EntityDeletionOrUpdateAdapter internally
- These hooks will never fire for any Room app regardless of test app

**B8 - FlowCollector.emit wrong overload signature**
- Affects: `hook_room_library()`
- Kotlin suspend functions require `(Object,Continuation)` not `(Object)`

**B9 - SQLCipher setTransactionSuccessful not hooked**
- Affects: `hook_SQLCipher()`
- `beginTransaction` and `endTransaction` are hooked; `setTransactionSuccessful` is not despite being a logical pair

**B10 - sqlite3_prepare16 variants: sql field captures only first character**
- Affects: `hook_native_sqlite()`
- `args[1].readUtf8String()` called on a UTF-16 string pointer for sqlite3_prepare16* variants
- Returns only the first character of the SQL statement
- Fix: use `args[1].readUtf16String()` for sqlite3_prepare16, sqlite3_prepare16_v2, sqlite3_prepare16_v3

**B11 - sqlite3_bind_double: wrong value due to ARM64 calling convention**
- Affects: `hook_native_sqlite()`
- ARM64 passes float arguments in FP registers (d0-d7), not general-purpose registers
- `args[2].readDouble()` reads from the wrong location; value is garbage
- Fix: use Frida's `this.context` or platform-specific register access for double arguments

**B12 - sqlite3_bind_blob: readUtf8String() called on binary data**
- Affects: `hook_native_sqlite()`
- Binary blob pointer is read as a UTF-8 string; fails on non-UTF8 byte sequences
- Produces "Error reading value" in captured events
- Fix: read args[3] (the blob length) and use `args[2].readByteArray(length)` then hex-encode

**B13 - sqlite3_bind_text not triggered: Android JNI uses bind_text16**
- Affects: `hook_native_sqlite()`
- Android's SQLite JNI bridge uses `sqlite3_bind_text16` for all Java String values
- `sqlite3_bind_text` (UTF-8) never called from the Java layer on standard Android
- `sqlite3_bind_text16` is not currently hooked
- Fix: add hook for `sqlite3_bind_text16`; document sqlite3_bind_text as unreachable from Java

##### Format inconsistency (parser impact)

**F1 - Mixed JSON and raw ANSI string emission**
- Approximately half of all hooks emit structured JSON via `createDatabaseEvent()`
- The other half emit raw strings with ANSI color codes via direct `am_send()`
- Raw string events fall through `DatabaseParser.parse_legacy_data()` as `database.legacy`,
  `database.sqlite.query_legacy`, `database.native.legacy`, `database.sqlcipher.legacy`,
  `database.wcdb.legacy`, or `database.room.legacy` with only `raw_data` in metadata
- Affected: query 7/9/10-arg, queryWithFactory, rawQueryWithFactory, insertWithOnConflict,
  openDatabase 4-arg, openOrCreateDatabase 3-arg, updateWithOnConflict, all WCDB hooks,
  sqlite3_prepare*, sqlite3_step, sqlite3_close*, sqlite3_bind_*, SQLCipher close/rawExecSQL,
  LiveData.observe, RoomDatabase.query, SupportSQLiteDatabase.execSQL

**F2 - ContentValues serialized as Java class description**
- `database.sqlite.insert`, `database.sqlite.update` show content_values entries as
  `<instance: java.lang.Object, $className: java.lang.Integer>` instead of actual values
- Fix: call `.toString()` on each value during ContentValues iteration, or use type-specific extraction

**F3 - Dual event emission for insert/insertOrThrow**
- Both methods call `insertWithOnConflict` internally
- Each insert operation emits `database.sqlite.insert` (correct) AND `database.sqlite.insert_legacy`
  (spurious from insertWithOnConflict hook)

**F4 - database_object field in Room callback contains "[object Object]"**
- `db.toString()` on a Frida Java wrapper returns `[object Object]`
- Fix: call `db.getPath()` or another meaningful method instead

##### Architectural gaps (not hook bugs)

**G1 - sqlite3_open16 not triggerable from API 24+ apps**
- Hook installs correctly on libsqlite.so
- Android API 24+ linker namespace isolation prevents app-side native code from calling
  libsqlite.so symbols directly
- App native test component uses a statically compiled SQLite amalgamation that does not
  route through the hooked libsqlite.so addresses
- Hook would fire correctly on API < 23 devices where namespace isolation does not exist
- Confirmed on API 34 test device: hook installs, no events observed

**G2 - sqlite3_bind_int not triggerable from API 24+ apps**
- Same linker namespace isolation issue as G1
- Android JNI bridge always uses sqlite3_bind_int64 for all Java integer bindings regardless of value type
- Hook would fire from native C code calling libsqlite.so directly (possible on API < 24)
- Confirmed on API 34 test device: hook installs, no events observed (only sqlite3_bind_int64 fires)

**G3 - Room.SupportSQLiteOpenHelper.Callback.onCreate timing**
- Fires only when the database file does not yet exist
- Test app calls `Context.deleteDatabase()` before each `Room.databaseBuilder()` call
  to ensure onCreate fires on every run

**G4 - Room+SQLCipher PRAGMA key path via SupportFactory**
- `SupportFactory` with byte[] passphrase sets the encryption key via JNI; never calls
  `execSQL("PRAGMA key=...")` in the Java layer
- The `database.sqlcipher.pragma` hook is only reachable via explicit Java-side
  `execSQL("PRAGMA key=...")` call, which SQLCipher 4.x rejects with an exception
- Hook fires before the exception propagates; event is captured despite the throw


## File System Hooks - E2E Test Results

### Test app

`tests/android_apps/e2e_tests/FileE2E`

- package `com.test.filee2e`
- Min SDK: 24

### Hook files

- `agent/file/file_system_hooks.ts`

### Logcat tags

- `FS_E2E` - MainActivity and all Java test classes
- `FS_E2E_NATIVE` - `file_delete_native.c` (native unlink trigger)

### Run commands

#### Baseline (no hooks)

```bash
cd tests/android_apps/e2e_tests/FileE2E
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk

adb shell am force-stop com.test.filee2e
adb shell am start -n com.test.filee2e/.MainActivity
adb logcat -v color time -s FS_E2E:'*' -s FS_E2E_NATIVE:'*' AndroidRuntime:E
```

#### With hooks

```bash
dexray-intercept -s -v --enable-filesystem com.test.filee2e
adb logcat -v color time -s FS_E2E:'*' -s FS_E2E_NATIVE:'*' AndroidRuntime:E
```

Note: `--hooks-filesystem` is a legacy alias that enables both `file_system_hooks`
and `database_hooks` together. Use `--enable-filesystem` to isolate file hooks only.

#### Profile event type summary (jq)

```bash
FILE=$(ls profile_com.test.filee2e_*.json | tail -1)
jq '.FILE_SYSTEM[].event_type' "$FILE" | sort | uniq -c | sort -rn
jq '[.FILE_SYSTEM[] | {event_type, file_path}]' "$FILE"
jq '[.FILE_SYSTEM[] | select(.event_type == "file.write") | {file_path, offset, length}]' "$FILE"
jq '[.FILE_SYSTEM[] | select(.event_type == "file.read") | {file_path, bytes_read, buffer_size}]' "$FILE"
jq '[.FILE_SYSTEM[] | select(.event_type | startswith("file.delete")) | {event_type, file_path}]' "$FILE"
```

---

### Baseline results (no hooks)

All 4 test modules complete with 0 failures.

| Module | Result | Notes |
|--------|--------|-------|
| FileConstructorTests | pass | 4 passed, 0 failed |
| FileInputStreamTests | pass | 6 passed, 0 failed |
| FileOutputStreamTests | pass | 8 passed, 0 failed |
| FileDeleteTests (Java) | pass | 3 passed, 0 failed |
| FileDeleteNative | pass | 1 passed, 0 failed |

---

### Hook coverage matrix

#### `hook_filesystem_accesses()` - Java file constructors and streams

##### `java.io.File` constructors

| Hook ID | Hook site | Event type | Exercised by app | Emitting events | Notes |
|---------|-----------|------------|-----------------|----------------|-------|
| FC-1 | `File.$init(File, String)` - new[0] | `file.create` | yes - `FileConstructorTests.testFile_File_String` | no - no implementation assigned | Declared in `var File.new[0]`; never assigned `.implementation`; no event emitted |
| FC-2 | `File.$init(String)` - new[1] | `file.create` | yes - `FileConstructorTests.testFile_String` | yes | Correct; path appears in profile |
| FC-3 | `File.$init(String, String)` - new[2] | `file.create` | yes - `FileConstructorTests.testFile_String_String` | yes | Correct; parent and child fields present |
| FC-4 | `File.$init(URI)` - new[3] | `file.create` | yes - `FileConstructorTests.testFile_URI` | no - no implementation assigned | Declared in `var File.new[3]`; never assigned `.implementation`; no event emitted |

##### `java.io.FileInputStream` constructors and reads

| Hook ID | Hook site | Event type | Exercised by app | Emitting events | Notes |
|---------|-----------|------------|-----------------|----------------|-------|
| FIS-1 | `FileInputStream.$init(File)` - new[0] | `file.stream.create` | yes - `FileInputStreamTests.testFIS_File` | yes | Correct; stream_type: input, file_path resolved |
| FIS-2 | `FileInputStream.$init(FileDescriptor)` - new[1] | `file.stream.create` | yes - `FileInputStreamTests.testFIS_FileDescriptor` | indirectly | No implementation assigned on new[1]; `fis_fd.log` appears in `file.stream.create` because the test opens `FileInputStream(File)` first to obtain the FD - that prior call fires FIS-1 |
| FIS-3 | `FileInputStream.$init(String)` - new[2] | `file.stream.create` | yes - `FileInputStreamTests.testFIS_String` | indirectly | No implementation assigned on new[2]; Android runtime internally chains `FileInputStream(String)` through `FileInputStream(File)`; FIS-1 fires on the internal delegation, not on the String constructor itself |
| FIS-4 | `FileInputStream.read()` - read[0] | `file.read` | yes - `FileInputStreamTests.testFIS_read_noarg` | indirectly | No implementation assigned on read[0]; Android runtime delegates no-arg `read()` to `read(byte[],int,int)` with a 1-byte internal buffer; FIS-6 fires instead |
| FIS-5 | `FileInputStream.read(byte[])` - read[1] | `file.read` | yes - `FileInputStreamTests.testFIS_read_bytes` | yes - with duplicate | Correct; also causes a duplicate event because Android internally delegates `read(byte[])` to `read(byte[],int,int)`; both read[1] and read[2] hooks fire on the same call; results in 2 `file.read` events for `fis_read1.log` |
| FIS-6 | `FileInputStream.read(byte[], int, int)` - read[2] | `file.read` | yes - `FileInputStreamTests.testFIS_read_bytes_offset` | yes | Correct; offset, length, bytes_read all present |

##### `java.io.FileOutputStream` constructors and writes

| Hook ID | Hook site | Event type | Exercised by app | Emitting events | Notes |
|---------|-----------|------------|-----------------|----------------|-------|
| FOS-1 | `FileOutputStream.$init(File)` - new[0] | `file.stream.create` | yes - `FileOutputStreamTests.testFOS_File` | no - no implementation assigned | No event; also does not populate `TraceFS`; downstream write events from this stream resolve as `[unknown]` |
| FOS-2 | `FileOutputStream.$init(File, boolean)` - new[1] | `file.stream.create` | yes - `FileOutputStreamTests.testFOS_File_Boolean` | no - no implementation assigned | Same gap as FOS-1 |
| FOS-3 | `FileOutputStream.$init(FileDescriptor)` - new[2] | `file.stream.create` | yes - `FileOutputStreamTests.testFOS_FileDescriptor` | no - no implementation assigned | Same gap as FOS-1 |
| FOS-4 | `FileOutputStream.$init(String)` - new[3] | `file.stream.create` | yes - `FileOutputStreamTests.testFOS_String` | no - no implementation assigned | Same gap as FOS-1 |
| FOS-5 | `FileOutputStream.$init(String, boolean)` - new[4] | `file.stream.create` | yes - `FileOutputStreamTests.testFOS_String_Boolean` | no - no implementation assigned | Same gap as FOS-1 |
| FOS-6 | `FileOutputStream.write(byte[])` - write[0] | `file.write` | yes - `FileOutputStreamTests.testFOS_write_bytes` | no - no implementation assigned | Declared in `var FileOuputStream.write[0]`; no event; data content not captured |
| FOS-7 | `FileOutputStream.write(int)` - write[1] | `file.write` | yes - `FileOutputStreamTests.testFOS_write_int` | no - no implementation assigned | Declared in `var FileOuputStream.write[1]`; no event; data content not captured |
| FOS-8 | `FileOutputStream.write(byte[], int, int)` - write[2] | `file.write` | yes - `FileOutputStreamTests.testFOS_write_bytes_offset` | yes - with path gap | Implementation present; fires for all write(byte[],int,int) calls including those from write[0] and write[1] internal delegation; `file_path` is always `[unknown]` because no `FileOutputStream` constructor hook populates `TraceFS`; data content and length are captured correctly |

#### `hook_filesystem_deletes()` - file deletion

| Hook ID | Hook site | Event type | Exercised by app | Emitting events | Notes |
|---------|-----------|------------|-----------------|----------------|-------|
| FD-1 | `File.delete()` | `file.delete.java` | yes - `FileDeleteTests.testJavaDelete_dex`, `testJavaDelete_jar` | yes | Fires only when path includes "jar" or ends with "dex"; filter uses `includes("jar")` not `endsWith(".jar")` - any path containing the string "jar" would trigger falsely |
| FD-2 | `unlink` (native libc) | `file.delete.native` | yes - `FileDeleteTests.testNativeUnlink` via `FileDeleteNative.unlinkFile` | yes | Correct; path and result captured |

## Runtime results (with hooks)

### App stability under hooks

All 4 modules, 22 Java tests + 1 native test completed with 0 failures - identical to baseline.

### Observed event types in profile (`--enable-filesystem`)

| Event type | Count | Source |
|------------|-------|--------|
| `file.write` | 17 | `FileOutputStream.write(byte[],int,int)` - all paths including internal delegation from write[0] and write[1] |
| `file.create` | 8 | `File.$init(String)` and `File.$init(String,String)` only; includes 1 system-internal path (`/system/etc/security/cacerts`) and 1 framework path (`base.apk`) |
| `file.stream.create` | 6 | `FileInputStream.$init(File)` only; FIS-2 and FIS-3 fire indirectly via internal delegation |
| `file.read` | 4 | `FileInputStream.read(byte[])` and `read(byte[],int,int)`; includes 1 duplicate for `fis_read1.log` due to internal delegation |
| `file.delete.java` | 2 | `File.delete()` on `.dex` and `.jar` paths |
| `file.delete.native` | 1 | `unlink()` via JNI |

### Hook flag note

`--hooks-filesystem` is a legacy CLI alias that enables both `file_system_hooks` and
`database_hooks` simultaneously. It produces `[HOOK ERROR]` lines for SQLCipher, WCDB,
and Room classes (expected - those libraries are absent from this app). Use
`--enable-filesystem` to enable file hooks in isolation.

---

## Known issues

### Hook-side bugs and gaps in `file_system_hooks.ts`

| ID | Description | Impact |
|----|-------------|--------|
| FS-1 | 12 of 20 declared hook sites have no `.implementation` assigned: `File.$init(File,String)` (new[0]), `File.$init(URI)` (new[3]), `FileInputStream.$init(FileDescriptor)` (new[1]), `FileInputStream.$init(String)` (new[2]), `FileInputStream.read()` (read[0]), all 5 `FileOutputStream.$init` overloads (new[0..4]), `FileOutputStream.write(byte[])` (write[0]), `FileOutputStream.write(int)` (write[1]) | No events emitted for these sites; app-side triggers exist for all of them |
| FS-2 | No `FileOutputStream` constructor hook populates `TraceFS`; `FileOutputStream.write(byte[],int,int)` (write[2]) resolves the target filename via `TraceFS["fd"+hashCode()]` then falls back to `TraceFD`; neither map is populated for output streams | All 17 `file.write` events show `file_path: "[unknown]"`; write content is captured correctly but is not attributable to a file path |
| FS-3 | `FileInputStream.read(byte[])` (read[1]) and `FileInputStream.read(byte[],int,int)` (read[2]) both have active implementations; Android internally delegates `read(byte[])` to `read(byte[],int,int)`; both hooks fire on a single `read(byte[])` call | Duplicate `file.read` events for every `read(byte[])` call; observed as 2 events for `fis_read1.log` |
| FS-4 | In `hook_filesystem_deletes()`: when `deactivate_unlink` is true, `safeAttach` is called first and then `safeReplace` is called on the same `unlinkPtr`; attaching and replacing the same native address in Frida is undefined - only one interceptor type can be active per address | When `deactivate_unlink` is true, behavior is undefined; one of the two interceptors will silently lose; logging logic from the attach body must be moved into the replace body |
| FS-5 | `get_path_from_fd` is imported at the top of the file but never called anywhere | Intended resolver for `FileInputStream.$init(FileDescriptor)` and `FileOutputStream.$init(FileDescriptor)` when those constructors are implemented; currently dead import |
| FS-6 | Safety wrappers (`safePerform`, `safeUse`, `safeOverload`, `safeImplementation`) are not used anywhere in this file; all hooks use raw `Java.use`, direct `.implementation =`, and bare `Java.perform` | Hook failures produce no `[HOOK ERROR]` output and may silently abort sibling hook installation; inconsistent with all other hook files in `agent/` |
| FS-7 | `File.delete()` hook filter uses `path.includes("jar")` rather than `path.endsWith(".jar")`; any file path containing the substring "jar" (e.g. `/jardir/file.txt`) triggers the hook | Minor false positive risk; `endsWith(".jar")` is the correct check |
| FS-8 | `File.delete()` hook returns hardcoded `true` regardless of whether deletion succeeded | Hook always reports deletion as successful; actual return value from `File.delete()` is discarded |
| FS-9 | `bytes_written` field in `FileSystemEvent` is never populated by any hook; `FileOutputStream.write(byte[],int,int)` emits `length` (the requested write size) but does not capture the return value | All `file.write` events show `bytes_written: null` in the profile JSON |
| FS-10 | `CONFIG.printLibc: false` in the hook config and comments reference libc-level `open`, `read`, `write` hooks as planned; no hook sites for these exist in the current implementation | No `file.open` or libc-level `file.read`/`file.write` events will ever appear; if implemented in future, a `LibcFileTests` class is needed in the test app |

### Parser and model issues

| ID | Location | Description |
|----|----------|-------------|
| FS-P-1 | `FileSystemEvent` | `bytes_written` field defined in model but never populated by any hook; always `null` in profile |
| FS-P-2 | `FileSystemParser` | `should_dump_ascii`, `should_dump_hex`, `max_display_length` are listed in `field_mapping` with `None` as target event field; these are processed locally but the pattern is inconsistent - they act as processing flags, not event fields, and could be removed from the mapping dict |
| FS-P-3 | `FileSystemParser` | `hexdump_display` is intentionally excluded from `get_event_data()` (ANSI codes for console only); the exclusion comment is correct but the field is still set on the event object; a consumer iterating `event.__dict__` would encounter it unexpectedly |

---

### Summary

| Hook group | Total declared sites | Implementation present | Emitting correctly | Emitting with known issue | Not emitting |
|------------|---------------------|----------------------|--------------------|--------------------------|--------------|
| `File.$init` | 4 | 2 (new[1], new[2]) | 2 | 0 | 2 (new[0], new[3]) |
| `FileInputStream.$init` | 3 | 1 (new[0]) | 1 | 2 (new[1], new[2] - indirect only) | 0 |
| `FileInputStream.read` | 3 | 2 (read[1], read[2]) | 1 (read[2]) | 2 (read[0] indirect; read[1] duplicate) | 0 |
| `FileOutputStream.$init` | 5 | 0 | 0 | 0 | 5 |
| `FileOutputStream.write` | 3 | 1 (write[2]) | 0 | 1 (write[2] - path always unknown) | 2 (write[0], write[1]) |
| `File.delete()` | 1 | 1 | 1 | 0 | 0 |
| `unlink` (native) | 1 | 1 | 1 | 0 | 0 |
| **Total** | **20** | **8** | **6** | **5** | **9** |


## Network Hooks - E2E Test Results

### Test app

`tests/android_apps/e2e_tests/NetworkE2E`
Package: `com.test.networke2e`

### Hook files

- `agent/network/web.ts`
- `agent/network/sockets.ts`

### Hook groups and profile types

- Web hooks -> `WEB`
- Socket hooks -> `NETWORK_SOCKETS`

### Logcat tags

- `NETWORK_E2E` - MainActivity and all Java test blocks
- `NET_NATIVE_SOCKETS` - native C socket tests in net_native_sockets.c

---

### Test environment

#### Recommended emulator

AVD (API 30 / 34, Google APIs x86_64) with network access enabled

#### Required permissions

`INTERNET` - normal permission, granted automatically from manifest.
No `adb shell pm grant` needed.

#### Hook run command

`dexray-intercept -s -v --hooks-network com.test.networke2e`

#### Baseline run command

```
adb shell am force-stop com.test.networke2e
adb shell am start -n com.test.networke2e/.MainActivity
adb logcat -v color threadtime -s NETWORK_E2E:'*' -s NET_NATIVE_SOCKETS:'*' -s AndroidRuntime:E
```

#### Profile event type summary (jq)

```
FILE=$(ls profile_com.test.networke2e_*.json | tail -1)
jq '.WEB[].event_type' "$FILE" | sort | uniq -c | sort -rn
jq '.NETWORK_SOCKETS[].event_type' "$FILE" | sort | uniq -c | sort -rn
```

---

### Baseline results (no hooks)

All test sections run to completion. No errors or crashes.

| Section | Result | Notes |
|---------|--------|-------|
| runWebViewTests | pass | All 7 WebView triggers confirmed individually in log |
| runUrlAndHttpUrlConnectionTests | pass | MiniHttpServer local phase + external postman-echo.com |
| runHttpsUrlConnectionTests | pass | postman-echo.com HTTPS GET 200 |
| runOkHttp3Tests | pass | postman-echo.com GET 200 |
| runOkHttpLegacyTests | pass | postman-echo.com GET 200 |
| runRetrofitTests | pass | sync 200 + async 200 |
| runVolleyTests | pass | postman-echo.com GET succeeded |
| runTcpSocketTests | pass | 3 accepts, Socket.$init and both connect overloads confirmed |
| runLocalSocketTests | pass | accept + connect confirmed |
| runUdpSocketTests | pass | DatagramSocket.connect confirmed |
| runWebSocketTests | pass | local MiniWebSocketServer echo confirmed |
| NativeSocketTests | pass | 26 passed, 0 failed |

---

### Hook coverage matrix

#### web.ts - `install_url_hooks()`

| Hook ID | Hook site | Event type | Observed | Count | Notes |
|---------|-----------|-----------|----------|-------|-------|
| WEB-1 | `URL.$init(String)` | `url.creation` | yes | 5 | Fires for MiniHttpServer URL, external URLs, and Volley-internal URL construction |
| WEB-2 | `URL.openConnection()` | `url.open_connection` | yes | 4 | Fires for each HttpURLConnection path |
| WEB-3 | `HttpURLConnection.connect` [url_hooks] | `url.connection` | no | 0 | Dead hook - assignment overwritten by `install_http_hooks` which assigns `.implementation` on the same method reference after this block; `url.connection` event type never emitted |
| WEB-4 | `URI.$init(String)` | `uri.creation` | yes | 19 | Includes SSL certificate validation URIs generated during TLS handshakes; genuine app-triggered URIs confirmed |

#### web.ts - `install_http_hooks()`

| Hook ID | Hook site | Event type | Observed | Count | Notes |
|---------|-----------|-----------|----------|-------|-------|
| WEB-5 | `HttpURLConnection.setRequestMethod` | `http.request_method` | no | 0 | Hook targets abstract base class; runtime object is `com.android.okhttp.internal.huc.HttpURLConnectionImpl`; abstract method hook does not intercept concrete override dispatch |
| WEB-6 | `HttpURLConnection.connect` [http_hooks] | `http.connect` | no | 0 | Same - concrete `HttpURLConnectionImpl.connect` not reached via abstract base class hook |
| WEB-7 | `HttpURLConnection.getOutputStream` | `http.output_stream` | no | 0 | Same |
| WEB-8 | `HttpURLConnection.getInputStream` | `http.input_stream` | no | 0 | Same |

#### web.ts - `install_https_hooks()`

| Hook ID | Hook site | Event type | Observed | Count | Notes |
|---------|-----------|-----------|----------|-------|-------|
| WEB-9 | `HttpsURLConnection.setRequestMethod` | `https.request_method` | no | 0 | Same pattern as WEB-5 - abstract base class hook; runtime object is concrete `HttpsURLConnectionImpl` |
| WEB-10 | `HttpsURLConnection.connect` | `https.connect` | no | 0 | Same |
| WEB-11 | `HttpsURLConnection.getInputStream` | `https.input_stream` | no | 0 | Same |

#### web.ts - `install_okhttp_hooks()`

| Hook ID | Hook site | Event type | Observed | Count | Notes |
|---------|-----------|-----------|----------|-------|-------|
| WEB-12 | `okhttp3.OkHttpClient.newCall(Request)` | `okhttp.request` | yes | 3 | OkHttp3 GET, Retrofit sync reuse, Retrofit async reuse |
| WEB-13 | `okhttp.OkHttpClient.newCall(Request)` | `okhttp_old.request` | no | 0 | HOOK ERROR at install: `java.lang.ClassNotFoundException: "okhttp.OkHttpClient"`; correct class name is `com.squareup.okhttp.OkHttpClient` |
| WEB-14 | `HttpURLConnectionImpl.setRequestProperty` | `okhttp.request_property` | yes | 2 | Concrete class hook works; fires for MiniHttpServer and external POST phases |
| WEB-15 | `HttpURLConnectionImpl.setRequestMethod` | `okhttp.request_method` | yes | 4 | Concrete class hook works |

#### web.ts - `install_retrofit_hooks()`

| Hook ID | Hook site | Event type | Observed | Count | Notes |
|---------|-----------|-----------|----------|-------|-------|
| WEB-16 | `retrofit2.OkHttpCall.execute` | `retrofit.request` | yes | 1 | Sync execute path confirmed |
| WEB-17 | `retrofit2.OkHttpCall.execute` | `retrofit.response` | yes | 1 | Response event on same execute call |
| WEB-18 | `retrofit2.Call.enqueue` | `retrofit.async_request` | no | 0 | Interface hook; `Call` is a Retrofit2 interface; Frida does not intercept the concrete `OkHttpCall.enqueue` dispatch via the interface declaration; `retrofit2.OkHttpCall.enqueue` is the correct target |

#### web.ts - `install_volley_hooks()`

| Hook ID | Hook site | Event type | Observed | Count | Notes |
|---------|-----------|-----------|----------|-------|-------|
| WEB-19 | `StringRequest.$init(int,String,Listener,ErrorListener)` | `volley.string_request` | yes | 1 | Correct |
| WEB-20 | `RequestQueue.add` | `volley.queue_request` | yes | 1 | Correct |

#### web.ts - `install_websocket_hooks()`

| Hook ID | Hook site | Event type | Observed | Count | Notes |
|---------|-----------|-----------|----------|-------|-------|
| WEB-21 | `okhttp3.WebSocket.send(String)` | `websocket.send_text` | no | 0 | Interface hook; runtime object is `okhttp3.internal.ws.RealWebSocket`; Frida does not intercept interface dispatch; `RealWebSocket.send` is the correct target |
| WEB-22 | `okhttp3.WebSocketListener.onOpen` | `websocket.opened` | no | 0 | Abstract class hook; app subclasses `WebSocketListener` with anonymous class; hook on abstract base does not intercept override dispatch on the subclass |
| WEB-23 | `okhttp3.WebSocketListener.onMessage(WebSocket,String)` | `websocket.message_received` | no | 0 | Same as WEB-22 |

#### web.ts - `install_webview_hooks()`

| Hook ID | Hook site | Event type | Observed | Count | Notes |
|---------|-----------|-----------|----------|-------|-------|
| WEB-24 | `WebView.loadUrl(String)` | `webview.load_url` | yes | 1 | Correct |
| WEB-25 | `WebView.loadUrl(String,Map)` | `webview.load_url_with_headers` | yes | 1 | Correct |
| WEB-26 | `WebView.loadData` | `webview.load_data` | yes | 1 | Correct |
| WEB-27 | `WebView.postUrl` | `webview.post_url` | yes | 1 | Correct |
| WEB-28 | `WebViewClient.onPageStarted` | `webview.page_started` | yes | 1 | Triggered via direct call on subclass instance; real WebView navigation not possible under Theme.NoDisplay |
| WEB-29 | `WebViewClient.onPageFinished` | `webview.page_finished` | yes | 2 | 1 from direct call + 1 emitted asynchronously by WebView engine after `loadUrl("https://example.com")` |
| WEB-30 | `WebViewClient.shouldOverrideUrlLoading(WebView,String)` | `webview.url_override` | yes | 1 | Triggered via direct call on subclass instance |

### sockets.ts - `hook_java_socket_communication()`

| Hook ID | Hook site | Event type | Observed | Count | Notes |
|---------|-----------|-----------|----------|-------|-------|
| SOCK-1 | `ServerSocket.accept()` | `socket.java.server_accept` | yes | 4 | 3 from runTcpSocketTests + 1 from OkHttp internal connection pool reuse |
| SOCK-2 | `Socket.$init(String,int)` | `socket.java.init` | yes | 1 | runTcpSocketTests Socket.$init trigger confirmed |
| SOCK-3 | `Socket.connect(SocketAddress,int)` | `socket.java.connect` | yes | 12 | Shares event type with SOCK-4; high count includes OkHttp and Retrofit internal connection management |
| SOCK-4 | `Socket.connect(SocketAddress)` | `socket.java.connect` | yes | (included above) | Same event type as SOCK-3; both overloads fire and emit identical event_type |
| SOCK-5 | `LocalServerSocket.accept()` | `socket.java.local_accept` | yes | 1 | runLocalSocketTests confirmed |
| SOCK-6 | `DatagramSocket.connect(InetAddress,int)` | `socket.java.datagram_connect` | yes | 1 | runUdpSocketTests confirmed |

### sockets.ts - `hook_bionic_socket_commuication()`

| Hook ID | Hook site | Event type | Observed | Count | Notes |
|---------|-----------|-----------|----------|-------|-------|
| SOCK-7 | `socket` (libc.so) | `socket.native.created` | partial | 16 | Event emitted via `addSocketToList` when a new fd passes through `bind` or `connect` hooks - not directly from the `socket` hook; a bare `socket()` call before `bind`/`connect` emits no event; `am_send` in the `socket` hook `onLeave` was previously present but is now commented out |
| SOCK-8 | `bind` (libc.so) | `socket.native.bind` | yes | 9 | Correct; fires for Java TCP, UDP, and WebSocket server binds |
| SOCK-9 | `connect` (libc.so) | `socket.native.connect` | yes | 7 | Correct; fires for outbound TCP connections |
| SOCK-10 | `write` (libc.so) | `socket.native.write` + `socket.native.write_data` | yes | 3 + 3 | Fires for Java socket write path; native `send()` data does not route through `write` |
| SOCK-11 | `read` (libc.so) | `socket.native.read` + `socket.native.read_data` | yes | 8 + 8 | Fires for Java socket read path |
| SOCK-12 | `sendto` (libc.so) | `socket.native.sendto` + `socket.native.sendto_data` | yes | 44 + 44 | High count expected; HTTPS and HTTP traffic uses `sendto` internally; explicit-address UDP path confirmed via NativeSocketTests test_sendto_recvfrom |
| SOCK-13 | `recvfrom` (libc.so) | `Libc::recvfrom` | yes | 29 | Fires correctly; event_type uses old `Libc::` format inconsistent with `socket.native.*` naming used by other hooks in same file |
| SOCK-14 | `send` (libc.so) | `Libc::send` | no | 0 | Hook installs without error; NativeSocketTests calls `send()` and confirms correct byte counts in logcat; events absent from profile; root cause: `onLeave` guard checks `this.sockType` which is never stored in `onEnter` (should be local `sockType`); guard evaluates to `undefined === "unix:stream"` which is false, so the guard passes; actual failure is in buffer read or `am_send` downstream - requires further investigation with verbose hook logging |
| SOCK-15 | `recv` (libc.so) | `Libc::recv` | no | 0 | Hook installs without error; NativeSocketTests calls `recv()` and confirms correct data in logcat; events absent; root cause: `buf.readByteArray(this.len)` where `this.len` is never set in `onEnter` (only `this.sd`, `this.addr`, `this.buflen` stored); `readByteArray(undefined)` throws before `am_send` is reached |
| SOCK-16 | `sendmsg` (libc.so) | `Libc::sendmsg` | yes | 2 | Fires; event_type uses old `Libc::` format; NativeSocketTests test_sendmsg_recvmsg confirmed as trigger |
| SOCK-17 | `recvmsg` (libc.so) | `Libc::recvmsg` | yes | 2 | Fires; same format inconsistency as SOCK-16 |
| SOCK-18 | `close` (libc.so) | `Libc::close` | no | 0 | Hook installs; `am_send` line present in source but commented out; no event ever emitted |

---

## Known issues

### Hook-side bugs

| ID | File | Description | Impact |
|----|------|-------------|--------|
| N-WEB-1 | web.ts | `install_url_hooks` assigns `.implementation` on `HttpURLConnection.connect` to emit `url.connection`; `install_http_hooks` then assigns `.implementation` on the same reference to emit `http.connect`; second assignment silently overwrites first | `url.connection` event type never emitted; WEB-3 dead |
| N-WEB-2 | web.ts | `HttpURLConnection`, `HttpsURLConnection` hooks target abstract base classes; runtime objects are `HttpURLConnectionImpl` / `HttpsURLConnectionImpl` concrete classes; Frida does not propagate `.implementation` assignments on abstract methods to concrete overrides | WEB-5 through WEB-11 (6 hook sites) never fire; all `http.*` and `https.*` event types absent |
| N-WEB-3 | web.ts | `okhttp.OkHttpClient.newCall` uses wrong class name `okhttp.OkHttpClient`; correct name is `com.squareup.okhttp.OkHttpClient` | HOOK ERROR at install; `okhttp_old.request` event never emitted; WEB-13 dead |
| N-WEB-4 | web.ts | `retrofit2.Call.enqueue` hooks the interface declaration; Frida does not intercept concrete `OkHttpCall.enqueue` dispatch via interface hook; correct target is `retrofit2.OkHttpCall.enqueue` | `retrofit.async_request` event never emitted; WEB-18 dead |
| N-WEB-5 | web.ts | `okhttp3.WebSocket.send` hooks the interface; runtime object is `okhttp3.internal.ws.RealWebSocket`; same interface interception limitation as N-WEB-4 | `websocket.send_text` event never emitted; WEB-21 dead |
| N-WEB-6 | web.ts | `okhttp3.WebSocketListener.onOpen` and `onMessage` hook abstract class methods; app subclass anonymous instance overrides these; hook on abstract base does not intercept subclass override dispatch | `websocket.opened` and `websocket.message_received` events never emitted; WEB-22 and WEB-23 dead |
| N-SOCK-1 | sockets.ts | `send` hook `onLeave`: guard uses `this.sockType` which is never stored in `onEnter`; evaluates as `undefined`; guard passes but subsequent buffer handling or `am_send` fails silently | `Libc::send` events never emitted despite correct `send()` calls from NativeSocketTests |
| N-SOCK-2 | sockets.ts | `recv` hook `onLeave`: `buf.readByteArray(this.len)` where `this.len` is never set in `onEnter`; `readByteArray(undefined)` throws before `am_send` is reached | `Libc::recv` events never emitted despite correct `recv()` calls from NativeSocketTests |
| N-SOCK-3 | sockets.ts | `close` hook: `am_send` line present but commented out | `Libc::close` events never emitted; hook otherwise functional |
| N-SOCK-4 | sockets.ts | `socket` hook `onLeave`: original `am_send` for `socket.native.created` commented out; event only emitted indirectly via `addSocketToList` when a subsequent `bind` or `connect` fires | A bare `socket()` call with no subsequent `bind`/`connect` produces no event |
| N-SOCK-5 | sockets.ts | Event type naming inconsistency: `bind`, `connect`, `write`, `read`, `sendto` emit `socket.native.*` format; `send`, `recv`, `sendmsg`, `recvmsg`, `recvfrom`, `close` emit old `Libc::*` format | Python parser treats `Libc::*` events as generic `[Network]` entries without rich field display; inconsistent profile output |

### Parser and model issues

| ID | Location | Description |
|----|----------|-------------|
| N-P-1 | `NetworkParser`, CLI display | `socket.java.*` events emit `server_info`, `endpoint`, or `connection_string` fields but no `socket_type` field; CLI display shows `(Unknown Socket)` for all Java-layer socket events |
| N-P-2 | `NetworkParser` | `Libc::*` event types have no structured parser branch; all fall through as `network.unknown` or display as generic `[Network]` entries with no field extraction |
| N-P-3 | `NetworkParser` | 43 `network.unknown` events in profile; sources include socket events where `Socket.type()` returns null before emit, events with unrecognised `event_type` strings, and malformed payloads from hook error paths |

### Test environment limitations

| Note | Detail |
|------|--------|
| External endpoints | Tests use postman-echo.com, jsonplaceholder.typicode.com, and connectivitycheck.gstatic.com as ordered fallbacks; first available endpoint is used; results may vary if all external endpoints are unreachable |
| WebView navigation under Theme.NoDisplay | `onPageStarted` and `onPageFinished` are triggered via direct calls on the `WebViewClient` subclass instance; real WebView navigation does not occur; hooks fire on the base class method via `super.onPageStarted/onPageFinished` call chain |
| Local MiniHttpServer | Single-connection server; guaranteed baseline for `http.*` hook paths independent of external availability |
| Local MiniWebSocketServer | Loopback echo server on port 8081; guaranteed baseline for WebSocket paths; `setReuseAddr(true)` prevents bind failures on rapid re-runs |
| Native socket tests | All NativeSocketTests run in single thread using loopback pairs; no threading required; `make_loopback_pair` helper used across all four native test functions |

---

## Summary

| Category | Total hook sites | Observed and emitting | Hook errors | Not emitting - hook bug | Not emitting - dead code |
|----------|-----------------|----------------------|-------------|------------------------|--------------------------|
| URL / URI | 4 | 3 (WEB-1/2/4) | 0 | 0 | 1 (WEB-3 overwritten) |
| HTTP | 4 | 0 | 0 | 4 (WEB-5 to WEB-8 abstract base) | 0 |
| HTTPS | 3 | 0 | 0 | 3 (WEB-9 to WEB-11 abstract base) | 0 |
| OkHttp | 4 | 2 (WEB-14/15) | 1 (WEB-13 wrong class name) | 0 | 1 (WEB-12 fires; WEB-13 dead) |
| Retrofit | 3 | 2 (WEB-16/17) | 0 | 1 (WEB-18 interface hook) | 0 |
| Volley | 2 | 2 (WEB-19/20) | 0 | 0 | 0 |
| WebSocket | 3 | 0 | 0 | 3 (WEB-21 interface; WEB-22/23 abstract) | 0 |
| WebView | 7 | 7 (WEB-24 to WEB-30) | 0 | 0 | 0 |
| Java sockets | 6 | 6 (SOCK-1 to SOCK-6) | 0 | 0 | 0 |
| Native sockets | 12 | 7 (SOCK-8/9/10/11/12/13/16/17 minus format issues) | 0 | 3 (SOCK-14/15 var bug; SOCK-18 commented out) | 1 (SOCK-7 partial only) |
| **Total** | **52** | **29** | **1** | **14** | **3** |


## Process Hooks - E2E Test Results

### Test app

`tests/android_apps/e2e_tests/ProcessE2E`

- package `com.test.processe2e`
- Min SDK: 24

### Hook files

- `agent/process/nativelibrary.ts`
- `agent/process/process.ts`

- `agent/process/runtime.ts`
- `agent/process/string.ts` - not wired in `hooking_profile_loader.ts`; dead stub; no test needed until implemented

### Logcat tags

- `PROCESS_RUNTIME_E2E` - MainActivity and all Java test classes
- `PROCESS_NATIVE` - `processnative.c`
- `PROCESS_CHILD` - `processchild.c` (dlopen target; constructor fires on successful dlopen)

### Hook groups and profile types

- `nativelibrary.ts` hooks -> `PROCESS_NATIVE_LIB`
- `process.ts` hooks -> `PROCESS_CREATION`

- `runtime.ts` hooks -> `RUNTIME_HOOKS`

### Run commands

#### Baseline (no hooks)

```bash
cd tests/android_apps/e2e_tests/ProcessE2E
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk

adb shell am force-stop com.test.processe2e
adb shell am start -n com.test.processe2e/.MainActivity
adb logcat -v color time -s PROCESS_RUNTIME_E2E:'*' -s PROCESS_NATIVE:'*' -s PROCESS_CHILD:'*' AndroidRuntime:E
```

#### With hooks - three separate runs (one per hook file)

```bash
dexray-intercept -s -v --enable-process com.test.processe2e
dexray-intercept -s -v --enable-native-libs com.test.processe2e
dexray-intercept -s -v --enable-runtime com.test.processe2e
```

Note: `--hooks-process` is a legacy alias that enables `process_hooks`, `runtime_hooks`,
and `native_library_hooks` simultaneously. Use the individual flags above to isolate
results per hook file.

#### Profile event type summary (jq)

```bash
FILE=$(ls profile_com.test.processe2e_*.json | tail -1)
jq '.PROCESS_CREATION[]? | .event_type' "$FILE" | sort | uniq -c | sort -rn
jq '.PROCESS_NATIVE_LIB[]? | .event_type' "$FILE" | sort | uniq -c | sort -rn
jq '.RUNTIME_HOOKS[]? | .event_type' "$FILE" | sort | uniq -c | sort -rn
```

#### Fork test note

`test_fork_execve` in `processnative.c` is disabled by default via `#ifdef ENABLE_FORK_TEST`.
`fork()` in a Frida-instrumented process causes the child to inherit Frida's internal threads
in an inconsistent state; `waitpid()` in the parent then hangs indefinitely. The trigger is
confirmed working in baseline. To re-enable after a hook-side fix, uncomment
`target_compile_options(processnative PRIVATE -DENABLE_FORK_TEST)` in `CMakeLists.txt`.

---

### Baseline results (no hooks)

All 5 test modules complete with 0 failures.

| Module | Result | Notes |
|--------|--------|-------|
| ProcessJavaTests | pass | 2 passed, 0 failed |
| RuntimeExecTests | pass | 6 passed, 0 failed |
| RuntimeLoadTests | pass | 2 passed, 0 failed |
| NativeProcessTests | pass | 1 passed, 0 failed |
| ReflectionTests | pass | 7 passed, 0 failed |
| ProcessNative (native) | pass | 5 passed, 0 failed |

---

### Hook coverage matrix

#### `nativelibrary.ts` - `hook_native_lib_loading()`

| Hook ID | Hook site | Event types | Exercised by app | Emitting | Notes |
|---------|-----------|-------------|-----------------|----------|-------|
| NL-1 | `dlopen` (global, success path) | `native.library.load`, `native.library.loaded` | yes - `test_dlopen` `dlopen("libprocesschild.so")` | yes | Fires for all app library loads including `liblog.so` and `libprocessnative.so` at startup |
| NL-2 | `dlopen` (global, failure path) | `native.library.load`, `native.library.load_failed` | yes - `test_dlopen` `dlopen("libdoesnotexist_e2e.so")` | yes | Confirmed `native.library.load_failed` emitting correctly |
| NL-3 | `android_dlopen_ext` (global, success path) | `native.library.load`, `native.library.loaded` | yes - same triggers as NL-1/NL-2 | no - did not fire on test device | Hook installs and resolves at `0x7f9754741bc0`; on this device/API level app-side `dlopen` routes through bare `dlopen`, not `android_dlopen_ext`; hook would fire on devices where the linker routes through `android_dlopen_ext` for namespace-isolated loads |
| NL-4 | `android_dlopen_ext` (global, failure path) | `native.library.load`, `native.library.load_failed` | yes - same as NL-2 | no - same reason as NL-3 | |

#### `process.ts` - `hook_java_process_creation()` and `hook_native_process_creation()`

| Hook ID | Hook site | Event types | Exercised by app | Emitting | Notes |
|---------|-----------|-------------|-----------------|----------|-------|
| PC-1 | `android.os.Process.sendSignal(int, int)` | `process.signal` | yes - `ProcessJavaTests.testSendSignal` (signal 0 to self) | yes | Also fires spuriously for every `killProcess` call due to internal delegation (see PC-11) |
| PC-2 | `android.os.Process.killProcess(int)` | `process.kill` | yes - `ProcessJavaTests.testKillProcess` (pid 99999) | yes | Correct; pid 99999 used to avoid side effects while guaranteeing hook fires |
| PC-3 | `android.os.Process.start(...)` | `process.creation` | not triggerable from user app | no | Zygote-internal method; requires rooted device with modified Zygote or system-level instrumentation; hook installs but will never fire from a user app |
| PC-4 | `libc.so!fork` (onEnter) | `process.fork.attempt` | yes - indirectly via `system()` which calls `fork` internally | yes | `test_fork_execve` disabled in hooked runs; `system()` also calls `fork` internally producing 1 event |
| PC-5 | `libc.so!fork` (onLeave) | `process.fork.result` | yes - same as PC-4 | yes | `child_pid` field present and correct |
| PC-6 | `libc.so!execve` (onEnter) | `process.execve.attempt` | yes - 6 from `Runtime.exec` internal dispatch + 1 from `test_execve_fail` = 7 total | yes | `Runtime.exec` internally spawns child processes via `execve`; all 7 events show `caller_pid` but `pathname` is null in JSON (see known issues) |
| PC-7 | `libc.so!execve` (onLeave) | `process.execve.result` | yes - `test_execve_fail` `execve("/no/such/binary/e2e")` | yes | `onLeave` fires only on execve failure; on success the child image is replaced and `onLeave` never returns; `return_value: -1, success: false` confirmed |
| PC-8 | `libc.so!system` (onEnter) | `process.system.call` | yes - `test_system` `system("echo native_system_call")` | yes | `command` field correct |
| PC-9 | `libc.so!system` (onLeave) | `process.system.result` | yes - same | yes | `return_value: 0, success: true` confirmed |

#### `runtime.ts` - `hook_runtime()` and `trace_reflection()`

| Hook ID | Hook site | Event types | Exercised by app | Emitting | Notes |
|---------|-----------|-------------|-----------------|----------|-------|
| RT-1 | `Runtime.exec` (all overloads via `.overloads.forEach`) | `runtime.exec` | yes - `RuntimeExecTests` all 6 overloads | yes - 13 events for 6 calls | Extra events from internal overload delegation; Android runtime dispatches some `exec` overloads through others internally |
| RT-2 | `Runtime.loadLibrary` (all overloads) | `runtime.load_library` | yes - `RuntimeLoadTests.testRuntimeLoadLibrary` | yes | `library_name: "log"` correct |
| RT-3 | `Runtime.load` (all overloads) | `runtime.load` | yes - `RuntimeLoadTests.testRuntimeLoad` | yes | `filename: "/system/lib64/liblog.so"` correct |
| RT-4 | `Class.getMethod(String, Class[])` | `reflection.get_method` | yes - `ReflectionTests.testGetMethod` | yes - 2 events | Second event from `testMethodInvoke_static` which also calls `getMethod` internally |
| RT-5 | `Class.getDeclaredMethod(String, Class[])` | `reflection.get_declared_method` | yes - `ReflectionTests.testGetDeclaredMethod` | yes - 2 events | Second event from `testMethodInvoke_instance` |
| RT-6 | `Class.forName(String, boolean, ClassLoader)` | `reflection.class_for_name` | yes - `ReflectionTests.testClassForName_3arg` | yes - 6 events | Multiple events due to internal class loading triggered by reflection operations; all show `initialize: true` |
| RT-7 | `Class.forName(String)` - 1-arg overload | `reflection.class_for_name` | yes - `ReflectionTests.testClassForName_1arg` - trigger present | no | 1-arg overload is not hooked in `runtime.ts`; only the 3-arg overload is targeted; confirmed: no event emitted for 1-arg calls |
| RT-8 | `ClassLoader.loadClass(String, boolean)` | `reflection.load_class` | yes - `ReflectionTests.testClassLoaderLoadClass` | yes - 2 events | Internal class names (`android.*`, `java.lang.*` etc.) filtered; `com.test.processe2e.ReflectionTarget` passes filter; second event from a separate internal load |
| RT-9 | `Method.invoke(Object, Object[])` | `reflection.method_invoke` | yes - `ReflectionTests.testMethodInvoke_static` and `testMethodInvoke_instance` | yes - 2 events | Arguments, result, method name all visible in CLI; null in JSON (see known issues) |

## Runtime results (with hooks)

### App stability under hooks

All 5 Java modules and native module completed with 0 failures in all three hook runs.

### Observed event types per profile key

| Profile key | Event type | Count | Source |
|-------------|------------|-------|--------|
| `PROCESS_CREATION` | `process.execve.attempt` | 7 | 6 from `Runtime.exec` internal dispatch + 1 from `test_execve_fail` |
| `PROCESS_CREATION` | `process.signal` | 2 | 1 from `sendSignal(selfPid, 0)` + 1 spurious from `killProcess` internal delegation |
| `PROCESS_CREATION` | `process.fork.attempt` | 1 | `system()` internal fork |
| `PROCESS_CREATION` | `process.fork.result` | 1 | same |
| `PROCESS_CREATION` | `process.kill` | 1 | `killProcess(99999)` |
| `PROCESS_CREATION` | `process.system.call` | 1 | `system("echo native_system_call")` |
| `PROCESS_CREATION` | `process.system.result` | 1 | same |
| `PROCESS_CREATION` | `process.execve.result` | 1 | `test_execve_fail` failure path |
| `PROCESS_NATIVE_LIB` | `native.library.load` | 4 | `liblog.so`, `libprocessnative.so`, `libprocesschild.so`, `libdoesnotexist_e2e.so` |
| `PROCESS_NATIVE_LIB` | `native.library.loaded` | 3 | `liblog.so`, `libprocessnative.so`, `libprocesschild.so` |
| `PROCESS_NATIVE_LIB` | `native.library.load_failed` | 1 | `libdoesnotexist_e2e.so` |
| `RUNTIME_HOOKS` | `runtime.exec` | 13 | 6 app calls + internal overload delegation |
| `RUNTIME_HOOKS` | `reflection.class_for_name` | 6 | 3-arg overload only; 1-arg not hooked |
| `RUNTIME_HOOKS` | `reflection.method_invoke` | 2 | static and instance invoke |
| `RUNTIME_HOOKS` | `reflection.load_class` | 2 | `com.test.processe2e.ReflectionTarget` |
| `RUNTIME_HOOKS` | `reflection.get_method` | 2 | `staticMethod` |
| `RUNTIME_HOOKS` | `reflection.get_declared_method` | 2 | `instanceMethod` |
| `RUNTIME_HOOKS` | `runtime.load_library` | 1 | `"log"` |
| `RUNTIME_HOOKS` | `runtime.load` | 1 | `/system/lib64/liblog.so` |

---

## Known issues

### Hook-side bugs and gaps

| ID | File | Description | Impact |
|----|------|-------------|--------|
| P-1 | `process.ts` | `Process.start` hook installs but is Zygote-internal; not callable from any user app; requires rooted device with modified Zygote for testing | `process.creation` events never emitted in practice |
| P-2 | `process.ts` | `Process.start` hook assigns `.implementation` directly without `safeOverload`; `Process.start` signature has changed across API levels; if the target method has multiple overloads on the running API the assignment throws silently | Fragile across API levels |
| P-3 | `process.ts` | `android.os.Process.killProcess(pid)` internally delegates to `Process.sendSignal(pid, SIGKILL)`; both `hook_java_process_creation` hooks fire for a single `killProcess` call | Every `killProcess` call produces one `process.kill` event and one spurious `process.signal` event with `signal: 9` |
| P-4 | `process.ts` | `process.execve.attempt` events have `pathname: null` in JSON; the hook emits `pathname` but `ProcessEvent` model has no `pathname` field - only `filename` and `command`; `pathname` is silently dropped by the parser | The path of the executed binary is not available in the profile for execve events |
| P-5 | `process.ts` | `hook_native_process_creation` attaches to `"libc.so"` by exact module name; on some Android versions libc exports resolve globally; using `null` for global lookup (as done elsewhere via `safeResolveExport(null, ...)`) would be more consistent and robust | Potential miss on devices where libc is loaded under a different module name |
| P-6 | `nativelibrary.ts` | `onEnter` callbacks for both `dlopen` and `android_dlopen_ext` call `Java.use('java.lang.Thread')` and `threadDef.$new()` directly inside a native `safeAttach` callback with no enclosing `Java.perform`; Java API access from native hooks requires `Java.perform` context | Latent crash risk; may throw on devices where the JVM is not yet available when the first `dlopen` fires at startup |
| P-7 | `nativelibrary.ts` | `android_dlopen_ext` hook installs and resolves correctly but does not fire on this device; on API 24+ app-side `dlopen` routes through bare `dlopen` symbol; `android_dlopen_ext` is used by the linker for namespace-isolated loads which are not directly triggered by app code | `native.library.load` and `native.library.loaded` events for `android_dlopen_ext` path never observed on standard emulator; hook may fire on real hardware or specific linker configurations |
| P-8 | `runtime.ts` | `Class.forName(String, boolean, ClassLoader)` - only the 3-arg overload is hooked; the common 1-arg `Class.forName(String)` overload is not; no `reflection.class_for_name` event emitted for 1-arg calls | Partial coverage of `Class.forName` usage; most app code uses the 1-arg overload |
| P-9 | `runtime.ts` | `ClassLoader.loadClass` and `Class.forName` hooks intercept internal class resolution by the Android framework; when the framework tries to load classes that do not exist in the app (e.g. `android.widget.ViewStub` searched in the app classloader), `original.call()` throws `ClassNotFoundException`; `safeImplementation` logs this as `[HOOK ERROR]` and then calls `original` a second time, producing a second throw | False-positive `[HOOK ERROR]` lines in CLI output for every failed internal class lookup; these are not real hook failures; noise increases significantly for apps with complex class loading |
| P-10 | `runtime.ts` | `Runtime.exec` hooks fire 13 times for 6 app calls due to Android's internal overload delegation; some `exec` overloads dispatch through others at the JVM level; both the outer and the inner overload hooks fire | Duplicate `runtime.exec` events per call; overload_index field would disambiguate but is null in JSON (see P-11) |

### Parser and model issues

| ID | Location | Description |
|----|----------|-------------|
| P-P-1 | `ProcessEvent` | `pathname` field not defined in model; `process.execve.attempt` hook emits `pathname` (the binary path) but it is silently dropped; only `caller_pid` survives in the JSON |
| P-P-2 | `ProcessEvent`, `ProcessParser` | `load_method`, `handle`, `success` fields emitted by `nativelibrary.ts` hooks not mapped in `ProcessEvent`; all show `null` in profile JSON despite being present in the hook payload |
| P-P-3 | `ProcessEvent`, `ProcessParser` | `overload_index`, `class_name`, `method_name`, `method_signature` fields emitted by `runtime.ts` reflection hooks not mapped in `ProcessEvent`; all show `null` in profile JSON; visible in CLI but lost in stored profile |
| P-P-4 | `ProcessEvent`, `ProcessParser` | `command` field from `runtime.exec` events not mapped in `ProcessEvent`; visible in CLI display but null in JSON |

### Test environment notes

| Note | Detail |
|------|--------|
| fork + Frida hang | `test_fork_execve` disabled by default via `ENABLE_FORK_TEST` compile flag; `fork()` in a Frida-instrumented process causes the child to inherit Frida's internal threads; `waitpid()` in the parent hangs indefinitely; re-enable after hook-side fix in `process.ts` |
| `Process.start` | Not testable from any user app; requires system-level or rooted device testing |
| `android_dlopen_ext` | Did not fire on x86_64 API 34 emulator; may fire on ARM real hardware or devices with different linker configurations |
| `execve.result` | Only observable on execve failure; on success the process image is replaced; `onLeave` never runs in the child |

---

## Summary

| Hook group | Total hook sites | Exercised by app | Emitting correctly | Emitting with known issue | Not emitting |
|------------|-----------------|-----------------|-------------------|--------------------------|--------------|
| `nativelibrary.ts` - dlopen | 2 paths (success, fail) | yes | yes | 0 | 0 |
| `nativelibrary.ts` - android_dlopen_ext | 2 paths (success, fail) | yes (same triggers) | 0 | 0 | 2 (device-dependent) |
| `process.ts` - Java | 3 (sendSignal, killProcess, start) | 2 (start untriggerable) | 2 | 1 (killProcess double-fires) | 1 (start) |
| `process.ts` - native fork | 2 (attempt, result) | yes (via system()) | yes | 0 | 0 |
| `process.ts` - native execve | 2 (attempt, result) | yes (attempt x7, result x1) | yes | 1 (pathname dropped) | 0 |
| `process.ts` - native system | 2 (call, result) | yes | yes | 0 | 0 |
| `runtime.ts` - exec | 1 (all overloads) | yes - all 6 | yes | 1 (duplicate events) | 0 |
| `runtime.ts` - load/loadLibrary | 2 | yes | yes | 0 | 0 |
| `runtime.ts` - reflection | 5 (getMethod, getDeclaredMethod, forName 3-arg, loadClass, invoke) | yes | yes | 1 (forName 1-arg missing) | 0 |
| `string.ts` | 0 (not wired) | n/a | 0 | 0 | 0 |


## Bypass / Security Hooks - E2E Test Results

### Test app

`tests/android_apps/e2e_tests/SecurityE2E`  
Package: `com.test.securitye2e`

### Hook file

- `agent/security/bypass.ts`

### Hook group and profile type

- Bypass hooks -> `BYPASS_DETECTION`

### Logcat tag

- `BYPASS_E2E` - MainActivity and all tests

---

### Test environment

#### Recommended emulator

AVD (API 30 / 34, Google APIs x86_64) with Frida server present in `/data/local/tmp` for frida-detection tests. Root-related Runtime.exec tests are best validated on a rooted emulator or device.

#### Hook run command

Any of these, depending on CLI conventions:

```bash
dexray-intercept -s -v --hooks-bypass com.test.securitye2e
 or
dexray-intercept -s -v --enable-bypass com.test.securitye2e
```

#### Baseline run command

```bash
cd tests/android_apps/e2e_tests/SecurityE2E
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk

adb shell am force-stop com.test.securitye2e
adb shell am start -n com.test.securitye2e/.MainActivity

adb logcat -v color threadtime -s BYPASS_E2E:'*' -s AndroidRuntime:E
```

#### Profile event type summary (jq)

```bash
FILE=$(ls profile_com.test.securitye2e_*.json | tail -1)
jq '.BYPASS_DETECTION[].event_type' "$FILE" | sort | uniq -c | sort -rn
```

---

### Baseline results (no hooks)

All five sections run to completion. No crashes.

| Section | Result | Notes |
|---------|--------|-------|
| runRootBypassTests | pass | `File.exists` for root paths + Runtime.exec calls; IOSExceptions for `su`/`busybox` are expected on non-rooted emulator |
| runFridaBypassTests | pass | Frida file paths, port 27042 connection, process list, thread name check |
| runDebuggerBypassTests | pass | isDebuggerConnected, FLAG_DEBUGGABLE, TracerPid read from `/proc/self/status` |
| runEmulatorBypassTests | pass | Build.* properties and SystemProperties.get for `ro.kernel.qemu` and `ro.product.model` |
| runHookBypassTests | pass | Throwable.getStackTrace and System.mapLibraryName |
| SecurityE2E lifecycle | pass | Activity uses Theme.NoDisplay + background test thread + immediate `finish()`; no IllegalStateException |

---

### Hook coverage matrix

#### Root detection bypass (`install_root_detection_bypass`)

| Hook ID | Hook site | Event type | Observed | Count | Notes |
|---------|-----------|-----------|----------|-------|-------|
| ROOT-1 | `File.exists()` on root paths | `bypass.root.file_check` | no | 0 | Hook installs first but is overwritten by FRIDA-1 which reassigns `File.exists.implementation` later; root path bypass never active |
| ROOT-2 | `Runtime.exec(String)` | `bypass.root.command_execution` | yes | 2 | `exec("su")` and `exec("which su")`; in hooked run no IOException is seen in logcat for `su`, indicating redirect to `echo 'command not found'` path is active |
| ROOT-3 | `Runtime.exec(String[])` | `bypass.root.command_execution` | yes | 2 | `exec({"su","-c","id"})` and `exec({"busybox","id"})`; both produce `bypass.root.command_execution` events |
| ROOT-4 | `Build.TAGS` field write at install | `bypass.root.build_tags` | no | 0 | Not implemented as a hook; writes `Build.TAGS.value` to `"release-keys"` at install only if original TAGS contains `"test-keys"`; on this emulator `Build.TAGS="dev-keys"` so condition is false and event never emits |
| ROOT-5 | `PackageManager.getInstalledPackages(int)` | `bypass.root.package_check` | no | 0 | Hook targets `android.content.pm.PackageManager` (abstract); runtime object is `android.app.ApplicationPackageManager`; abstract-class hook does not intercept concrete override; no events emitted even though `pm.getInstalledPackages(0)` is called |

#### Frida detection bypass (`install_frida_detection_bypass`)

| Hook ID | Hook site | Event type | Observed | Count | Notes |
|---------|-----------|-----------|----------|-------|-------|
| FRIDA-1 | `File.exists()` on Frida paths | `bypass.frida.file_check` | yes | 4 | Wins `.implementation` overwrite against ROOT-1; hooked run shows `/data/local/tmp/frida-server` as false vs true in baseline; bypass correct |
| FRIDA-2 | `Socket.$init(String,int)` for port 27042 | `bypass.frida.port_check` | yes | 1 | Event emitted, then hook throws `ConnectException("Connection refused")`; `safeImplementation` catches a Java exception (not a JS Error) and logs `[HOOK ERROR] Non-Error value thrown`, but the bypass behavior (connection refused) is correct |
| FRIDA-3 | `ActivityManager.getRunningAppProcesses()` | `bypass.frida.process_check` | no | 0 | HOOK ERROR at runtime: `cannot read property 'value' of undefined`; hook assumes `process.processName.value` but `processName` is a plain String, so correct field access should be `process.processName` |
| FRIDA-4 | `Thread.getName()` | `bypass.frida.thread_check` | yes | 1 | For thread named `"frida-worker"`, hooked run logs `Thread.getName() result (may be bypassed): main`; event emitted with original and bypassed names |

#### Debugger detection bypass (`install_debugger_detection_bypass`)

| Hook ID | Hook site | Event type | Observed | Count | Notes |
|---------|-----------|-----------|----------|-------|-------|
| DBG-1 | `Debug.isDebuggerConnected()` | `bypass.debugger.connection_check` | yes | 1 | Event emitted; hooked run reports `false`; baseline also reports `false`; bypass path retains a stable `false` regardless of attachment |
| DBG-2 | `PackageManager.getApplicationInfo(String,int)` | `bypass.debugger.flag_check` | no | 0 | Hook targets abstract `PackageManager`; runtime object is `ApplicationPackageManager`; FLAG_DEBUGGABLE remains true in hooked logcat; no events emitted |
| DBG-3 | `BufferedReader.readLine()` | `bypass.debugger.tracer_check` | no | 0 | Fatal script error at install: `readLine(): has more than one overload`; method has `readLine()` and `readLine(boolean)` variants; direct `.implementation` assignment without a `safeOverload` target aborts `install_debugger_detection_bypass`; TracerPid remains `0` on this emulator even with Frida attached |

### Emulator detection bypass (`install_emulator_detection_bypass`)

| Hook ID | Hook site | Event type | Observed | Count | Notes |
|---------|-----------|-----------|----------|-------|-------|
| EMU-1 | `Build.*` field writes at install | `bypass.emulator.build_property` | no | 0 | For each property in `[BRAND, DEVICE, MODEL, PRODUCT, MANUFACTURER, HARDWARE]`, hook checks against indicator list and writes a hard-coded safe value at install if matched, emitting an event once. On this emulator: `BRAND="google"`, `DEVICE="generic_x86_64_arm64"`, `MODEL="sdk_gphone_x86_64"`, `PRODUCT="sdk_gphone_x86_64"`, `MANUFACTURER="Google"`, `HARDWARE="ranchu"`. None match the hard-coded indicator arrays so no events are generated. Field reads in the test app do not trigger events. |
| EMU-2 | `SystemProperties.get(String)` | `bypass.emulator.system_property` | yes | 1 | Hook emits event only when key is `ro.kernel.qemu` and value `"1"`, or when key is `ro.product.model` and value contains `"google_sdk"`. Baseline run logs `ro.kernel.qemu=1`; hooked run logs `ro.kernel.qemu=0` and profile contains a single `bypass.emulator.system_property` event. `ro.product.model` is `"sdk_gphone_x86_64"` so the second condition does not fire. |

### Hook detection bypass (`install_hook_detection_bypass`)

| Hook ID | Hook site | Event type | Observed | Count | Notes |
|---------|-----------|-----------|----------|-------|-------|
| HOOK-1 | `Throwable.getStackTrace()` | `bypass.hook.stack_trace` | no | 0 | Hook filters frames where class name contains `"de.robv.android.xposed"`, `"frida"`, or `"gum"` and emits `bypass.hook.stack_trace` events only for filtered frames. On this test setup, `Throwable.getStackTrace()` does not contain these class names in Java frames, so no events are emitted. Hook still functions as a bypass but generates no observable events in tests. |
| HOOK-2 | `System.mapLibraryName(String)` | `bypass.hook.library_check` | yes | 1 | Event emitted for `System.mapLibraryName("frida")`; test also calls `System.mapLibraryName("c")` to confirm non-Frida names pass through without events. |

---

## Known issues

### Hook-side bugs and design limitations (bypass.ts)

| ID | Area | Description | Impact |
|----|------|-------------|--------|
| SEC-BUG-1 | Root vs Frida file hooks | `install_root_detection_bypass` and `install_frida_detection_bypass` both assign `.implementation` on `java.io.File.exists`. The Frida installer runs later and overwrites the root detector hook. | `bypass.root.file_check` never emits; only `bypass.frida.file_check` is active, so root path file checks are not bypassed or recorded. |
| SEC-BUG-2 | `BufferedReader.readLine` | `BufferedReader.readLine` has two overloads (`readLine()` and `readLine(boolean)`). Direct `readLine.implementation = ...` throws `Error: readLine(): has more than one overload` during hook installation. | `install_debugger_detection_bypass` body is aborted at this line; `bypass.debugger.tracer_check` is never installed. |
| SEC-BUG-3 | ActivityManager process hook | `ActivityManager.getRunningAppProcesses` hook reads `process.processName.value`, but `RunningAppProcessInfo.processName` is a plain String, not a Frida-wrapped field. | Runtime HOOK ERROR: `cannot read property 'value' of undefined`. `bypass.frida.process_check` never emits, and Frida-related processes are not removed from the list. |
| SEC-BUG-4 | PackageManager class targeting | Hooks for `getInstalledPackages(int)` and `getApplicationInfo(String,int)` target `android.content.pm.PackageManager` (abstract). Runtime type is `android.app.ApplicationPackageManager`. | `bypass.root.package_check` and `bypass.debugger.flag_check` do not fire at all. FLAG_DEBUGGABLE remains unchanged in hooked run. |
| SEC-BUG-5 | Socket exception handling | `Socket.$init` hook throws a Java `ConnectException` for port 27042 to simulate connection refusal. `safeImplementation` catches this as a non-Error value and logs `[HOOK ERROR] Non-Error value thrown`. | Misleading HOOK ERROR log, though bypass behavior is correct. Error handler may call `original.apply` in some error paths; current code emits event before throw so behavior is acceptable but fragile. |
| SEC-BUG-6 | Build.* property hooks | `Build.TAGS` and other emulator-detection properties are patched at install time only if they match a static indicator list. Field reads in the app do not trigger events. | No `bypass.root.build_tags` or `bypass.emulator.build_property` events in typical emulator/device setups unless the exact hard-coded indicator values are present at hook installation. |
| SEC-BUG-7 | Stack trace-based hook detection | `bypass.hook.stack_trace` emits only when Java stack frames contain `"de.robv.android.xposed"`, `"frida"`, or `"gum"`. Frida attaches at native layer and does not appear in Java stack traces in this environment. | Hook is effectively mute in tests; no events emitted despite successful installation. It will only emit when Java-level Xposed or similar frameworks are present. |

### Parser and model considerations (bypass.py)

| ID | Location | Description |
|----|----------|-------------|
| SEC-P-1 | BypassParser | Maps a broad variety of original/bypassed fields (`original_tags`, `bypassed_tags`, `original_name`, `bypassed_name`, `original_line`, `bypassed_line`, `original_flags`) into `original_value`/`bypassed_value`. This loses detail about which specific field was changed, but keeps the delta in a uniform place. |
| SEC-P-2 | BypassParser | `property` field is mapped to `property_name` and `file_path`, `command`, `host`, `port` are surfaced as first-class fields. Remaining data in the JSON is preserved as metadata, so no bypass information is silently dropped. |

### Test environment limitations

| Note | Detail |
|------|--------|
| Runtime.exec tests | On non-rooted emulator/device, `Runtime.exec("su")` and `exec(["su","-c","id"])` naturally fail with `Permission denied`. Hooks still emit `bypass.root.command_execution` events and redirect to non-privileged commands. Full end-to-end bypass behavior (command execution) should be reconfirmed on rooted environment. |
| TracerPid behavior | On this API 30 x86_64 emulator, `TracerPid` in `/proc/self/status` is `0` even with Frida attached via spawn. Even if DBG-3 were fixed, `bypass.debugger.tracer_check` would not emit because its condition explicitly checks for non-zero TracerPid. |
| Emulator Build properties | This emulator reports `BRAND=google`, `DEVICE=generic_x86_64_arm64`, `MODEL=sdk_gphone_x86_64`, `PRODUCT=sdk_gphone_x86_64`, `MANUFACTURER=Google`, `HARDWARE=ranchu`. None match the hard-coded emulator indicators arrays in `install_emulator_detection_bypass`, so no `bypass.emulator.build_property` events are seen. Other emulator images (for example AOSP generic_x86) may exercise this path. |
| Hook detection | No Java-level Xposed or similar frameworks are present in this environment, so `bypass.hook.stack_trace` is not exercised. The implemented hook is only observable when such frameworks are active. |

---

## Summary

| Category | Total hooks (TS) | Exercised by app | Emitting events | Hook errors | Not emitting - hook bug | Not emitting - condition/env |
|----------|------------------|------------------|-----------------|-------------|------------------------|------------------------------|
| Root detection | 5 | 5 | 1 (command exec) | 0 | 3 (ROOT-1 overwrite, ROOT-4 install-only, ROOT-5 abstract PM) | 1 (Build.TAGS condition not matched) |
| Frida detection | 4 | 4 | 3 (`file_check`, `port_check`, `thread_check`) | 1 (FRIDA-3 processName access) | 0 | 0 |
| Debugger detection | 3 | 3 | 1 (`connection_check`) | 1 (DBG-3 readLine overload) | 1 (DBG-2 abstract PM) | 0 |
| Emulator detection | 2 | 2 | 1 (`system_property`) | 0 | 0 | 1 (`build_property` not matched) |
| Hook detection | 2 | 2 | 1 (`library_check`) | 0 | 0 | 1 (`stack_trace` never matching in tests) |
| **Total** | **16** | **16** | **7** | **2** | **4** | **3** |



## DEX Hooks - E2E Test Results

### Test app

`tests/android_apps/e2e_tests/DexE2E`
Package: `com.test.dexe2e`

### Hook files

- `agent/dex/dex_unpacking.ts`
- `agent/dex/load_library.ts`

### Hook groups and profile types

- DEX unpacking hooks -> `DEX_LOADING`
- Library loading hooks -> `DYNAMIC_LIB_LOADING`

### Logcat tags

- `DEX_E2E` - MainActivity
- `DEX_CLASS_LOADER` - DexClassLoaderTests
- `DEX_PATH_LOADER` - PathClassLoaderTests
- `DEX_DELEGATE_LOADER` - DelegateLastClassLoaderTests
- `DEX_INMEM_LOADER` - InMemoryDexClassLoaderTests
- `DEX_SYS_LOADLIB` - SystemLoadLibraryTests
- `DEX_RT_LOADLIB` - RuntimeLoadLibraryTests
- `DEX_E2E_NATIVE` - dexe2e_native.c (JNI_OnLoad confirmation)

---

### Test environment

#### Recommended device

Rooted Android 11 hardware (Pixel 4a 5G confirmed). Android 11 is required
for the 4-arg `DelegateLastClassLoader` constructor (API 29+) and for
confirming `OpenCommon` symbol resolution in `libart.so`.
Emulator testing is also valid for the Java-layer hooks.

#### Hook run commands

```
dexray-intercept -s -v --enable-dex-unpacking --enable-java-dex com.test.dexe2e
```

#### Baseline run command

```
adb shell am force-stop com.test.dexe2e
adb shell am start -n com.test.dexe2e/.MainActivity
adb logcat -v color threadtime \
  -s DEX_E2E:'*' \
  -s DEX_CLASS_LOADER:'*' \
  -s DEX_PATH_LOADER:'*' \
  -s DEX_DELEGATE_LOADER:'*' \
  -s DEX_INMEM_LOADER:'*' \
  -s DEX_SYS_LOADLIB:'*' \
  -s DEX_RT_LOADLIB:'*' \
  -s DEX_E2E_NATIVE:'*' \
  -s AndroidRuntime:E
```

#### Profile event type summary (jq)

```
FILE=$(ls profile_com.test.dexe2e_*.json | tail -1)
jq '.DEX_LOADING[].event_type' "$FILE" | sort | uniq -c | sort -rn
jq '.DYNAMIC_LIB_LOADING[].event_type' "$FILE" | sort | uniq -c | sort -rn
```

---

### Baseline results (no hooks)

All test classes run to completion. No errors or crashes.

| Test class | Passes | Notes |
|---|---|---|
| DexClassLoaderTests | 2 | `DexClassLoader.$init` + `loadClass(TestPayload)` |
| PathClassLoaderTests | 2 | 2-arg + 3-arg constructors |
| DelegateLastClassLoaderTests | 3 | 2-arg + 3-arg + 4-arg constructors (API 30 device) |
| InMemoryDexClassLoaderTests | 4 | `(ByteBuffer,ClassLoader)` + `(ByteBuffer[],ClassLoader)` + both `loadClass` |
| SystemLoadLibraryTests | 2 | `System.load` + `System.loadLibrary` |
| RuntimeLoadLibraryTests | 2 | `Runtime.load` + `Runtime.loadLibrary` |
| **Total** | **15** | **0 failed** |

---

### Hook coverage matrix

#### dex_unpacking.ts - native layer (`dumpDex` via `safeAttach`)

| Hook ID | Hook site | Event type(s) | Observed | Count | Notes |
|---------|-----------|--------------|----------|-------|-------|
| DEX-N1 | `libart.so` `OpenCommon` (resolved via `safeEnumerateMatches` on Android 11) | `dex.unpacking.detected` | Yes | 16 | Fires at startup for app's own DEX files (base.apk 2300 bytes, classes2.dex 21252 bytes) and for each subsequent load of test_classes.dex (732 bytes) by classloader tests; 4 events appear as legacy `dex.unpacking` in profile due to parser routing issue DEX-P3 |

#### dex_unpacking.ts - Java layer (`dex_api_unpacking`)

| Hook ID | Hook site | Event type(s) | Observed | Count | Notes |
|---------|-----------|--------------|----------|-------|-------|
| DEX-J1 | `DexClassLoader.$init(String,String,String,ClassLoader)` | `dex.classloader.creation`, `dex.file_copy` | Yes | 1 | Correct; also triggers DEX-N1 when ART loads the DEX buffer |
| DEX-J2 | `PathClassLoader.$init(String,ClassLoader)` | `dex.classloader.creation`, `dex.file_copy` | Yes | inflated | Fires directly from PathClassLoaderTests + indirectly as super() from each DelegateLastClassLoader construction; count is higher than direct app triggers |
| DEX-J3 | `PathClassLoader.$init(String,String,ClassLoader)` | `dex.classloader.creation`, `dex.file_copy` | Yes | inflated | Same super() chain effect as DEX-J2 |
| DEX-J4 | `DelegateLastClassLoader.$init(String,ClassLoader)` | `dex.classloader.creation`, `dex.file_copy` | Yes | 1 direct | |
| DEX-J5 | `DelegateLastClassLoader.$init(String,String,ClassLoader)` | `dex.classloader.creation`, `dex.file_copy` | Yes | 1 direct | |
| DEX-J6 | `DelegateLastClassLoader.$init(String,String,ClassLoader,boolean)` | `dex.classloader.creation`, `dex.file_copy` | Yes | 1 direct | API 29+; confirmed on Android 11 |
| DEX-J7 | `InMemoryDexClassLoader.$init(ByteBuffer,ClassLoader)` | `dex.in_memory_loader`, `dex.memory_dump`, `dex.dump_success` | Yes | 1 each | CLI shows "Unknown bytes" for buffer_size and bytes_written - DEX-P1; also triggers DEX-N1 via ART with synthetic location `Anonymous-DexFile@<addr>.jar` |
| DEX-J8 | `InMemoryDexClassLoader.$init(ByteBuffer[],ClassLoader)` | - | No | 0 | Not hooked in `dex_api_unpacking`; app trigger present (`test_in_memory_dex_class_loader_multi_buffer`) for when hook is added |
| - | `dex.unpacking.file_creation` | - | No | 0 | Only emitted inside the `catch` block of `dumpDexToFile`; never fires under normal execution where process name resolves correctly |

#### load_library.ts

| Hook ID | Hook site | Event type | Observed | Count | Notes |
|---------|-----------|-----------|----------|-------|-------|
| LIB-1 | `System.load(String)` | `library.system.load` | Yes | 1 | Fires; CLI shows "Unknown" for library_path due to DEX-P1 |
| LIB-2 | `System.loadLibrary(String)` | `library.system.load_library` | Yes | 1 | library_name surfaces correctly in CLI |
| LIB-3 | `Runtime.load(String)` | `library.runtime.load` | Yes | 1 | Same "Unknown" path issue as LIB-1 |
| LIB-4 | `Runtime.loadLibrary(String)` | `library.runtime.load_library` | Yes | 1 | Correct |


### Runtime results (with hooks)

#### App stability

All 15 tests pass under hooks - identical to baseline. No crashes.

#### Observed event types

| event_type | Count | Source |
|---|---|---|
| `dex.unpacking.detected` | 12 | native OpenCommon hook per DEX buffer parsed by ART |
| `dex.classloader.creation` | 11 | Java classloader constructors including super() chain |
| `dex.file_copy` | 11 | `dump()` call inside each classloader hook |
| `dex.loading` | 11 | Legacy string payload from `copy_file()` inside `dump()` |
| `dex.unpacking` | 4 | Legacy parse path for `dex.unpacking.detected` events (DEX-P3) |
| `dex.in_memory_loader` | 1 | `InMemoryDexClassLoader.$init(ByteBuffer,ClassLoader)` |
| `dex.memory_dump` | 1 | Dump attempt inside `InMemoryDexClassLoader` hook |
| `dex.dump_success` | 1 | Post-dump check inside `InMemoryDexClassLoader` hook |
| `library.system.load` | 1 | `System.load(String)` |
| `library.system.load_library` | 1 | `System.loadLibrary(String)` |
| `library.runtime.load` | 1 | `Runtime.load(String)` |
| `library.runtime.load_library` | 1 | `Runtime.loadLibrary(String)` |

---

### Known issues

#### Hook-side bugs and structural problems

| ID | File | Description | Impact |
|----|------|-------------|--------|
| DEX-I1 | `dex_unpacking.ts` | `dex_api_unpacking` is called twice per hook install: once from `install_dex_memory_hooks` and once from `install_dex_classloader_hooks`; the second call silently overwrites all `.implementation` assignments from the first; the full `safePerform` block including all `safeUse` calls executes twice | Redundant overhead; misleading devlog ("ClassLoader hooks successfully installed" even when memory hooks succeeded); if fallback intent was that `install_dex_classloader_hooks` only runs when the native hook fails, the condition gates are inverted - currently both always run |
| DEX-I2 | `dex_unpacking.ts` | `DelegateLastClassLoader` extends `PathClassLoader`; each `DelegateLastClassLoader` construction calls `super()` which triggers the `PathClassLoader` hook; 3 Delegate constructions produce 3 additional spurious `PathClassLoader` events with the same DEX path | Event counts for `PathClassLoader` are inflated; 11 total classloader events observed for 7 actual app-side constructor calls |
| DEX-I3 | `dex_unpacking.ts` | `InMemoryDexClassLoader.$init(ByteBuffer[],ClassLoader)` (API 27+) not hooked; only the single-buffer `(ByteBuffer,ClassLoader)` overload is covered | No event for multi-buffer in-memory DEX loading; app trigger present for when hook is added |
| DEX-I4 | `dex_unpacking.ts` | Buffer consumption bug: hook calls `original.call(this, dexbuffer, loader)` before the dump loop; the `InMemoryDexClassLoader` constructor internally exhausts the `ByteBuffer`; after `original` returns `dexbuffer.remaining()` is 0; the dump loop `dexbuffer.get()` throws `BufferUnderflowException`; `safeImplementation` catches this and calls `original` a second time with the exhausted buffer | Second `original` call may produce a broken or empty loader; dump loop never executes; `dex.dump_success` and `dex.dump_error` events are emitted based on `remaining` captured before `original` which is always non-zero, making `dex.dump_success` a false positive |
| DEX-I5 | `dex_unpacking.ts` | `dex.unpacking.file_creation` only emitted inside the `catch` block of `dumpDexToFile` when the initial `new File(dexPath)` throws; under normal execution this path is never reached | Event type observable only on first-run path failures; effectively dead in practice |

#### DEX exfiltration pipeline issue

The hook writes DEX files to `/data/data/<package>/` (app-private storage). The Python side then attempts `adb pull` from that path and reports a success message regardless of whether the pull succeeded.

**Root cause:** `/data/data/<package>/` is owned by the app UID. `adb pull` runs as the `shell` user and has no read access to app-private directories without `adb root`. Even on Magisk-rooted devices, `adb root` must be called explicitly to restart `adbd` as root before pulls from this path will succeed.

**Observed symptom:**
```
Failed to pull file: adb: error: failed to stat remote object '/data/data/com.test.dexe2e/2300.dex': Permission denied [*] Dumped DEX payload to: unpacked/samples/2300.dex <- false positive
```

The file is written on-device but is not retrievable and the local output path is empty. The tool reports success unconditionally.

**Three candidate fixes (for future implementation - not addressed in this session):**

Option A - Change write path to `/data/local/tmp/`
- Hook writes to `/data/local/tmp/<package>/` instead of `/data/data/<package>/`

- `/data/local/tmp/` is world-writable and world-readable; `adb pull` works without `adb root` on any device
- Minimal change: one path string in `dumpDexToFile` and `dex_api_unpacking`

- Downside: files accumulate across runs; shared namespace risks filename collisions if two apps are profiled simultaneously
- Does not fix the false-positive success message on the Python side

Option B - Call `adb root` before pull
- Python side issues `adb root` before attempting pull; retries after adbd restarts

- Works only on rooted devices where `adbd` can restart as root (Magisk-rooted devices support this)
- Fragile: `adb root` fails silently on some Magisk configurations

- Does not change the write path or fix the false-positive message

Option C - Send DEX bytes directly over the Frida channel
- In `dumpDexToFile`, call `am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event), dexBuffer)` with the raw bytes as the third binary argument

- The same mechanism is already used by socket hooks for `socket.native.write_data` and `socket.native.read_data`
- Python side writes the binary payload to the output directory directly - no `adb pull` involved, no filesystem permission issue
- Eliminates the on-device filesystem write for exfiltration; the write to `/data/data/` can be kept as a device-side side copy or removed

- Python `DEXParser` needs a handler for binary payloads attached to `dex.unpacking.detected` events
- Architecturally cleanest; consistent with existing binary data patterns; works on non-rooted devices

**Regardless of option chosen:** the Python-side success message must be made conditional on the file actually landing locally (check return code of the pull or check file existence after write).

#### Parser and model issues

| ID | Location | Description |
|----|----------|-------------|
| DEX-P1 | `DEXEvent.get_event_data()` | `fields` list contains only `['unpacking', 'dumped', 'orig_location', 'even_type']`; all new structured fields set by `DEXParser` via `setattr` - including `hooked_function`, `magic`, `size`, `original_location`, `dumped_path`, `file_type`, `class_loader_type`, `file_path`, `library_path`, `library_name`, `method`, `loader_type`, `buffer_size`, `bytes_written`, `file_name` - are silently absent from the serialized profile JSON; rich structured data is present on the Python object but never written to the profile |
| DEX-P2 | CLI display | `DYNAMIC_LIB_LOADING` events routed to `[Process]` display section; `library_path` and `library_name` show "Unknown" because the fields are dropped at serialization (DEX-P1) |
| DEX-P3 | `DEXParser` | Some `dex.unpacking.detected` events emitted as structured JSON by the native hook fall through `parse_legacy_data` and are recorded as `dex.unpacking`; the hook always emits JSON via `createDEXEvent`, so the cause is a parser routing condition that incorrectly classifies some valid JSON payloads as legacy format |
| DEX-P4 | `DEXParser`, `copy_file()` | `dex.loading` events are a legacy-format artifact of `copy_file()` being called inside `dump()`; `copy_file` sends a non-JSON string payload producing a legacy parse result; every classloader construction emits both `dex.classloader.creation` (correct JSON) and `dex.loading` (legacy duplicate) representing the same operation |

#### Test environment notes

| Note | Detail |
|------|--------|
| Native hook symbol resolution | On Android 11 `OpenCommon` resolves in `libart.so`; on Android 10+ hook also checks `libdexfile.so`; confirmed mangled symbol `_ZN3art13DexFileLoader10OpenCommonE...` at runtime |
| `dex_api_unpacking` double install | Both `--enable-dex-unpacking` and `--enable-java-dex` must be passed for all hooks to activate; passing only `--enable-java-dex` skips the native `OpenCommon` hook; passing only `--enable-dex-unpacking` installs both native and Java hooks due to the double-call structure |
| InMemoryDexClassLoader location string | ART assigns synthetic location `Anonymous-DexFile@<address>.jar` to in-memory DEX files; this is normal and expected in `original_location` for in-memory loads |
| `adb pull` permission | See exfiltration pipeline issue above; DEX files are written to `/data/data/` on-device but not retrievable without `adb root` |

---

### Summary

| Category | Total hook sites | Observed and emitting | Hook errors | Not emitting - hook bug | Not hooked - trigger present |
|---|---|---|---|---|---|
| Native OpenCommon/OpenMemory | 1 | 1 (DEX-N1) | 0 | 0 | 0 |
| DexClassLoader | 1 | 1 (DEX-J1) | 0 | 0 | 0 |
| PathClassLoader | 2 | 2 (DEX-J2/J3) | 0 | 0 | 0 |
| DelegateLastClassLoader | 3 | 3 (DEX-J4/J5/J6) | 0 | 0 | 0 |
| InMemoryDexClassLoader | 2 | 1 (DEX-J7 with dump bug) | 0 | 0 | 1 (DEX-J8 not hooked) |
| System library loading | 2 | 2 (LIB-1/LIB-2) | 0 | 0 | 0 |
| Runtime library loading | 2 | 2 (LIB-3/LIB-4) | 0 | 0 | 0 |
| **Total** | **13** | **12** | **0** | **0** | **1** |


## JNI Hooks - E2E Test Results

### Test app

`tests/android_apps/e2e_tests/JniE2E`

- Package: `com.test.jnie2e`
- Min SDK: 24

- Native libs: 8 separate `.so` files, one per test module

### Hook files

- `agent/jni/jni_trace.ts`
- `agent/jni/jnitrace-engine/` (embedded engine used via `JNIInterceptor` and `JNILibraryWatcher`)

### Profile type

`JNI_TRACE`

### Logcat tags

- `JNI_E2E` - `MainActivity` (module start / completion)
- `JNI_ENV_CORE` - `libjni_env_core.so` / EnvCoreTests (reflection, AllocObject, GetJavaVM, DefineClass, direct buffers)
- `JNI_ENV_FIELDS` - `libjni_env_methods_fields.so` / EnvMethodsFieldsTests (Get/Set instance and static fields)
- `JNI_ENV_CALLS` - `libjni_env_calls.so` / EnvCallsTests (Call\*Method, CallStatic\*Method, CallNonvirtual\*Method, NewObject\*)
- `JNI_ENV_STRINGS` - `libjni_env_strings.so` / EnvStringTests (UTF, jchar, critical string APIs)
- `JNI_ENV_ARRAYS` - `libjni_env_arrays.so` / EnvArrayTests (all primitive and object arrays)
- `JNI_ENV_REFS` - `libjni_env_refs.so` / EnvRefTests (local/global/weak refs, frames, IsSameObject, GetObjectRefType)
- `JNI_ENV_EXCEPT` - `libjni_env_exceptions.so` / EnvExceptionTests (Throw/ThrowNew, Exception\*, MonitorEnter/Exit)
- `JNI_ENV_REGVM` - `libjni_env_regvm.so` / EnvRegistrationVmTests (RegisterNatives/UnregisterNatives, JavaVM methods)
- `JNI_ENV_REGVM_JAVA` - Java side for `RegistrationTarget.nativeSimple`

---

### Run commands

#### Baseline (no hooks)

```bash
cd tests/android_apps/e2e_tests/JniE2E
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk

adb shell am force-stop com.test.jnie2e
adb shell am start -n com.test.jnie2e/.MainActivity

adb logcat -v color threadtime \
  -s JNI_E2E:'*' \
  -s JNI_ENV_CORE:'*' \
  -s JNI_ENV_FIELDS:'*' \
  -s JNI_ENV_CALLS:'*' \
  -s JNI_ENV_STRINGS:'*' \
  -s JNI_ENV_ARRAYS:'*' \
  -s JNI_ENV_REFS:'*' \
  -s JNI_ENV_EXCEPT:'*' \
  -s JNI_ENV_REGVM:'*' \
  -s JNI_ENV_REGVM_JAVA:'*' \
  AndroidRuntime:E
```

#### With hooks

```bash
dexray-intercept -s -v --enable-jni-hooks com.test.jnie2e
```

**CLI flag naming note:** JNI hooks use `--enable-jni-hooks`. All other hook categories
use `--hooks-<category>` or `--enable-<category>`. The flag should be renamed to `--hooks-jni`
for consistency; `--enable-jni-hooks` should remain as a deprecated alias.

#### Profile event query (jq)

```bash
FILE=$(ls profile_com.test.jnie2e_*.json | tail -1)
jq '.JNI_TRACE[].event_type' "$FILE" | sort | uniq -c | sort -rn
jq '[.JNI_TRACE[] | select(.event_type == "jni.env.call") | .metadata.method] | sort | unique' "$FILE"
jq '[.JNI_TRACE[] | select(.event_type == "jni.vm.call") | .metadata.method] | sort | unique' "$FILE"
jq '[.JNI_TRACE[] | select(.event_type == "jni.library.tracked") | .metadata.library_path]' "$FILE"
jq '[.JNI_TRACE[] | select(.metadata.method == "RegisterNatives") | .metadata.registered_natives]' "$FILE"
jq '[.JNI_TRACE[] | select(.metadata.method == "GetObjectRefType") | {method: .metadata.method, return_value: .metadata.return_value}]' "$FILE"
```

---

### Baseline results (no hooks)

All tests enabled including `test_nonvirtual_calls` and `test_get_object_ref_type`.
All 8 modules complete with 0 failures. Prior skip comments in `jni_env_calls.c`
and `jni_env_refs.c` attributed failures to the app side. Both tests pass cleanly
without hooks. Failures only occur under hooks. Both tests must remain uncommented
in the canonical test app.

| Module | Tests | Result | Notes |
|--------|-------|--------|-------|
| EnvCoreTests | 20 | pass | reflection, AllocObject, GetJavaVM, DefineClass, direct buffers |
| EnvMethodsFieldsTests | 23 | pass | all instance and static field types |
| EnvCallsTests | 99 | pass | includes 30 nonvirtual tests |
| EnvStringTests | 8 | pass | UTF, jchar, critical string APIs |
| EnvArrayTests | 24 | pass | all primitive and object arrays, regions and critical |
| EnvRefTests | 12 | pass | includes 3 GetObjectRefType tests |
| EnvExceptionTests | 10 | pass | Throw, ThrowNew, Exception\*, MonitorEnter/Exit |
| EnvRegistrationVmTests | 6 | pass | RegisterNatives/UnregisterNatives, JavaVM::GetEnv/Attach/Detach |
| **Total** | **202** | **pass** | |

---

### Hooked runs overview

Three hooked runs were performed to isolate crash points:

| Run | `test_nonvirtual_calls` | `test_get_object_ref_type` | App result | Events captured |
|-----|------------------------|---------------------------|------------|-----------------|
| A | enabled | enabled | crash at first `CallNonvirtualIntMethod` - EnvStrings, Arrays, Refs, Exceptions, RegVM lost | 224 `jni.env.call`, 4 `jni.library.tracked` |
| B | disabled | enabled | crash at first `GetObjectRefType` call - EnvExceptions, RegVM lost | 320 `jni.env.call`, 7 `jni.library.tracked` |
| C | disabled | disabled | all 8 modules complete, 0 failures | 350 `jni.env.call`, 9 `jni.library.tracked`, 6 `jni.vm.call` |

Run C is the stable production-equivalent run and is the basis for the coverage matrix below.

---

### Crash analysis

#### Crash A - `CallNonvirtual*Method` families

**Trigger:** `test_nonvirtual_calls` - first call is `CallNonvirtualIntMethod`

**Signal:** `SIGSEGV` code 1 (`SEGV_MAPERR`) - null pointer dereference
**Fault address:** `0x0` (pc = `0x0000000000000000`)
**Frame #0:** `<unknown>` (pc 0x0)
**Frame #1:** `<anonymous:72c7bf5000>` offset `0x144` - inside jnitrace-engine anonymous mapping

**Frida script error observed in CLI:**
```
TypeError: cannot read property 'fridaParams' of undefined
    at <anonymous> (/agent/hooking_profile_loader.js:23248)
```

**Root cause:**

The ABI for nonvirtual calls differs from regular instance calls:

- Regular: `ret (*)(JNIEnv*, jobject, jmethodID, ...)`
- Nonvirtual: `ret (*)(JNIEnv*, jobject, jclass, jmethodID, ...)`

The extra `jclass` argument sits at index 2; `jmethodID` is at index 3.
The jnitrace-engine assumes `jmethodID` is always at index 2. It reads the `jclass`
handle as if it were a `jmethodID`, resolves a bogus method object that has no
`fridaParams` property, throws the `TypeError` inside the interception stub, then
returns via a corrupt pointer which produces pc=0x0 and the null-dereference crash.

**Impact:** All 30 `CallNonvirtual*Method/V/A` variants crash the process on the
first invocation. No events are emitted for any of them. All modules after
`EnvCallsTests` are unreachable in Run A.

**Affected variants (all 30):** Object, Boolean, Byte, Char, Short, Int, Long, Float,
Double, Void - each with plain / V / A suffix.

---

#### Crash B - `GetObjectRefType`

**Trigger:** `test_get_object_ref_type` - first call is `GetObjectRefType(local jstring)`

**Signal:** `SIGSEGV` code 2 (`SEGV_ACCERR`) - address mapped but not executable
**Fault address:** `0x72c8674590`
**Frame #0:** `<anonymous:72c861e000>` offset `0x56590` - inside jnitrace-engine anonymous mapping
**Frame #1:** `libjni_env_refs.so` offset `0x15a8`
**Frame #2:** `libjni_env_refs.so` `Java_com_test_jnie2e_EnvRefTests_runTests+252`

**Root cause:**

The jnitrace-engine installs a hook trampoline for `GetObjectRefType`. When the native
code calls through the hooked function table entry, the engine's internal dispatch attempts
to execute code at an address that is mapped but marked non-executable (`SEGV_ACCERR`,
not `SEGV_MAPERR`). The trampoline or return stub points into a data or read-only region
of the anonymous engine mapping rather than an executable trampoline page. The likely
cause is that `GetObjectRefType` has an unusual return type (`jobjectRefType`, a C enum)
which the engine's return value interceptor does not handle correctly and produces a
malformed stub.

The crash happens inside or immediately after the trampoline, before `onLeave` can emit
an event. Confirmed: no `jni.env.call` event with `method: "GetObjectRefType"` appears
in the Run B profile JSON despite the function being called.

Baseline (no hooks): `test_get_object_ref_type` passes with correct values:

- local ref → `JNILocalRefType (1)`
- global ref → `JNIGlobalRefType (2)`

- weak ref → `JNIWeakGlobalRefType (3)`

**Impact:** `GetObjectRefType` is non-functional under hooks and unsafe to call
when `jni_trace` is enabled. All modules after `EnvRefTests` are unreachable in Run B.

The app-side implementation of `test_get_object_ref_type` is correct and passes without hooks;
the failure is entirely in the `jnitrace-engine`’s interception of `GetObjectRefType`


## Hook coverage matrix - Run C (stable)

### Event counts

| Event type | Count |
|------------|-------|
| `jni.env.call` | 350 |
| `jni.library.tracked` | 9 |
| `jni.vm.call` | 6 |

### Libraries tracked

All 8 app `.so` files plus `libopenjdk.so` (Android system, tracked at startup):

| Library |
|---------|
| `/apex/com.android.art/lib64/libopenjdk.so` |
| `libjni_env_core.so` |
| `libjni_env_methods_fields.so` |
| `libjni_env_calls.so` |
| `libjni_env_strings.so` |
| `libjni_env_arrays.so` |
| `libjni_env_refs.so` |
| `libjni_env_exceptions.so` |
| `libjni_env_regvm.so` |

---

### `JavaVM` methods

Emitted as `event_type: "jni.vm.call"` with `jni_struct: "JavaVM"`.

| Method | Status | Notes |
|--------|--------|-------|
| `GetEnv` | working | fires from `JNI_OnLoad` and from `test_javavm_getenv` |
| `AttachCurrentThread` | working | worker thread in EnvRegistrationVmTests |
| `AttachCurrentThreadAsDaemon` | working | daemon thread in EnvRegistrationVmTests |
| `DetachCurrentThread` | working | fires twice per run - once per background thread |
| `DestroyJavaVM` | not triggered | intentionally omitted - destroys the VM; cannot be safely called from a running app |

---

### `JNIEnv` methods

#### Core and reflection

| Method | Fires | Enrichment fields populated |
|--------|-------|-----------------------------|
| `GetVersion` | yes | — |
| `FindClass` | yes | `class_name` |
| `GetSuperclass` | yes | — |
| `IsAssignableFrom` | yes | — |
| `IsInstanceOf` | yes | — |
| `GetObjectClass` | yes | — |
| `AllocObject` | yes | — |
| `ToReflectedMethod` | yes | — |
| `FromReflectedMethod` | yes | — |
| `ToReflectedField` | yes | — |
| `FromReflectedField` | yes | — |
| `DefineClass` | yes | `define_class_name`, `class_data_length`, `class_data_hex` (first 64 bytes); returns NULL on ART as expected; hook observes class bytes regardless |
| `GetJavaVM` | yes | `java_vm_ptr` |
| `NewDirectByteBuffer` | yes | `direct_buffer_address`, `direct_buffer_capacity` |
| `GetDirectBufferAddress` | yes | `direct_buffer_address`, `direct_buffer_capacity`, `buffer_hex` (up to 1 KB) |
| `GetDirectBufferCapacity` | yes | `direct_buffer_capacity` |

#### Method and field ID lookup

| Method | Fires | Enrichment fields populated |
|--------|-------|-----------------------------|
| `GetMethodID` | yes | `method_name`, `method_signature`, `method_descriptor` |
| `GetStaticMethodID` | yes | `method_name`, `method_signature`, `method_descriptor` |
| `GetFieldID` | yes | `field_name`, `field_signature`, `field_descriptor` |
| `GetStaticFieldID` | yes | `field_name`, `field_signature`, `field_descriptor` |

#### Object construction

| Method | Fires | Enrichment fields populated |
|--------|-------|-----------------------------|
| `NewObject` | yes | `java_params`, `java_args`, `java_method_descriptor`, `java_ret_type` |
| `NewObjectV` | yes | same |
| `NewObjectA` | yes | same |

#### Instance method calls

| Method | Fires | Enrichment fields populated |
|--------|-------|-----------------------------|
| `CallObjectMethod/V/A` | yes | `java_params`, `java_args`, `java_ret_type`, `java_ret_value` (jstring decoded to UTF-8; object refs annotated by JVM descriptor) |
| `CallBooleanMethod/V/A` | yes | same (boolean decoded as True/False) |
| `CallByteMethod/V/A` | yes | same |
| `CallCharMethod/V/A` | yes | same (char decoded as integer code point) |
| `CallShortMethod/V/A` | yes | same |
| `CallIntMethod/V/A` | yes | same |
| `CallLongMethod/V/A` | yes | same |
| `CallFloatMethod/V/A` | yes | same |
| `CallDoubleMethod/V/A` | yes | same |
| `CallVoidMethod/V/A` | yes | `java_params`, `java_args`, `java_ret_type` (no return value) |
| `CallNonvirtual*Method/V/A` (all 30) | **no - crash A** | see crash analysis above |

#### Static method calls

| Method | Fires | Enrichment fields populated |
|--------|-------|-----------------------------|
| `CallStaticObjectMethod/V/A` | yes | `java_params`, `java_args`, `java_ret_type`, `java_ret_value` |
| `CallStaticBooleanMethod/V/A` | yes | same |
| `CallStaticByteMethod/V/A` | yes | same |
| `CallStaticCharMethod/V/A` | yes | same |
| `CallStaticShortMethod/V/A` | yes | same |
| `CallStaticIntMethod/V/A` | yes | same |
| `CallStaticLongMethod/V/A` | yes | same |
| `CallStaticFloatMethod/V/A` | yes | same |
| `CallStaticDoubleMethod/V/A` | yes | same |
| `CallStaticVoidMethod/V/A` | yes | `java_params`, `java_args`, `java_ret_type` |

#### Instance fields

| Method | Fires | Notes |
|--------|-------|-------|
| `GetFieldID` | yes | see method/field ID lookup above |
| `GetObjectField` | yes | handle only; object type/content not decoded (see JNI-E-7) |
| `GetBooleanField` | yes | value as 0/1 |
| `GetByteField` | yes | value as integer |
| `GetCharField` | yes | value as integer code point |
| `GetShortField` | yes | value as integer |
| `GetIntField` | yes | value as integer |
| `GetLongField` | yes | value as integer |
| `GetFloatField` | yes | value as float |
| `GetDoubleField` | yes | value as float |
| `SetObjectField` | yes | handle only |
| `SetBooleanField` | yes | value recorded |
| `SetByteField` | yes | value recorded |
| `SetCharField` | yes | value recorded |
| `SetShortField` | yes | value recorded |
| `SetIntField` | yes | value recorded |
| `SetLongField` | yes | value recorded |
| `SetFloatField` | yes | value recorded |
| `SetDoubleField` | yes | value recorded |

#### Static fields

| Method | Fires | Notes |
|--------|-------|-------|
| `GetStaticFieldID` | yes | see method/field ID lookup above |
| `GetStatic*Field` (all 9 types) | yes | same field value notes as instance fields |
| `SetStatic*Field` (all 9 types) | yes | same |

#### String APIs

| Method | Fires | Enrichment fields populated |
|--------|-------|-----------------------------|
| `NewStringUTF` | yes | `string_argument` (content decoded to UTF-8) |
| `GetStringUTFLength` | yes | — |
| `GetStringUTFChars` | yes | `string_return` (content decoded); handle registered in `jstringValues` map for downstream argument decoding |
| `ReleaseStringUTFChars` | yes | — |
| `GetStringUTFRegion` | yes | arguments only; buffer content not read (see JNI-E-1) |
| `NewString` | yes | jchar buffer pointer only; content not decoded (see JNI-E-3) |
| `GetStringLength` | yes | length as integer |
| `GetStringChars` | yes | pointer only; jchar content not decoded (see JNI-E-4) |
| `ReleaseStringChars` | yes | — |
| `GetStringRegion` | yes | arguments only; jchar buffer not read (see JNI-E-2) |
| `GetStringCritical` | yes | `string_return` decoded via prior `jstringValues` lookup |
| `ReleaseStringCritical` | yes | — |

#### Array APIs

| Method | Fires | Enrichment fields populated |
|--------|-------|-----------------------------|
| `NewBooleanArray` / `NewByteArray` / `NewCharArray` / `NewShortArray` / `NewIntArray` / `NewLongArray` / `NewFloatArray` / `NewDoubleArray` | yes | `array_length` |
| `NewObjectArray` | yes | length only; element class and initial element not decoded (see JNI-E-5) |
| `GetArrayLength` | yes | `array_length` |
| `GetObjectArrayElement` | yes | handle only; type/content not decoded (see JNI-E-6) |
| `SetObjectArrayElement` | yes | handle only |
| `Set*ArrayRegion` (all 8 primitive types) | yes | `array_length`, `array_hex`, `array_values` (numeric types) |
| `Get*ArrayElements` (all 8 primitive types) | yes | `array_length`, `array_hex`, `array_values` |
| `Release*ArrayElements` (all 8 primitive types) | yes | `array_length`, `array_hex` (pre-read before release) |
| `Get*ArrayRegion` (all 8 primitive types) | yes | `array_length`, `array_hex`, `array_values` |
| `GetPrimitiveArrayCritical` | yes | `array_length`, `array_hex` |
| `ReleasePrimitiveArrayCritical` | yes | `array_length`, `array_hex`, `array_values` (pre-read) |

#### References and frames

| Method | Fires | Notes |
|--------|-------|-------|
| `PushLocalFrame` | yes | — |
| `PopLocalFrame` | yes | — |
| `EnsureLocalCapacity` | yes | — |
| `NewLocalRef` | yes | — |
| `DeleteLocalRef` | yes | — |
| `IsSameObject` | yes | — |
| `NewGlobalRef` | yes | — |
| `DeleteGlobalRef` | yes | — |
| `NewWeakGlobalRef` | yes | — |
| `DeleteWeakGlobalRef` | yes | — |
| `GetObjectRefType` | **no - crash B** | see crash analysis above |

#### Exceptions and monitors

| Method | Fires | Enrichment fields populated |
|--------|-------|-----------------------------|
| `ThrowNew` | yes | `throw_message` (exception message decoded) |
| `Throw` | yes | exception handle only; class name and message not decoded (see JNI-E-8) |
| `ExceptionOccurred` | yes | — |
| `ExceptionCheck` | yes | — |
| `ExceptionDescribe` | yes | — |
| `ExceptionClear` | yes | — |
| `MonitorEnter` | yes | — |
| `MonitorExit` | yes | — |
| `FatalError` | not triggered | intentionally omitted - aborts process |

#### Registration

| Method | Fires | Enrichment fields populated |
|--------|-------|-----------------------------|
| `RegisterNatives` | yes | `registered_natives` array of `{name, signature, address}`; fires from `JNI_OnLoad` and from `test_register_natives` |
| `UnregisterNatives` | yes | — |


## Known issues

### Hook-side crashes

| ID | Method(s) | Signal | Root cause | Status |
|----|-----------|--------|------------|--------|
| JNI-C-1 | All 30 `CallNonvirtual*Method/V/A` | SIGSEGV SEGV_MAPERR pc=0x0 | jnitrace-engine assumes `jmethodID` at index 2; nonvirtual ABI places extra `jclass` at index 2 and `jmethodID` at index 3; engine reads `jclass` handle as `jmethodID`, resolves bogus method object with no `fridaParams`, throws TypeError, returns via corrupt pointer | hook-side bug in jnitrace-engine; all 30 variants non-functional under hooks |
| JNI-C-2 | `GetObjectRefType` | SIGSEGV SEGV_ACCERR fault in anonymous engine mapping | hook trampoline or return stub for `GetObjectRefType` points into a mapped but non-executable region; likely caused by `jobjectRefType` (C enum) return type not handled correctly by the engine's return value interceptor; crash occurs before `onLeave` can emit any event | hook-side bug in jnitrace-engine; function non-functional under hooks |

### Enrichment gaps

| ID | Method(s) | Missing data | Notes |
|----|-----------|-------------|-------|
| JNI-E-1 | `GetStringUTFRegion` | buffer content not read | only arguments recorded; destination buffer pointer is available but not dereferenced and read back as UTF-8 |
| JNI-E-2 | `GetStringRegion` | jchar buffer content not read | same pattern as JNI-E-1 for the jchar variant |
| JNI-E-3 | `NewString` | jchar input not decoded | input jchar buffer pointer recorded but content not read as UTF-16 |
| JNI-E-4 | `GetStringChars` | jchar return not decoded | return pointer recorded but content not read; contrast with `GetStringUTFChars` which does decode |
| JNI-E-5 | `NewObjectArray` | element class and initial element not decoded | only array length recorded |
| JNI-E-6 | `GetObjectArrayElement` / `SetObjectArrayElement` | object content not decoded | handle recorded; type and value not resolved |
| JNI-E-7 | All `Get/Set*Field` and `GetStatic/SetStatic*Field` (18 instance + 18 static) | field value not decoded inline in event | value is present in the `return` field for getters and in `arguments` for setters as raw JNI values; no structured `field_value` key is populated separately |
| JNI-E-8 | `Throw` | exception class name and message not decoded | exception object handle recorded; contrast with `ThrowNew` which does decode the message string |
| JNI-E-9 | `RegisterNatives` address field | native function address is a raw pointer string; no module or symbol resolution attempted | fix: resolve via `DebugSymbol.fromAddress` or `Process.findModuleByAddress` |

### CLI and profile structure issues

| ID | Description |
|----|-------------|
| JNI-P-1 | Flag `--enable-jni-hooks` does not follow the naming convention of other categories (`--hooks-<category>` / `--enable-<category>`); should be renamed to `--hooks-jni` with `--enable-jni-hooks` kept as a deprecated alias |
| JNI-P-2 | `jni.vm.call` events only appear when the regvm module runs; if the app is killed by a hook crash before reaching `EnvRegistrationVmTests`, no `jni.vm.call` events are generated at all (Runs A and B) |
| JNI-P-3 | `ReleaseStringUTFChars` fires but the decoded string is not correlated with the preceding `GetStringUTFChars` event for the same handle in the profile JSON |
| JNI-P-4 | `GetObjectRefType` generates no events and `[]` is returned by the jq query rather than the key being absent; confirms the trigger exists and the function is called but the crash is entirely hook-side |

### Practical guidance

For coverage runs with hooks enabled, `test_nonvirtual_calls` and
`test_get_object_ref_type` must be disabled in the test app to avoid hook-side
crashes. All other tests can run as-is.

For full semantic validation of `CallNonvirtual*Method` and `GetObjectRefType`,
run JniE2E without hooks (baseline). All 202 tests pass. Both functions are
app-correct but currently unsupported by the jnitrace-engine.

---

## Summary

### JNIEnv method coverage (Run C - stable)

| Category | Total hook sites | Firing correctly | Firing with enrichment gap | Crash (hook-side) | Not triggered (by design) |
|----------|-----------------|-----------------|---------------------------|-------------------|--------------------------|
| Core / reflection | 16 | 16 | 0 | 0 | 0 |
| Method and field ID lookup | 4 | 4 | 0 | 0 | 0 |
| Object construction | 3 | 3 | 0 | 0 | 0 |
| Instance method calls (`Call*Method/V/A`) | 30 | 30 | 0 | 0 | 0 |
| Nonvirtual method calls (`CallNonvirtual*Method/V/A`) | 30 | 0 | 0 | 30 | 0 |
| Static method calls (`CallStatic*Method/V/A`) | 30 | 30 | 0 | 0 | 0 |
| Instance fields (Get/Set, all types) | 18 | 18 | 18 | 0 | 0 |
| Static fields (GetStatic/SetStatic, all types) | 18 | 18 | 18 | 0 | 0 |
| String APIs | 12 | 12 | 4 | 0 | 0 |
| Array APIs | 41 | 41 | 3 | 0 | 0 |
| References and frames | 11 | 10 | 0 | 1 | 0 |
| Exceptions and monitors | 8 | 8 | 1 | 0 | 0 |
| Registration | 2 | 2 | 1 | 0 | 0 |
| Special (`FatalError`) | 1 | 0 | 0 | 0 | 1 |
| **Total JNIEnv** | **224** | **192** | **45** | **31** | **1** |

Note: enrichment gap counts are not mutually exclusive with "firing correctly" - a
method can fire and produce an event while still missing one or more decoded fields.

### JavaVM method coverage

| Method | Status | Notes |
|--------|--------|-------|
| `GetEnv` | working | fires from `JNI_OnLoad` and `test_javavm_getenv` |
| `AttachCurrentThread` | working | — |
| `AttachCurrentThreadAsDaemon` | working | — |
| `DetachCurrentThread` | working | fires twice per run |
| `DestroyJavaVM` | not triggered | intentionally omitted |

### App stability under hooks

| Run | Configuration | Result |
|-----|--------------|--------|
| A | both crash triggers enabled | crash in `EnvCallsTests` at first `CallNonvirtualIntMethod` |
| B | nonvirtual disabled, GetObjectRefType enabled | crash in `EnvRefTests` at first `GetObjectRefType` |
| C | both crash triggers disabled | all 8 modules complete, 0 failures |
import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"
import { Where } from "../utils/misc.js"
import { safePerform, safeUse, safeOverload } from "../utils/safe_java.js"

const PROFILE_HOOKING_TYPE: string = "TELEPHONY"

function createTelephonyEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function hook_sms() {
    // fix: monolithic try-catch removed, safePerform owns the boundary
    safePerform("telephony:hook_sms", () => {
        const SmsManager = safeUse('android.telephony.SmsManager', "telephony:hook_sms");
        if (!SmsManager) return;

        const threadDef = safeUse('java.lang.Thread', "telephony:hook_sms");
        if (!threadDef) return;
        const threadInstance = threadDef.$new();

        // Hook SmsManager's sendTextMessage method
        const sendText = safeOverload(
                    SmsManager.sendTextMessage,
                    "telephony:SmsManager.sendTextMessage",
                    'java.lang.String', 'java.lang.String', 'java.lang.String',
                    'android.app.PendingIntent', 'android.app.PendingIntent'
                );
        if (sendText) {
            sendText.implementation = function(
                destinationAddress: string, scAddress: string, text: string,
                sentIntent: any, deliveryIntent: any
            ) {
                const stack = threadInstance.currentThread().getStackTrace();
                createTelephonyEvent("telephony.sms.send_text", {
                    library: 'android.telephony.SmsManager',
                    method: 'sendTextMessage',
                    destination_address: destinationAddress,
                    service_center_address: scAddress,
                    message_text: text,
                    text_length: text ? text.length : 0,
                    has_sent_intent: sentIntent !== null,
                    has_delivery_intent: deliveryIntent !== null,
                    stack_trace: Where(stack)
                });
                return this.sendTextMessage(destinationAddress, scAddress, text, sentIntent, deliveryIntent);
            };
        }

        // Hook SmsManager's sendMultipartTextMessage method
        const sendMultipart = safeOverload(
            SmsManager.sendMultipartTextMessage,
            "telephony:SmsManager.sendMultipartTextMessage",
            'java.lang.String', 'java.lang.String', 'java.util.ArrayList',
            'java.util.ArrayList', 'java.util.ArrayList'
        );
        if (sendMultipart) {
            sendMultipart.implementation = function(
                destinationAddress: string, scAddress: string,
                parts: any, sentIntents: any, deliveryIntents: any
            ) {
                const stack = threadInstance.currentThread().getStackTrace();
                const partsArray = parts ? parts.toArray() : [];
                createTelephonyEvent("telephony.sms.send_multipart", {
                    library: 'android.telephony.SmsManager',
                    method: 'sendMultipartTextMessage',
                    destination_address: destinationAddress,
                    service_center_address: scAddress,
                    message_parts: partsArray,
                    parts_count: partsArray.length,
                    has_sent_intents: sentIntents !== null,
                    has_delivery_intents: deliveryIntents !== null,
                    stack_trace: Where(stack)
                });
                return this.sendMultipartTextMessage(destinationAddress, scAddress, parts, sentIntents, deliveryIntents);
            };
        }
    });
}

// BUG: Java.use called outside Java.perform => do not uncomment without fixing first
// Fix needed: safePerform("telephony:hook_mms", () => {
//     const Mms = safeUse('android.telephony.Mms', "telephony:hook_mms");
//     if (!Mms) return;
//     ... hook implementations ...
// });
function hook_mms() {
    // is only available on newer android versions
    // const MmsManager = Java.use('android.telephony.Mms');
    // currently sent via Intents and therefore we have to investigate further how to handle and hooks this
}

function hook_device_infos() {
    // fix: monolithic try-catch removed => safePerform + independent safeUse per class
    // Each class resolved independently => failure of one does not abort others
    safePerform("telephony:hook_device_infos", () => {
        const secureSettings = safeUse('android.provider.Settings$Secure', "telephony:hook_device_infos");
        const contentResolver = safeUse('android.content.ContentResolver', "telephony:hook_device_infos");
        const wifiInfo = safeUse('android.net.wifi.WifiInfo', "telephony:hook_device_infos");
        const bluetoothAdapter = safeUse('android.bluetooth.BluetoothAdapter', "telephony:hook_device_infos");
        const telephonyManager = safeUse('android.telephony.TelephonyManager', "telephony:hook_device_infos");
        const build = safeUse('android.os.Build', "telephony:hook_device_infos");
        const systemProperties = safeUse('android.os.SystemProperties', "telephony:hook_device_infos");
        const threadDef = safeUse('java.lang.Thread', "telephony:hook_device_infos");
        if (!threadDef) return;
        const threadInstance = threadDef.$new();

        const seenEvents: { [key: string]: string } = {};

        if (systemProperties) {
            // Hook system properties get method
            const sysPropsGet = safeOverload(
                systemProperties.get,
                "telephony:SystemProperties.get",
                'java.lang.String'
            );
            if (sysPropsGet) {
                sysPropsGet.implementation = function(key_value: string) {
                    const result = this.get(key_value);
                    const stack = threadInstance.currentThread().getStackTrace();
                    // deduplication: only log when value changes for a given key
                    const eventKey = `system_prop:${key_value}`;
                    if (seenEvents[eventKey] !== result) {
                        seenEvents[eventKey] = result;
                        createTelephonyEvent("telephony.system_properties.get", {
                            library: "android.os.SystemProperties",
                            method: "get",
                            property_key: key_value,
                            property_value: result,
                            stack_trace: Where(stack)
                        });
                    }
                    return result;
                };
            }
        }

        // Hook build properties
        if (build) {
            const buildProperties = [
                'MODEL', 'DEVICE', 'BOARD', 'PRODUCT', 'HARDWARE', 'FINGERPRINT',
                'MANUFACTURER', 'BOOTLOADER', 'BRAND', 'HOST', 'ID', 'DISPLAY',
                'TAGS', 'SERIAL', 'TYPE', 'USER', 'UNKNOWN'
            ];
            
            buildProperties.forEach(prop => {
                Object.defineProperty(build, prop, {
                    get: function() {
                        const result = build[prop].value;
                        createTelephonyEvent("telephony.build.get_property", {
                            library: "android.os.Build",
                            method: `android.os.Build.${prop}`,
                            property: prop,
                            value: result
                        });
                        return result;
                    },
                    set: function(newValue) {
                        // This setter can be used to monitor if the value is set
                        // For now, it just returns without modifying the value
                        createTelephonyEvent("telephony.build.set_property", {
                            library: "android.os.Build",
                            method: `android.os.Build.${prop}`,
                            property: prop,
                            attempted_value: newValue
                        });
                    },
                    configurable: true
                });
            });
        }

        // Hook telephony manager methods
        if (telephonyManager) {
            // previously used .overloads[0] => replaced with safeOverload no-arg for safety
            const getLine1Number = safeOverload(
                telephonyManager.getLine1Number,
                "telephony:TelephonyManager.getLine1Number"
            );
            if (getLine1Number) {
                getLine1Number.implementation = function() {
                    const result = this.getLine1Number();
                    const stack = threadInstance.currentThread().getStackTrace();
                    createTelephonyEvent("telephony.manager.get_phone_number", {
                        library: "android.telephony.TelephonyManager",
                        method: "getLine1Number",
                        phone_number: result,
                        stack_trace: Where(stack)
                    });
                    return result;
                };
            }

            const getSubscriberId = safeOverload(
                telephonyManager.getSubscriberId,
                "telephony:TelephonyManager.getSubscriberId"
            );
            if (getSubscriberId) {
                getSubscriberId.implementation = function() {
                    const result = this.getSubscriberId();
                    const stack = threadInstance.currentThread().getStackTrace();
                    createTelephonyEvent("telephony.manager.get_imsi", {
                        library: "android.telephony.TelephonyManager",
                        method: "getSubscriberId",
                        imsi: result,
                        stack_trace: Where(stack)
                    });
                    return result;
                };
            }

            // previously used .overloads[0] => replaced with safeOverload no-arg for safety
            const getDeviceId = safeOverload(
                telephonyManager.getDeviceId,
                "telephony:TelephonyManager.getDeviceId"
            );
            if (getDeviceId) {
                getDeviceId.implementation = function() {
                    const result = this.getDeviceId();
                    const stack = threadInstance.currentThread().getStackTrace();
                    createTelephonyEvent("telephony.manager.get_device_id", {
                        library: "android.telephony.TelephonyManager",
                        method: "getDeviceId",
                        device_id: result,
                        stack_trace: Where(stack)
                    });
                    return result;
                };
            }

            // previously used .overloads[0] => replaced with safeOverload no-arg for safety
            const getImei = safeOverload(
                telephonyManager.getImei,
                "telephony:TelephonyManager.getImei"
            );
            if (getImei) {
                getImei.implementation = function() {
                    const result = this.getImei();
                    const stack = threadInstance.currentThread().getStackTrace();
                    createTelephonyEvent("telephony.manager.get_imei", {
                        library: "android.telephony.TelephonyManager",
                        method: "getImei",
                        imei: result,
                        stack_trace: Where(stack)
                    });
                    return result;
                };
            }

            const getSimOperator = safeOverload(
                telephonyManager.getSimOperator,
                "telephony:TelephonyManager.getSimOperator"
            );
            if (getSimOperator) {
                getSimOperator.implementation = function() {
                    const result = this.getSimOperator();
                    const stack = threadInstance.currentThread().getStackTrace();
                    createTelephonyEvent("telephony.manager.get_sim_operator", {
                        library: "android.telephony.TelephonyManager",
                        method: "getSimOperator",
                        sim_operator: result,
                        stack_trace: Where(stack)
                    });
                    return result;
                };
            }
        }

        if (bluetoothAdapter) {
            bluetoothAdapter.getAddress.implementation = function() {
                const result = this.getAddress();
                const stack = threadInstance.currentThread().getStackTrace();
                createTelephonyEvent("telephony.bluetooth.get_address", {
                    library: "android.bluetooth.BluetoothAdapter",
                    method: "getAddress",
                    mac_address: result,
                    stack_trace: Where(stack)
                });
                return result;
            };
        }

        if (wifiInfo) {
            wifiInfo.getMacAddress.implementation = function() {
                const result = this.getMacAddress();
                const stack = threadInstance.currentThread().getStackTrace();
                createTelephonyEvent("telephony.wifi.get_mac_address", {
                    library: "android.net.wifi.WifiInfo",
                    method: "getMacAddress",
                    mac_address: result,
                    stack_trace: Where(stack)
                });
                return result;
            };

            wifiInfo.getSSID.implementation = function() {
                const result = this.getSSID();
                const stack = threadInstance.currentThread().getStackTrace();
                createTelephonyEvent("telephony.wifi.get_ssid", {
                    library: "android.net.wifi.WifiInfo",
                    method: "getSSID",
                    ssid: result,
                    stack_trace: Where(stack)
                });
                return result;
            };

            wifiInfo.getBSSID.implementation = function() {
                const result = this.getBSSID();
                const stack = threadInstance.currentThread().getStackTrace();
                createTelephonyEvent("telephony.wifi.get_bssid", {
                    library: "android.net.wifi.WifiInfo",
                    method: "getBSSID",
                    bssid: result,
                    stack_trace: Where(stack)
                });
                return result;
            };
        }

        if (contentResolver) {
            const query1 = safeOverload(
                contentResolver.query,
                "telephony:ContentResolver.query",
                'android.net.Uri', '[Ljava.lang.String;',
                'android.os.Bundle', 'android.os.CancellationSignal'
            );
            if (query1) {
                query1.implementation = function(uri: string, str: any, bundle: any, sig: any) {
                    const stack = threadInstance.currentThread().getStackTrace();
                    if (uri == 'content://com.google.android.gsf.gservicesa') {
                        createTelephonyEvent("telephony.content_resolver.query_gsf", {
                            library: "android.content.ContentResolver",
                            method: "query",
                            uri: uri,
                            action: "cloaking_gsf_query",
                            stack_trace: Where(stack)
                        });
                        return null;
                    } else {
                        const result = this.query(uri, str, bundle, sig);
                        createTelephonyEvent("telephony.content_resolver.query", {
                            library: "android.content.ContentResolver",
                            method: "query",
                            uri: uri,
                            has_result: result !== null,
                            stack_trace: Where(stack)
                        });
                        return result;
                    }
                };
            }

            const query2 = safeOverload(
                contentResolver.query,
                "telephony:ContentResolver.query",
                'android.net.Uri', '[Ljava.lang.String;',
                'java.lang.String', '[Ljava.lang.String;', 'java.lang.String'
            );
            if (query2) {
                query2.implementation = function(uri: string, astr: any, bstr: string, cstr: any, dstr: string) {
                    const stack = threadInstance.currentThread().getStackTrace();
                    if (uri == 'content://com.google.android.gsf.gservicesa') {
                        createTelephonyEvent("telephony.content_resolver.query_gsf", {
                            library: "android.content.ContentResolver",
                            method: "query",
                            uri: uri,
                            action: "cloaking_gsf_query",
                            stack_trace: Where(stack)
                        });
                        return null;
                    } else {
                        // note: Java.use inside .implementation => valid, in Java.perform context
                        const result = Java.use('android.app.ActivityThread')
                            .currentApplication()
                            .getApplicationContext()
                            .getContentResolver()
                            .query(uri, astr, bstr, cstr, dstr);
                        createTelephonyEvent("telephony.content_resolver.query", {
                            library: "android.content.ContentResolver",
                            method: "query",
                            uri: uri,
                            has_result: result !== null,
                            stack_trace: Where(stack)
                        });
                        return result;
                    }
                };
            }

            const query3 = safeOverload(
                contentResolver.query,
                "telephony:ContentResolver.query",
                'android.net.Uri', '[Ljava.lang.String;',
                'java.lang.String', '[Ljava.lang.String;',
                'java.lang.String', 'android.os.CancellationSignal'
            );
            if (query3) {
                query3.implementation = function(uri: string, astr: any, bstr: string, cstr: any, sig: any) {
                    const stack = threadInstance.currentThread().getStackTrace();
                    if (uri == 'content://com.google.android.gsf.gservicesa') {
                        createTelephonyEvent("telephony.content_resolver.query_gsf", {
                            library: "android.content.ContentResolver",
                            method: "query",
                            uri: uri,
                            action: "cloaking_gsf_query",
                            stack_trace: Where(stack)
                        });
                        return null;
                    } else {
                        const result = this.query(uri, astr, bstr, cstr, sig);
                        createTelephonyEvent("telephony.content_resolver.query", {
                            library: "android.content.ContentResolver",
                            method: "query",
                            uri: uri,
                            has_result: result !== null,
                            stack_trace: Where(stack)
                        });
                        return result;
                    }
                };
            }
        }

        if (secureSettings) {
            secureSettings.getString.implementation = function(contentresolver: any, query: string) {
                const result = this.getString(contentresolver, query);
                const stack = threadInstance.currentThread().getStackTrace();
                /*if (query === 'android_id') {
                    createTelephonyEvent("telephony.secure_settings.get_android_id", {
                        library: "android.provider.Settings$Secure",
                        method: "getString",
                        query: query,
                        action: "cloaking_android_id",
                        stack_trace: Where(stack)
                    });
                    return payl0ad;
                } else { */
                createTelephonyEvent("telephony.secure_settings.get_string", {
                    library: "android.provider.Settings$Secure",
                    method: "getString",
                    query: query,
                    value: result,
                    stack_trace: Where(stack)
                });
                return result;
            };
        }
    });
}


/*
// currently these hooks seems to stop the behavour of the malware cateletis
function hook_device_infos_and_cloak(){
    Java.perform(() => {
        try {
            //const networkInterface = Java.use('java.net.NetworkInterface');
            const secureSettings = Java.use('android.provider.Settings$Secure');
            const contentResolver = Java.use('android.content.ContentResolver');
            const wifiInfo = Java.use('android.net.wifi.WifiInfo');
            const bluetoothAdapter = Java.use('android.bluetooth.BluetoothAdapter');
            //const mediaDrm = Java.use('android.media.MediaDrm');
            const telephonyManager = Java.use('android.telephony.TelephonyManager');
            const build = Java.use('android.os.Build');
            const systemProperties = Java.use('android.os.SystemProperties');
            const buildProperties = Java.use('android.os.Build');
    
            //-----------------------------------------------
            /*
            buildProperties.MODEL.value = "payload";
            buildProperties.DEVICE.value = "payload";
            buildProperties.BOARD.value = "payload";
            buildProperties.PRODUCT.value = "payload";
            buildProperties.HARDWARE.value = "payload";
            buildProperties.FINGERPRINT.value = "payload";
            buildProperties.MANUFACTURER.value = "payload";
            buildProperties.BOOTLOADER.value = "payload";
            buildProperties.BRAND.value = "payload";
            buildProperties.HOST.value = "payload";
            buildProperties.ID.value = "payload";
            buildProperties.DISPLAY.value = "payload";
            buildProperties.TAGS.value = "payload";
            buildProperties.SERIAL.value = "payload";
            buildProperties.TYPE.value = "payload";
            buildProperties.USER.value = "payload";
            buildProperties.UNKNOWN.value = "payload";/
    
            //-----------------------------------------------
    
            const payl0ad = "payload";
    
            //am_send(PROFILE_HOOKING_TYPE, "Payload: " + payl0ad);
    
            systemProperties.get.overload('java.lang.String').implementation = function (key_value: string) {
                var result = this.get(key_value);
                var json_obj = {
                    event_type: "Java::SystemProperties",
                    method: "android.os.SystemProperties.get(key)",
                    event: "Get system properties called using key",
                    key: key_value,
                    return: result

                }
                am_send(PROFILE_HOOKING_TYPE, JSON.stringify(json_obj));
                return result;
            }
    
            build.getSerial.implementation = function () {
                am_send(PROFILE_HOOKING_TYPE, '[+] Application is fetching the OS serial, returning ' + payl0ad);
                return payl0ad;
            }
    
            telephonyManager.getLine1Number.overloads[0].implementation = function () {
                am_send(PROFILE_HOOKING_TYPE, '[+] Application is fetching the phone number, returning ' + payl0ad);
                return payl0ad;
            }
    
            telephonyManager.getSubscriberId.overload().implementation = function () {
                am_send(PROFILE_HOOKING_TYPE, '[i] Application asks for device IMSI, returning:' + payl0ad);
                return payl0ad;
            }
            telephonyManager.getSubscriberId.overload('int').implementation = function () {
                am_send(PROFILE_HOOKING_TYPE, '[i] Application asks for device IMSI, returning ' + payl0ad);
                return payl0ad;
            }
    
            telephonyManager.getDeviceId.overloads[0].implementation = function () {
                am_send(PROFILE_HOOKING_TYPE, '[i] Application asks for device IMEI, returning' + payl0ad);
                return payl0ad;
            }
            telephonyManager.getDeviceId.overloads[1].implementation = function (slot: number) {
                am_send(PROFILE_HOOKING_TYPE, '[i] Application asks for device IMEI, returning:' + payl0ad);
                return payl0ad;
            }
    
            telephonyManager.getImei.overloads[0].implementation = function () {
                am_send(PROFILE_HOOKING_TYPE, '[i] Application asks for device IMEI, returning :' + payl0ad);
                return payl0ad;
            }
            telephonyManager.getImei.overloads[1].implementation = function (slot: number) {
                am_send(PROFILE_HOOKING_TYPE, '[i] Application asks for device IMEI, returning: ' + payl0ad);
                return payl0ad;
            }
    
            telephonyManager.getSimOperator.overload().implementation = function () {
                am_send(PROFILE_HOOKING_TYPE, '[+] getSimOperator call detected, returning:' + payl0ad);
                return payl0ad;
            }
            telephonyManager.getSimOperator.overload('int').implementation = function (sm: number) {
                am_send(PROFILE_HOOKING_TYPE, '[+] getSimOperator call detected, returning:' + payl0ad);
                return payl0ad;
            }
    
            bluetoothAdapter.getAddress.implementation = function () {
                am_send(PROFILE_HOOKING_TYPE, "[+] Cloaking BT Mac Address, returning:" + payl0ad);
                return payl0ad;
            }
    
            wifiInfo.getMacAddress.implementation = function () {
                var result = this.getMacAddress();
                var json_obj = {
                    event_type: "Java::WifiInfo",
                    method: "android.net.wifi.WifiInfo.getMacAddress()",
                    event: "retrieving wifi Mac Address",
                    return: result

                }
                am_send(PROFILE_HOOKING_TYPE, JSON.stringify(json_obj));
                return result;
            }
            wifiInfo.getSSID.implementation = function () {
                var result = this.getSSID();
                var json_obj = {
                    event_type: "Java::WifiInfo",
                    method: "android.net.wifi.WifiInfo.getSSID()",
                    event: "retrieving SSID",
                    return: result

                }
                am_send(PROFILE_HOOKING_TYPE, JSON.stringify(json_obj));
                return result;
                //am_send(PROFILE_HOOKING_TYPE, "[+] Cloaking SSID, returning:" + payl0ad);
                //return payl0ad;
            }
            wifiInfo.getBSSID.implementation = function () {
                var result = this.getBSSID();
                var json_obj = {
                    event_type: "Java::WifiInfo",
                    method: "android.net.wifi.WifiInfo.getBSSID()",
                    event: "retrieving  Router Mac Address",
                    return: result

                }
                am_send(PROFILE_HOOKING_TYPE, JSON.stringify(json_obj));
                return result;
                //am_send(PROFILE_HOOKING_TYPE, "[+] Cloaking Router Mac Address, returning:" + payl0ad);
                //return payl0ad;
            }
    
            contentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle', 'android.os.CancellationSignal').implementation = function (uri: string, str: any, bundle: any, sig: any) {
                if (uri == 'content://com.google.android.gsf.gservicesa') {
                    am_send(PROFILE_HOOKING_TYPE, '[+] Cloaking Google Services Framework Identifier Query, returning null');
                    return null;
                } else
                    return payl0ad;
            }
    
            contentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function (uri: string, astr: any, bstr: string, cstr: any, dstr: string) {
                if (uri == 'content://com.google.android.gsf.gservicesa') {
                    am_send(PROFILE_HOOKING_TYPE, '[+] Cloaking Google Services Framework Identifier Query, returning null');
                    return null;
                } else
                    return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext().getContentResolver().query(uri, astr, bstr, cstr, dstr);
            }
    
            contentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal').implementation = function (uri: string, astr: any, bstr: string, cstr: any, sig: any) {
                if (uri == 'content://com.google.android.gsf.gservicesa') {
                    am_send(PROFILE_HOOKING_TYPE, '[+] Cloaking Google Services Framework Identifier Query, returning null');
                    return null;
                } else
                    return payl0ad;
            }
    
            secureSettings.getString.implementation = function (contentresolver: any, query: string) {
                am_send(PROFILE_HOOKING_TYPE, '[+] Cloaking Android ID, returning dummy value:' + payl0ad);
                if (query == 'android_id')
                    return payl0ad;
                else
                    return this.getString(contentresolver, query);
            }
        } catch (error) {
            am_send(PROFILE_HOOKING_TYPE, "Error: "+(error as Error).toString());
        }
    });
}*/


export function install_telephony_manager_hooks(){
    devlog("\n")
    devlog("install telephony manager hooks");

    try {
        hook_device_infos();
    } catch (error) {
        devlog(`[HOOK] Failed to install device info hooks: ${error}`);
    }

    try {
        hook_sms();
    } catch (error) {
        devlog(`[HOOK] Failed to install SMS hooks: ${error}`);
    }

    //try {
    //    hook_mms();
    //} catch (error) {
    //    devlog(`[HOOK] Failed to install MMS hooks: ${error}`);
    //}
}
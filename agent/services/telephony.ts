import { log, devlog, am_send } from "../utils/logging.js"

/**
 * Mostly stuff from TelephonyManager gets hooked
 * https://codeshare.frida.re/@Ch0pin/log4jfrida/
 */

 const PROFILE_HOOKING_TYPE: string = "TELEPHONY"

 function hook_sms(){
    const SmsManager = Java.use('android.telephony.SmsManager');
    

    // Hook SmsManager's sendTextMessage method
    SmsManager.sendTextMessage.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'android.app.PendingIntent', 'android.app.PendingIntent').implementation = function (destinationAddress: string, scAddress: string, text: string, sentIntent: any, deliveryIntent: any) {
        const event_type_content = 'Java::SMS';
        var json_result = {
            event_type: event_type_content,
            method: 'android.telephony.SmsManager.sendTextMessage',
            Destination_Address: destinationAddress,
            Source_Address: scAddress,
            Content: text,
            SentIntent: sentIntent ? sentIntent.toString() : null,
            DeliveryIntent: deliveryIntent ? deliveryIntent.toString() : null,
        }
        am_send("UNTERSUCUNG",JSON.stringify(json_result));
        am_send(PROFILE_HOOKING_TYPE, JSON.stringify(json_result));
        return this.sendTextMessage(destinationAddress, scAddress, text, sentIntent, deliveryIntent);
    };

    // Hook SmsManager's sendMultipartTextMessage method
    SmsManager.sendMultipartTextMessage.overload('java.lang.String', 'java.lang.String', 'java.util.ArrayList', 'java.util.ArrayList', 'java.util.ArrayList').implementation = function (destinationAddress: string, scAddress: string, parts: any, sentIntents: any, deliveryIntents: any) {
        const event_type_content = 'Java::SMS_Multipart';
        const partsArray = parts.toArray();
        const sentIntentsArray = sentIntents ? sentIntents.toArray() : null;
        const deliveryIntentsArray = deliveryIntents ? deliveryIntents.toArray() : null;
        var json_result = {
            event_type: event_type_content,
            method: 'android.telephony.SmsManager.sendMultipartTextMessage',
            Destination_Address: destinationAddress,
            Source_Address: scAddress,
            Content_Parts: partsArray,
            SentIntent: sentIntentsArray,
            DeliveryIntent: deliveryIntentsArray,
        }
        am_send("UNTERSUCUNG2",JSON.stringify(json_result));
        am_send(PROFILE_HOOKING_TYPE, JSON.stringify(json_result));
        return this.sendMultipartTextMessage(destinationAddress, scAddress, parts, sentIntents, deliveryIntents);
    };

   

}

function hook_mms(){
    // is only available on newer android versions
    const MmsManager = Java.use('android.telephony.Mms'); 

     // currently these are send via Itents and therefore we have to investigate further how to handle and hooks this
     

}

function hook_device_infos() {
    Java.perform(() => {
        try {
            const secureSettings = Java.use('android.provider.Settings$Secure');
            const contentResolver = Java.use('android.content.ContentResolver');
            const wifiInfo = Java.use('android.net.wifi.WifiInfo');
            const bluetoothAdapter = Java.use('android.bluetooth.BluetoothAdapter');
            const telephonyManager = Java.use('android.telephony.TelephonyManager');
            const build = Java.use('android.os.Build');
            const systemProperties = Java.use('android.os.SystemProperties');

            const seenEvents: { [key: string]: string } = {};

            
            function sendHookEvent(eventType: string, method: string, event: string, key: string | null = null, result: any = null) {
                const json_obj: any = {
                    event_type: eventType,
                    method: method,
                    event: event,
                };
                if (key !== null) json_obj.key = key;
                if (result !== null) json_obj.return = result;

                // Remove empty or null key-value pairs
                Object.keys(json_obj).forEach(key => {
                    if (json_obj[key] === null || json_obj[key] === '') {
                        delete json_obj[key];
                    }
                });

                const eventKey = `${event}:${key}`;
                if (event === "Get system properties called using key" && seenEvents[eventKey] === result) {
                    return;
                }

                seenEvents[eventKey] = result;
                am_send(PROFILE_HOOKING_TYPE, JSON.stringify(json_obj));
            }


            // Hook system properties get method
            systemProperties.get.overload('java.lang.String').implementation = function (key_value: string) {
                const result = this.get(key_value);
                sendHookEvent("Java::SystemProperties", "android.os.SystemProperties.get(key)", "Get system properties called using key", key_value, result);
                return result;
            };

            // Hook build properties
            const buildProperties = [
                'MODEL', 'DEVICE', 'BOARD', 'PRODUCT', 'HARDWARE', 'FINGERPRINT',
                'MANUFACTURER', 'BOOTLOADER', 'BRAND', 'HOST', 'ID', 'DISPLAY',
                'TAGS', 'SERIAL', 'TYPE', 'USER', 'UNKNOWN'
            ];

            buildProperties.forEach(prop => {
                Object.defineProperty(build, prop, {
                    get: function () {
                        const result = build[prop].value;
                        sendHookEvent("Java::Build", `android.os.Build.${prop}`, `Fetching ${prop}`, null, result);
                        return result;
                    },
                    set: function (newValue) {
                        // This setter can be used to monitor if the value is set
                        // For now, it just returns without modifying the value
                        sendHookEvent("Java::Build", `android.os.Build.${prop}`, `Attempt to set ${prop}`, null, newValue);
                    },
                    configurable: true
                });
            });

            // Hook telephony manager methods
            telephonyManager.getLine1Number.overloads[0].implementation = function () {
                const result = this.getLine1Number();
                sendHookEvent("Java::TelephonyManager", "android.telephony.TelephonyManager.getLine1Number()", "Fetching phone number", null, result);
                return result;
            };

            telephonyManager.getSubscriberId.overload().implementation = function () {
                const result = this.getSubscriberId();
                sendHookEvent("Java::TelephonyManager", "android.telephony.TelephonyManager.getSubscriberId()", "Fetching device IMSI", null, result);
                return result;
            };

            telephonyManager.getSubscriberId.overload('int').implementation = function (slot: number) {
                const result = this.getSubscriberId(slot);
                sendHookEvent("Java::TelephonyManager", "android.telephony.TelephonyManager.getSubscriberId(int)", "Fetching device IMSI", null, result);
                return result;
            };

            telephonyManager.getDeviceId.overloads[0].implementation = function () {
                const result = this.getDeviceId();
                sendHookEvent("Java::TelephonyManager", "android.telephony.TelephonyManager.getDeviceId()", "Fetching device IMEI", null, result);
                return result;
            };

            telephonyManager.getDeviceId.overloads[1].implementation = function (slot: number) {
                const result = this.getDeviceId(slot);
                sendHookEvent("Java::TelephonyManager", "android.telephony.TelephonyManager.getDeviceId(int)", "Fetching device IMEI", null, result);
                return result;
            };

            telephonyManager.getImei.overloads[0].implementation = function () {
                const result = this.getImei();
                sendHookEvent("Java::TelephonyManager", "android.telephony.TelephonyManager.getImei()", "Fetching device IMEI", null, result);
                return result;
            };

            telephonyManager.getImei.overloads[1].implementation = function (slot: number) {
                const result = this.getImei(slot);
                sendHookEvent("Java::TelephonyManager", "android.telephony.TelephonyManager.getImei(int)", "Fetching device IMEI", slot.toString(), result);
                return result;
            };

            telephonyManager.getSimOperator.overload().implementation = function () {
                const result = this.getSimOperator();
                sendHookEvent("Java::TelephonyManager", "android.telephony.TelephonyManager.getSimOperator()", "Fetching SIM operator", null, result);
                return result;
            };

            telephonyManager.getSimOperator.overload('int').implementation = function (sm: number) {
                const result = this.getSimOperator(sm);
                sendHookEvent("Java::TelephonyManager", "android.telephony.TelephonyManager.getSimOperator(int)", "Fetching SIM operator", sm.toString(), result);
                return result;
            };

            bluetoothAdapter.getAddress.implementation = function () {
                const result = this.getAddress();
                sendHookEvent("Java::BluetoothAdapter", "android.bluetooth.BluetoothAdapter.getAddress()", "Fetching Bluetooth MAC address", null, result);
                return result;
            };

            wifiInfo.getMacAddress.implementation = function () {
                const result = this.getMacAddress();
                sendHookEvent("Java::WifiInfo", "android.net.wifi.WifiInfo.getMacAddress()", "Retrieving WiFi MAC address", null, result);
                return result;
            };

            wifiInfo.getSSID.implementation = function () {
                const result = this.getSSID();
                sendHookEvent("Java::WifiInfo", "android.net.wifi.WifiInfo.getSSID()", "Retrieving SSID", null, result);
                return result;
            };

            wifiInfo.getBSSID.implementation = function () {
                const result = this.getBSSID();
                sendHookEvent("Java::WifiInfo", "android.net.wifi.WifiInfo.getBSSID()", "Retrieving router MAC address", null, result);
                return result;
            };

            contentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle', 'android.os.CancellationSignal').implementation = function (uri: string, str: any, bundle: any, sig: any) {
                if (uri == 'content://com.google.android.gsf.gservicesa') {
                    sendHookEvent("Java::ContentResolver", "android.content.ContentResolver.query()", "Cloaking Google Services Framework Identifier Query", uri, null);
                    return null;
                } else {
                    const result = this.query(uri, str, bundle, sig);
                    sendHookEvent("Java::ContentResolver", "android.content.ContentResolver.query()", "Querying content resolver", uri, result);
                    return result;
                }
            };

            contentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function (uri: string, astr: any, bstr: string, cstr: any, dstr: string) {
                if (uri == 'content://com.google.android.gsf.gservicesa') {
                    sendHookEvent("Java::ContentResolver", "android.content.ContentResolver.query()", "Cloaking Google Services Framework Identifier Query", uri, null);
                    return null;
                } else {
                    const result = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext().getContentResolver().query(uri, astr, bstr, cstr, dstr);
                    sendHookEvent("Java::ContentResolver", "android.content.ContentResolver.query()", "Querying content resolver", uri, result);
                    return result;
                }
            };

            contentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal').implementation = function (uri: string, astr: any, bstr: string, cstr: any, sig: any) {
                if (uri == 'content://com.google.android.gsf.gservicesa') {
                    sendHookEvent("Java::ContentResolver", "android.content.ContentResolver.query()", "Cloaking Google Services Framework Identifier Query", uri, null);
                    return null;
                } else {
                    const result = this.query(uri, astr, bstr, cstr, sig);
                    sendHookEvent("Java::ContentResolver", "android.content.ContentResolver.query()", "Querying content resolver", uri, result);
                    return result;
                }
            };

            secureSettings.getString.implementation = function (contentresolver: any, query: string) {
                const result = this.getString(contentresolver, query);
                /*if (query === 'android_id') {
                    sendHookEvent("Java::SecureSettings", "android.provider.Settings$Secure.getString()", "Cloaking Android ID", query, payl0ad);
                    return payl0ad;
                } else { */
                    sendHookEvent("Java::SecureSettings", "android.provider.Settings$Secure.getString()", "Retrieving secure setting", query, result);
                    return result;
                //}
            };
        } catch (error) {
            am_send(PROFILE_HOOKING_TYPE, "Error: " + (error as Error).toString());
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
    hook_device_infos();
    hook_sms();
    //hook_mms();

}
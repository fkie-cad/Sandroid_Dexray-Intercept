import { log, devlog, am_send } from "../utils/logging.js"
import { Java } from "../utils/javalib.js"

const PROFILE_HOOKING_TYPE: string = "BLUETOOTH"

/**
 * Mostly stuff from TelephonyManager gets hooked
 * https://github.com/dpnishant/appmon/blob/master/scripts/Android/Bluetooth/Bluetooth.js
 * 
 */


 function hook_bluetooth(){
    Java.perform(function () {
    const BluetoothGatt = Java.use("android.bluetooth.BluetoothGatt");
    const BluetoothGattCharacteristic = Java.use("android.bluetooth.BluetoothGattCharacteristic");

    BluetoothGatt.readCharacteristic.overload("android.bluetooth.BluetoothGattCharacteristic").implementation = function(characteristic: any) {
        const send_data: any = {};    
        send_data.event_type = 'Java::Bluetooth';
        send_data.lib = 'android.bluetooth.BluetoothGatt';
        send_data.method = 'readCharacteristic';
        send_data.artifact = [];

        const data: any = {};
        data.name = characteristic.getUuid().toString();
        data.value = characteristic.getValue().toString();
        data.argSeq = 0;
        send_data.artifact.push(data);
        am_send(PROFILE_HOOKING_TYPE, JSON.stringify(send_data));

        return this.readCharacteristic.overload("android.bluetooth.BluetoothGattCharacteristic").apply(this, arguments);
    };

    BluetoothGattCharacteristic.setValue.overload("[B").implementation = function(value: any) {
        const send_data: any = {};
        send_data.event_type = 'Java::Bluetooth';
        send_data.lib = 'android.bluetooth.BluetoothGattCharacteristic';
        send_data.method = 'setValue';
        send_data.artifact = [];

        const data: any = {};
        data.name = this.getUuid().toString();
        data.value = value.toString();
        data.argSeq = 0;
        send_data.artifact.push(data);
        am_send(PROFILE_HOOKING_TYPE,JSON.stringify(send_data));

        return this.setValue.overload("[B").apply(this, arguments);
    };
    });

}



export function install_bluetooth_hooks(){
    devlog("\n")
    devlog("install bluetooth hooks");
    hook_bluetooth();

}
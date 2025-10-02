import { log, devlog, am_send } from "../utils/logging.js"
import { Java } from "../utils/javalib.js"
import { Where, bytesToHex } from "../utils/misc.js"

const PROFILE_HOOKING_TYPE: string = "BLUETOOTH"

function createBluetoothEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function hook_bluetooth(){
    Java.perform(() => {
        try {
            const BluetoothGatt = Java.use("android.bluetooth.BluetoothGatt");
            const BluetoothGattCharacteristic = Java.use("android.bluetooth.BluetoothGattCharacteristic");
            const BluetoothAdapter = Java.use("android.bluetooth.BluetoothAdapter");
            const BluetoothDevice = Java.use("android.bluetooth.BluetoothDevice");
            const threadDef = Java.use('java.lang.Thread');
            const threadInstance = threadDef.$new();

            // Hook BluetoothGatt.readCharacteristic
            BluetoothGatt.readCharacteristic.overload("android.bluetooth.BluetoothGattCharacteristic").implementation = function(characteristic: any) {
                const stack = threadInstance.currentThread().getStackTrace();
                const uuid = characteristic.getUuid().toString();
                const value = characteristic.getValue();
                
                createBluetoothEvent("bluetooth.gatt.read_characteristic", {
                    library: 'android.bluetooth.BluetoothGatt',
                    method: 'readCharacteristic',
                    characteristic_uuid: uuid,
                    characteristic_value: value ? bytesToHex(new Uint8Array(value)) : null,
                    stack_trace: Where(stack)
                });

                return this.readCharacteristic.overload("android.bluetooth.BluetoothGattCharacteristic").apply(this, arguments);
            };

            // Hook BluetoothGattCharacteristic.setValue
            BluetoothGattCharacteristic.setValue.overload("[B").implementation = function(value: any) {
                const stack = threadInstance.currentThread().getStackTrace();
                const uuid = this.getUuid().toString();
                
                createBluetoothEvent("bluetooth.gatt.set_characteristic_value", {
                    library: 'android.bluetooth.BluetoothGattCharacteristic',
                    method: 'setValue',
                    characteristic_uuid: uuid,
                    value_hex: value ? bytesToHex(new Uint8Array(value)) : null,
                    value_length: value ? value.length : 0,
                    stack_trace: Where(stack)
                });

                return this.setValue.overload("[B").apply(this, arguments);
            };

            // Hook BluetoothAdapter methods
            if (BluetoothAdapter.getDefaultAdapter) {
                BluetoothAdapter.getDefaultAdapter.implementation = function() {
                    const stack = threadInstance.currentThread().getStackTrace();
                    const result = this.getDefaultAdapter();
                    
                    createBluetoothEvent("bluetooth.adapter.get_default", {
                        library: 'android.bluetooth.BluetoothAdapter',
                        method: 'getDefaultAdapter',
                        adapter_available: result !== null,
                        stack_trace: Where(stack)
                    });

                    return result;
                };
            }

            // Hook BluetoothAdapter.enable
            BluetoothAdapter.enable.implementation = function() {
                const stack = threadInstance.currentThread().getStackTrace();
                const result = this.enable();
                
                createBluetoothEvent("bluetooth.adapter.enable", {
                    library: 'android.bluetooth.BluetoothAdapter',
                    method: 'enable',
                    success: result,
                    stack_trace: Where(stack)
                });

                return result;
            };

            // Hook BluetoothAdapter.disable
            BluetoothAdapter.disable.implementation = function() {
                const stack = threadInstance.currentThread().getStackTrace();
                const result = this.disable();
                
                createBluetoothEvent("bluetooth.adapter.disable", {
                    library: 'android.bluetooth.BluetoothAdapter',
                    method: 'disable',
                    success: result,
                    stack_trace: Where(stack)
                });

                return result;
            };

            // Hook BluetoothAdapter.startDiscovery
            BluetoothAdapter.startDiscovery.implementation = function() {
                const stack = threadInstance.currentThread().getStackTrace();
                const result = this.startDiscovery();
                
                createBluetoothEvent("bluetooth.adapter.start_discovery", {
                    library: 'android.bluetooth.BluetoothAdapter',
                    method: 'startDiscovery',
                    success: result,
                    stack_trace: Where(stack)
                });

                return result;
            };

            // Hook BluetoothDevice.createBond
            BluetoothDevice.createBond.implementation = function() {
                const stack = threadInstance.currentThread().getStackTrace();
                const deviceAddress = this.getAddress();
                const deviceName = this.getName();
                const result = this.createBond();
                
                createBluetoothEvent("bluetooth.device.create_bond", {
                    library: 'android.bluetooth.BluetoothDevice',
                    method: 'createBond',
                    device_address: deviceAddress,
                    device_name: deviceName,
                    success: result,
                    stack_trace: Where(stack)
                });

                return result;
            };

        } catch (error) {
            createBluetoothEvent("bluetooth.error", {
                error_message: (error as Error).toString(),
                error_type: "hook_bluetooth"
            });
        }
    });
}



export function install_bluetooth_hooks(){
    devlog("\n")
    devlog("install bluetooth hooks");

    try {
        hook_bluetooth();
    } catch (error) {
        devlog(`[HOOK] Failed to install bluetooth hooks: ${error}`);
    }
}
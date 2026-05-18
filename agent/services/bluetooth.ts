import { log, devlog, am_send } from "../utils/logging.js"
import { Java } from "../utils/javalib.js"
import { Where, bytesToHex } from "../utils/misc.js"
import { safePerform, safeUse, safeOverload } from "../utils/safe_java.js"

const PROFILE_HOOKING_TYPE: string = "BLUETOOTH"

function createBluetoothEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function hook_bluetooth() {
    safePerform("bluetooth:hook_bluetooth", () => {
        const BluetoothGatt = safeUse(
            "android.bluetooth.BluetoothGatt",
            "bluetooth:hook_bluetooth"
        );
        const BluetoothGattCharacteristic = safeUse(
            "android.bluetooth.BluetoothGattCharacteristic",
            "bluetooth:hook_bluetooth"
        );
        const BluetoothAdapter = safeUse(
            "android.bluetooth.BluetoothAdapter",
            "bluetooth:hook_bluetooth"
        );
        const BluetoothDevice = safeUse(
            "android.bluetooth.BluetoothDevice",
            "bluetooth:hook_bluetooth"
        );
        const threadDef = safeUse('java.lang.Thread', "bluetooth:hook_bluetooth");
        if (!threadDef) return;
        const threadInstance = threadDef.$new();

        // Hook BluetoothGatt.readCharacteristic
        if (BluetoothGatt) {
            const readChar = safeOverload(
                BluetoothGatt.readCharacteristic,
                "bluetooth:BluetoothGatt.readCharacteristic",
                "android.bluetooth.BluetoothGattCharacteristic"
            );
            if (readChar) {
                readChar.implementation = function(characteristic: any) {
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

                    return this.readCharacteristic
                        .overload("android.bluetooth.BluetoothGattCharacteristic")
                        .apply(this, arguments);
                };
            }
        }

        // Hook BluetoothGattCharacteristic.setValue
       if (BluetoothGattCharacteristic) {
            const setValue = safeOverload(
                BluetoothGattCharacteristic.setValue,
                "bluetooth:BluetoothGattCharacteristic.setValue",
                "[B"
            );
            if (setValue) {
                setValue.implementation = function(value: any) {
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
            }
        }

        // Hook BluetoothAdapter methods
        if (BluetoothAdapter) {
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
        }

            // Hook BluetoothDevice.createBond
        if (BluetoothDevice) {
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
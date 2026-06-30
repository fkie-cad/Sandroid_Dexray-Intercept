import { log, devlog, am_send } from "../utils/logging.js"
import { Java } from "../utils/javalib.js"
import { Where, bytesToHex } from "../utils/misc.js"
import { safePerform, safeUse, safeOverload, safeImplementation } from "../utils/safe_java.js"

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

        if (BluetoothGatt) {
            const readChar = safeOverload(
                BluetoothGatt.readCharacteristic,
                "bluetooth:BluetoothGatt.readCharacteristic",
                "android.bluetooth.BluetoothGattCharacteristic"
            );
            if (readChar) {
                readChar.implementation = safeImplementation(
                    "bluetooth:BluetoothGatt.readCharacteristic",
                    readChar,
                    function(original, characteristic: any) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        const uuid = characteristic.getUuid().toString();
                        // getValue() removed - value is not available at this point (pre-read)
                        // actual value captured by the getValue hook after onCharacteristicRead fires
                        createBluetoothEvent("bluetooth.gatt.read_characteristic", {
                            library: 'android.bluetooth.BluetoothGatt',
                            method: 'readCharacteristic',
                            characteristic_uuid: uuid,
                            stack_trace: Where(stack)
                        });
                        return original.call(this, characteristic);
                    }
                );
            }
        }

        if (BluetoothGattCharacteristic) {
            const setValue = safeOverload(
                BluetoothGattCharacteristic.setValue,
                "bluetooth:BluetoothGattCharacteristic.setValue",
                "[B"
            );
            if (setValue) {
                setValue.implementation = safeImplementation(
                    "bluetooth:BluetoothGattCharacteristic.setValue",
                    setValue,
                    function(original, value: any) {
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
                        return original.call(this, value);
                    }
                );
            }

            // getValue() fires when the app reads the characteristic value after onCharacteristicRead
            // completes - this is where the actual remote value is available, unlike readCharacteristic
            // which fires before the async round-trip
            const getValueRef = safeOverload(
                BluetoothGattCharacteristic.getValue,
                "bluetooth:BluetoothGattCharacteristic.getValue"
            );
            if (getValueRef) {
                getValueRef.implementation = safeImplementation(
                    "bluetooth:BluetoothGattCharacteristic.getValue",
                    getValueRef,
                    function(original) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        const result = original.call(this);
                        const uuid = this.getUuid().toString();
                        createBluetoothEvent("bluetooth.gatt.get_characteristic_value", {
                            library: 'android.bluetooth.BluetoothGattCharacteristic',
                            method: 'getValue',
                            characteristic_uuid: uuid,
                            value_hex: result ? bytesToHex(new Uint8Array(result)) : null,
                            value_length: result ? result.length : 0,
                            stack_trace: Where(stack)
                        });
                        return result;
                    }
                );
            }
        }

        if (BluetoothAdapter) {
            // capture reference before assigning .implementation for non-overload methods
            // getDefaultAdapter is static with no overloads; safeOverload used for consistency
            const getDefaultAdapterRef = safeOverload(
                BluetoothAdapter.getDefaultAdapter,
                "bluetooth:BluetoothAdapter.getDefaultAdapter"
            );
            if (getDefaultAdapterRef) {
                getDefaultAdapterRef.implementation = safeImplementation(
                    "bluetooth:BluetoothAdapter.getDefaultAdapter",
                    getDefaultAdapterRef,
                    function(original) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        const result = original.call(this);
                        createBluetoothEvent("bluetooth.adapter.get_default", {
                            library: 'android.bluetooth.BluetoothAdapter',
                            method: 'getDefaultAdapter',
                            adapter_available: result !== null,
                            stack_trace: Where(stack)
                        });
                        return result;
                    }
                );
            }

            const enableRef = safeOverload(
                BluetoothAdapter.enable,
                "bluetooth:BluetoothAdapter.enable"
            );
            if (enableRef) {
                enableRef.implementation = safeImplementation(
                    "bluetooth:BluetoothAdapter.enable",
                    enableRef,
                    function(original) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        const result = original.call(this);
                        createBluetoothEvent("bluetooth.adapter.enable", {
                            library: 'android.bluetooth.BluetoothAdapter',
                            method: 'enable',
                            success: result,
                            stack_trace: Where(stack)
                        });
                        return result;
                    }
                );
            }

            // disable() gained a disable(boolean killApps) overload on API 33+
            // each overload is resolved and hooked independently - failure of one does not affect the other
            // or block startDiscovery / createBond below
            const disableNoArg = safeOverload(
                BluetoothAdapter.disable,
                "bluetooth:BluetoothAdapter.disable[]"
            );
            if (disableNoArg) {
                disableNoArg.implementation = safeImplementation(
                    "bluetooth:BluetoothAdapter.disable[]",
                    disableNoArg,
                    function(original) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        const result = original.call(this);
                        createBluetoothEvent("bluetooth.adapter.disable", {
                            library: 'android.bluetooth.BluetoothAdapter',
                            method: 'disable',
                            success: result,
                            stack_trace: Where(stack)
                        });
                        return result;
                    }
                );
            }

            // API 33+ overload - kill_apps indicates whether connected apps are also killed
            const disableWithKillApps = safeOverload(
                BluetoothAdapter.disable,
                "bluetooth:BluetoothAdapter.disable[boolean]",
                "boolean"
            );
            if (disableWithKillApps) {
                disableWithKillApps.implementation = safeImplementation(
                    "bluetooth:BluetoothAdapter.disable[boolean]",
                    disableWithKillApps,
                    function(original, killApps: boolean) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        const result = original.call(this, killApps);
                        createBluetoothEvent("bluetooth.adapter.disable", {
                            library: 'android.bluetooth.BluetoothAdapter',
                            method: 'disable',
                            success: result,
                            kill_apps: killApps,
                            stack_trace: Where(stack)
                        });
                        return result;
                    }
                );
            }

            const startDiscoveryRef = safeOverload(
                BluetoothAdapter.startDiscovery,
                "bluetooth:BluetoothAdapter.startDiscovery"
            );
            if (startDiscoveryRef) {
                startDiscoveryRef.implementation = safeImplementation(
                    "bluetooth:BluetoothAdapter.startDiscovery",
                    startDiscoveryRef,
                    function(original) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        const result = original.call(this);
                        createBluetoothEvent("bluetooth.adapter.start_discovery", {
                            library: 'android.bluetooth.BluetoothAdapter',
                            method: 'startDiscovery',
                            success: result,
                            stack_trace: Where(stack)
                        });
                        return result;
                    }
                );
            }
        }

        if (BluetoothDevice) {
            const createBondRef = safeOverload(
                BluetoothDevice.createBond,
                "bluetooth:BluetoothDevice.createBond"
            );
            if (createBondRef) {
                createBondRef.implementation = safeImplementation(
                    "bluetooth:BluetoothDevice.createBond",
                    createBondRef,
                    function(original) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        const deviceAddress = this.getAddress();
                        const deviceName = this.getName();
                        const result = original.call(this);
                        createBluetoothEvent("bluetooth.device.create_bond", {
                            library: 'android.bluetooth.BluetoothDevice',
                            method: 'createBond',
                            device_address: deviceAddress,
                            device_name: deviceName,
                            success: result,
                            stack_trace: Where(stack)
                        });
                        return result;
                    }
                );
            }
        }
    });
}

export function install_bluetooth_hooks() {
    devlog("\n");
    devlog("install bluetooth hooks");

    try {
        hook_bluetooth();
    } catch (error) {
        devlog(`[HOOK] Failed to install bluetooth hooks: ${error}`);
    }
}
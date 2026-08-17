import { devlog, am_send } from "../utils/logging.js"
import { bytesToHex } from "../utils/misc.js"
import { safePerform, safeUse, safeOverload, safeImplementation } from "../utils/safe_java.js"
import { collectJavaStackTrace } from "../utils/stacktrace.js"

const PROFILE_HOOKING_TYPE: string = "BLUETOOTH"

let _inBluetoothDisable = false;

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
                        const java_stack_trace = collectJavaStackTrace();
                        const uuid = characteristic.getUuid().toString();
                        // getValue() removed - value is not available at this point (pre-read)
                        // actual value captured by the getValue hook after onCharacteristicRead fires
                        createBluetoothEvent("bluetooth.gatt.read_characteristic", {
                            library: 'android.bluetooth.BluetoothGatt',
                            method: 'readCharacteristic',
                            characteristic_uuid: uuid,
                            ...(java_stack_trace ? { java_stack_trace } : {})
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
                        const java_stack_trace = collectJavaStackTrace();
                        const uuid = this.getUuid().toString();
                        createBluetoothEvent("bluetooth.gatt.set_characteristic_value", {
                            library: 'android.bluetooth.BluetoothGattCharacteristic',
                            method: 'setValue',
                            characteristic_uuid: uuid,
                            value_hex: value ? bytesToHex(new Uint8Array(value)) : null,
                            value_length: value ? value.length : 0,
                            ...(java_stack_trace ? { java_stack_trace } : {})
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
                        const java_stack_trace = collectJavaStackTrace();
                        const result = original.call(this);
                        const uuid = this.getUuid().toString();
                        createBluetoothEvent("bluetooth.gatt.get_characteristic_value", {
                            library: 'android.bluetooth.BluetoothGattCharacteristic',
                            method: 'getValue',
                            characteristic_uuid: uuid,
                            value_hex: result ? bytesToHex(new Uint8Array(result)) : null,
                            value_length: result ? result.length : 0,
                            ...(java_stack_trace ? { java_stack_trace } : {})
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
                        const java_stack_trace = collectJavaStackTrace();
                        const result = original.call(this);
                        createBluetoothEvent("bluetooth.adapter.get_default", {
                            library: 'android.bluetooth.BluetoothAdapter',
                            method: 'getDefaultAdapter',
                            adapter_available: result !== null,
                            ...(java_stack_trace ? { java_stack_trace } : {})
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
                        const java_stack_trace = collectJavaStackTrace();
                        const result = original.call(this);
                        createBluetoothEvent("bluetooth.adapter.enable", {
                            library: 'android.bluetooth.BluetoothAdapter',
                            method: 'enable',
                            success: result,
                            ...(java_stack_trace ? { java_stack_trace } : {})
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
                        if (_inBluetoothDisable) {
                            return original.call(this);
                        }

                        _inBluetoothDisable = true;
                        try {
                            const java_stack_trace = collectJavaStackTrace();
                            const result = original.call(this);
                            createBluetoothEvent("bluetooth.adapter.disable", {
                                library: 'android.bluetooth.BluetoothAdapter',
                                method: 'disable',
                                success: result,
                                ...(java_stack_trace ? { java_stack_trace } : {})
                            });
                            return result;
                        } finally {
                            _inBluetoothDisable = false;
                        }
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
                        if (_inBluetoothDisable) {
                            return original.call(this, killApps);
                        }

                        _inBluetoothDisable = true;
                        try {
                            const java_stack_trace = collectJavaStackTrace();
                            const result = original.call(this, killApps);
                            createBluetoothEvent("bluetooth.adapter.disable", {
                                library: 'android.bluetooth.BluetoothAdapter',
                                method: 'disable',
                                success: result,
                                kill_apps: killApps,
                                ...(java_stack_trace ? { java_stack_trace } : {})
                            });
                            return result;
                        } finally {
                            _inBluetoothDisable = false;
                        }
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
                        const java_stack_trace = collectJavaStackTrace();
                        const result = original.call(this);
                        createBluetoothEvent("bluetooth.adapter.start_discovery", {
                            library: 'android.bluetooth.BluetoothAdapter',
                            method: 'startDiscovery',
                            success: result,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return result;
                    }
                );
            }
            
            // Capture adapter address in the Bluetooth category so users enabling only
            // bluetooth hooks receive device-address access events
            const getAddressRef = safeOverload(
                BluetoothAdapter.getAddress,
                "bluetooth:BluetoothAdapter.getAddress"
            );
            if (getAddressRef) {
                getAddressRef.implementation = safeImplementation(
                    "bluetooth:BluetoothAdapter.getAddress",
                    getAddressRef,
                    function(original) {
                        const java_stack_trace = collectJavaStackTrace();
                        const result = original.call(this);
                        createBluetoothEvent("bluetooth.adapter.get_address", {
                            library: 'android.bluetooth.BluetoothAdapter',
                            method: 'getAddress',
                            mac_address: result,
                            ...(java_stack_trace ? { java_stack_trace } : {})
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
                        const java_stack_trace = collectJavaStackTrace();
                        const deviceAddress = this.getAddress();
                        const deviceName = this.getName();
                        const result = original.call(this);
                        createBluetoothEvent("bluetooth.device.create_bond", {
                            library: 'android.bluetooth.BluetoothDevice',
                            method: 'createBond',
                            device_address: deviceAddress,
                            device_name: deviceName,
                            success: result,
                            ...(java_stack_trace ? { java_stack_trace } : {})
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
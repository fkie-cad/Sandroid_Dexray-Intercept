import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"
import { hook_config } from "../hooking_profile_loader.js"

const PROFILE_HOOKING_TYPE: string = "IPC_SHARED-PREF"
const HOOK_NAME = 'shared_prefs_hooks'

interface SharedPrefEvent {
    event_type: string;
    timestamp: number;
    method?: string;
    file?: string;
    key?: string;
    value?: string;
    mode?: number;
    data?: any;
}

function createSharedPrefEvent(eventType: string, data: Partial<SharedPrefEvent>): void {
    // Check if hook is enabled at runtime
    if (!hook_config[HOOK_NAME]) {
        return;
    }
    const event: SharedPrefEvent = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function install_shared_preferences_hooks() {
    devlog("Installing SharedPreferences hooks");
    
    Java.perform(() => {
        const SharedPrefs = Java.use('android.app.SharedPreferencesImpl');
        const SharedPrefsEditor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');

        // Hook SharedPreferences initialization
        SharedPrefs.$init.overload('java.io.File', 'int').implementation = function(file, mode) {
            const result = this.$init(file, mode);
            
            createSharedPrefEvent("shared_prefs.init", {
                method: "SharedPreferencesImpl.$init",
                file: file.getAbsolutePath(),
                mode: mode
            });
            
            return result;
        };

        // Hook SharedPreferences Editor putString
        SharedPrefsEditor.putString.overload('java.lang.String', 'java.lang.String').implementation = function(key, value) {
            createSharedPrefEvent("shared_prefs.put_string", {
                method: "putString",
                key: key,
                value: value
            });
            
            return this.putString(key, value);
        };

        // Hook other Editor methods
        const editorMethods = [
            { method: 'putInt', args: ['java.lang.String', 'int'] },
            { method: 'putLong', args: ['java.lang.String', 'long'] },
            { method: 'putFloat', args: ['java.lang.String', 'float'] },
            { method: 'putBoolean', args: ['java.lang.String', 'boolean'] }
        ];

        editorMethods.forEach(({ method, args }) => {
            try {
                SharedPrefsEditor[method].overload(...args).implementation = function(key: string, value: any) {
                    createSharedPrefEvent(`shared_prefs.${method.toLowerCase()}`, {
                        method: method,
                        key: key,
                        value: value.toString()
                    });
                    
                    return this[method](key, value);
                };
            } catch (e) {
                devlog(`Could not hook SharedPrefsEditor.${method}: ${e}`);
            }
        });


    });
}

function install_datastore_hooks() {
    devlog("Installing DataStore hooks");
    
    Java.perform(() => {
        try {
            // Hook the DataStore class
            const DataStore = Java.use("androidx.datastore.core.DataStore");

            // Hook updateData
            DataStore.updateData.overload("kotlin.coroutines.Continuation").implementation = function (continuation) {
                const result = this.updateData(continuation);

                // Log the result if possible
                result.then((data: any) => {
                    createSharedPrefEvent("datastore.update", {
                        method: "updateData",
                        data: data ? data.toString() : null
                    });
                });

                return result;
            };

            // Hook data (flow)
            if (DataStore.getData) {
                DataStore.getData.overload().implementation = function () {
                    const flow = this.getData();

                    // Hook into the flow to log emitted data
                    flow.collect((data: any) => {
                        createSharedPrefEvent("datastore.get", {
                            method: "getData",
                            data: data ? data.toString() : null
                        });
                    });

                    return flow;
                };
            }
        } catch (e) {
            devlog(`DataStore not available: ${e}`);
        }

        try {
            // Hook Preferences DataStore (key-value)
            const Preferences = Java.use("androidx.datastore.preferences.core.Preferences");
            Preferences.get.overload("androidx.datastore.preferences.core.Preferences$Key").implementation = function (key) {
                const value = this.get(key);
                
                createSharedPrefEvent("datastore_prefs.get", {
                    method: "get",
                    key: key ? key.toString() : "unknown",
                    value: value ? value.toString() : null
                });
                
                return value;
            };

            // Hook Preferences.Key class
            const PreferencesKey = Java.use("androidx.datastore.preferences.core.Preferences$Key");
            PreferencesKey.$init.overload("java.lang.String").implementation = function (keyName) {
                createSharedPrefEvent("datastore_prefs.key_init", {
                    method: "$init",
                    key: keyName
                });
                
                return this.$init(keyName);
            };
        } catch (e) {
            devlog(`Preferences DataStore not available: ${e}`);
        }
    });
}

export function install_shared_prefs_hooks(){
    devlog("\n");
    devlog("Installing shared preferences hooks");

    try {
        install_shared_preferences_hooks();
    } catch (error) {
        devlog(`[HOOK] Failed to install shared preferences hooks: ${error}`);
    }

    try {
        install_datastore_hooks();
    } catch (error) {
        devlog(`[HOOK] Failed to install datastore hooks: ${error}`);
    }
}
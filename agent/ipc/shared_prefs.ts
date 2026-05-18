import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"
import { safePerform, safeUse, safeOverload } from "../utils/safe_java.js"

const PROFILE_HOOKING_TYPE: string = "IPC_SHARED-PREF"

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
    const event: SharedPrefEvent = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function install_shared_preferences_hooks() {
    devlog("\n")
    devlog("Installing SharedPreferences hooks");
    
    safePerform("shared_prefs:install_shared_preferences_hooks", () => {
        const SharedPrefs = safeUse('android.app.SharedPreferencesImpl', "shared_prefs:install_shared_preferences_hooks");
        const SharedPrefsEditor = safeUse('android.app.SharedPreferencesImpl$EditorImpl', "shared_prefs:install_shared_preferences_hooks");

        // Hook SharedPreferences initialization
        if (SharedPrefs) {
                const sharedPrefsInit = safeOverload(
                    SharedPrefs.$init,
                    "shared_prefs:SharedPreferencesImpl.$init",
                    'java.io.File', 'int'
                );
                if (sharedPrefsInit) {
                    sharedPrefsInit.implementation = function(file, mode) {
                        const result = this.$init(file, mode);
                        createSharedPrefEvent("shared_prefs.init", {
                            method: "SharedPreferencesImpl.$init",
                            file: file.getAbsolutePath(),
                            mode: mode
                        });
                        return result;
                    };
                }
            }

        // Hook SharedPreferences Editor putString
        if (SharedPrefsEditor) {
            const putString = safeOverload(
                SharedPrefsEditor.putString,
                "shared_prefs:SharedPreferencesImpl$EditorImpl.putString",
                'java.lang.String', 'java.lang.String'
            );
            if (putString) {
                putString.implementation = function(key, value) {
                    createSharedPrefEvent("shared_prefs.put_string", {
                        method: "putString",
                        key: key,
                        value: value
                    });
                    return this.putString(key, value);
                };
            }

            // Hook other Editor methods
            const editorMethods = [
                { method: 'putInt',     args: ['java.lang.String', 'int'] },
                { method: 'putLong',    args: ['java.lang.String', 'long'] },
                { method: 'putFloat',   args: ['java.lang.String', 'float'] },
                { method: 'putBoolean', args: ['java.lang.String', 'boolean'] }
            ];

            editorMethods.forEach(({ method, args }) => {
                const overload = safeOverload(
                    SharedPrefsEditor[method],
                    `shared_prefs:SharedPreferencesImpl$EditorImpl.${method}`,
                    ...args
                );
                if (overload) {
                    overload.implementation = function(key: string, value: any) {
                        createSharedPrefEvent(`shared_prefs.${method.toLowerCase()}`, {
                            method: method,
                            key: key,
                            value: value.toString()
                        });
                        return this[method](key, value);
                    };
                }
            });
        }
    });
}

function install_datastore_hooks() {
    devlog("\n")
    devlog("Installing DataStore hooks");
    
    safePerform("shared_prefs:install_datastore_hooks", () => {
        // Hook the DataStore class
        const DataStore = safeUse("androidx.datastore.core.DataStore", "shared_prefs:install_datastore_hooks");
        if (DataStore) {
            // Hook updateData
            const updateData = safeOverload(
                DataStore.updateData,
                "shared_prefs:DataStore.updateData",
                "kotlin.coroutines.Continuation"
            );
            if (updateData) {
                updateData.implementation = function(continuation) {
                    // Log the result if possible
                    const result = this.updateData(continuation);
                    result.then((data: any) => {
                        createSharedPrefEvent("datastore.update", {
                            method: "updateData",
                            data: data ? data.toString() : null
                        });
                    });
                    return result;
                };
            }

            // Hook data (flow)
            if (DataStore.getData) {
                DataStore.getData.overload().implementation = function() {
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
        }

        // Hook Preferences DataStore (key-value)
        const Preferences = safeUse("androidx.datastore.preferences.core.Preferences", "shared_prefs:install_datastore_hooks");
        if (Preferences) {
            const prefsGet = safeOverload(
                Preferences.get,
                "shared_prefs:Preferences.get",
                "androidx.datastore.preferences.core.Preferences$Key"
            );

            // Hook Preferences.Key class
            if (prefsGet) {
                prefsGet.implementation = function(key) {
                    const value = this.get(key);
                    createSharedPrefEvent("datastore_prefs.get", {
                        method: "get",
                        key: key ? key.toString() : "unknown",
                        value: value ? value.toString() : null
                    });
                    return value;
                };
            }
        }

        const PreferencesKey = safeUse("androidx.datastore.preferences.core.Preferences$Key", "shared_prefs:install_datastore_hooks");
        if (PreferencesKey) {
            const keyInit = safeOverload(
                PreferencesKey.$init,
                "shared_prefs:Preferences$Key.$init",
                "java.lang.String"
            );
            if (keyInit) {
                keyInit.implementation = function(keyName) {
                    createSharedPrefEvent("datastore_prefs.key_init", {
                        method: "$init",
                        key: keyName
                    });
                    return this.$init(keyName);
                };
            }
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
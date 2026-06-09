import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"
import { safePerform, safeUse, safeOverload, safeImplementation } from "../utils/safe_java.js"

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

function hook_shared_preferences() {
    devlog("Installing SharedPreferences hooks");
    
    safePerform("shared_prefs:hook_shared_preferences", () => {
        const SharedPrefs = safeUse('android.app.SharedPreferencesImpl', "shared_prefs:hook_shared_preferences");
        const SharedPrefsEditor = safeUse('android.app.SharedPreferencesImpl$EditorImpl', "shared_prefs:hook_shared_preferences");

        if (SharedPrefs) {
            // Hook SharedPreferences initialization
            const sharedPrefsInit = safeOverload(
                SharedPrefs.$init,
                "shared_prefs:SharedPreferencesImpl.$init",
                'java.io.File', 'int'
            );
            if (sharedPrefsInit) {
                sharedPrefsInit.implementation = safeImplementation(
                    "shared_prefs:SharedPreferencesImpl.$init",
                    sharedPrefsInit,
                    function(original, file, mode) {
                        const result = original.call(this, file, mode);
                        createSharedPrefEvent("shared_prefs.init", {
                            method: "SharedPreferencesImpl.$init",
                            file: file.getAbsolutePath(),
                            mode: mode
                        });
                        return result;
                    }
                );
            }
        }

        if (SharedPrefsEditor) {
            // Hook SharedPreferences Editor putString
            const putString = safeOverload(
                SharedPrefsEditor.putString,
                "shared_prefs:SharedPreferencesImpl$EditorImpl.putString",
                'java.lang.String', 'java.lang.String'
            );
            if (putString) {
                putString.implementation = safeImplementation(
                    "shared_prefs:SharedPreferencesImpl$EditorImpl.putString",
                    putString,
                    function(original, key, value) {
                        createSharedPrefEvent("shared_prefs.put_string", {
                            method: "putString",
                            key: key,
                            value: value
                        });
                        return original.call(this, key, value);
                    }
                );
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
                    overload.implementation = safeImplementation(
                        `shared_prefs:SharedPreferencesImpl$EditorImpl.${method}`,
                        overload,
                        function(original, key: string, value: any) {
                            createSharedPrefEvent(`shared_prefs.${method.toLowerCase()}`, {
                                method: method,
                                key: key,
                                value: value.toString()
                            });
                            return original.call(this, key, value);
                        }
                    );
                }
            });
        }
    });
}

function hook_datastore() {
    devlog("Installing DataStore hooks");

    safePerform("shared_prefs:hook_datastore", () => {
        const DataStore = safeUse(
            "androidx.datastore.core.DataStore",
            "shared_prefs:hook_datastore"
        );
        if (DataStore && (DataStore as any).updateData && (DataStore as any).updateData.overloads) {
            (DataStore as any).updateData.overloads.forEach((overload: any, index: number) => {
                overload.implementation = safeImplementation(
                    `shared_prefs:DataStore.updateData[${index}]`,
                    overload,
                    function (original, ...args: any[]) {
                        createSharedPrefEvent("datastore.update", {
                            method: "updateData"
                        });
                        return original.apply(this, args);
                    }
                );
            });
        }

        if (DataStore && (DataStore as any).getData) {
            const getData = safeOverload(
                (DataStore as any).getData,
                "shared_prefs:DataStore.getData"
            );
            if (getData) {
                getData.implementation = safeImplementation(
                    "shared_prefs:DataStore.getData",
                    getData,
                    function (original) {
                        const flow = original.call(this);
                        createSharedPrefEvent("datastore.get", {
                            method: "getData"
                        });
                        return flow;
                    }
                );
            }
        }

        const Preferences = safeUse(
            "androidx.datastore.preferences.core.Preferences",
            "shared_prefs:hook_datastore"
        );
        if (Preferences) {
            const prefsGet = safeOverload(
                (Preferences as any).get,
                "shared_prefs:Preferences.get",
                "androidx.datastore.preferences.core.Preferences$Key"
            );
            if (prefsGet) {
                prefsGet.implementation = safeImplementation(
                    "shared_prefs:Preferences.get",
                    prefsGet,
                    function (original, key: any) {
                        const value = original.call(this, key);
                        createSharedPrefEvent("datastore_prefs.get", {
                            method: "get",
                            key: key ? key.toString() : "unknown",
                            value: value ? value.toString() : null
                        });
                        return value;
                    }
                );
            }
        }

        const MutablePreferences = safeUse(
            "androidx.datastore.preferences.core.MutablePreferences",
            "shared_prefs:hook_datastore"
        );
        if (MutablePreferences) {
            const mutableGet = safeOverload(
                (MutablePreferences as any).get,
                "shared_prefs:MutablePreferences.get",
                "androidx.datastore.preferences.core.Preferences$Key"
            );
            if (mutableGet) {
                mutableGet.implementation = safeImplementation(
                    "shared_prefs:MutablePreferences.get",
                    mutableGet,
                    function (original, key: any) {
                        const value = original.call(this, key);
                        createSharedPrefEvent("datastore_prefs.get", {
                            method: "get",
                            key: key ? key.toString() : "unknown",
                            value: value ? value.toString() : null
                        });
                        return value;
                    }
                );
            }
        }

        const PreferencesKey = safeUse(
            "androidx.datastore.preferences.core.Preferences$Key",
            "shared_prefs:hook_datastore"
        );
        if (PreferencesKey) {
            const keyInit = safeOverload(
                PreferencesKey.$init,
                "shared_prefs:Preferences$Key.$init",
                "java.lang.String"
            );
            if (keyInit) {
                keyInit.implementation = safeImplementation(
                    "shared_prefs:Preferences$Key.$init",
                    keyInit,
                    function (original, keyName: string) {
                        createSharedPrefEvent("datastore_prefs.key_init", {
                            method: "$init",
                            key: keyName
                        });
                        return original.call(this, keyName);
                    }
                );
            }
        }
    });
}

export function install_shared_prefs_hooks(){
    devlog("\n");
    devlog("Installing shared preferences hooks");

    try {
        hook_shared_preferences();
    } catch (error) {
        devlog(`[HOOK] Failed to install shared preferences hooks: ${error}`);
    }

    try {
        hook_datastore();
    } catch (error) {
        devlog(`[HOOK] Failed to install datastore hooks: ${error}`);
    }
}
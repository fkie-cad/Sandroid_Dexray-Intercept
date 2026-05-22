import { log, devlog, am_send } from "../utils/logging.js"
import { Java } from "../utils/javalib.js"
import { safePerform, safeUse, safeOverload, safeImplementation } from "../utils/safe_java.js"

const PROFILE_HOOKING_TYPE: string = "DYNAMIC_LIB_LOADING"

function createLibraryEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function install_system_library_hooks(): void {
    devlog("Installing System library loading hooks");

    safePerform("load_library:install_system_library_hooks", () => {
        const SystemDef = safeUse(
            'java.lang.System',
            "load_library:install_system_library_hooks"
        );
        if (!SystemDef) return;

        const SystemLoad_1 = safeOverload(
            SystemDef.load, "load_library:System.load", 'java.lang.String'
        );
        const SystemLoad_2 = safeOverload(
            SystemDef.loadLibrary, "load_library:System.loadLibrary", 'java.lang.String'
        );

        if (SystemLoad_1) {
            SystemLoad_1.implementation = safeImplementation(
                "load_library:System.load",
                SystemLoad_1,
                function(original, library: string) {
                    createLibraryEvent("library.system.load", {
                        method: "System.load(String)",
                        library_path: library,
                        loader_type: "System"
                    });
                    return original.call(this, library);
                }
            );
        }

        if (SystemLoad_2) {
            SystemLoad_2.implementation = safeImplementation(
                "load_library:System.loadLibrary",
                SystemLoad_2,
                function(original, library: string) {
                    createLibraryEvent("library.system.load_library", {
                        method: "System.loadLibrary(String)",
                        library_name: library,
                        loader_type: "System"
                    });
                    original.call(this, library);
                }
            );
        }
    });
}

function install_runtime_library_hooks(): void {
    devlog("Installing Runtime library loading hooks");

    safePerform("load_library:install_runtime_library_hooks", () => {
        const RuntimeDef = safeUse(
            'java.lang.Runtime',
            "load_library:install_runtime_library_hooks"
        );
        if (!RuntimeDef) return;

        const RuntimeLoad_1 = safeOverload(
            RuntimeDef.load, "load_library:Runtime.load", 'java.lang.String'
        );
        const RuntimeLoad_2 = safeOverload(
            RuntimeDef.loadLibrary, "load_library:Runtime.loadLibrary", 'java.lang.String'
        );

        if (RuntimeLoad_1) {
            RuntimeLoad_1.implementation = safeImplementation(
                "load_library:Runtime.load",
                RuntimeLoad_1,
                function(original, library: string) {
                    createLibraryEvent("library.runtime.load", {
                        method: "Runtime.load(String)",
                        library_path: library,
                        loader_type: "Runtime"
                    });
                    original.call(this, library);
                }
            );
        }

        if (RuntimeLoad_2) {
            RuntimeLoad_2.implementation = safeImplementation(
                "load_library:Runtime.loadLibrary",
                RuntimeLoad_2,
                function(original, library: string) {
                    createLibraryEvent("library.runtime.load_library", {
                        method: "Runtime.loadLibrary(String)",
                        library_name: library,
                        loader_type: "Runtime"
                    });
                    original.call(this, library);
                }
            );
        }
    });
}

export function install_java_dex_unpacking_hooks(): void {
    devlog("\n");
    devlog("Installing library loading hooks");

    try {
        install_system_library_hooks();
    } catch (error) {
        devlog(`[HOOK] Failed to install system library hooks: ${error}`);
        createLibraryEvent("library.system.hook_error", { error: error.toString() });
    }

    try {
        install_runtime_library_hooks();
    } catch (error) {
        devlog(`[HOOK] Failed to install runtime library hooks: ${error}`);
        createLibraryEvent("library.runtime.hook_error", { error: error.toString() });
    }
}
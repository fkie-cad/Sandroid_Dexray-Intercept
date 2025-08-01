import { log, devlog, am_send } from "../utils/logging.js"
import { Java } from "../utils/javalib.js"

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
    
    Java.perform(() => {
        const SystemDef = Java.use('java.lang.System');
        
        const SystemLoad_1 = SystemDef.load.overload('java.lang.String');
        const SystemLoad_2 = SystemDef.loadLibrary.overload('java.lang.String');
        
        SystemLoad_1.implementation = function(library: string) {
            createLibraryEvent("library.system.load", {
                method: "System.load(String)",
                library_path: library,
                loader_type: "System"
            });
            
            return SystemLoad_1.call(this, library);
        };
        
        SystemLoad_2.implementation = function(library: string) {
            createLibraryEvent("library.system.load_library", {
                method: "System.loadLibrary(String)",
                library_name: library,
                loader_type: "System"
            });
            
            SystemLoad_2.call(this, library);
        };
    });
}

function install_runtime_library_hooks(): void {
    devlog("Installing Runtime library loading hooks");
    
    Java.perform(() => {
        const RuntimeDef = Java.use('java.lang.Runtime');
        
        const RuntimeLoad_1 = RuntimeDef.load.overload('java.lang.String');
        const RuntimeLoad_2 = RuntimeDef.loadLibrary.overload('java.lang.String');
        
        RuntimeLoad_1.implementation = function(library: string) {
            createLibraryEvent("library.runtime.load", {
                method: "Runtime.load(String)",
                library_path: library,
                loader_type: "Runtime"
            });
            
            RuntimeLoad_1.call(this, library);
        };
        
        RuntimeLoad_2.implementation = function(library: string) {
            createLibraryEvent("library.runtime.load_library", {
                method: "Runtime.loadLibrary(String)",
                library_name: library,
                loader_type: "Runtime"
            });
            
            RuntimeLoad_2.call(this, library);
        };
    });
}


export function install_java_dex_unpacking_hooks(): void {
    devlog("\n");
    devlog("Installing library loading hooks");
    
    try {
        install_system_library_hooks();
        install_runtime_library_hooks();
    } catch(e) {
        createLibraryEvent("library.hook_error", {
            error: e.toString()
        });
    }
}

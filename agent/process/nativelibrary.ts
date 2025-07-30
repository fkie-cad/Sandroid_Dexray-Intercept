import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Where } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"
const PROFILE_HOOKING_TYPE: string = "PROCESS_NATIVE_LIB"

function createNativeLibEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function hook_native_lib_loading(){
    // Find dlopen across all modules (older system versions)
    var dlopen: NativePointer | null = null;
    for (const module of Process.enumerateModules()) {
        try {
            dlopen = module.findExportByName("dlopen");
            if (dlopen) break;
        } catch (e) {
            continue;
        }
    }

    if(dlopen != null){
        devlog(`Found dlopen at: ${dlopen}`);
        Interceptor.attach(dlopen, {
            onEnter: function(args){
                const soName = args[0].readCString();
                const threadDef = Java.use('java.lang.Thread');
                const threadInstance = threadDef.$new();
                const stack = threadInstance.currentThread().getStackTrace();
                
                createNativeLibEvent("native.library.load", {
                    library_name: soName,
                    load_method: "dlopen",
                    library_path: soName,
                    module_base: dlopen.toString(),
                    stack_trace: Where(stack)
                });

                if(soName && soName.indexOf("libc.so") !== -1){
                    this.hook_libc = true;
                }
                this.library_name = soName;
            },
            onLeave: function(retval){
                if(retval && !retval.isNull()){
                    createNativeLibEvent("native.library.loaded", {
                        library_name: this.library_name,
                        load_method: "dlopen",
                        handle: retval.toString(),
                        success: true
                    });
                    
                    if(this.hook_libc) {
                        // Additional processing for libc loading if needed
                        devlog("libc.so loaded, additional hooks could be installed here");
                    }
                } else {
                    createNativeLibEvent("native.library.load_failed", {
                        library_name: this.library_name,
                        load_method: "dlopen",
                        error: "dlopen returned NULL"
                    });
                }
            }
        });
    }

    // Find android_dlopen_ext across all modules (newer system versions)
    var android_dlopen_ext: NativePointer | null = null;
    for (const module of Process.enumerateModules()) {
        try {
            android_dlopen_ext = module.findExportByName("android_dlopen_ext");
            if (android_dlopen_ext) break;
        } catch (e) {
            continue;
        }
    }

    if(android_dlopen_ext != null){
        devlog(`Found android_dlopen_ext at: ${android_dlopen_ext}`);
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function(args){
                const soName = args[0].readCString();
                const flags = args[1];
                const extinfo = args[2];
                const threadDef = Java.use('java.lang.Thread');
                const threadInstance = threadDef.$new();
                const stack = threadInstance.currentThread().getStackTrace();
                
                createNativeLibEvent("native.library.load", {
                    library_name: soName,
                    load_method: "android_dlopen_ext",
                    library_path: soName,
                    flags: flags ? flags.toInt32() : null,
                    extinfo: extinfo ? extinfo.toString() : null,
                    module_base: android_dlopen_ext.toString(),
                    stack_trace: Where(stack)
                });

                if(soName && soName.indexOf("libc.so") !== -1){
                    this.hook_libc = true;
                }
                this.library_name = soName;
            },
            onLeave: function(retval){
                if(retval && !retval.isNull()){
                    createNativeLibEvent("native.library.loaded", {
                        library_name: this.library_name,
                        load_method: "android_dlopen_ext",
                        handle: retval.toString(),
                        success: true
                    });
                    
                    if(this.hook_libc) {
                        // Additional processing for libc loading if needed
                        devlog("libc.so loaded via android_dlopen_ext");
                    }
                } else {
                    createNativeLibEvent("native.library.load_failed", {
                        library_name: this.library_name,
                        load_method: "android_dlopen_ext",
                        error: "android_dlopen_ext returned NULL"
                    });
                }
            }
        });
    }
}




export function install_native_library_hooks(){
    devlog("\n")
    devlog("install native hooks");
    hook_native_lib_loading();

}


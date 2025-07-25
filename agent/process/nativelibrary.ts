import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"

const PROFILE_HOOKING_TYPE: string = "PROCESS_NATIVE_LIB"

/**
 * 
/**
 * https://github.com/FrenchYeti/dexcalibur/blob/master/inspectors/Native/main.js
 *   https://www.jianshu.com/p/4291ee42c412
 * 
 * 
 */

function hook_native_lib_loading(){
    //第一种方式（针对较老的系统版本）
// Find dlopen across all modules
var dlopen: NativePointer | null = null;
for (const module of Process.enumerateModules()) {
    try {
        dlopen = module.findExportByName("dlopen");
        if (dlopen) break;
    } catch (e) {
        continue;
    }
}
//am_send(PROFILE_HOOKING_TYPE, "address of dlopen: " + dlopen);
if(dlopen != null){
    Interceptor.attach(dlopen,{
        onEnter: function(args){
            var soName = args[0].readCString();
            am_send(PROFILE_HOOKING_TYPE,"[Libc::dlopen] loading dynamic library:"+soName );
            //console.log(soName);
            if(soName.indexOf("libc.so") != -1){
                this.hook = true;
            }
        },
        onLeave: function(retval){
            if(this.hook) { 
                dlopentodo();
            };
        }
    });
}

//第二种方式（针对新系统版本）
// Find android_dlopen_ext across all modules
var android_dlopen_ext: NativePointer | null = null;
for (const module of Process.enumerateModules()) {
    try {
        android_dlopen_ext = module.findExportByName("android_dlopen_ext");
        if (android_dlopen_ext) break;
    } catch (e) {
        continue;
    }
}
//am_send(PROFILE_HOOKING_TYPE, "address of android_dlopen_ext: " + android_dlopen_ext);
if(android_dlopen_ext != null){
    Interceptor.attach(android_dlopen_ext,{
        onEnter: function(args){
            var soName = args[0].readCString();
            am_send(PROFILE_HOOKING_TYPE,"[Libc::android_dlopen_ext] loading dynamic library:"+soName );
            //console.log(soName);
            if(soName.indexOf("libc.so") != -1){
                this.hook = true;
            }
        },
        onLeave: function(retval){
            if(this.hook) {
                dlopentodo();
            };
        }
    });
}
function dlopentodo(){
    //todo ...
}

}




export function install_native_library_hooks(){
    devlog("\n")
    devlog("install native hooks");
    hook_native_lib_loading();

}


import { log, devlog, am_send } from "../utils/logging.js"
import { Java } from "../utils/javalib.js"
const PROFILE_HOOKING_TYPE: string = "DYNAMIC_LIB_LOADING"

function install_loading_dynamic_library_hooks(){

    Java.perform(function() {

        var SystemDef = Java.use('java.lang.System');
    
        var RuntimeDef = Java.use('java.lang.Runtime');
    
        var SystemLoad_1 = SystemDef.load.overload('java.lang.String');
    
        var SystemLoad_2 = SystemDef.loadLibrary.overload('java.lang.String');
    
        var RuntimeLoad_1 = RuntimeDef.load.overload('java.lang.String');
    
        var RuntimeLoad_2 = RuntimeDef.loadLibrary.overload('java.lang.String');
    
        
    
        SystemLoad_1.implementation = function(library) {
            am_send(PROFILE_HOOKING_TYPE,"[Java::System.load] Loading dynamic library => " + library);
 
            return SystemLoad_1.call(this, library);
        }
    
        SystemLoad_2.implementation = function(library) {
            am_send(PROFILE_HOOKING_TYPE,"[Java::System.loadLibrary] Loading dynamic library => " + library);

            SystemLoad_2.call(this, library);
            return;
        }
    
        RuntimeLoad_1.implementation = function(library) {
            am_send(PROFILE_HOOKING_TYPE,"[Java::Runtime.load] Loading dynamic library => " + library);
   
            RuntimeLoad_1.call(this, library);
            return;
        }
    
        RuntimeLoad_2.implementation = function(library) {
            am_send(PROFILE_HOOKING_TYPE,"[Java::Runtime.loadLibrary] Loading dynamic library => " + library);
        
            RuntimeLoad_2.call(this, library);
            return;
        }
    
        
    
    });

}


export function install_java_dex_unpacking_hooks(){
    devlog("install library loading hooks");
    try {
        install_loading_dynamic_library_hooks();
    }catch(e) {
        am_send(PROFILE_HOOKING_TYPE,"Error: "+e);
    }
}

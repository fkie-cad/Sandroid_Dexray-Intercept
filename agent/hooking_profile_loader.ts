import { install_file_system_hooks } from "./file/file_system_hooks.js";
import { install_database_hooks } from "./database/sql.js"
import { install_dex_unpacking_hooks } from "./dex/dex_unpacking.js"
import { install_java_dex_unpacking_hooks } from "./dex/load_library.js"
import { install_shared_prefs_hooks } from "./ipc/shared_prefs.js"
import { install_binder_hooks } from "./ipc/binder.js"
import { install_intent_hooks } from "./ipc/intents.js"
import { install_broadcast_hooks } from "./ipc/broadcast.js"
import { install_aes_hooks } from "./crypto/aes.js"
import { install_encodings_hooks } from "./crypto/encodings.js"
import { install_keystore_hooks } from "./crypto/keystore.js"
import { install_web_hooks } from "./network/web.js"
import { install_socket_hooks } from "./network/sockets.js"
import { install_native_library_hooks } from "./process/nativelibrary.js"
import { install_process_hooks } from "./process/process.js"
import { install_runtime_hooks } from "./process/runtime.js"
import { install_bluetooth_hooks } from "./services/bluetooth.js"
import { install_camera_hooks } from "./services/camera.js"
import { install_clipboard_hooks } from "./services/clipboard.js"
import { install_location_hooks } from "./services/location.js"
import { install_telephony_manager_hooks } from "./services/telephony.js"
import { install_bypass_hooks } from "./security/bypass.js"
import { am_send, log, devlog } from "./utils/logging.js"


export let show_verbose: boolean = false;
export let deactivate_unlink: boolean = false;
export let enable_stacktrace: boolean = false;

// Hook configuration - all hooks disabled by default
interface HookConfig {
    [key: string]: boolean;
}

export let hook_config: HookConfig = {
    // File system hooks
    'file_system_hooks': false,
    'database_hooks': false,
    
    // DEX and native library hooks
    'dex_unpacking_hooks': false,
    'java_dex_unpacking_hooks': false,
    'native_library_hooks': false,
    
    // IPC hooks
    'shared_prefs_hooks': false,
    'binder_hooks': false,
    'intent_hooks': false,
    'broadcast_hooks': false,
    
    // Crypto hooks
    'aes_hooks': false,
    'encodings_hooks': false,
    'keystore_hooks': false,
    
    // Network hooks
    'web_hooks': false,
    'socket_hooks': false,
    
    // Process hooks
    'process_hooks': false,
    'runtime_hooks': false,
    
    // Service hooks
    'bluetooth_hooks': false,
    'camera_hooks': false,
    'clipboard_hooks': false,
    'location_hooks': false,
    'telephony_hooks': false,
    
    // Bypass hooks
    'bypass_hooks': false,
};

/* TODO
- Globalen Shalter ob die Ausgaben von read/write operationen mehr ausgegeben werden sollen
- bei diesen Write/Read-Operationen ist es so, das deren Inhalte nur kurz im Speicher sind und daher 
  nicht ohne weiteres an das frida-Python-Backend geschickt werden können. Daher muss vor dem am_send() speicher allokiert werden
  und danach wieder freigegeben werden (insbesondere bei .xml)
- Read Ausgaben ebenfalls anzeigen bei FileSystemHooks
- https://trustedsec.com/blog/mobile-hacking-using-frida-to-monitor-encryption AES noch detailierter machen
- HTTP an aus mehr infos (https://sleepydogyp.github.io/2021/07/09/Frida-Hook-Android-APP%E7%AC%94%E8%AE%B0%EF%BC%88%E4%B8%89%EF%BC%89/)
-- > bei Catelytit app
--> https://github.com/frida/frida/issues/1483 als ertes
--> Hooking von String Deryption
- function AliasInfo(keyAlias)  in der keystore reparieren sowie am_send einführen

*/

/*
 * This way we are providing boolean values from the commandline directly to our frida script
 */
send("verbose_mode")
const verbose_mode_recv_state = recv('verbose_mode', value => {
    show_verbose = value.payload;
});
verbose_mode_recv_state.wait();

send("deactivate_unlink")
const deactivate_unlink_recv_state = recv('deactivate_unlink', value => {
    deactivate_unlink = value.payload;
});
deactivate_unlink_recv_state.wait();

// Handle initial hook configuration
send("hook_config")
const hook_config_recv_state = recv('hook_config', value => {
    if (typeof value.payload === 'object') {
        // Update entire hook configuration
        Object.assign(hook_config, value.payload);
        devlog(`[HOOK] Received hook configuration: ${JSON.stringify(value.payload)}`);
    }
});
hook_config_recv_state.wait();

send("enable_stacktrace")
const enable_stacktrace_recv_state = recv('enable_stacktrace', value => {
    enable_stacktrace = value.payload;
});
enable_stacktrace_recv_state.wait();


/*
 * our final hooks gets loaded
 */ 

function install_hook_conditionally(hook_name: string, install_function: () => void) {
    if (hook_config[hook_name]) {
        try {
            install_function();
            devlog(`[HOOK] Enabled: ${hook_name}`);
        } catch (error) {
            devlog(`[HOOK] Failed to enable ${hook_name}: ${error}`);
        }
    }
}

function load_profile_hooks(){
    if(enable_stacktrace){
        log("[Dexray] Stacktrace enabled");
    }
    log("[HOOK] Loading hooks based on configuration...");
    
    // File system hooks
    install_hook_conditionally('file_system_hooks', install_file_system_hooks);
    install_hook_conditionally('database_hooks', install_database_hooks);
    
    // DEX and native library hooks
    install_hook_conditionally('dex_unpacking_hooks', install_dex_unpacking_hooks);
    install_hook_conditionally('java_dex_unpacking_hooks', install_java_dex_unpacking_hooks); // Warning: may crash certain apps
    install_hook_conditionally('native_library_hooks', install_native_library_hooks);
    
    // IPC hooks
    install_hook_conditionally('shared_prefs_hooks', install_shared_prefs_hooks);
    install_hook_conditionally('binder_hooks', install_binder_hooks);
    install_hook_conditionally('intent_hooks', install_intent_hooks);
    install_hook_conditionally('broadcast_hooks', install_broadcast_hooks);
    
    // Crypto hooks
    install_hook_conditionally('aes_hooks', install_aes_hooks);
    install_hook_conditionally('encodings_hooks', install_encodings_hooks);
    install_hook_conditionally('keystore_hooks', install_keystore_hooks);
    
    // Network hooks
    install_hook_conditionally('web_hooks', install_web_hooks);
    install_hook_conditionally('socket_hooks', install_socket_hooks);
    
    // Process hooks
    install_hook_conditionally('process_hooks', install_process_hooks);
    install_hook_conditionally('runtime_hooks', install_runtime_hooks);
    
    // Service hooks
    install_hook_conditionally('bluetooth_hooks', install_bluetooth_hooks);
    install_hook_conditionally('telephony_hooks', install_telephony_manager_hooks);
    install_hook_conditionally('camera_hooks', install_camera_hooks);
    install_hook_conditionally('clipboard_hooks', install_clipboard_hooks);
    install_hook_conditionally('location_hooks', install_location_hooks);
    
    // Bypass hooks
    install_hook_conditionally('bypass_hooks', install_bypass_hooks);
    
    const enabled_hooks = Object.entries(hook_config).filter(([_, enabled]) => enabled).map(([name, _]) => name);
    log(`[HOOK] Active hooks: ${enabled_hooks.join(', ') || 'none'}`);
}

load_profile_hooks();


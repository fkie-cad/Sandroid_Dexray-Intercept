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
import { hookRegistry } from "./utils/hook_registry.js"


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

/**
 * Install a hook unconditionally with error handling
 * Hooks are always installed but check hook_config internally before sending events
 */
function install_hook_unconditionally(hook_name: string, install_function: () => void) {
    try {
        install_function();
        devlog(`[HOOK] Installed: ${hook_name}`);
    } catch (error) {
        devlog(`[HOOK] Failed to install ${hook_name}: ${error}`);
    }
}

function load_profile_hooks(){
    if(enable_stacktrace){
        log("[Dexray] Stacktrace enabled");
    }
    log("[HOOK] Installing all hooks (runtime reconfiguration enabled)...");

    // File system hooks
    install_hook_unconditionally('file_system_hooks', install_file_system_hooks);
    install_hook_unconditionally('database_hooks', install_database_hooks);

    // DEX and native library hooks
    install_hook_unconditionally('dex_unpacking_hooks', install_dex_unpacking_hooks);
    install_hook_unconditionally('java_dex_unpacking_hooks', install_java_dex_unpacking_hooks); // Warning: may crash certain apps
    install_hook_unconditionally('native_library_hooks', install_native_library_hooks);

    // IPC hooks
    install_hook_unconditionally('shared_prefs_hooks', install_shared_prefs_hooks);
    install_hook_unconditionally('binder_hooks', install_binder_hooks);
    install_hook_unconditionally('intent_hooks', install_intent_hooks);
    install_hook_unconditionally('broadcast_hooks', install_broadcast_hooks);

    // Crypto hooks
    install_hook_unconditionally('aes_hooks', install_aes_hooks);
    install_hook_unconditionally('encodings_hooks', install_encodings_hooks);
    install_hook_unconditionally('keystore_hooks', install_keystore_hooks);

    // Network hooks
    install_hook_unconditionally('web_hooks', install_web_hooks);
    install_hook_unconditionally('socket_hooks', install_socket_hooks);

    // Process hooks
    install_hook_unconditionally('process_hooks', install_process_hooks);
    install_hook_unconditionally('runtime_hooks', install_runtime_hooks);

    // Service hooks
    install_hook_unconditionally('bluetooth_hooks', install_bluetooth_hooks);
    install_hook_unconditionally('telephony_hooks', install_telephony_manager_hooks);
    install_hook_unconditionally('camera_hooks', install_camera_hooks);
    install_hook_unconditionally('clipboard_hooks', install_clipboard_hooks);
    install_hook_unconditionally('location_hooks', install_location_hooks);

    // Bypass hooks
    install_hook_unconditionally('bypass_hooks', install_bypass_hooks);

    const enabled_hooks = Object.entries(hook_config).filter(([_, enabled]) => enabled).map(([name, _]) => name);
    log(`[HOOK] All hooks installed. Active: ${enabled_hooks.join(', ') || 'none'}`);
}

/**
 * Setup persistent runtime message handler for hook reconfiguration
 * This allows enabling/disabling hooks at runtime via the Python API
 */
function setupRuntimeMessageHandler() {
    function listenForConfig() {
        recv('runtime_hook_config', (message) => {
            try {
                const payload = message.payload;

                if (typeof payload === 'object' && payload !== null) {
                    const { hook_name, enabled } = payload;

                    if (hook_name && hook_name in hook_config) {
                        // Update global hook_config
                        hook_config[hook_name] = enabled;

                        // Handle native hooks (detach/reattach)
                        hookRegistry.setNativeHooksEnabled(hook_name, enabled);

                        devlog(`[HOOK] Runtime update: ${hook_name} = ${enabled}`);

                        // Send ACK back to Python
                        send({
                            profileType: 'HOOK_CONFIG_ACK',
                            profileContent: JSON.stringify({
                                hook_name: hook_name,
                                enabled: enabled,
                                success: true
                            }),
                            timestamp: new Date().toISOString()
                        });
                    } else {
                        devlog(`[HOOK] Unknown hook name in runtime config: ${hook_name}`);
                        send({
                            profileType: 'HOOK_CONFIG_ACK',
                            profileContent: JSON.stringify({
                                hook_name: hook_name,
                                enabled: enabled,
                                success: false,
                                error: 'Unknown hook name'
                            }),
                            timestamp: new Date().toISOString()
                        });
                    }
                }
            } catch (e) {
                devlog(`[HOOK] Error processing runtime config: ${e}`);
            }

            // Continue listening for more messages (Frida recv is one-shot)
            listenForConfig();
        });
    }

    listenForConfig();
    devlog('[HOOK] Runtime message handler active');
}

// Load all hooks and setup runtime handler
load_profile_hooks();
setupRuntimeMessageHandler();


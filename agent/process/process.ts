import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"
import { Where } from "../utils/misc.js"
import { hook_config } from "../hooking_profile_loader.js"

const PROFILE_HOOKING_TYPE: string = "PROCESS_CREATION"
const HOOK_NAME = 'process_hooks'

function createProcessEvent(eventType: string, data: any): void {
    // Check if hook is enabled at runtime
    if (!hook_config[HOOK_NAME]) {
        return;
    }
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function hook_java_process_creation() {
    Java.perform(() => {
        try {
            const Process = Java.use('android.os.Process');
            const threadDef = Java.use('java.lang.Thread');
            const threadInstance = threadDef.$new();

            if (Process.start) {
                Process.start.implementation = function (
                    processClass: any, niceName: string, uid: number,
                    gid: number, gids: any, debugFlags: number, mountExternal: number,
                    targetSdkVersion: number, seInfo: string, abi: string,
                    instructionSet: string, appDataDir: string, zygoteArgs: any
                ) {
                    const stack = threadInstance.currentThread().getStackTrace();
                    
                    createProcessEvent("process.creation", {
                        library: 'android.os.Process',
                        method: 'start',
                        process_class: processClass ? processClass.toString() : null,
                        nice_name: niceName,
                        uid: uid,
                        gid: gid,
                        gids: gids ? (Array.isArray(gids) ? gids : gids.toString()) : null,
                        debug_flags: debugFlags,
                        mount_external: mountExternal,
                        target_sdk_version: targetSdkVersion,
                        selinux_info: seInfo,
                        abi: abi,
                        instruction_set: instructionSet,
                        app_data_dir: appDataDir,
                        zygote_args: zygoteArgs ? zygoteArgs.toString() : null,
                        stack_trace: Where(stack)
                    });

                    return this.start.apply(this, arguments);
                };
            }

            // Hook additional process methods
            if (Process.killProcess) {
                Process.killProcess.implementation = function (pid: number) {
                    createProcessEvent("process.kill", {
                        library: 'android.os.Process',
                        method: 'killProcess',
                        target_pid: pid
                    });

                    return this.killProcess(pid);
                };
            }

            if (Process.sendSignal) {
                Process.sendSignal.implementation = function (pid: number, signal: number) {
                    createProcessEvent("process.signal", {
                        library: 'android.os.Process',
                        method: 'sendSignal',
                        target_pid: pid,
                        signal: signal
                    });

                    return this.sendSignal(pid, signal);
                };
            }

        } catch (error) {
            createProcessEvent("process.error", {
                error_message: (error as Error).toString(),
                error_type: "hook_java_process_creation"
            });
        }
    });
}



function hook_native_process_creation(){
    // Hook native process creation functions like fork, execve, system
    
    // Hook fork system call
    const forkPtr = Process.getModuleByName("libc.so").getExportByName("fork");
    if (forkPtr) {
        Interceptor.attach(forkPtr, {
            onEnter: function(args) {
                createProcessEvent("process.fork.attempt", {
                    native_function: "fork",
                    caller_pid: Process.id
                });
            },
            onLeave: function(retval) {
                const pid = retval.toInt32();
                createProcessEvent("process.fork.result", {
                    native_function: "fork",
                    caller_pid: Process.id,
                    child_pid: pid,
                    success: pid >= 0
                });
            }
        });
    }

    // Hook execve system call
    const execvePtr = Process.getModuleByName("libc.so").getExportByName("execve");
    if (execvePtr) {
        Interceptor.attach(execvePtr, {
            onEnter: function(args) {
                const pathname = args[0].readCString();
                createProcessEvent("process.execve.attempt", {
                    native_function: "execve",
                    pathname: pathname,
                    caller_pid: Process.id
                });
            },
            onLeave: function(retval) {
                const result = retval.toInt32();
                createProcessEvent("process.execve.result", {
                    native_function: "execve",
                    return_value: result,
                    success: result === 0
                });
            }
        });
    }

    // Hook system function
    const systemPtr = Process.getModuleByName("libc.so").getExportByName("system");
    if (systemPtr) {
        Interceptor.attach(systemPtr, {
            onEnter: function(args) {
                const command = args[0].readCString();
                createProcessEvent("process.system.call", {
                    native_function: "system",
                    command: command,
                    caller_pid: Process.id
                });
            },
            onLeave: function(retval) {
                const result = retval.toInt32();
                createProcessEvent("process.system.result", {
                    native_function: "system",
                    return_value: result,
                    success: result !== -1
                });
            }
        });
    }
}

export function install_process_hooks(){
    devlog("\n")
    devlog("install process hooks");

    try {
        hook_java_process_creation();
    } catch (error) {
        devlog(`[HOOK] Failed to install Java process hooks: ${error}`);
    }

    try {
        hook_native_process_creation();
    } catch (error) {
        devlog(`[HOOK] Failed to install native process hooks: ${error}`);
    }
}


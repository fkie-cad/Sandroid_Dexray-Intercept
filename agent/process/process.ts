import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"
import { Where } from "../utils/misc.js"
import { safePerform, safeUse, safeImplementation } from "../utils/safe_java.js"

const PROFILE_HOOKING_TYPE: string = "PROCESS_CREATION"

function createProcessEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function hook_java_process_creation() {
    safePerform("process:hook_java_process_creation", () => {
        const Process = safeUse('android.os.Process', "process:hook_java_process_creation");
        if (!Process) return;

        const threadDef = safeUse('java.lang.Thread', "process:hook_java_process_creation");
        if (!threadDef) return;
        const threadInstance = threadDef.$new();

        if (Process.start) {
            const startRef = Process.start;
            startRef.implementation = safeImplementation(
                "process:Process.start",
                startRef,
                function(original, ...args: any[]) {
                    const [
                        processClass, niceName, uid, gid, gids,
                        debugFlags, mountExternal, targetSdkVersion,
                        seInfo, abi, instructionSet, appDataDir, zygoteArgs
                    ] = args;
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
                    return original.apply(this, args);
                }
            );
        }

        if (Process.killProcess) {
            const killProcessRef = Process.killProcess;
            killProcessRef.implementation = safeImplementation(
                "process:Process.killProcess",
                killProcessRef,
                function(original, pid: number) {
                    createProcessEvent("process.kill", {
                        library: 'android.os.Process',
                        method: 'killProcess',
                        target_pid: pid
                    });
                    return original.call(this, pid);
                }
            );
        }

        if (Process.sendSignal) {
            const sendSignalRef = Process.sendSignal;
            sendSignalRef.implementation = safeImplementation(
                "process:Process.sendSignal",
                sendSignalRef,
                function(original, pid: number, signal: number) {
                    createProcessEvent("process.signal", {
                        library: 'android.os.Process',
                        method: 'sendSignal',
                        target_pid: pid,
                        signal: signal
                    });
                    return original.call(this, pid, signal);
                }
            );
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
    devlog("\n");
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
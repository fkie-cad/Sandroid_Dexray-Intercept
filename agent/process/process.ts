import { devlog, am_send } from "../utils/logging.js"
import { safePerform, safeUse, safeImplementation, PropagateException } from "../utils/safe_java.js"
import { safeAttachExport } from "../utils/safe_native.js"
import { collectJavaStackTrace } from "../utils/stacktrace.js"

const PROFILE_HOOKING_TYPE: string = "PROCESS_CREATION"

function createProcessEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

// Tracks OS thread IDs currently executing a killProcess() call. killProcess()
// internally delegates to sendSignal(pid, SIGKILL) on the same thread; this
// guard suppresses the resulting nested process.signal event while leaving
// the original call-through and its actual signal delivery unaffected.
const activeKillProcessThreads = new Set<number>();

// Same pattern as activeKillProcessThreads, scoped to the quiet variants.
// killProcessQuiet() delegates to sendSignalQuiet(pid, SIGKILL); the two
// families never delegate into each other, so each needs its own guard.
const activeKillProcessQuietThreads = new Set<number>();

function hook_java_process_creation() {
    safePerform("process:hook_java_process_creation", () => {
        const Process = safeUse('android.os.Process', "process:hook_java_process_creation");
        if (!Process) return;

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
                    const java_stack_trace = collectJavaStackTrace();
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
                        ...(java_stack_trace ? { java_stack_trace } : {})
                    });
                    try {
                        return original.apply(this, args);
                    } catch (error) {
                        throw new PropagateException(error);
                    }
                }
            );
        }

        if (Process.killProcess) {
            const killProcessRef = Process.killProcess;
            killProcessRef.implementation = safeImplementation(
                "process:Process.killProcess",
                killProcessRef,
                function(original, pid: number) {
                    const java_stack_trace = collectJavaStackTrace();
                    createProcessEvent("process.kill", {
                        library: 'android.os.Process',
                        method: 'killProcess',
                        target_pid: pid,
                        ...(java_stack_trace ? { java_stack_trace } : {})
                    });

                    const threadId = Process.myTid();
                    activeKillProcessThreads.add(threadId);
                    try {
                        return original.call(this, pid);
                    } catch (error) {
                        throw new PropagateException(error);
                    } finally {
                        activeKillProcessThreads.delete(threadId);
                    }
                }
            );
        }

        if (Process.sendSignal) {
            const sendSignalRef = Process.sendSignal;
            sendSignalRef.implementation = safeImplementation(
                "process:Process.sendSignal",
                sendSignalRef,
                function(original, pid: number, signal: number) {
                    // Suppress the event when this call is killProcess()'s
                    // internal delegation on the same thread; the actual
                    // signal delivery via original.call() is unaffected.
                    if (!activeKillProcessThreads.has(Process.myTid())) {
                        const java_stack_trace = collectJavaStackTrace();
                        createProcessEvent("process.signal", {
                            library: 'android.os.Process',
                            method: 'sendSignal',
                            target_pid: pid,
                            signal: signal,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                    }
                    try {
                        return original.call(this, pid, signal);
                    } catch (error) {
                        throw new PropagateException(error);
                    }
                }
            );
        }

        if (Process.killProcessQuiet) {
            const killProcessQuietRef = Process.killProcessQuiet;
            killProcessQuietRef.implementation = safeImplementation(
                "process:Process.killProcessQuiet",
                killProcessQuietRef,
                function(original, pid: number) {
                    const java_stack_trace = collectJavaStackTrace();
                    createProcessEvent("process.kill_quiet", {
                        library: 'android.os.Process',
                        method: 'killProcessQuiet',
                        target_pid: pid,
                        ...(java_stack_trace ? { java_stack_trace } : {})
                    });

                    const threadId = Process.myTid();
                    activeKillProcessQuietThreads.add(threadId);
                    try {
                        return original.call(this, pid);
                    } catch (error) {
                        throw new PropagateException(error);
                    } finally {
                        activeKillProcessQuietThreads.delete(threadId);
                    }
                }
            );
        }

        if (Process.sendSignalQuiet) {
            const sendSignalQuietRef = Process.sendSignalQuiet;
            sendSignalQuietRef.implementation = safeImplementation(
                "process:Process.sendSignalQuiet",
                sendSignalQuietRef,
                function(original, pid: number, signal: number) {
                    if (!activeKillProcessQuietThreads.has(Process.myTid())) {
                        const java_stack_trace = collectJavaStackTrace();
                        createProcessEvent("process.signal_quiet", {
                            library: 'android.os.Process',
                            method: 'sendSignalQuiet',
                            target_pid: pid,
                            signal: signal,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                    }
                    try {
                        return original.call(this, pid, signal);
                    } catch (error) {
                        throw new PropagateException(error);
                    }
                }
            );
        }

        if (Process.killProcessGroup) {
            const killProcessGroupRef = Process.killProcessGroup;
            killProcessGroupRef.implementation = safeImplementation(
                "process:Process.killProcessGroup",
                killProcessGroupRef,
                function(original, uid: number, pid: number) {
                    const java_stack_trace = collectJavaStackTrace();
                    createProcessEvent("process.kill_group", {
                        library: 'android.os.Process',
                        method: 'killProcessGroup',
                        target_uid: uid,
                        target_pid: pid,
                        ...(java_stack_trace ? { java_stack_trace } : {})
                    });
                    try {
                        return original.call(this, uid, pid);
                    } catch (error) {
                        throw new PropagateException(error);
                    }
                }
            );
        }

        if (Process.sendSignalToProcessGroup) {
            const sendSignalToProcessGroupRef = Process.sendSignalToProcessGroup;
            sendSignalToProcessGroupRef.implementation = safeImplementation(
                "process:Process.sendSignalToProcessGroup",
                sendSignalToProcessGroupRef,
                function(original, uid: number, pid: number, signal: number) {
                    const java_stack_trace = collectJavaStackTrace();
                    createProcessEvent("process.signal_group", {
                        library: 'android.os.Process',
                        method: 'sendSignalToProcessGroup',
                        target_uid: uid,
                        target_pid: pid,
                        signal: signal,
                        ...(java_stack_trace ? { java_stack_trace } : {})
                    });
                    try {
                        return original.call(this, uid, pid, signal);
                    } catch (error) {
                        throw new PropagateException(error);
                    }
                }
            );
        }

        if (Process.setUid) {
            const setUidRef = Process.setUid;
            setUidRef.implementation = safeImplementation(
                "process:Process.setUid",
                setUidRef,
                function(original, uid: number) {
                    const java_stack_trace = collectJavaStackTrace();
                    createProcessEvent("process.set_uid", {
                        library: 'android.os.Process',
                        method: 'setUid',
                        target_uid: uid,
                        ...(java_stack_trace ? { java_stack_trace } : {})
                    });
                    try {
                        return original.call(this, uid);
                    } catch (error) {
                        throw new PropagateException(error);
                    }
                }
            );
        }

        if (Process.setGid) {
            const setGidRef = Process.setGid;
            setGidRef.implementation = safeImplementation(
                "process:Process.setGid",
                setGidRef,
                function(original, gid: number) {
                    const java_stack_trace = collectJavaStackTrace();
                    createProcessEvent("process.set_gid", {
                        library: 'android.os.Process',
                        method: 'setGid',
                        target_gid: gid,
                        ...(java_stack_trace ? { java_stack_trace } : {})
                    });
                    try {
                        return original.call(this, gid);
                    } catch (error) {
                        throw new PropagateException(error);
                    }
                }
            );
        }

        if (Process.setArgV0) {
            const setArgV0Ref = Process.setArgV0;
            setArgV0Ref.implementation = safeImplementation(
                "process:Process.setArgV0",
                setArgV0Ref,
                function(original, name: string) {
                    const java_stack_trace = collectJavaStackTrace();
                    createProcessEvent("process.rename", {
                        library: 'android.os.Process',
                        method: 'setArgV0',
                        new_name: name,
                        ...(java_stack_trace ? { java_stack_trace } : {})
                    });
                    try {
                        return original.call(this, name);
                    } catch (error) {
                        throw new PropagateException(error);
                    }
                }
            );
        }
    });
}

function hook_native_process_creation(){
    // Hook native process creation functions like fork, execve, system
    
    // Hook fork system call
    safeAttachExport("libc.so", "fork", "process:fork", {
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

    // Hook execve system call
    safeAttachExport("libc.so", "execve", "process:execve", {
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

    // Hook system function
    safeAttachExport("libc.so", "system", "process:system", {
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
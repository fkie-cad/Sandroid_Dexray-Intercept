import { devlog, am_send } from "../utils/logging.js"
import { safePerform, safeUse, safeOverload, safeImplementation, PropagateException } from "../utils/safe_java.js"
import { collectJavaStackTrace } from "../utils/stacktrace.js"

const PROFILE_HOOKING_TYPE: string = "RUNTIME_HOOKS"

function createRuntimeEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

/**
 * https://github.com/dpnishant/appmon/tree/master/scripts/Android
 * https://github.com/Ch0pin/medusa/blob/master/modules/runtime/runtime.med
 */

// Tracks per-thread nested-call depth for Runtime.exec. Some exec() overloads
// internally delegate to other exec() overloads on the same thread before
// reaching the real implementation; this guard emits only the outermost,
// application-facing call while leaving every internal call-through intact.
const activeExecDepth = new Map<number, number>();

function hook_runtime() {
    safePerform("runtime:hook_runtime", () => {
        const Runtime = safeUse('java.lang.Runtime', "runtime:hook_runtime");
        if (!Runtime) return;

        // exec: hook all overloads
        Runtime.exec.overloads.forEach((overload: any, index: number) => {
            overload.implementation = safeImplementation(
                `runtime:Runtime.exec[${index}]`,
                overload,
                function(original, ...args: any[]) {
                    const threadId = Process.getCurrentThreadId();
                    const depth = activeExecDepth.get(threadId) || 0;
                    const isOutermost = depth === 0;
                    activeExecDepth.set(threadId, depth + 1);

                    if (isOutermost) {
                        const java_stack_trace = collectJavaStackTrace();

                        let commandStr = null;
                        const command = args[0];
                        const envp = args[1];
                        const dir = args[2];

                        if (command) {
                            if (Array.isArray(command)) {
                                commandStr = command.join(' ');
                            } else {
                                commandStr = command.toString();
                            }
                        }

                        createRuntimeEvent("runtime.exec", {
                            library: 'java.lang.Runtime',
                            method: 'exec',
                            overload_index: index,
                            command: commandStr,
                            environment: envp ? envp.toString() : null,
                            working_directory: dir ? dir.toString() : null,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                    }

                    try {
                        return original.apply(this, args);
                    } catch (error) {
                        throw new PropagateException(error);
                    } finally {
                        const remaining = activeExecDepth.get(threadId)! - 1;
                        if (remaining <= 0) {
                            activeExecDepth.delete(threadId);
                        } else {
                            activeExecDepth.set(threadId, remaining);
                        }
                    }
                }
            );
        });

        // loadLibrary: all overloads
        Runtime.loadLibrary.overloads.forEach((overload: any, index: number) => {
            overload.implementation = safeImplementation(
                `runtime:Runtime.loadLibrary[${index}]`,
                overload,
                function(original, libname: any) {
                    const java_stack_trace = collectJavaStackTrace();
                    createRuntimeEvent("runtime.load_library", {
                        library: 'java.lang.Runtime',
                        method: 'loadLibrary',
                        overload_index: index,
                        library_name: libname ? libname.toString() : null,
                        ...(java_stack_trace ? { java_stack_trace } : {})
                    });
                    try {
                        return original.call(this, libname);
                    } catch (error) {
                        throw new PropagateException(error);
                    }
                }
            );
        });
    
        // load: iterate all available overloads
        Runtime.load.overloads.forEach((overload: any, index: number) => {
            overload.implementation = safeImplementation(
                `runtime:Runtime.load[${index}]`,
                overload,
                function(original, filename: any) {
                    const java_stack_trace = collectJavaStackTrace();
                    createRuntimeEvent("runtime.load", {
                        library: 'java.lang.Runtime',
                        method: 'load',
                        overload_index: index,
                        filename: filename ? filename.toString() : null,
                        ...(java_stack_trace ? { java_stack_trace } : {})
                    });
                    try {
                        return original.call(this, filename);
                    } catch (error) {
                        throw new PropagateException(error);
                    }
                }
            );
        });

        // addShutdownHook / removeShutdownHook: confirmed via direct dispatch
        // probing to never delegate into each other; no reentrancy guard needed.
        if (Runtime.addShutdownHook) {
            const addShutdownHookRef = Runtime.addShutdownHook;
            addShutdownHookRef.implementation = safeImplementation(
                "runtime:Runtime.addShutdownHook",
                addShutdownHookRef,
                function(original, hook: any) {
                    const java_stack_trace = collectJavaStackTrace();
                    createRuntimeEvent("runtime.add_shutdown_hook", {
                        library: 'java.lang.Runtime',
                        method: 'addShutdownHook',
                        thread_name: hook ? hook.getName() : null,
                        ...(java_stack_trace ? { java_stack_trace } : {})
                    });
                    try {
                        return original.call(this, hook);
                    } catch (error) {
                        throw new PropagateException(error);
                    }
                }
            );
        }

        if (Runtime.removeShutdownHook) {
            const removeShutdownHookRef = Runtime.removeShutdownHook;
            removeShutdownHookRef.implementation = safeImplementation(
                "runtime:Runtime.removeShutdownHook",
                removeShutdownHookRef,
                function(original, hook: any) {
                    let removed;
                    try {
                        removed = original.call(this, hook);
                    } catch (error) {
                        throw new PropagateException(error);
                    }
                    const java_stack_trace = collectJavaStackTrace();
                    createRuntimeEvent("runtime.remove_shutdown_hook", {
                        library: 'java.lang.Runtime',
                        method: 'removeShutdownHook',
                        thread_name: hook ? hook.getName() : null,
                        removed: removed,
                        ...(java_stack_trace ? { java_stack_trace } : {})
                    });
                    return removed;
                }
            );
        }

        // exit / halt: the original call never returns on the normal path, so
        // the event is emitted before the call-through rather than after.
        if (Runtime.exit) {
            const exitRef = Runtime.exit;
            exitRef.implementation = safeImplementation(
                "runtime:Runtime.exit",
                exitRef,
                function(original, code: number) {
                    const java_stack_trace = collectJavaStackTrace();
                    createRuntimeEvent("runtime.exit", {
                        library: 'java.lang.Runtime',
                        method: 'exit',
                        exit_code: code,
                        ...(java_stack_trace ? { java_stack_trace } : {})
                    });
                    try {
                        return original.call(this, code);
                    } catch (error) {
                        throw new PropagateException(error);
                    }
                }
            );
        }

        if (Runtime.halt) {
            const haltRef = Runtime.halt;
            haltRef.implementation = safeImplementation(
                "runtime:Runtime.halt",
                haltRef,
                function(original, code: number) {
                    const java_stack_trace = collectJavaStackTrace();
                    createRuntimeEvent("runtime.halt", {
                        library: 'java.lang.Runtime',
                        method: 'halt',
                        exit_code: code,
                        ...(java_stack_trace ? { java_stack_trace } : {})
                    });
                    try {
                        return original.call(this, code);
                    } catch (error) {
                        throw new PropagateException(error);
                    }
                }
            );
        }
    });
}

// Tracks per-thread nested-call depth shared across both Class.forName
// hooks below. The 1-arg hook redirects into the 3-arg overload instead of
// calling its own original; this guard prevents that redirect from emitting
// a second event.
const activeForNameDepth = new Map<number, number>();

// Resolves the classloader of the immediate Java caller on the current
// thread, skipping frames belonging to stack trace collection and to the
// forName call chain itself.
function resolveImmediateCallerClassLoader(context: string): any {
    const threadDef = safeUse('java.lang.Thread', context);
    if (!threadDef) return null;

    let frames: any[];
    try {
        frames = threadDef.currentThread().getStackTrace();
    } catch (error) {
        return null;
    }

    for (let i = 0; i < frames.length; i++) {
        const frameClassName = frames[i].getClassName();
        if (
            frameClassName === 'dalvik.system.VMStack' ||
            frameClassName === 'java.lang.Thread' ||
            frameClassName === 'java.lang.Class'
        ) {
            continue;
        }

        const CallerClass = safeUse(frameClassName, context);
        if (!CallerClass) return null;
        return CallerClass.class.getClassLoader();
    }

    return null;
}

function trace_reflection() {
    safePerform("runtime:trace_reflection", () => {
        const internalClasses: string[] = ["android.", "com.android", "java.lang", "java.io"];

        function isInternalClassName(class_name: string): boolean {
            for (const internalClass of internalClasses) {
                if (class_name.startsWith(internalClass)) {
                    return true;
                }
            }
            return false;
        }

        const classDef = safeUse('java.lang.Class', "runtime:trace_reflection");
        const classLoaderDef = safeUse('java.lang.ClassLoader', "runtime:trace_reflection");
        const Method = safeUse('java.lang.reflect.Method', "runtime:trace_reflection");

        // Hook Class.getMethod
        if (classDef) {
            const getMethod = safeOverload(
                classDef.getMethod,
                "runtime:Class.getMethod",
                'java.lang.String', '[Ljava.lang.Class;'
            );
            if (getMethod) {
                getMethod.implementation = safeImplementation(
                    "runtime:Class.getMethod",
                    getMethod,
                    function(original, methodName: string, paramTypes: any) {
                        let method;
                        try {
                            method = original.call(this, methodName, paramTypes);
                        } catch (error) {
                            throw new PropagateException(error);
                        }
                        const java_stack_trace = collectJavaStackTrace();
                        createRuntimeEvent("reflection.get_method", {
                            library: 'java.lang.Class',
                            method: 'getMethod',
                            method_name: methodName,
                            method_signature: method.toGenericString(),
                            class_name: this.getName(),
                            access_type: 'public',
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return method;
                    }
                );
            }

            // Hook Class.getDeclaredMethod
            const getDeclaredMethod = safeOverload(
                classDef.getDeclaredMethod,
                "runtime:Class.getDeclaredMethod",
                'java.lang.String', '[Ljava.lang.Class;'
            );
            if (getDeclaredMethod) {
                getDeclaredMethod.implementation = safeImplementation(
                    "runtime:Class.getDeclaredMethod",
                    getDeclaredMethod,
                    function(original, methodName: string, paramTypes: any) {
                        let method;
                        try {
                            method = original.call(this, methodName, paramTypes);
                        } catch (error) {
                            throw new PropagateException(error);
                        }
                        const java_stack_trace = collectJavaStackTrace();
                        createRuntimeEvent("reflection.get_declared_method", {
                            library: 'java.lang.Class',
                            method: 'getDeclaredMethod',
                            method_name: methodName,
                            method_signature: method.toGenericString(),
                            class_name: this.getName(),
                            access_type: 'any',
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return method;
                    }
                );
            }

            // Hook Class.forName(String, boolean, ClassLoader).
            // Explicit classloader argument avoids the caller-sensitivity
            // issue affecting the 1-arg overload below.
            const forName = safeOverload(
                classDef.forName,
                "runtime:Class.forName",
                'java.lang.String', 'boolean', 'java.lang.ClassLoader'
            );
            if (forName) {
                forName.implementation = safeImplementation(
                    "runtime:Class.forName",
                    forName,
                    function(original, class_name: string, flag: boolean, class_loader: any) {
                        const threadId = Process.getCurrentThreadId();
                        const depth = activeForNameDepth.get(threadId) || 0;
                        const isOutermost = depth === 0;
                        activeForNameDepth.set(threadId, depth + 1);

                        if (isOutermost) {
                            const isInternal = isInternalClassName(class_name);
                            const java_stack_trace = collectJavaStackTrace();
                            createRuntimeEvent("reflection.class_for_name", {
                                library: 'java.lang.Class',
                                method: 'forName',
                                overload_signature: 'forName(java.lang.String,boolean,java.lang.ClassLoader)',
                                class_name: class_name,
                                initialize: flag,
                                class_loader: class_loader ? class_loader.toString() : null,
                                is_internal: isInternal,
                                ...(java_stack_trace ? { java_stack_trace } : {})
                            });
                        }

                        try {
                            return original.call(this, class_name, flag, class_loader);
                        } catch (error) {
                            throw new PropagateException(error);
                        } finally {
                            const remaining = activeForNameDepth.get(threadId)! - 1;
                            if (remaining <= 0) {
                                activeForNameDepth.delete(threadId);
                            } else {
                                activeForNameDepth.set(threadId, remaining);
                            }
                        }
                    }
                );
            }

            // Hook Class.forName(String).
            // - forName(String) resolves its caller's classloader via a
            //   native, caller-sensitive stack lookup.
            // - Replacing this overload's implementation breaks that lookup,
            //   since the runtime sees our trampoline as the caller instead
            //   of the real application code.
            // - Resolves the real caller's classloader itself and redirects
            //   to the explicit-classloader overload above instead of
            //   calling through to the unsafe original.
            // - The depth guard shared with the hook above prevents this
            //   redirect from emitting a second event.
            const forNameOneArg = safeOverload(
                classDef.forName,
                "runtime:Class.forName[1-arg]",
                'java.lang.String'
            );
            if (forNameOneArg) {
                forNameOneArg.implementation = safeImplementation(
                    "runtime:Class.forName[1-arg]",
                    forNameOneArg,
                    function(original, class_name: string) {
                        const threadId = Process.getCurrentThreadId();
                        const depth = activeForNameDepth.get(threadId) || 0;
                        const isOutermost = depth === 0;
                        activeForNameDepth.set(threadId, depth + 1);

                        if (isOutermost) {
                            const isInternal = isInternalClassName(class_name);
                            const java_stack_trace = collectJavaStackTrace();
                            createRuntimeEvent("reflection.class_for_name", {
                                library: 'java.lang.Class',
                                method: 'forName',
                                overload_signature: 'forName(java.lang.String)',
                                class_name: class_name,
                                initialize: true,
                                is_internal: isInternal,
                                ...(java_stack_trace ? { java_stack_trace } : {})
                            });
                        }

                        try {
                            const callerClassLoader = resolveImmediateCallerClassLoader("runtime:Class.forName[1-arg]");
                            return classDef.forName(class_name, true, callerClassLoader);
                        } catch (error) {
                            throw new PropagateException(error);
                        } finally {
                            const remaining = activeForNameDepth.get(threadId)! - 1;
                            if (remaining <= 0) {
                                activeForNameDepth.delete(threadId);
                            } else {
                                activeForNameDepth.set(threadId, remaining);
                            }
                        }
                    }
                );
            }
        }

        // Hook ClassLoader.loadClass
        if (classLoaderDef) {
            const loadClass = safeOverload(
                classLoaderDef.loadClass,
                "runtime:ClassLoader.loadClass",
                'java.lang.String', 'boolean'
            );
            if (loadClass) {
                loadClass.implementation = safeImplementation(
                    "runtime:ClassLoader.loadClass",
                    loadClass,
                    function(original, class_name: string, resolve: boolean) {
                        const isInternal = isInternalClassName(class_name);
                        const java_stack_trace = collectJavaStackTrace();
                        createRuntimeEvent("reflection.load_class", {
                            library: 'java.lang.ClassLoader',
                            method: 'loadClass',
                            class_name: class_name,
                            resolve: resolve,
                            is_internal: isInternal,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        try {
                            return original.call(this, class_name, resolve);
                        } catch (error) {
                            throw new PropagateException(error);
                        }
                    }
                );
            }
        }

        // Hook Method.invoke
        if (Method) {
            const invoke = safeOverload(
                Method.invoke,
                "runtime:Method.invoke",
                'java.lang.Object', '[Ljava.lang.Object;'
            );
            if (invoke) {
                invoke.implementation = safeImplementation(
                    "runtime:Method.invoke",
                    invoke,
                    function(original, instance: any, args: any) {
                        const java_stack_trace = collectJavaStackTrace();
                        let result;
                        try {
                            result = original.call(this, instance, args);
                        } catch (error) {
                            throw new PropagateException(error);
                        }

                        let argumentsStr = null;
                        if (args) {
                            try {
                                argumentsStr = args.map((arg: any) => arg ? arg.toString() : 'null').join(', ');
                            } catch (e) {
                                argumentsStr = 'arguments_processing_error';
                            }
                        }

                        createRuntimeEvent("reflection.method_invoke", {
                            library: 'java.lang.reflect.Method',
                            method: 'invoke',
                            method_name: this.getName(),
                            method_signature: this.toGenericString(),
                            target_instance: instance ? instance.toString() : null,
                            arguments: argumentsStr,
                            result: result ? result.toString() : null,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });

                        return result;
                    }
                );
            }
        }
    });
}

export function install_runtime_hooks() {
    devlog("\n");
    devlog("install runtime hooks");

    try {
        hook_runtime();
    } catch (error) {
        devlog(`[HOOK] Failed to install runtime hooks: ${error}`);
    }

    try {
        trace_reflection();
    } catch (error) {
        devlog(`[HOOK] Failed to install reflection tracing hooks: ${error}`);
    }
}
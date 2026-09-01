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
    });
}

function trace_reflection() {
    safePerform("runtime:trace_reflection", () => {
        const internalClasses: string[] = ["android.", "com.android", "java.lang", "java.io"];

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

            // Hook Class.forName
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
                        let isInternal = false;
                        for (const internalClass of internalClasses) {
                            if (class_name.startsWith(internalClass)) {
                                isInternal = true;
                                break;
                            }
                        }
                        if (!isInternal) {
                            const java_stack_trace = collectJavaStackTrace();
                            createRuntimeEvent("reflection.class_for_name", {
                                library: 'java.lang.Class',
                                method: 'forName',
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
                        let isInternal = false;
                        for (const internalClass of internalClasses) {
                            if (class_name.startsWith(internalClass)) {
                                isInternal = true;
                                break;
                            }
                        }
                        if (!isInternal) {
                            const java_stack_trace = collectJavaStackTrace();
                            createRuntimeEvent("reflection.load_class", {
                                library: 'java.lang.ClassLoader',
                                method: 'loadClass',
                                class_name: class_name,
                                resolve: resolve,
                                is_internal: isInternal,
                                ...(java_stack_trace ? { java_stack_trace } : {})
                            });
                        }
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
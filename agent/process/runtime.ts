import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd, java_stack_trace } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"
import { Where } from "../utils/misc.js"
import { safePerform, safeUse, safeOverload } from "../utils/safe_java.js"

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

function hook_runtime(){
    safePerform("runtime:hook_runtime", () => {
        const Runtime = safeUse('java.lang.Runtime', "runtime:hook_runtime");
        if (!Runtime) return;

        const threadDef = safeUse('java.lang.Thread', "runtime:hook_runtime");
        if (!threadDef) return;
        const threadInstance = threadDef.$new();
        
        // Hook Runtime.exec overloads
        // exec: iterate all available overloads — no hardcoded count
        Runtime.exec.overloads.forEach((overload: any, index: number) => {
            overload.implementation = function(command: any, envp: any, dir: any) {
                const stack = threadInstance.currentThread().getStackTrace();

                let commandStr = null;
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
                    stack_trace: Where(stack)
                });

                return overload.apply(this, arguments);
            };
        });
    
        // Hook Runtime.loadLibrary overloads
        Runtime.loadLibrary.overloads.forEach((overload: any, index: number) => {
            overload.implementation = function(libname: any) {
                const stack = threadInstance.currentThread().getStackTrace();

                createRuntimeEvent("runtime.load_library", {
                    library: 'java.lang.Runtime',
                    method: 'loadLibrary',
                    overload_index: index,
                    library_name: libname ? libname.toString() : null,
                    stack_trace: Where(stack)
                });

                return overload.apply(this, arguments);
            };
        });
    
        // Hook Runtime.load overloads
        // load: iterate all available overloads
        Runtime.load.overloads.forEach((overload: any, index: number) => {
            overload.implementation = function(filename: any) {
                const stack = threadInstance.currentThread().getStackTrace();

                createRuntimeEvent("runtime.load", {
                    library: 'java.lang.Runtime',
                    method: 'load',
                    overload_index: index,
                    filename: filename ? filename.toString() : null,
                    stack_trace: Where(stack)
                });

                return overload.apply(this, arguments);
            };
        });
    });
}

function trace_reflection() {
    // monolithic try-catch removed — safePerform owns the boundary
    // each class resolved independently via safeUse, one absent class
    // does not abort the others
    safePerform("runtime:trace_reflection", () => {
        const internalClasses: string[] = ["android.", "com.android", "java.lang", "java.io"];

        const threadDef = safeUse('java.lang.Thread', "runtime:trace_reflection");
        if (!threadDef) return;
        const threadInstance = threadDef.$new();

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
                getMethod.implementation = function(methodName: string, paramTypes: any) {
                    const method = getMethod.call(this, methodName, paramTypes);
                    const stack = threadInstance.currentThread().getStackTrace();
                    createRuntimeEvent("reflection.get_method", {
                        library: 'java.lang.Class',
                        method: 'getMethod',
                        method_name: methodName,
                        method_signature: method.toGenericString(),
                        class_name: this.getName(),
                        access_type: 'public',
                        stack_trace: Where(stack)
                    });
                    return method;
                };
            }

            // Hook Class.getDeclaredMethod
            const getDeclaredMethod = safeOverload(
                    classDef.getDeclaredMethod,
                    "runtime:Class.getDeclaredMethod",
                    'java.lang.String', '[Ljava.lang.Class;'
                );
            if (getDeclaredMethod) {
                getDeclaredMethod.implementation = function(methodName: string, paramTypes: any) {
                    const method = getDeclaredMethod.call(this, methodName, paramTypes);
                    const stack = threadInstance.currentThread().getStackTrace();
                    createRuntimeEvent("reflection.get_declared_method", {
                        library: 'java.lang.Class',
                        method: 'getDeclaredMethod',
                        method_name: methodName,
                        method_signature: method.toGenericString(),
                        class_name: this.getName(),
                        access_type: 'any',
                        stack_trace: Where(stack)
                    });
                    return method;
                };
            }
    
            // Hook Class.forName
            const forName = safeOverload(
            classDef.forName,
            "runtime:Class.forName",
            'java.lang.String', 'boolean', 'java.lang.ClassLoader'
            );
            if (forName) {
                forName.implementation = function(class_name: string, flag: boolean, class_loader: any) {
                    let isInternal = false;
                    for (const internalClass of internalClasses) {
                        if (class_name.startsWith(internalClass)) {
                            isInternal = true;
                            break;
                        }
                    }
                    if (!isInternal) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        createRuntimeEvent("reflection.class_for_name", {
                            library: 'java.lang.Class',
                            method: 'forName',
                            class_name: class_name,
                            initialize: flag,
                            class_loader: class_loader ? class_loader.toString() : null,
                            is_internal: isInternal,
                            stack_trace: Where(stack)
                        });
                    }
                    return forName.call(this, class_name, flag, class_loader);
                };
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
                loadClass.implementation = function(class_name: string, resolve: boolean) {
                    let isInternal = false;
                    for (const internalClass of internalClasses) {
                        if (class_name.startsWith(internalClass)) {
                            isInternal = true;
                            break;
                        }
                    }
                    if (!isInternal) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        createRuntimeEvent("reflection.load_class", {
                            library: 'java.lang.ClassLoader',
                            method: 'loadClass',
                            class_name: class_name,
                            resolve: resolve,
                            is_internal: isInternal,
                            stack_trace: Where(stack)
                        });
                    }
                    return loadClass.call(this, class_name, resolve);
                };
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
                invoke.implementation = function(instance: any, args: any) {
                    const stack = threadInstance.currentThread().getStackTrace();
                    const result = invoke.call(this, instance, args);

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
                        stack_trace: Where(stack)
                    });

                    return result;
                };
            }
        }
    });
}


export function install_runtime_hooks(){
    devlog("\n")
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


import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd, java_stack_trace } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"
import { Where } from "../utils/misc.js"

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
 * 
/**
 * https://github.com/dpnishant/appmon/tree/master/scripts/Android
 * https://github.com/Ch0pin/medusa/blob/master/modules/runtime/runtime.med
 */

function hook_runtime(){
    Java.perform(() => {
        try {
            const Runtime = Java.use('java.lang.Runtime');
            const threadDef = Java.use('java.lang.Thread');
            const threadInstance = threadDef.$new();
    
            // Hook Runtime.exec overloads
            for (let i = 0; i < 6; i++) {
                if (Runtime.exec.overloads[i]) {
                    Runtime.exec.overloads[i].implementation = function (
                        command: any,
                        envp: any,
                        dir: any
                    ) {
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
                            overload_index: i,
                            command: commandStr,
                            environment: envp ? envp.toString() : null,
                            working_directory: dir ? dir.toString() : null,
                            stack_trace: Where(stack)
                        });

                        return Runtime.exec.overloads[i].apply(this, arguments);
                    };
                }
            }
    
            // Hook Runtime.loadLibrary overloads
            for (let i = 0; i < 2; i++) {
                if (Runtime.loadLibrary.overloads[i]) {
                    Runtime.loadLibrary.overloads[i].implementation = function (
                        libname: any
                    ) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        
                        createRuntimeEvent("runtime.load_library", {
                            library: 'java.lang.Runtime',
                            method: 'loadLibrary',
                            overload_index: i,
                            library_name: libname ? libname.toString() : null,
                            stack_trace: Where(stack)
                        });

                        return Runtime.loadLibrary.overloads[i].apply(this, arguments);
                    };
                }
            }
    
            // Hook Runtime.load overloads
            for (let i = 0; i < 2; i++) {
                if (Runtime.load.overloads[i]) {
                    Runtime.load.overloads[i].implementation = function (
                        filename: any
                    ) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        
                        createRuntimeEvent("runtime.load", {
                            library: 'java.lang.Runtime',
                            method: 'load',
                            overload_index: i,
                            filename: filename ? filename.toString() : null,
                            stack_trace: Where(stack)
                        });

                        return Runtime.load.overloads[i].apply(this, arguments);
                    };
                }
            }

        } catch (error) {
            createRuntimeEvent("runtime.error", {
                error_message: (error as Error).toString(),
                error_type: "hook_runtime"
            });
        }
    });
}

function trace_reflection(){
    Java.perform(() => {
        try {
            const internalClasses: string[] = ["android.", "com.android", "java.lang", "java.io"];
            const threadDef = Java.use('java.lang.Thread');
            const threadInstance = threadDef.$new();
        
            const classDef = Java.use('java.lang.Class');
            const classLoaderDef = Java.use('java.lang.ClassLoader');
            const Method = Java.use('java.lang.reflect.Method');
        
            const forName = classDef.forName.overload('java.lang.String', 'boolean', 'java.lang.ClassLoader');
            const loadClass = classLoaderDef.loadClass.overload('java.lang.String', 'boolean');
            const getMethod = classDef.getMethod.overload('java.lang.String', '[Ljava.lang.Class;');
            const getDeclaredMethod = classDef.getDeclaredMethod.overload('java.lang.String', '[Ljava.lang.Class;');
            const invoke = Method.invoke.overload('java.lang.Object', '[Ljava.lang.Object;');

            // Hook Class.getMethod
            getMethod.implementation = function (methodName: string, paramTypes: any) {
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
            }

            // Hook Class.getDeclaredMethod
            getDeclaredMethod.implementation = function (methodName: string, paramTypes: any) {
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
            }
        
            // Hook Class.forName
            forName.implementation = function (class_name: string, flag: boolean, class_loader: any) {
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
            }
        
            // Hook ClassLoader.loadClass
            loadClass.implementation = function (class_name: string, resolve: boolean) {
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
            }

            // Hook Method.invoke
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

        } catch (error) {
            createRuntimeEvent("reflection.error", {
                error_message: (error as Error).toString(),
                error_type: "trace_reflection"
            });
        }
    });
}


export function install_runtime_hooks(){
    devlog("\n")
    devlog("install runtime hooks");
    hook_runtime();
    trace_reflection();
}


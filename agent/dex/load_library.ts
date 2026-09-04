import { devlog, am_send } from "../utils/logging.js"
import {
    safePerform,
    safeUse,
    safeOverload,
    safeImplementation,
    PropagateException
} from "../utils/safe_java.js"
import { collectJavaStackTrace } from "../utils/stacktrace.js"

const PROFILE_HOOKING_TYPE: string = "DYNAMIC_LIB_LOADING"

interface LibraryLoadOrigin {
    eventType: string;
    originMethod: string;
    loaderType: string;
}

function createLibraryEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function getCallerClassName(callerClass: any): string | null {
    if (callerClass === null || callerClass === undefined) {
        return null;
    }

    try {
        return callerClass.getName().toString();
    } catch {
        return null;
    }
}

function getLibraryLoadOrigin(
    Thread: any,
    operation: "load" | "load_library"
): LibraryLoadOrigin {
    const internalOrigin: LibraryLoadOrigin = {
        eventType: `library.internal.${operation}`,
        originMethod: operation === "load"
            ? "Runtime.load0(Class, String)"
            : "Runtime.loadLibrary0(ClassLoader, Class, String)",
        loaderType: "RuntimeInternal"
    };

    let frames: any;

    try {
        frames = Thread.currentThread().getStackTrace();
    } catch {
        return internalOrigin;
    }

    for (let index = 0; index < frames.length; index++) {
        let frame: string;

        try {
            frame = frames[index].toString();
        } catch {
            continue;
        }

        if (operation === "load") {
            if (frame.includes("java.lang.System.load(")) {
                return {
                    eventType: "library.system.load",
                    originMethod: "System.load(String)",
                    loaderType: "System"
                };
            }

            if (frame.includes("java.lang.Runtime.load(")) {
                return {
                    eventType: "library.runtime.load",
                    originMethod: "Runtime.load(String)",
                    loaderType: "Runtime"
                };
            }
        } else {
            if (frame.includes("java.lang.System.loadLibrary(")) {
                return {
                    eventType: "library.system.load_library",
                    originMethod: "System.loadLibrary(String)",
                    loaderType: "System"
                };
            }

            if (frame.includes("java.lang.Runtime.loadLibrary(")) {
                return {
                    eventType: "library.runtime.load_library",
                    originMethod: "Runtime.loadLibrary(String)",
                    loaderType: "Runtime"
                };
            }
        }
    }

    return internalOrigin;
}

function install_runtime_library_hooks(): void {
    devlog("Installing safe Runtime library loading hooks");

    safePerform("load_library:install_runtime_library_hooks", () => {
        const RuntimeDef = safeUse(
            "java.lang.Runtime",
            "load_library:install_runtime_library_hooks"
        );
        const Thread = safeUse(
            "java.lang.Thread",
            "load_library:install_runtime_library_hooks"
        );

        if (!RuntimeDef || !Thread) {
            return;
        }

        const load0 = safeOverload(
            RuntimeDef.load0,
            "load_library:Runtime.load0",
            "java.lang.Class",
            "java.lang.String"
        );

        if (load0) {
            load0.implementation = safeImplementation(
                "load_library:Runtime.load0",
                load0,
                function (original, callerClass: any, libraryPath: string) {
                    const origin = getLibraryLoadOrigin(Thread, "load");
                    const javaStackTrace = collectJavaStackTrace();

                    createLibraryEvent(origin.eventType, {
                        method: origin.originMethod,
                        library_path: libraryPath,
                        loader_type: origin.loaderType,
                        internal_method: "Runtime.load0(Class, String)",
                        caller_class: getCallerClassName(callerClass),
                        ...(javaStackTrace
                            ? { java_stack_trace: javaStackTrace }
                            : {})
                    });

                    try {
                        return original.call(
                            this,
                            callerClass,
                            libraryPath
                        );
                    } catch (error) {
                        throw new PropagateException(error);
                    }
                }
            );
        }

        const loadLibrary0 = safeOverload(
            RuntimeDef.loadLibrary0,
            "load_library:Runtime.loadLibrary0",
            "java.lang.ClassLoader",
            "java.lang.Class",
            "java.lang.String"
        );

        if (loadLibrary0) {
            loadLibrary0.implementation = safeImplementation(
                "load_library:Runtime.loadLibrary0",
                loadLibrary0,
                function (
                    original,
                    classLoader: any,
                    callerClass: any,
                    libraryName: string
                ) {
                    const origin = getLibraryLoadOrigin(
                        Thread,
                        "load_library"
                    );
                    const javaStackTrace = collectJavaStackTrace();

                    createLibraryEvent(origin.eventType, {
                        method: origin.originMethod,
                        library_name: libraryName,
                        loader_type: origin.loaderType,
                        internal_method:
                            "Runtime.loadLibrary0(ClassLoader, Class, String)",
                        caller_class: getCallerClassName(callerClass),
                        ...(javaStackTrace
                            ? { java_stack_trace: javaStackTrace }
                            : {})
                    });

                    try {
                        return original.call(
                            this,
                            classLoader,
                            callerClass,
                            libraryName
                        );
                    } catch (error) {
                        throw new PropagateException(error);
                    }
                }
            );
        }
    });
}

export function install_java_dex_unpacking_hooks(): void {
    devlog("\n");
    devlog("Installing library loading hooks");

    try {
        install_runtime_library_hooks();
    } catch (error) {
        devlog(
            `[HOOK] Failed to install Runtime library loading hooks: ${error}`
        );
        createLibraryEvent("library.runtime.hook_error", {
            error: error.toString()
        });
    }
}
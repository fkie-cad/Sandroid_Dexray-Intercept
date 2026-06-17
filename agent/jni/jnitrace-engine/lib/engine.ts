import { ReferenceManager } from "./utils/reference_manager";
import { Config } from "./utils/config";

import { JNIEnvInterceptor } from "./jni/jni_env_interceptor";
import { JNIEnvInterceptorX86 } from "./jni/x86/jni_env_interceptor_x86";
import { JNIEnvInterceptorX64 } from "./jni/x64/jni_env_interceptor_x64";
import { JNIEnvInterceptorARM } from "./jni/arm/jni_env_interceptor_arm";
import { JNIEnvInterceptorARM64 } from "./jni/arm64/jni_env_interceptor_arm64";

import { JavaVMInterceptor } from "./jni/java_vm_interceptor";
import { JNIThreadManager } from "./jni/jni_thread_manager";

import { JNICallbackManager } from "./internal/jni_callback_manager";

import { JNILibraryWatcher } from ".";

/* @ts-ignore - _Module.findExportByName exists at runtime in all Frida versions */
const _Module: any = Module;

const REGISTER_NATIVE_SYMBOLS = {
    // art::ClassLinker::RegisterNative(art::Thread*, art::ArtMethod*, void const*)
    // Present on Android 12+ (API 31-35).
    classLinker: [
        "_ZN3art11ClassLinker14RegisterNativeEPNS_6ThreadEPNS_9ArtMethodEPKv",
    ],
    // art::ArtMethod::RegisterNative(void const*)
    // Modern non-mirror ArtMethod::RegisterNative used on Android 6–11.
    //
    // Older ART versions (Android 4.4–5.x) use mirror::ArtMethod::RegisterNative:
    //   Android 4.4.x: void mirror::ArtMethod::RegisterNative(Thread*, const void*)
    //   Android 5.0/5.1: void mirror::ArtMethod::RegisterNative(Thread*, const void*, bool)
    // These mirror variants would require separate hooks with different signatures
    // if support for those versions is needed.
    artMethod: [
        "_ZN3art9ArtMethod14RegisterNativeEPKv"
        // Mirror variant symbols for Android 4.4–5.x would go here if needed, e.g.
        //"_ZN3art6mirror9ArtMethod14RegisterNativeEPNS_6ThreadEPKv"
    ]
};

export function run (callbackManager: JNICallbackManager): void {
    const JNI_ENV_INDEX = 0;
    const JAVA_VM_INDEX = 0;
    const LIB_TRACK_FIRST_INDEX = 0;
    
    const threads = new JNIThreadManager();
    const references = new ReferenceManager();
    
    let jniEnvInterceptor: JNIEnvInterceptor | undefined = undefined;
    if (Process.arch === "ia32") {
        jniEnvInterceptor = new JNIEnvInterceptorX86(
            references, threads, callbackManager
        );
    } else if (Process.arch === "x64") {
        jniEnvInterceptor = new JNIEnvInterceptorX64(
            references, threads, callbackManager
        );
    } else if (Process.arch === "arm") {
        jniEnvInterceptor = new JNIEnvInterceptorARM(
            references, threads, callbackManager
        );
    } else if (Process.arch === "arm64") {
        jniEnvInterceptor = new JNIEnvInterceptorARM64(
            references, threads, callbackManager
        );
    }
    
    if (jniEnvInterceptor === undefined) {
        throw new Error(
            Process.arch + " currently unsupported, please file an issue."
        );
    }
    
    const javaVMInterceptor = new JavaVMInterceptor(
        references,
        threads,
        jniEnvInterceptor,
        callbackManager
    );
    
    jniEnvInterceptor.setJavaVMInterceptor(javaVMInterceptor);
    
    const trackedLibs: Map<string, boolean> = new Map<string, boolean>();
    const libBlacklist: Map<string, boolean> = new Map<string, boolean>();
    const hookedNatives = new Set<string>();

    /**
     * Determines whether a library at the given path should be traced
     * according to the user's -l filter configuration.
     *
     * Also notifies JNILibraryWatcher when a library is seen.
     *
     * @param path Full path to the library (e.g., /data/app/.../lib/arm64/libnative.so).
     * @returns true if the library should be traced, false otherwise.
     */
    function checkLibrary (path: string): boolean {
        const EMPTY_ARRAY_LENGTH = 0;
        const ONE_ELEMENT_ARRAY_LENGTH = 1;
    
        let willFollowLib = false;

        if (path === null) {
            return false;
        }
    
        JNILibraryWatcher.doCallback(path);

        const config = Config.getInstance();
        // Wildcard: trace all libraries
        if (config.libraries.length === ONE_ELEMENT_ARRAY_LENGTH &&
            config.libraries[LIB_TRACK_FIRST_INDEX] === "*") {
            willFollowLib = true;
        }

        // Pattern matching: check if any filter pattern appears in path
        if (!willFollowLib) {
            willFollowLib = config.libraries.some(
                (l: string): boolean => path.includes(l)
            );
        }
    
        return willFollowLib;
    }
    
    /**
     * Pure filter equivalent of checkLibrary(), without side effects.
     *
     * @param path  Full path to the library.
     * @returns     true if the library matches current -l filters, false otherwise.
     */
    function isLibraryTracked (path: string): boolean {
        if (path === null) {
            return false;
        }

        const config = Config.getInstance();
        const libs = config.libraries;

        // Wildcard: trace all libraries
        if (libs.length === 1 && libs[LIB_TRACK_FIRST_INDEX] === "*") {
            return true;
        }

        // Pattern matching: any filter pattern contained in the path
        return libs.some((pattern: string): boolean => path.includes(pattern));
    }

    /**
     * Intercepts a JNI_OnLoad function to swap the JavaVM pointer
     * with a shadow JavaVM that allows tracing of JavaVM API calls.
     *
     * @param jniOnLoadAddr Address of the JNI_OnLoad function.
     * @returns             InvocationListener for the installed hook.
     */
    function interceptJNIOnLoad (jniOnLoadAddr: NativePointer): InvocationListener {
        return Interceptor.attach(jniOnLoadAddr, {
            onEnter (args: NativePointer[]): void {
                let shadowJavaVM = NULL;
                const javaVM = ptr(args[JAVA_VM_INDEX].toString());
    
                if (!threads.hasJavaVM()) {
                    threads.setJavaVM(javaVM);
                }
    
                if (!javaVMInterceptor.isInitialised()) {
                    shadowJavaVM = javaVMInterceptor.create();
                } else {
                    shadowJavaVM = javaVMInterceptor.get();
                }
    
                args[JAVA_VM_INDEX] = shadowJavaVM;
            }
        });
    }
    
    /**
     * Intercepts a native JNI function (e.g., Java_* export or ART stub)
     * to swap the JNIEnv pointer with a shadow JNIEnv so that subsequent JNI
     * calls made by the native code are traced.
     *
     * @param jniFunctionAddr Address of the native function to intercept
     * @returns               InvocationListener for the installed hook
     */
    function interceptJNIFunction (jniFunctionAddr: NativePointer): InvocationListener {
        return Interceptor.attach(jniFunctionAddr, {
            onEnter (args: NativePointer[]): void {
                if (jniEnvInterceptor === undefined) {
                    return;
                }

                const threadId = this.threadId;
                const jniEnv = ptr(args[JNI_ENV_INDEX].toString());

                threads.setJNIEnv(threadId, jniEnv);

                const shadowJNIEnv = jniEnvInterceptor.isInitialised()
                    ? jniEnvInterceptor.get()
                    : jniEnvInterceptor.create();

                args[JNI_ENV_INDEX] = shadowJNIEnv;
            }
        });
    }

    /**
     * Attempts to hook ClassLinker::RegisterNative or ArtMethod::RegisterNative
     * in libart.so so that native registrations are observed and their
     * entrypoints can be intercepted.
     *
     * @returns true if a RegisterNative symbol was found and hooked, false otherwise.
     */
    function setupRegisterNativeHook(): boolean {
        const libart = Process.findModuleByName("libart.so");
        if (libart === null) {
            return false;
        }

        let hookAddress: NativePointer | null = null;
        let strategy: "ClassLinker" | "ArtMethod" | null = null;

        // Try ClassLinker symbols first (Android 12+)
        for (const symbol of REGISTER_NATIVE_SYMBOLS.classLinker) {
            hookAddress = _Module.findExportByName("libart.so", symbol);
            if (hookAddress !== null) {
                strategy = "ClassLinker";
                break;
            }
        }

        // Fallback to ArtMethod symbols (Android 8-11)
        if (hookAddress === null) {
            for (const symbol of REGISTER_NATIVE_SYMBOLS.artMethod) {
                hookAddress = _Module.findExportByName("libart.so", symbol);
                if (hookAddress !== null) {
                    strategy = "ArtMethod";
                    break;
                }
            }
        }

        // Give up if not found
        if (hookAddress === null || strategy === null) {
            return false;
        }

        // Install the hook
        try {
            if (strategy === "ClassLinker") {
                installClassLinkerHook(hookAddress);
            } else {
                installArtMethodHook(hookAddress);
            }
            return true;
        } catch (e) {
            return false;
        }
    }

    /**
     * Installs a hook on ClassLinker::RegisterNative (Android 12+).
     *
     * C++ signature:
     *   const void* ClassLinker::RegisterNative(Thread* self,
     *                                           ArtMethod* method,
     *                                           const void* native_method);
     *
     * The hook uses the returned const void* (retval) as the final
     * native entrypoint when non-null, falling back to the input
     * native_method argument if retval is null.
     *
     * @param address Address of ClassLinker::RegisterNative in libart.so.
     * @returns       void.
     */
    function installClassLinkerHook(address: NativePointer): void {
        Interceptor.attach(address, {
            onEnter(args: NativePointer[]): void {
                // C++ member function:
                // args[0] = ClassLinker* (this)
                // args[1] = Thread* self
                // args[2] = ArtMethod* method
                // args[3] = const void* native_method (input)
                this.nativePtr = args[3];
            },
            onLeave(retval: NativePointer): void {
                // Prefer returned entrypoint; fall back to input if retval is null
                const finalEntryPoint = retval.isNull()
                    ? (this.nativePtr as NativePointer)
                    : retval;

                // Apply filtering
                if (!shouldHookNative(finalEntryPoint)) {
                    return;
                }

                // Hook the final entry point
                try {
                    interceptJNIFunction(finalEntryPoint);
                } catch (e) {
                    // Failed to attach; skip
                }
            }
        });
    }

    /**
     * Installs a hook on ArtMethod::RegisterNative (Android 8-11).
     *
     * C++ signature:
     *   const void* ArtMethod::RegisterNative(const void* native_method);
     *
     * The hook uses the returned const void* (retval) as the final
     * native entrypoint when non-null, falling back to the input
     * native_method argument if retval is null.
     *
     * @param address Address of ArtMethod::RegisterNative in libart.so.
     * @returns       void.
     */
    function installArtMethodHook(address: NativePointer): void {
        Interceptor.attach(address, {
            onEnter(args: NativePointer[]): void {
                // C++ member function: this pointer is args[0]
                // args[0] = ArtMethod* (this)
                // args[1] = const void* native_method (input)
                this.nativePtr = args[1];
            },
            onLeave(retval: NativePointer): void {
                const finalEntryPoint = retval.isNull()
                    ? (this.nativePtr as NativePointer)
                    : retval;

                // Apply filtering
                if (!shouldHookNative(finalEntryPoint)) {
                    return;
                }

                // Hook the final entry point
                try {
                    interceptJNIFunction(finalEntryPoint);
                } catch (e) {
                    // Failed to attach; skip
                }
            }
        });
    }

    /**
     * Multi-stage filter to decide if a native function should be hooked.
     *
     * Stage 1: module filter against -l patterns.
     * Stage 2: deduplication against already hooked addresses.
     * Stage 3: includeExport / excludeExport symbol filtering.
     *
     * @param nativePtr Address of the candidate native function.
     * @returns         true if the function should be hooked, false otherwise.
     */
    function shouldHookNative(nativePtr: NativePointer): boolean {
        // Stage 1: Module check
        const module = Process.findModuleByAddress(nativePtr);
        if (module === null) {
            return false;
        }

        if (!isLibraryTracked(module.path)) {
            return false;
        }

        // Stage 2: Deduplication
        const key = nativePtr.toString();
        if (hookedNatives.has(key)) {
            return false;
        }

        // Stage 3: Symbol filter
        const symbol = DebugSymbol.fromAddress(nativePtr);
        const symbolName = symbol?.name || "<unknown>";

        if (symbolName !== "<unknown>") {
            const config = Config.getInstance();
            const check = symbolName;

            // Include filter
            if (config.includeExport.length > 0) {
                const included = config.includeExport.some(
                    (p: string): boolean => check.indexOf(p) !== -1
                );
                if (!included) {
                    return false;
                }
            }

            // Exclude filter
            if (config.excludeExport.length > 0) {
                const excluded = config.excludeExport.some(
                    (p: string): boolean => check.indexOf(p) !== -1
                );
                if (excluded) {
                    return false;
                }
            }
        }

        // Mark as hooked
        hookedNatives.add(key);
        return true;
    }

    // Install RegisterNative hook; dlsym and JNIEnv::RegisterNatives remain as backstops.
    setupRegisterNativeHook();

    const dlopenRef = _Module.findExportByName(null, "dlopen");
    const dlopenExtRef = _Module.findExportByName(null, "android_dlopen_ext");
    const dlsymRef = _Module.findExportByName(null, "dlsym");
    const dlcloseRef = _Module.findExportByName(null, "dlclose");

    /**
     * Common handler for both dlopen() and android_dlopen_ext().
     *
     * Inspects the filename, applies -l filters, and updates trackedLibs /
     * libBlacklist based on the handle.
     *
     * @param filename Pointer to the filename string.
     * @param handle   Library handle returned by dlopen/android_dlopen_ext.
     * @returns        The handle (unchanged).
     */
    const handleDlopenResult = (
        filename: NativePointer,
        handle: NativePointer
    ): NativePointer => {
        const path = filename.readCString();

        if (path !== null) {
            if (checkLibrary(path)) {
                // eslint-disable-next-line @typescript-eslint/no-base-to-string
                trackedLibs.set(handle.toString(), true);
            } else {
                // eslint-disable-next-line @typescript-eslint/no-base-to-string
                libBlacklist.set(handle.toString(), true);
            }
        }

        return handle;
    };

    if ((dlopenRef !== null || dlopenExtRef !== null) &&
        dlsymRef !== null &&
        dlcloseRef !== null) {

        const HANDLE_INDEX = 0;

        if (dlopenRef !== null) {
            Interceptor.attach(dlopenRef, {
                onEnter (args: NativePointer[]): void {
                    // Save filename pointer for use in onLeave
                    this.filename = args[0] as NativePointer;
                },
                onLeave (retval: NativePointer): void {
                    if (this.filename !== undefined) {
                        handleDlopenResult(this.filename, retval);
                    }
                }
            });
        }

        if (dlopenExtRef !== null) {
            Interceptor.attach(dlopenExtRef, {
                onEnter (args: NativePointer[]): void {
                    // android_dlopen_ext(const char *filename, int flags, const android_dlextinfo *extinfo)
                    this.filename = args[0] as NativePointer;
                },
                onLeave (retval: NativePointer): void {
                    if (this.filename !== undefined) {
                        handleDlopenResult(this.filename, retval);
                    }
                }
            });
        }

        const dlsym = new NativeFunction(
            dlsymRef,
            "pointer",
            ["pointer", "pointer"]
        );

        Interceptor.attach(dlsym, {
            onEnter (args: NativePointer[]): void {
                const SYMBOL_INDEX = 1;

                this.handle = args[HANDLE_INDEX].toString();

                if (libBlacklist.has(this.handle)) {
                    return;
                }

                this.symbol = args[SYMBOL_INDEX].readCString();
            },
            onLeave (retval: NativePointer): void {
                if (retval.isNull() || libBlacklist.has(this.handle)) {
                    return;
                }

                const config = Config.getInstance();
                const EMPTY_ARRAY_LEN = 0;

                if (config.includeExport.length > EMPTY_ARRAY_LEN) {
                    const included = config.includeExport.filter(
                        (i: string): boolean => (this.symbol as string).includes(i)
                    );
                    if (included.length === EMPTY_ARRAY_LEN) {
                        return;
                    }
                }
                if (config.excludeExport.length > EMPTY_ARRAY_LEN) {
                    const excluded = config.excludeExport.filter(
                        (e: string): boolean => (this.symbol as string).includes(e)
                    );
                    if (excluded.length > EMPTY_ARRAY_LEN) {
                        return;
                    }
                }

                if (!trackedLibs.has(this.handle)) {
                    // Android 7 and above miss the initial dlopen call.
                    // Give it another chance in dlsym.
                    const mod = Process.findModuleByAddress(retval);
                    if (mod !== null && checkLibrary(mod.path)) {
                        trackedLibs.set(this.handle, true);
                    }
                }

                const symbol = this.symbol as string;

                if (trackedLibs.has(this.handle)) {
                    if (symbol === "JNI_OnLoad") {
                        interceptJNIOnLoad(ptr(retval.toString()));
                    } else if (symbol.startsWith("Java_")) {
                        const addr = ptr(retval.toString());
                        const key = addr.toString();

                        if (hookedNatives.has(key)) {
                            return;
                        }

                        hookedNatives.add(key);
                        interceptJNIFunction(addr);
                    }
                } else  {
                    let name = config.libraries[LIB_TRACK_FIRST_INDEX];

                    if (name !== "*") {
                        const mod = Process.findModuleByAddress(retval);
                        if (mod === null) {
                            return;
                        }
                        name = mod.name;
                    }

                    if (/lib.+\.so/.exec(name) === null) {
                        return;
                    }

                    if (config.libraries.includes(name) || name === "*") {
                        const addr = ptr(retval.toString());
                        const key = addr.toString();

                        if (hookedNatives.has(key)) {
                            return;
                        }

                        hookedNatives.add(key);
                        interceptJNIFunction(addr);
                    }
                }
            }
        });

        const dlclose = new NativeFunction(dlcloseRef, "int", ["pointer"]);
        Interceptor.attach(dlclose, {
            onEnter (args: NativePointer[]): void {
                const handle = args[HANDLE_INDEX].toString();
                if (trackedLibs.has(handle)) {
                    this.handle = handle;
                }
            },
            onLeave (retval: NativePointer): void {
                if (this.handle !== undefined) {
                    if (retval.toInt32() === 0) {
                        trackedLibs.delete(this.handle);
                    }
                }
            }
        });
    }
}

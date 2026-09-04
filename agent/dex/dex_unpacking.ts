import { devlog, am_send } from "../utils/logging.js"
import { getAndroidVersion, copy_file, removeLeadingColon } from "../utils/android_runtime_requests.js"
import { safePerform, safeUse, safeOverload, safeImplementation, PropagateException } from "../utils/safe_java.js"
import { safeResolveExport, safeNativeFunction, safeAttach, safeEnumerateMatches, stripModulePrefix } from "../utils/safe_native.js"
import { collectJavaStackTrace, collectNativeBacktrace } from "../utils/stacktrace.js"

const PROFILE_HOOKING_TYPE: string = "DEX_LOADING"

const activeInMemoryDexLoaderDepth = new Map<number, number>();
const activeClassLoaderConstructorDepth = new Map<number, number>();

interface DEXInfo {
    magicString: string;
    version: string;
    ext: string;
    size: number;
    sizeOffset?: number;
    found?: boolean;
    wrongMagic?: any;
}

interface UnpackingEvent {
    event_type: string;
    dex_path?: string;
    file_path?: string;
    magic?: string;
    size?: number;
    version?: string;
    location?: string;
    hooked_function?: string;
    class_loader_type?: string;
}

interface NativeDexHookTarget {
    moduleName: string;
    symbolName: string;
    address: NativePointer;
    dataArgumentIndexes: number[];
    sizeArgumentIndex: number | null;
}

function createDEXEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function callJavaOriginal(
    original: any,
    receiver: any,
    ...args: any[]
): any {
    try {
        return original.call(receiver, ...args);
    } catch (error) {
        throw new PropagateException(error);
    }
}

/**
 * TODO Future: 
 *
 * 1. integrate the logic from here to extend the DEX unpacking: AppProfiling/testing_3rd_party_scripts/FridaScripts
 * 2. Testing with futher files from here: https://pentest.blog/n-ways-to-unpack-mobile-malware/
 * 
 */

/**
 * Extended version original from:
 * Author: guoqiangck & enovella 
 * Created: 2019/6/11 
 * Dump dex file for packed apks
 * Hook art/runtime/dex_file.cc OpenMemory or OpenCommon
 * Support Version: Android 4.4 up to Android 11.0
 * 
 * we updated this to work with newer Android versions. Further so that its incooperate with SanDroid
 * Last update: 24.11.23
 */



// Read a C++ std string

function invokeClassLoaderConstructor(
    original: any,
    receiver: any,
    args: any[],
    eventData: any,
    destinationPath: string
): any {
    const threadId = Process.getCurrentThreadId();
    const depth =
        activeClassLoaderConstructorDepth.get(threadId) || 0;
    const isOutermost = depth === 0;

    activeClassLoaderConstructorDepth.set(threadId, depth + 1);

    try {
        if (isOutermost) {
            const javaStackTrace = collectJavaStackTrace();

            createDEXEvent("dex.classloader.creation", {
                ...eventData,
                ...(javaStackTrace
                    ? { java_stack_trace: javaStackTrace }
                    : {})
            });

            dump(eventData.file_path, destinationPath);
        }

        return callJavaOriginal(original, receiver, ...args);
    } finally {
        const remaining =
            activeClassLoaderConstructorDepth.get(threadId)! - 1;

        if (remaining <= 0) {
            activeClassLoaderConstructorDepth.delete(threadId);
        } else {
            activeClassLoaderConstructorDepth.set(
                threadId,
                remaining
            );
        }
    }
}


// function get_package_name(): string {
//     let package_name = "";

//     safePerform("dex:get_package_name", () => {
//         // Get the Android application context
//         const ActivityThread = safeUse(
//             "android.app.ActivityThread",
//             "dex:get_package_name"
//         );
//         if (!ActivityThread) return;

//         // sometimes we are to early to get the context
//         const context = ActivityThread.currentApplication().getApplicationContext();
//         // Retrieve the package name
//         package_name = context.getPackageName();

//         // Log the package name
//         //console.log('Package Name:', package_name);
//     });

//     return package_name;
// }


/* Read a C++ std string (basic_string) to a nomal string */
function readStdString(ptr_str: NativePointer): string {
    const isTiny: boolean = (ptr_str.readU8() & 1) === 0;
    if (isTiny) {
        return ptr_str.add(1).readUtf8String();
    }
    return ptr_str.add(2 * Process.pointerSize).readPointer().readUtf8String();
}

// //@ts-ignore
// function getFunctionName(g_AndroidOSVersion: number): string {
//     let functionName = "";

//     // ApiResolver is the safe alternative to Process.getModuleByName(...).enumerateExports():
//     // it resolves the module + does the substring match in one call that returns [] (never
//     // throws) when the library or symbol is absent. Match names come back as "module!symbol",
//     // so stripModulePrefix keeps the bare symbol name that dumpDex re-resolves.

//     // Android 4: hook dexFileParse
//     // Android 5: hook OpenMemory
//     // after Android 5: hook OpenCommon (libdexfile.so on Android 10+, libart.so before)
//     if (g_AndroidOSVersion > 4) {
//         // OpenCommon is in libdexfile.so in android 10 and later
//         const soName: string = g_AndroidOSVersion >= 10 ? "libdexfile.so" : "libart.so";

//         const openMemory = safeEnumerateMatches(
//             `exports:${soName}!*OpenMemory*`,
//             "dex:getFunctionName"
//         );
//         if (openMemory.length > 0) {
//             functionName = stripModulePrefix(openMemory[0].name);
//         } else {
//             const openCommon = safeEnumerateMatches(
//                 `exports:${soName}!*OpenCommon*`,
//                 "dex:getFunctionName"
//             );
//             for (const match of openCommon) {
//                 if (g_AndroidOSVersion >= 10 && match.name.indexOf("ArtDexFileLoader") !== -1)
//                     continue;
//                 functionName = stripModulePrefix(match.name);
//                 break;
//             }
//         }
//     } else { //android 4
//         const dvm = safeEnumerateMatches(
//             "exports:libdvm.so!*dexFileParse*",
//             "dex:getFunctionName"
//         );
//         if (dvm.length > 0) {
//             functionName = stripModulePrefix(dvm[0].name);
//         } else {
//             // libdvm not present (or no match) - fall back to libart's OpenMemory
//             const art = safeEnumerateMatches(
//                 "exports:libart.so!*OpenMemory*",
//                 "dex:getFunctionName"
//             );
//             if (art.length > 0) {
//                 functionName = stripModulePrefix(art[0].name);
//             }
//         }
//     }

//     return functionName;
// }

// Select a native DEX-loading entry point and its ABI-specific buffer layout.
function getNativeDexHookTarget(
    androidVersion: number
): NativeDexHookTarget | null {
    if (androidVersion >= 10) {
        // Android 14+ routes DEX loading through the container overload,
        // where the DEX buffer and size follow two C++ object arguments.
        // Earlier Android 10+ runtimes use the direct buffer overload.
        const layouts = androidVersion >= 14
            ? [
                {
                    marker: "OpenCommonENSt3__110shared_ptr",
                    dataArgumentIndexes: [2],
                    sizeArgumentIndex: 3
                }
            ]
            : [
                {
                    marker: "OpenCommonEPKhm",
                    dataArgumentIndexes: [0, 1],
                    sizeArgumentIndex: null
                }
            ];

        for (const moduleName of ["libart.so", "libdexfile.so"]) {
            const matches = safeEnumerateMatches(
                `exports:${moduleName}!*OpenCommon*`,
                "dex:getNativeDexHookTarget"
            );

            for (const layout of layouts) {
                const match = matches.find(candidate => {
                    const symbolName = stripModulePrefix(candidate.name);

                    return (
                        !symbolName.includes("ArtDexFileLoader") &&
                        symbolName.includes(layout.marker)
                    );
                });

                if (match) {
                    return {
                        moduleName: moduleName,
                        symbolName: stripModulePrefix(match.name),
                        address: match.address,
                        dataArgumentIndexes: layout.dataArgumentIndexes,
                        sizeArgumentIndex: layout.sizeArgumentIndex
                    };
                }
            }
        }

        return null;
    }

    const moduleName = androidVersion > 4 ? "libart.so" : "libdvm.so";
    const query = androidVersion > 4
        ? `exports:${moduleName}!*OpenMemory*`
        : "exports:libdvm.so!*dexFileParse*";
    const matches = safeEnumerateMatches(
        query,
        "dex:getNativeDexHookTarget"
    );

    if (matches.length === 0) {
        return null;
    }

    return {
        moduleName: moduleName,
        symbolName: stripModulePrefix(matches[0].name),
        address: matches[0].address,
        dataArgumentIndexes: [0, 1],
        sizeArgumentIndex: null
    };
}

function getg_processName(): string {
    let g_processName: string = "";

    const fopenPtr  = safeResolveExport("libc.so", "fopen",  "dex:getg_processName");
    const fgetsPtr  = safeResolveExport("libc.so", "fgets",  "dex:getg_processName");
    const fclosePtr = safeResolveExport("libc.so", "fclose", "dex:getg_processName");

    const fopenFunc  = safeNativeFunction(fopenPtr,  "pointer", ["pointer", "pointer"],        "dex:fopen");
    const fgetsFunc  = safeNativeFunction(fgetsPtr,  "int",     ["pointer", "int", "pointer"], "dex:fgets");
    const fcloseFunc = safeNativeFunction(fclosePtr, "int",     ["pointer"],                   "dex:fclose");

    // If any libc symbol is missing the process name can't be read - bail cleanly.
    if (!fopenFunc || !fgetsFunc || !fcloseFunc) return g_processName;

    const pathPtr      = Memory.allocUtf8String("/proc/self/cmdline");
    const openFlagsPtr = Memory.allocUtf8String("r");

    const fp = fopenFunc(pathPtr, openFlagsPtr);
    if (!fp.isNull()) {
        const buffData = Memory.alloc(128);
        const ret = fgetsFunc(buffData, 128, fp);
        if (ret !== 0) {
            g_processName = buffData.readCString();
            //devlog("ProcessName: " + g_processName);
        }
        fcloseFunc(fp);
    }

    return g_processName;
}


function checkMagic(dataAddr: NativePointer) { // Throws access violation errors, not handled at all.
    const dexMagic     = "dex\n"; // [0x64, 0x65, 0x78, 0x0a]
    const dexVersions  = ["035", "037", "038", "039", "040"]; // Same as above (hex -> ascii)
    const odexVersions = ["036"];
    const kDexMagic    = "cdex"; // [0x63, 0x64, 0x65, 0x78]
    const kDexVersions = ["001"];
    const magicTrailing = 0x00;

    let readData: ArrayBuffer | null;
    try {
        readData = dataAddr.readByteArray(8);
    } catch (e) {
        devlog("[DEX] Error reading memory at address " + dataAddr);
        return { found: false, wrongMagic: 0xDEADBEEF };
    }

    const magic            = Array.from(new Uint8Array(readData));
    const foundStart       = magic.slice(0, 4).map(i => String.fromCharCode(i)).join("");
    const foundVersion     = magic.slice(4, 7).map(i => String.fromCharCode(i)).join("");
    const foundMagicString = foundStart.replace("\n", "") + foundVersion; // Printable string

    if (foundStart === dexMagic && dexVersions.includes(foundVersion) && magic[7] === magicTrailing) {
        // Found a dex
        return { found: true, ext: "dex",  sizeOffset: 0x20, magicString: foundMagicString };
    } else if (foundStart === dexMagic && odexVersions.includes(foundVersion) && magic[7] === magicTrailing) {
        // Found an odex (only version number differs, same magic)
        return { found: true, ext: "odex", sizeOffset: 0x1C, magicString: foundMagicString };
    } else if (foundStart === kDexMagic && kDexVersions.includes(foundVersion) && magic[7] === magicTrailing) {
        // Found a compact dex
        return { found: true, ext: "cdex", sizeOffset: 0x20, magicString: foundMagicString };
    } else {
        return { found: false, wrongMagic: magic };
    }
}

function dumpDexToFile(
    begin: NativePointer,
    dexInfo: any,
    processName: string,
    location: string,
    hookedFunction: string,
    context?: CpuContext
): void {
    const dexSize = begin.add(dexInfo.sizeOffset).readInt();
    const nativeBacktrace = collectNativeBacktrace(context);

    devlog(
        `[DEX] Detected ${dexInfo.ext} file: ${dexSize} bytes from ` +
        `${location || "unknown location"}`
    );

    let dumpedPath: string | null = null;
    let dumpError: string | null = null;
    const attemptedPath =
        processName.length > 0
            ? `/data/data/${processName}/${dexSize}.${dexInfo.ext}`
            : null;

    if (attemptedPath !== null) {
        try {
            const dexBuffer = begin.readByteArray(dexSize);

            if (dexBuffer === null) {
                throw new Error("Unable to read DEX buffer");
            }

            const dexFile = new File(attemptedPath, "wb");
            dexFile.write(dexBuffer);
            dexFile.flush();
            dexFile.close();

            dumpedPath = attemptedPath;

            devlog(`[DEX] File written successfully: ${dumpedPath}`);
        } catch (error) {
            dumpError = error instanceof Error
                ? error.message
                : String(error);

            devlog(
                `[DEX] Unable to write local DEX copy at ${attemptedPath}: ` +
                `${dumpError}`
            );
        }
    }

    createDEXEvent("dex.unpacking.detected", {
        hooked_function: hookedFunction,
        magic: dexInfo.magicString,
        version: dexInfo.version,
        size: dexSize,
        original_location: location,
        file_type: dexInfo.ext,
        ...(dumpedPath !== null ? { dumped_path: dumpedPath } : {}),
        ...(attemptedPath !== null
            ? { dump_attempted_path: attemptedPath }
            : {}),
        ...(dumpError !== null ? { dump_error: dumpError } : {}),
        ...(nativeBacktrace ? { native_backtrace: nativeBacktrace } : {})
    });

    devlog(
        `[DEX] Unpacking event sent for ${dexInfo.magicString} ` +
        `(${dexSize} bytes)`
    );
}


function dumpDex(
    target: NativeDexHookTarget,
    processName: string
): void {
    const hookedFunction =
        `${target.moduleName}::${target.symbolName}`;

    safeAttach(target.address, `dex:${target.symbolName}`, {
        onEnter: function (args: NativePointer[]) {
            let begin: NativePointer | null = null;
            let dexInfo: any = null;

            for (const argumentIndex of target.dataArgumentIndexes) {
                const candidate = args[argumentIndex];
                const candidateInfo = checkMagic(candidate);

                if (candidateInfo.found) {
                    begin = candidate;
                    dexInfo = candidateInfo;
                    break;
                }
            }

            // OpenCommon can receive non-DEX inputs during normal ART startup.
            // Ignore unmatched invocations without producing hook errors.
            if (begin === null || dexInfo === null) {
                return;
            }

            if (target.sizeArgumentIndex !== null) {
                try {
                    const suppliedSize = args[
                        target.sizeArgumentIndex
                    ].toUInt32();

                    if (suppliedSize > 0) {
                        dexInfo.suppliedSize = suppliedSize;
                    }
                } catch {
                    // The DEX header remains the authoritative size source.
                }
            }

            let location: string | null = null;

            for (let index = 0; index < 10; index++) {
                try {
                    location = readStdString(args[index]);
                } catch {
                    continue;
                }

                if (
                    location !== null &&
                    location.length > 0 &&
                    location.includes("/")
                ) {
                    break;
                }
            }

            dumpDexToFile(
                begin,
                dexInfo,
                processName,
                location || "",
                hookedFunction,
                this.context
            );
        }
    });

    devlog(
        `[DEX] Interceptor attached to ${hookedFunction} at ` +
        `${target.address}`
    );
}

function dump(file_path: string, dst_path: string): void {
    const location = removeLeadingColon(file_path);
    const java_stack_trace = collectJavaStackTrace();
    createDEXEvent("dex.file_copy", {
        original_location: location,
        destination_path: dst_path,
        ...(java_stack_trace ? { java_stack_trace } : {})
    });
    copy_file(PROFILE_HOOKING_TYPE, location, dst_path);
}

interface InMemoryDexBufferSummary {
    size: number;
    magic: string | null;
}

function inspectInMemoryDexBuffer(
    buffer: any,
    getByte: any
): InMemoryDexBufferSummary {
    const size = buffer.remaining();
    const duplicate = buffer.duplicate();
    const previewLength = Math.min(8, duplicate.remaining());
    const bytes: number[] = [];

    for (let index = 0; index < previewLength; index++) {
        bytes.push(Number(getByte.call(duplicate)) & 0xff);
    }

    if (bytes.length < 8) {
        return {
            size: size,
            magic: null
        };
    }

    const start = String.fromCharCode(
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3]
    );
    const version = String.fromCharCode(
        bytes[4],
        bytes[5],
        bytes[6]
    );
    const hasDexMagic =
        (start === "dex\n" || start === "cdex") &&
        bytes[7] === 0;

    return {
        size: size,
        magic: hasDexMagic
            ? start.replace("\n", "") + version
            : null
    };
}

function emitInMemoryDexLoaderEvent(
    method: string,
    summaries: InMemoryDexBufferSummary[],
    javaStackTrace: string[] | null
): void {
    const bufferSizes = summaries.map(summary => summary.size);
    const event: any = {
        class_loader_type: "InMemoryDexClassLoader",
        method: method,
        buffer_count: summaries.length,
        buffer_sizes: bufferSizes,
        total_buffer_size: bufferSizes.reduce(
            (total, size) => total + size,
            0
        ),
        buffer_magics: summaries.map(summary => summary.magic),
        ...(javaStackTrace
            ? { java_stack_trace: javaStackTrace }
            : {})
    };

    if (summaries.length === 1) {
        event.buffer_size = summaries[0].size;
        event.magic = summaries[0].magic;
    }

    createDEXEvent("dex.in_memory_loader", event);
}

function dex_api_unpacking(g_processName: string): void {
    safePerform("dex:dex_api_unpacking", () => {
        const dst_path = `/data/data/${g_processName}`;

        // Hook DexClassLoader
        const DexClassLoader = safeUse(
            "dalvik.system.DexClassLoader",
            "dex:dex_api_unpacking"
        );
        if (DexClassLoader) {
            // No overload selector - hooks the single canonical constructor.
            const dexInit = DexClassLoader.$init;
            if (dexInit) {
                dexInit.implementation = safeImplementation(
                    "dex:DexClassLoader.$init",
                    dexInit,
                    function (original, filepath: string, b: any, c: any, d: any) {
                        const java_stack_trace = collectJavaStackTrace();
                        createDEXEvent("dex.classloader.creation", {
                            class_loader_type: "DexClassLoader",
                            file_path: filepath,
                            method: "$init(String, String, String, ClassLoader)",
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        dump(filepath, dst_path);
                        return callJavaOriginal(original, this, filepath, b, c, d);
                    }
                );
            }
        }

        // Hook PathClassLoader
        const PathClassLoader = safeUse(
            "dalvik.system.PathClassLoader",
            "dex:dex_api_unpacking"
        );
        if (PathClassLoader) {
            const pathInit2 = safeOverload(
                PathClassLoader.$init,
                "dex:PathClassLoader.$init",
                "java.lang.String", "java.lang.ClassLoader"
            );
            if (pathInit2) {
                pathInit2.implementation = safeImplementation(
                    "dex:PathClassLoader.$init(String,ClassLoader)",
                    pathInit2,
                    function (original, file_path: string, parent: any) {
                        return invokeClassLoaderConstructor(
                            original,
                            this,
                            [file_path, parent],
                            {
                                class_loader_type: "PathClassLoader",
                                file_path: file_path,
                                method: "$init(String, ClassLoader)"
                            },
                            dst_path
                        );
                    }
                );
            }

            const pathInit3 = safeOverload(
                PathClassLoader.$init,
                "dex:PathClassLoader.$init",
                "java.lang.String", "java.lang.String", "java.lang.ClassLoader"
            );
            if (pathInit3) {
                pathInit3.implementation = safeImplementation(
                    "dex:PathClassLoader.$init(String,String,ClassLoader)",
                    pathInit3,
                    function (original, file_path: string, librarySearchPath: string, parent: any) {
                        return invokeClassLoaderConstructor(
                            original,
                            this,
                            [file_path, librarySearchPath, parent],
                            {
                                class_loader_type: "PathClassLoader",
                                file_path: file_path,
                                library_search_path: librarySearchPath,
                                method: "$init(String, String, ClassLoader)"
                            },
                            dst_path
                        );
                    }
                );
            }
        }

        // Hook DelegateLastClassLoader
        const DelegateLastClassLoader = safeUse(
            "dalvik.system.DelegateLastClassLoader",
            "dex:dex_api_unpacking"
        );
        if (DelegateLastClassLoader) {
            const delegateInit2 = safeOverload(
                DelegateLastClassLoader.$init,
                "dex:DelegateLastClassLoader.$init",
                "java.lang.String", "java.lang.ClassLoader"
            );
            if (delegateInit2) {
                delegateInit2.implementation = safeImplementation(
                    "dex:DelegateLastClassLoader.$init(String,ClassLoader)",
                    delegateInit2,
                    function (original, file_path: string, parent: any) {
                        return invokeClassLoaderConstructor(
                            original,
                            this,
                            [file_path, parent],
                            {
                                class_loader_type: "DelegateLastClassLoader",
                                file_path: file_path,
                                method: "$init(String, ClassLoader)"
                            },
                            dst_path
                        );
                    }
                );
            }

            const delegateInit3 = safeOverload(
                DelegateLastClassLoader.$init,
                "dex:DelegateLastClassLoader.$init",
                "java.lang.String", "java.lang.String", "java.lang.ClassLoader"
            );
            if (delegateInit3) {
                delegateInit3.implementation = safeImplementation(
                    "dex:DelegateLastClassLoader.$init(String,String,ClassLoader)",
                    delegateInit3,
                    function (original, file_path: string, librarySearchPath: string, parent: any) {
                        return invokeClassLoaderConstructor(
                            original,
                            this,
                            [file_path, librarySearchPath, parent],
                            {
                                class_loader_type: "DelegateLastClassLoader",
                                file_path: file_path,
                                library_search_path: librarySearchPath,
                                method: "$init(String, String, ClassLoader)"
                            },
                            dst_path
                        );
                    }
                );
            }

            // API 29+ (Android 10): boolean resourceLoading overload
            const BuildVersion = safeUse("android.os.Build$VERSION", "dex:dex_api_unpacking");
            if (BuildVersion && BuildVersion.SDK_INT.value > 28) {
                const delegateInit4 = safeOverload(
                    DelegateLastClassLoader.$init,
                    "dex:DelegateLastClassLoader.$init",
                    "java.lang.String", "java.lang.String",
                    "java.lang.ClassLoader", "boolean"
                );
                if (delegateInit4) {
                    delegateInit4.implementation = safeImplementation(
                        "dex:DelegateLastClassLoader.$init(String,String,ClassLoader,boolean)",
                        delegateInit4,
                        function (
                            original,
                            file_path: string,
                            librarySearchPath: string,
                            parent: any,
                            resourceLoading: boolean
                        ) {
                            return invokeClassLoaderConstructor(
                                original,
                                this,
                                [
                                    file_path,
                                    librarySearchPath,
                                    parent,
                                    resourceLoading
                                ],
                                {
                                    class_loader_type:
                                        "DelegateLastClassLoader",
                                    file_path: file_path,
                                    library_search_path:
                                        librarySearchPath,
                                    resource_loading: resourceLoading,
                                    method:
                                        "$init(String, String, ClassLoader, boolean)"
                                },
                                dst_path
                            );
                        }
                    );
                }
            }
        }

        // Hook InMemoryDexClassLoader constructors available from API 26.
        const InMemoryDexClassLoader = safeUse(
            "dalvik.system.InMemoryDexClassLoader",
            "dex:dex_api_unpacking"
        );
        const ByteBuffer = safeUse(
            "java.nio.ByteBuffer",
            "dex:dex_api_unpacking"
        );

        if (InMemoryDexClassLoader && ByteBuffer) {
            const getByte = safeOverload(
                ByteBuffer.get,
                "dex:ByteBuffer.get"
            );

            const memInit = safeOverload(
                InMemoryDexClassLoader.$init,
                "dex:InMemoryDexClassLoader.$init",
                "java.nio.ByteBuffer",
                "java.lang.ClassLoader"
            );

            if (memInit && getByte) {
                memInit.implementation = safeImplementation(
                    "dex:InMemoryDexClassLoader.$init(ByteBuffer,ClassLoader)",
                    memInit,
                    function (original, dexBuffer: any, loader: any) {
                        const threadId = Process.getCurrentThreadId();
                        const depth =
                            activeInMemoryDexLoaderDepth.get(threadId) || 0;
                        const isOutermost = depth === 0;

                        activeInMemoryDexLoaderDepth.set(
                            threadId,
                            depth + 1
                        );

                        try {
                            if (isOutermost) {
                                const javaStackTrace =
                                    collectJavaStackTrace();

                                emitInMemoryDexLoaderEvent(
                                    "$init(ByteBuffer, ClassLoader)",
                                    [
                                        inspectInMemoryDexBuffer(
                                            dexBuffer,
                                            getByte
                                        )
                                    ],
                                    javaStackTrace
                                );
                            }

                            return callJavaOriginal(
                                original,
                                this,
                                dexBuffer,
                                loader
                            );
                        } finally {
                            const remaining =
                                activeInMemoryDexLoaderDepth.get(threadId)! - 1;

                            if (remaining <= 0) {
                                activeInMemoryDexLoaderDepth.delete(threadId);
                            } else {
                                activeInMemoryDexLoaderDepth.set(
                                    threadId,
                                    remaining
                                );
                            }
                        }
                    }
                );
            }

            const memInitMulti = safeOverload(
                InMemoryDexClassLoader.$init,
                "dex:InMemoryDexClassLoader.$init",
                "[Ljava.nio.ByteBuffer;",
                "java.lang.ClassLoader"
            );

            if (memInitMulti && getByte) {
                memInitMulti.implementation = safeImplementation(
                    "dex:InMemoryDexClassLoader.$init(ByteBuffer[],ClassLoader)",
                    memInitMulti,
                    function (original, dexBuffers: any, loader: any) {
                        const threadId = Process.getCurrentThreadId();
                        const depth =
                            activeInMemoryDexLoaderDepth.get(threadId) || 0;
                        const isOutermost = depth === 0;

                        activeInMemoryDexLoaderDepth.set(
                            threadId,
                            depth + 1
                        );

                        try {
                            if (isOutermost) {
                                const summaries: InMemoryDexBufferSummary[] =
                                    [];

                                for (
                                    let index = 0;
                                    index < dexBuffers.length;
                                    index++
                                ) {
                                    summaries.push(
                                        inspectInMemoryDexBuffer(
                                            dexBuffers[index],
                                            getByte
                                        )
                                    );
                                }

                                const javaStackTrace =
                                    collectJavaStackTrace();

                                emitInMemoryDexLoaderEvent(
                                    "$init(ByteBuffer[], ClassLoader)",
                                    summaries,
                                    javaStackTrace
                                );
                            }

                            return callJavaOriginal(
                                original,
                                this,
                                dexBuffers,
                                loader
                            );
                        } finally {
                            const remaining =
                                activeInMemoryDexLoaderDepth.get(threadId)! - 1;

                            if (remaining <= 0) {
                                activeInMemoryDexLoaderDepth.delete(threadId);
                            } else {
                                activeInMemoryDexLoaderDepth.set(
                                    threadId,
                                    remaining
                                );
                            }
                        }
                    }
                );
            }
        }
    });
}


function install_dex_memory_hooks(): void {
    devlog("Installing DEX memory-based unpacking hooks");

    const androidVersion: number = getAndroidVersion();
    devlog(`[DEX] Android version: ${androidVersion}`);

    const target = getNativeDexHookTarget(androidVersion);

    devlog(
        `[DEX] Target function: ` +
        `${target
            ? `${target.moduleName}::${target.symbolName}`
            : "NOT FOUND"}`
    );

    const processName: string = getg_processName();
    devlog(`[DEX] Process name: ${processName || "NOT FOUND"}`);

    if (target !== null && processName !== "") {
        dumpDex(target, processName);
        devlog("[DEX] Memory hooks successfully installed");
    } else {
        devlog(
            "[DEX] ERROR: Failed to install memory hooks - " +
            "missing target or process name"
        );
    }
}

function install_dex_classloader_hooks(): void {
    devlog("Installing DEX class loader hooks");

    const g_processName: string = getg_processName();
    devlog(`[DEX] Process name for classloader hooks: ${g_processName || "NOT FOUND"}`);

    if (g_processName !== "") {
        dex_api_unpacking(g_processName);
        devlog("[DEX] ClassLoader hooks successfully installed");
    } else {
        devlog("[DEX] ERROR: Failed to install classloader hooks - no process name");
    }
}


function advanced_unpacking_procedure(){
// only relevant after we see the results of the testing
//for instance how to do unpacking if certain methods will be noped till a certain point of time
// s. https://github.com/CodingGay/BlackDex/blob/main/README_EN.md
// we could further add this https://github.com/Ch0pin/medusa/blob/master/modules/memory_dump/dump_jiagu.med
}




export function install_dex_unpacking_hooks(): void {
    devlog("\n");
    devlog("Installing DEX unpacking hooks");

    try {
        install_dex_memory_hooks();
    } catch (error) {
        devlog(`[HOOK] Failed to install DEX memory hooks: ${error}`);
    }

    try {
        install_dex_classloader_hooks();
    } catch (error) {
        devlog(`[HOOK] Failed to install DEX classloader hooks: ${error}`);
    }

    try {
        advanced_unpacking_procedure();
    } catch (error) {
        devlog(`[HOOK] Failed to install advanced unpacking hooks: ${error}`);
    }
}

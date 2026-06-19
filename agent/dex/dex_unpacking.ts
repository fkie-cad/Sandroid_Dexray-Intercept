import { devlog, am_send } from "../utils/logging.js"
import { getAndroidVersion, copy_file, removeLeadingColon } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"
import { safePerform, safeUse, safeOverload, safeImplementation } from "../utils/safe_java.js"
import { safeResolveExport, safeNativeFunction, safeAttach, safeEnumerateMatches, stripModulePrefix } from "../utils/safe_native.js"

const PROFILE_HOOKING_TYPE: string = "DEX_LOADING"

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

function createDEXEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
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


function get_package_name(): string {
    let package_name = "";

    safePerform("dex:get_package_name", () => {
        // Get the Android application context
        const ActivityThread = safeUse(
            "android.app.ActivityThread",
            "dex:get_package_name"
        );
        if (!ActivityThread) return;

        // sometimes we are to early to get the context
        const context = ActivityThread.currentApplication().getApplicationContext();
        // Retrieve the package name
        package_name = context.getPackageName();

        // Log the package name
        //console.log('Package Name:', package_name);
    });

    return package_name;
}


/* Read a C++ std string (basic_string) to a nomal string */
function readStdString(ptr_str: NativePointer): string {
    const isTiny: boolean = (ptr_str.readU8() & 1) === 0;
    if (isTiny) {
        return ptr_str.add(1).readUtf8String();
    }
    return ptr_str.add(2 * Process.pointerSize).readPointer().readUtf8String();
}

//@ts-ignore
function getFunctionName(g_AndroidOSVersion: number): string {
    let functionName = "";

    // ApiResolver is the safe alternative to Process.getModuleByName(...).enumerateExports():
    // it resolves the module + does the substring match in one call that returns [] (never
    // throws) when the library or symbol is absent. Match names come back as "module!symbol",
    // so stripModulePrefix keeps the bare symbol name that dumpDex re-resolves.

    // Android 4: hook dexFileParse
    // Android 5: hook OpenMemory
    // after Android 5: hook OpenCommon (libdexfile.so on Android 10+, libart.so before)
    if (g_AndroidOSVersion > 4) {
        // OpenCommon is in libdexfile.so in android 10 and later
        const soName: string = g_AndroidOSVersion >= 10 ? "libdexfile.so" : "libart.so";

        const openMemory = safeEnumerateMatches(
            `exports:${soName}!*OpenMemory*`,
            "dex:getFunctionName"
        );
        if (openMemory.length > 0) {
            functionName = stripModulePrefix(openMemory[0].name);
        } else {
            const openCommon = safeEnumerateMatches(
                `exports:${soName}!*OpenCommon*`,
                "dex:getFunctionName"
            );
            for (const match of openCommon) {
                if (g_AndroidOSVersion >= 10 && match.name.indexOf("ArtDexFileLoader") !== -1)
                    continue;
                functionName = stripModulePrefix(match.name);
                break;
            }
        }
    } else { //android 4
        const dvm = safeEnumerateMatches(
            "exports:libdvm.so!*dexFileParse*",
            "dex:getFunctionName"
        );
        if (dvm.length > 0) {
            functionName = stripModulePrefix(dvm[0].name);
        } else {
            // libdvm not present (or no match) - fall back to libart's OpenMemory
            const art = safeEnumerateMatches(
                "exports:libart.so!*OpenMemory*",
                "dex:getFunctionName"
            );
            if (art.length > 0) {
                functionName = stripModulePrefix(art[0].name);
            }
        }
    }

    return functionName;
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
    hooked_fct: string
): void {
    const dexSize = begin.add(dexInfo.sizeOffset).readInt();

    devlog(`[DEX] Dumping ${dexInfo.ext} file: ${dexSize} bytes from ${location || "unknown location"}`);

    let dexPath = `/data/data/${processName}/${dexSize}.${dexInfo.ext}`;
    let dexFile: File;

    try {
        dexFile = new File(dexPath, "wb");
        devlog(`[DEX] Created file: ${dexPath}`);
    } catch (e) {
        const g_package_name = get_package_name();
        dexPath = `/data/data/${g_package_name}/${dexSize}.${dexInfo.ext}`;

        devlog(`[DEX] Retry with package name: ${g_package_name}, path: ${dexPath}`);

        // Log file creation attempt
        if (g_package_name.length > 4) {
            createDEXEvent("dex.unpacking.file_creation", {
                attempted_path: dexPath,
                package_name: g_package_name
            });
        }
        dexFile = new File(dexPath, "wb");
    }

    const dexBuffer = begin.readByteArray(dexSize);
    if (dexBuffer) {
        dexFile.write(dexBuffer);
    }
    dexFile.flush();
    dexFile.close();

    devlog(`[DEX] File written successfully: ${dexPath}`);

    // Send structured unpacking event
    createDEXEvent("dex.unpacking.detected", {
        hooked_function: hooked_fct,
        magic: dexInfo.magicString,
        version: dexInfo.version,
        size: dexSize,
        original_location: location,
        dumped_path: dexPath,
        file_type: dexInfo.ext
    });

    devlog(`[DEX] Unpacking event sent for ${dexInfo.magicString} (${dexSize} bytes)`);
}

function dumpDex(moduleFuncName: string, g_processName: string, g_AndroidOSVersion: number): void {
    let wrongMagic0: any;

    if (moduleFuncName === "") {
        devlog("[DEX] Error: cannot find correct module function.");
        return;
    }

    let hookFunction: NativePointer | null;
    let hooked_fct: string;

    if (g_AndroidOSVersion > 4) {
        hookFunction = safeResolveExport("libart.so", moduleFuncName, "dex:dumpDex");
        hooked_fct   = `Libart.so::${moduleFuncName}`;
    } else {
        hookFunction = safeResolveExport("libdvm.so", moduleFuncName, "dex:dumpDex");
        if (hookFunction === null) {
            hookFunction = safeResolveExport("libart.so", moduleFuncName, "dex:dumpDex");
            //dem = demangleAndExtractFunctionName("libart",moduleFuncName)
            hooked_fct   = `Libart.so::${moduleFuncName}`;
        } else {
            hooked_fct = `Libdvm.so::${moduleFuncName}`;
        }
    }

    safeAttach(hookFunction, `dex:${moduleFuncName}`, {
        onEnter: function (args: NativePointer[]) {
            let begin: NativePointer;
            let dexInfo: any;
            let location: string | null = null;

            dexInfo = checkMagic(args[0]);
            begin   = args[0];

            if (!dexInfo.found) {
                wrongMagic0 = dexInfo.wrongMagic;
                dexInfo     = checkMagic(args[1]);
                begin       = args[1];
            }

            if (!dexInfo.found) {
                throw new Error(
                    "Could not identify magic, found invalid values " +
                    wrongMagic0.map((i: number) => i.toString(16).padStart(2, "0")).join("") +
                    " " +
                    dexInfo.wrongMagic.map((i: number) => i.toString(16).padStart(2, "0")).join("")
                );
            }

            // Try all parameters
            for (let i = 0; i < 10; i++) {
                try {
                    location = readStdString(args[i]);
                } catch {} // Illegal memory access
                if (location != null && location.length > 0 && location.includes("/")) {
                    // != null catches both undefined and null
                    break;
                }
            }

            dumpDexToFile(begin, dexInfo, g_processName, location, hooked_fct);
        }
    });

    devlog(`[DEX] Interceptor attached to ${hooked_fct} at ${hookFunction}`);
}

function dump(file_path: string, dst_path: string): void {
    const location = removeLeadingColon(file_path);
    createDEXEvent("dex.file_copy", {
        original_location: location,
        destination_path: dst_path
    });
    copy_file(PROFILE_HOOKING_TYPE, location, dst_path);
}

function dex_api_unpacking(g_processName: string): void {
    safePerform("dex:dex_api_unpacking", () => {
        const filename = `/data/data/${g_processName}/dump.dex`;
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
                        createDEXEvent("dex.classloader.creation", {
                            class_loader_type: "DexClassLoader",
                            file_path: filepath,
                            method: "$init(String, String, String, ClassLoader)"
                        });
                        dump(filepath, dst_path);
                        return original.call(this, filepath, b, c, d);
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
                        createDEXEvent("dex.classloader.creation", {
                            class_loader_type: "PathClassLoader",
                            file_path: file_path,
                            method: "$init(String, ClassLoader)"
                        });
                        dump(file_path, dst_path);
                        return original.call(this, file_path, parent);
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
                        createDEXEvent("dex.classloader.creation", {
                            class_loader_type: "PathClassLoader",
                            file_path: file_path,
                            library_search_path: librarySearchPath,
                            method: "$init(String, String, ClassLoader)"
                        });
                        dump(file_path, dst_path);
                        return original.call(this, file_path, librarySearchPath, parent);
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
                        createDEXEvent("dex.classloader.creation", {
                            class_loader_type: "DelegateLastClassLoader",
                            file_path: file_path,
                            method: "$init(String, ClassLoader)"
                        });
                        dump(file_path, dst_path);
                        return original.call(this, file_path, parent);
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
                        createDEXEvent("dex.classloader.creation", {
                            class_loader_type: "DelegateLastClassLoader",
                            file_path: file_path,
                            library_search_path: librarySearchPath,
                            method: "$init(String, String, ClassLoader)"
                        });
                        dump(file_path, dst_path);
                        return original.call(this, file_path, librarySearchPath, parent);
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
                            createDEXEvent("dex.classloader.creation", {
                                class_loader_type: "DelegateLastClassLoader",
                                file_path: file_path,
                                library_search_path: librarySearchPath,
                                resource_loading: resourceLoading,
                                method: "$init(String, String, ClassLoader, boolean)"
                            });
                            dump(file_path, dst_path);
                            return original.call(this, file_path, librarySearchPath, parent, resourceLoading);
                        }
                    );
                }
            }
        }

        // Hook InMemoryDexClassLoader (API 26+)
        const InMemoryDexClassLoader = safeUse(
            "dalvik.system.InMemoryDexClassLoader",
            "dex:dex_api_unpacking"
        );
        if (InMemoryDexClassLoader) {
            const memInit = safeOverload(
                InMemoryDexClassLoader.$init,
                "dex:InMemoryDexClassLoader.$init",
                "java.nio.ByteBuffer", "java.lang.ClassLoader"
            );
            if (memInit) {
                memInit.implementation = safeImplementation(
                    "dex:InMemoryDexClassLoader.$init(ByteBuffer,ClassLoader)",
                    memInit,
                    function (original, dexbuffer: any, loader: any) {
                        const remaining = dexbuffer.remaining();

                        createDEXEvent("dex.in_memory_loader", {
                            class_loader_type: "InMemoryDexClassLoader",
                            buffer_size: remaining,
                            method: "$init(ByteBuffer, ClassLoader)"
                        });

                        const object = original.call(this, dexbuffer, loader);

                        // Dump the ByteBuffer contents to file
                        createDEXEvent("dex.memory_dump", {
                            file_name: filename,
                            bytes_to_write: remaining
                        });

                        const f   = new File(filename, "wb");
                        const buf = new Uint8Array(remaining);
                        for (let i = 0; i < remaining; i++) {
                            buf[i] = dexbuffer.get();
                        }
                        f.write(Array.from(buf));
                        f.close();

                        // Check if dump was successful
                        const remainingAfter = dexbuffer.remaining();
                        if (remainingAfter > 0) {
                            createDEXEvent("dex.dump_error", {
                                remaining_bytes: remainingAfter,
                                file_name: filename
                            });
                        } else {
                            createDEXEvent("dex.dump_success", {
                                file_name: filename,
                                bytes_written: remaining
                            });
                        }

                        return object;
                    }
                );
            }
        }
    });
}


function install_dex_memory_hooks(): void {
    devlog("Installing DEX memory-based unpacking hooks");

    const g_AndroidOSVersion: number = getAndroidVersion();
    devlog(`[DEX] Android version: ${g_AndroidOSVersion}`);

    const g_moduleFunctionName: string = getFunctionName(g_AndroidOSVersion);
    devlog(`[DEX] Target function name: ${g_moduleFunctionName || "NOT FOUND"}`);

    const g_processName: string = getg_processName();
    devlog(`[DEX] Process name: ${g_processName || "NOT FOUND"}`);

    if (g_moduleFunctionName !== "" && g_processName !== "") {
        dumpDex(g_moduleFunctionName, g_processName, g_AndroidOSVersion);
        dex_api_unpacking(g_processName);
        devlog("[DEX] Memory hooks successfully installed");
    } else {
        devlog(`[DEX] ERROR: Failed to install memory hooks - missing function name or process name`);
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

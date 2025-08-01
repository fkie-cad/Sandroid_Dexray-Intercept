import { am_send, log, devlog } from "../utils/logging.js"
import { getAndroidVersion, arraybuffer2hexstr, copy_file, removeLeadingColon } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"

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


 function get_package_name() : string {
  var package_name = "";

  Java.perform(function () {
    // Get the Android application context
    try {
      var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
      // Retrieve the package name
      var packageName = context.getPackageName();
      package_name = packageName;
    }catch(e){} // sometimes we are to early to get the context

    // Log the package name
    //console.log('Package Name:', packageName);
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
function getFunctionName(g_AndroidOSVersion) : string{
    var i = 0;
    var functionName = "";

    // Android 4: hook dvmDexFileOpenPartial
    // Android 5: hook OpenMemory
    // after Android 5: hook OpenCommon
    if (g_AndroidOSVersion > 4){ // android 5 and later version
        // OpenCommon is in libdexfile.so in android 10 and later
        const soName : string = g_AndroidOSVersion >= 10 ? "libdexfile.so" : "libart.so";
        const artModule = Process.getModuleByName(soName);
        var artExports = artModule.enumerateExports();
        for(i = 0; i< artExports.length; i++){
            if(artExports[i].name.indexOf("OpenMemory") !== -1){
                functionName = artExports[i].name;
                //devlog("Export index: " + i + " -> "+ functionName);
                break;
            }else if(artExports[i].name.indexOf("OpenCommon") !== -1){
                if (g_AndroidOSVersion >= 10 && artExports[i].name.indexOf("ArtDexFileLoader") !== -1)
                    continue;
                functionName = artExports[i].name;
                //devlog("Export index: " + i + " -> "+ functionName);
                break;
            }
        }
    }else{ //android 4
        const dvmModule = Process.getModuleByName("libdvm.so");
        var dvmExports = dvmModule.enumerateExports();
        if (dvmExports.length !== 0) {
            for(i = 0; i< dvmExports.length; i++){
                if(dvmExports[i].name.indexOf("dexFileParse") !== -1){
                    functionName = dvmExports[i].name;
                    //devlog("Export index: " + i + " -> "+ functionName);
                    break;
                }
            }
        }else {
            const libartModule = Process.getModuleByName("libart.so");
            dvmExports = libartModule.enumerateExports();
            for(i = 0; i< dvmExports.length; i++){
                if(dvmExports[i].name.indexOf("OpenMemory") !== -1){
                    functionName = dvmExports[i].name;
                    //devlog("Export index: " + i + " -> "+ functionName);
                    break;
                }
            }
        }
    }
    return functionName;
}

function getg_processName() : string {
    let g_processName: string = "";

    const libcModule = Process.getModuleByName("libc.so");
    var fopenPtr = libcModule.findExportByName("fopen");
    var fgetsPtr = libcModule.findExportByName("fgets");
    var fclosePtr = libcModule.findExportByName("fclose");

    var fopenFunc = new NativeFunction(fopenPtr, 'pointer', ['pointer', 'pointer']);
    var fgetsFunc = new NativeFunction(fgetsPtr, 'int', ['pointer', 'int', 'pointer']);
    var fcloseFunc = new NativeFunction(fclosePtr, 'int', ['pointer']);

    var pathPtr = Memory.allocUtf8String("/proc/self/cmdline");
    var openFlagsPtr = Memory.allocUtf8String("r");

    var fp = fopenFunc(pathPtr, openFlagsPtr);
    if(fp.isNull() === false){
        var buffData = Memory.alloc(128);
        var ret = fgetsFunc(buffData, 128, fp);
        if(ret !== 0){
            g_processName = buffData.readCString();
            //devlog("ProcessName: " + g_processName);
        }
        fcloseFunc(fp);
    }
    return g_processName;
}




function checkMagic(dataAddr: NativePointer) { // Throws access violation errors, not handled at all.
    let dexMagic : string = 'dex\n'; // [0x64, 0x65, 0x78, 0x0a]
    let dexVersions = ['035', '037', '038', '039', '040']; // Same as above (hex -> ascii)
    let odexVersions = ['036'];
    let kDexMagic = 'cdex'; // [0x63, 0x64, 0x65, 0x78]
    let kDexVersions = ['001'];
    let magicTrailing = 0x00;

    let readData
    try {
        readData = dataAddr.readByteArray(8)
    } catch (e) {
        devlog('Error reading memory at address' + dataAddr);
        return {found: false, wrongMagic: 0xDEADBEEF};
    }
    let magic = Array.from( new Uint8Array( readData ) );

    let foundStart = magic.slice(0,4).map(i => String.fromCharCode(i)).join('');
    let foundVersion = magic.slice(4,7).map(i => String.fromCharCode(i)).join('');
    let foundMagicString = foundStart.replace('\n', '') + foundVersion; // Printable string

    if (foundStart === dexMagic && dexVersions.includes(foundVersion) && magic[7] === magicTrailing) {
        // Found a dex
        return {found: true, ext: 'dex', sizeOffset: 0x20, magicString: foundMagicString};
    } else if (foundStart === dexMagic && odexVersions.includes(foundVersion) && magic[7] === magicTrailing) {
        // Found an odex (only version number differs, same magic)
        return {found: true, ext: 'odex', sizeOffset: 0x1C, magicString: foundMagicString};
    } else if (foundStart === kDexMagic && kDexVersions.includes(foundVersion) && magic[7] === magicTrailing) {
        // Found a compact dex
        return {found: true, ext: 'cdex', sizeOffset: 0x20, magicString: foundMagicString};
    } else {
        return {found: false, wrongMagic: magic};
    }
}

function dumpDexToFile(begin: NativePointer, dexInfo: any, processName: string, location: string, hooked_fct: string): void {
    const dexSize = begin.add(dexInfo.sizeOffset).readInt();
    let dexPath = "/data/data/" + processName + "/" + dexSize + "." + dexInfo.ext;
    let dexFile: File;
    
    try {
        dexFile = new File(dexPath, "wb");
    } catch(e) {
        const g_package_name = get_package_name();
        dexPath = "/data/data/" + g_package_name + "/" + dexSize + "." + dexInfo.ext;
        
        // Log file creation attempt
        if(g_package_name.length > 4) {
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
}

function dumpDex(moduleFuncName, g_processName, g_AndroidOSVersion){
    let wrongMagic0;
    if (moduleFuncName == "") {
        devlog("Error: cannot find correct module function.");
        return;
    }

    var hookFunction;
    var hooked_fct;
    if (g_AndroidOSVersion > 4) {
        const libartModule = Process.getModuleByName("libart.so");
        hookFunction = libartModule.findExportByName(moduleFuncName);
            hooked_fct = "Libart.so::"+moduleFuncName;
    } else {
        const libdvmModule = Process.getModuleByName("libdvm.so");
        hookFunction = libdvmModule.findExportByName(moduleFuncName);
        if(hookFunction == null) {
            const libartModule = Process.getModuleByName("libart.so");
            hookFunction = libartModule.findExportByName(moduleFuncName);
            //dem = demangleAndExtractFunctionName("libart",moduleFuncName)
            hooked_fct = "Libart.so::"+moduleFuncName;
        }else{
            hooked_fct = "Libdvm.so::"+moduleFuncName;
        }
    }

    Interceptor.attach(hookFunction,{
        onEnter: function(args : NativePointer[]){
            let begin, dexInfo, location;

            dexInfo = checkMagic(args[0]);
            begin = args[0];
            if (!dexInfo.found) {
                wrongMagic0 = dexInfo.wrongMagic
                dexInfo = checkMagic(args[1]);
                begin = args[1];
            }
            if (!dexInfo.found) {
                throw new Error(
                    'Could not identify magic, found invalid values ' +
                    wrongMagic0.map(i => i.toString(16).padStart(2, '0')).join('') +
                    ' ' +
                    dexInfo.wrongMagic.map(i => i.toString(16).padStart(2, '0')).join('')
                )
            }

            for (let i = 0; i < 10; i++) {
            // Try all parameters
                try {
                    location = readStdString(args[i]);
                } catch {} // Illegal memory access
                if (location != null && location.length > 0 && location.includes('/')) {
                    // != null catches both undefined and null
                    break;
                }
            }

            dumpDexToFile(begin, dexInfo, g_processName, location, hooked_fct);
        },
    });
}




function install_dex_memory_hooks(): void {
    devlog("Installing DEX memory-based unpacking hooks");
    
    const g_AndroidOSVersion: number = getAndroidVersion();
    const g_moduleFunctionName: string = getFunctionName(g_AndroidOSVersion);
    const g_processName: string = getg_processName();

    if (g_moduleFunctionName !== "" && g_processName !== "") {
        dumpDex(g_moduleFunctionName, g_processName, g_AndroidOSVersion);
        dex_api_unpacking(g_processName);
    }
}

function install_dex_classloader_hooks(): void {
    devlog("Installing DEX class loader hooks");
    
    const g_processName: string = getg_processName();
    if (g_processName !== "") {
        dex_api_unpacking(g_processName);
    }
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
    Java.perform(() => {
        const filename = "/data/data/" + g_processName + "/dump.dex";
        const dst_path = "/data/data/" + g_processName;
        
        // Hook DexClassLoader
        const dexclassLoader = Java.use("dalvik.system.DexClassLoader");
        dexclassLoader.$init.implementation = function(filepath: string, b: any, c: any, d: any) {
            createDEXEvent("dex.classloader.creation", {
                class_loader_type: "DexClassLoader",
                file_path: filepath,
                method: "$init(String, String, String, ClassLoader)"
            });
            dump(filepath, dst_path);
            return this.$init(filepath, b, c, d);
        };

        // Hook PathClassLoader
        const pathLoader = Java.use('dalvik.system.PathClassLoader');    
        pathLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(file_path: string, parent: any) {
            createDEXEvent("dex.classloader.creation", {
                class_loader_type: "PathClassLoader",
                file_path: file_path,
                method: "$init(String, ClassLoader)"
            });
            dump(file_path, dst_path);
            return this.$init(file_path, parent);
        };
    
        pathLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function(file_path: string, librarySearchPath: string, parent: any) {
            createDEXEvent("dex.classloader.creation", {
                class_loader_type: "PathClassLoader",
                file_path: file_path,
                library_search_path: librarySearchPath,
                method: "$init(String, String, ClassLoader)"
            });
            dump(file_path, dst_path);
            return this.$init(file_path, librarySearchPath, parent);
        };

        // Hook DelegateLastClassLoader
        const delegateLoader = Java.use('dalvik.system.DelegateLastClassLoader');
        delegateLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(file_path: string, parent: any) {
            createDEXEvent("dex.classloader.creation", {
                class_loader_type: "DelegateLastClassLoader",
                file_path: file_path,
                method: "$init(String, ClassLoader)"
            });
            dump(file_path, dst_path);
            return this.$init(file_path, parent);
        };
    
        delegateLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function(file_path: string, librarySearchPath: string, parent: any) {
            createDEXEvent("dex.classloader.creation", {
                class_loader_type: "DelegateLastClassLoader",
                file_path: file_path,
                library_search_path: librarySearchPath,
                method: "$init(String, String, ClassLoader)"
            });
            dump(file_path, dst_path);
            return this.$init(file_path, librarySearchPath, parent);
        };
    
        if (Java.use('android.os.Build$VERSION').SDK_INT.value > 28) {
            delegateLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader', 'boolean').implementation = function(file_path: string, librarySearchPath: string, parent: any, resourceLoading: boolean) {
                createDEXEvent("dex.classloader.creation", {
                    class_loader_type: "DelegateLastClassLoader",
                    file_path: file_path,
                    library_search_path: librarySearchPath,
                    resource_loading: resourceLoading,
                    method: "$init(String, String, ClassLoader, boolean)"
                });
                dump(file_path, dst_path);
                return this.$init(file_path, librarySearchPath, parent, resourceLoading);
            };
        }


        // Hook InMemoryDexClassLoader
        const memoryclassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
        memoryclassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function(dexbuffer: any, loader: any) {
            const remaining = dexbuffer.remaining();
            
            createDEXEvent("dex.in_memory_loader", {
                class_loader_type: "InMemoryDexClassLoader",
                buffer_size: remaining,
                method: "$init(ByteBuffer, ClassLoader)"
            });

            const object = this.$init(dexbuffer, loader);

            // Dump the ByteBuffer contents to file
            createDEXEvent("dex.memory_dump", {
                file_name: filename,
                bytes_to_write: remaining
            });

            const f = new File(filename, 'wb');
            const buf = new Uint8Array(remaining);
            for (let i = 0; i < remaining; i++) {
                buf[i] = dexbuffer.get();
            }
            
            const numberArray = Array.from(buf);
            f.write(numberArray);
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
        };
    });
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
    
    install_dex_memory_hooks();
    install_dex_classloader_hooks();
    advanced_unpacking_procedure();
}

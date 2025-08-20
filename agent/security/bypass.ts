import { log, devlog, am_send } from "../utils/logging.js"
import { Where } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"

const PROFILE_HOOKING_TYPE: string = "BYPASS_DETECTION"

function createBypassEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

export function install_root_detection_bypass() {
    devlog("Installing root detection bypass hooks");
    
    Java.perform(() => {
        try {
            // Hook common root detection methods
            
            // 1. File.exists() - commonly used to check for su binary and root apps
            const File = Java.use("java.io.File");
            File.exists.implementation = function() {
                const path = this.getAbsolutePath();
                const result = this.exists();
                
                // Common root detection paths
                const rootPaths = [
                    "/system/bin/su", "/system/xbin/su", "/sbin/su",
                    "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
                    "/data/data/com.noshufou.android.su",
                    "/data/data/com.koushikdutta.superuser",
                    "/data/data/eu.chainfire.supersu",
                    "/system/xbin/busybox", "/system/bin/busybox",
                    "/system/app/RootCloak.apk",
                    "/dev/com.koushikdutta.superuser.daemon/"
                ];
                
                if (rootPaths.some(rootPath => path.includes(rootPath))) {
                    createBypassEvent("bypass.root.file_check", {
                        file_path: path,
                        original_result: result,
                        bypassed_result: false,
                        detection_method: "File.exists()"
                    });
                    return false; // Bypass by returning false
                }
                
                return result;
            };
            
            // 2. Runtime.exec() - used to execute shell commands for root detection
            const Runtime = Java.use("java.lang.Runtime");
            Runtime.exec.overload("java.lang.String").implementation = function(command) {
                const rootCommands = ["su", "which su", "busybox", "id"];
                
                if (rootCommands.some(cmd => command.includes(cmd))) {
                    createBypassEvent("bypass.root.command_execution", {
                        command: command,
                        detection_method: "Runtime.exec()",
                        action: "blocked"
                    });
                    
                    // Return a fake process that indicates command not found
                    return this.exec("echo 'command not found'");
                }
                
                return this.exec(command);
            };
            
            Runtime.exec.overload("[Ljava.lang.String;").implementation = function(commands) {
                const commandStr = commands.join(" ");
                const rootCommands = ["su", "which", "busybox", "id"];
                
                if (rootCommands.some(cmd => commandStr.includes(cmd))) {
                    createBypassEvent("bypass.root.command_execution", {
                        command: commandStr,
                        detection_method: "Runtime.exec(String[])",
                        action: "blocked"
                    });
                    
                    return this.exec(["echo", "command not found"]);
                }
                
                return this.exec(commands);
            };
            
            // 3. Build properties check
            const Build = Java.use("android.os.Build");
            const originalTags = Build.TAGS.value;
            
            // Hook field access if TAGS contains "test-keys"
            if (originalTags && originalTags.includes("test-keys")) {
                Build.TAGS.value = "release-keys";
                createBypassEvent("bypass.root.build_tags", {
                    original_tags: originalTags,
                    bypassed_tags: "release-keys",
                    detection_method: "Build.TAGS"
                });
            }
            
            // 4. PackageManager - check for root apps
            const PackageManager = Java.use("android.content.pm.PackageManager");
            PackageManager.getInstalledPackages.overload("int").implementation = function(flags) {
                const packages = this.getInstalledPackages(flags);
                const rootApps = [
                    "com.noshufou.android.su", "com.koushikdutta.superuser",
                    "eu.chainfire.supersu", "com.saurik.substrate",
                    "com.zachspong.temprootremovejb", "com.ramdroid.appquarantine",
                    "com.topjohnwu.magisk", "com.kingroot.kinguser"
                ];
                
                const filteredPackages = Java.cast(packages, Java.use("java.util.List"));
                for (let i = filteredPackages.size() - 1; i >= 0; i--) {
                    const packageInfo = filteredPackages.get(i);
                    const packageName = packageInfo.packageName.value;
                    
                    if (rootApps.includes(packageName)) {
                        createBypassEvent("bypass.root.package_check", {
                            package_name: packageName,
                            detection_method: "PackageManager.getInstalledPackages()",
                            action: "removed_from_list"
                        });
                        filteredPackages.remove(i);
                    }
                }
                
                return filteredPackages;
            };
            
        } catch (error) {
            devlog(`[BYPASS] Error installing root detection bypass: ${error}`);
        }
    });
}

export function install_frida_detection_bypass() {
    devlog("Installing Frida detection bypass hooks");
    
    Java.perform(() => {
        try {
            // 1. File existence checks for frida-server and related files
            const File = Java.use("java.io.File");
            const originalExists = File.exists;
            File.exists.implementation = function() {
                const path = this.getAbsolutePath();
                const result = originalExists.call(this);
                
                const fridaPaths = [
                    "/data/local/tmp/frida-server",
                    "/data/local/tmp/re.frida.server",
                    "/system/lib/libfrida-gadget.so",
                    "/system/lib64/libfrida-gadget.so"
                ];
                
                if (fridaPaths.some(fridaPath => path.includes(fridaPath))) {
                    createBypassEvent("bypass.frida.file_check", {
                        file_path: path,
                        original_result: result,
                        bypassed_result: false,
                        detection_method: "File.exists()"
                    });
                    return false;
                }
                
                return result;
            };
            
            // 2. Port scanning for default Frida port (27042)
            const Socket = Java.use("java.net.Socket");
            Socket.$init.overload("java.lang.String", "int").implementation = function(host, port) {
                if (port === 27042) {
                    createBypassEvent("bypass.frida.port_check", {
                        host: host,
                        port: port,
                        detection_method: "Socket connection",
                        action: "connection_refused"
                    });
                    throw Java.use("java.net.ConnectException").$new("Connection refused");
                }
                return this.$init(host, port);
            };
            
            // 3. Process name checks
            const ActivityManager = Java.use("android.app.ActivityManager");
            ActivityManager.getRunningAppProcesses.implementation = function() {
                const processes = this.getRunningAppProcesses();
                
                if (processes) {
                    const processArray = Java.cast(processes, Java.use("java.util.ArrayList"));
                    for (let i = processArray.size() - 1; i >= 0; i--) {
                        const process = processArray.get(i);
                        const processName = process.processName.value;
                        
                        if (processName.includes("frida") || processName.includes("gum") || 
                            processName.includes("gmain") || processName.includes("pool-frida")) {
                            createBypassEvent("bypass.frida.process_check", {
                                process_name: processName,
                                detection_method: "ActivityManager.getRunningAppProcesses()",
                                action: "removed_from_list"
                            });
                            processArray.remove(i);
                        }
                    }
                }
                
                return processes;
            };
            
            // 4. Thread name checks
            const Thread = Java.use("java.lang.Thread");
            Thread.getName.implementation = function() {
                const name = this.getName();
                
                if (name && (name.includes("frida") || name.includes("gum") || name.includes("pool-frida"))) {
                    createBypassEvent("bypass.frida.thread_check", {
                        original_name: name,
                        bypassed_name: "main",
                        detection_method: "Thread.getName()"
                    });
                    return "main";
                }
                
                return name;
            };
            
        } catch (error) {
            devlog(`[BYPASS] Error installing Frida detection bypass: ${error}`);
        }
    });
}

export function install_debugger_detection_bypass() {
    devlog("Installing debugger detection bypass hooks");
    
    Java.perform(() => {
        try {
            // 1. Debug.isDebuggerConnected()
            const Debug = Java.use("android.os.Debug");
            Debug.isDebuggerConnected.implementation = function() {
                createBypassEvent("bypass.debugger.connection_check", {
                    original_result: this.isDebuggerConnected(),
                    bypassed_result: false,
                    detection_method: "Debug.isDebuggerConnected()"
                });
                return false;
            };
            
            // 2. ApplicationInfo.FLAG_DEBUGGABLE
            const ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
            const PackageManager = Java.use("android.content.pm.PackageManager");
            PackageManager.getApplicationInfo.overload("java.lang.String", "int").implementation = function(packageName, flags) {
                const appInfo = this.getApplicationInfo(packageName, flags);
                
                if (appInfo && (appInfo.flags.value & ApplicationInfo.FLAG_DEBUGGABLE.value) !== 0) {
                    createBypassEvent("bypass.debugger.flag_check", {
                        package_name: packageName,
                        original_flags: appInfo.flags.value,
                        detection_method: "ApplicationInfo.FLAG_DEBUGGABLE",
                        action: "flag_removed"
                    });
                    appInfo.flags.value = appInfo.flags.value & ~ApplicationInfo.FLAG_DEBUGGABLE.value;
                }
                
                return appInfo;
            };
            
            // 3. Process status checks
            const File = Java.use("java.io.File");
            const BufferedReader = Java.use("java.io.BufferedReader");
            const FileReader = Java.use("java.io.FileReader");
            
            BufferedReader.readLine.implementation = function() {
                const line = this.readLine();
                
                if (line && line.includes("TracerPid:") && !line.includes("TracerPid:\t0")) {
                    createBypassEvent("bypass.debugger.tracer_check", {
                        original_line: line,
                        bypassed_line: "TracerPid:\t0",
                        detection_method: "/proc/self/status TracerPid",
                        action: "modified_output"
                    });
                    return "TracerPid:\t0";
                }
                
                return line;
            };
            
        } catch (error) {
            devlog(`[BYPASS] Error installing debugger detection bypass: ${error}`);
        }
    });
}

export function install_emulator_detection_bypass() {
    devlog("Installing emulator detection bypass hooks");
    
    Java.perform(() => {
        try {
            // 1. Build properties that indicate emulator
            const Build = Java.use("android.os.Build");
            
            // Common emulator indicators
            const emulatorIndicators = {
                BRAND: ["generic", "Android"],
                DEVICE: ["generic", "generic_x86"],
                MODEL: ["Android SDK built for x86", "google_sdk"],
                PRODUCT: ["sdk", "google_sdk", "sdk_x86"],
                MANUFACTURER: ["Genymotion", "unknown"],
                HARDWARE: ["goldfish", "vbox86"]
            };
            
            Object.keys(emulatorIndicators).forEach(prop => {
                const originalValue = Build[prop].value;
                if (emulatorIndicators[prop].includes(originalValue)) {
                    const safeValue = prop === "BRAND" ? "samsung" : "SM-G973F";
                    Build[prop].value = safeValue;
                    
                    createBypassEvent("bypass.emulator.build_property", {
                        property: prop,
                        original_value: originalValue,
                        bypassed_value: safeValue,
                        detection_method: `Build.${prop}`
                    });
                }
            });
            
            // 2. System properties
            const SystemProperties = Java.use("android.os.SystemProperties");
            SystemProperties.get.overload("java.lang.String").implementation = function(key) {
                const value = this.get(key);
                
                // Common emulator system properties
                if (key === "ro.kernel.qemu" && value === "1") {
                    createBypassEvent("bypass.emulator.system_property", {
                        property: key,
                        original_value: value,
                        bypassed_value: "0",
                        detection_method: "SystemProperties.get()"
                    });
                    return "0";
                }
                
                if (key === "ro.product.model" && value.includes("google_sdk")) {
                    createBypassEvent("bypass.emulator.system_property", {
                        property: key,
                        original_value: value,
                        bypassed_value: "SM-G973F",
                        detection_method: "SystemProperties.get()"
                    });
                    return "SM-G973F";
                }
                
                return value;
            };
            
        } catch (error) {
            devlog(`[BYPASS] Error installing emulator detection bypass: ${error}`);
        }
    });
}

export function install_hook_detection_bypass() {
    devlog("Installing hook detection bypass hooks");
    
    Java.perform(() => {
        try {
            // 1. Xposed framework detection
            const throwable = Java.use("java.lang.Throwable");
            throwable.getStackTrace.implementation = function() {
                const stack = this.getStackTrace();
                const filteredStack = [];
                
                for (let i = 0; i < stack.length; i++) {
                    const frame = stack[i];
                    const className = frame.getClassName();
                    
                    // Filter out Xposed, Frida, and other hooking framework traces
                    if (!className.includes("de.robv.android.xposed") &&
                        !className.includes("com.android.internal.os.ZygoteInit") &&
                        !className.includes("frida") &&
                        !className.includes("gum")) {
                        filteredStack.push(frame);
                    } else {
                        createBypassEvent("bypass.hook.stack_trace", {
                            filtered_class: className,
                            detection_method: "StackTrace analysis",
                            action: "filtered_frame"
                        });
                    }
                }
                
                return Java.array("java.lang.StackTraceElement", filteredStack);
            };
            
            // 2. Native method verification bypass
            const System = Java.use("java.lang.System");
            System.mapLibraryName.implementation = function(libname) {
                const result = this.mapLibraryName(libname);
                
                // Check if it's trying to verify native methods
                if (libname.includes("frida") || libname.includes("substrate")) {
                    createBypassEvent("bypass.hook.library_check", {
                        library_name: libname,
                        detection_method: "System.mapLibraryName()",
                        action: "library_check_bypassed"
                    });
                }
                
                return result;
            };
            
        } catch (error) {
            devlog(`[BYPASS] Error installing hook detection bypass: ${error}`);
        }
    });
}

export function install_bypass_hooks(): void {
    devlog("\n")
    devlog("Installing anti-analysis bypass hooks");
    
    install_root_detection_bypass();
    install_frida_detection_bypass();
    install_debugger_detection_bypass();
    install_emulator_detection_bypass();
    install_hook_detection_bypass();
    
    log("[BYPASS] All anti-analysis bypass hooks installed");
}
import { log, devlog, am_send } from "../utils/logging.js"
import { Where } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"
import { safePerform, safeUse, safeOverload, safeImplementation } from "../utils/safe_java.js"

const PROFILE_HOOKING_TYPE: string = "BYPASS_DETECTION"

function createBypassEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

/**
 * NOTE:
 * Original code used raw Java.perform + Java.use + direct .implementation,
 * with large try/catch blocks in each installer. This version refactors
 * the installers to:
 *   - use safePerform for Java.perform
 *   - use safeUse / safeOverload for class/method resolution
 *   - use safeImplementation around each hook body
 *
 * Functional logic is preserved; commented-out / legacy lines remain.
 */



export function install_root_detection_bypass() {
    devlog("Installing root detection bypass hooks");

    safePerform("bypass:install_root_detection_bypass", () => {
        // Hook common root detection methods

        // 1. File.exists() - commonly used to check for su binary and root apps
        const File = safeUse("java.io.File", "bypass:root:file");
        if (File) {
            const existsRef = File.exists;
            if (existsRef) {
                existsRef.implementation = safeImplementation(
                    "bypass:File.exists[root]",
                    existsRef,
                    function (original) {
                        const path = this.getAbsolutePath();
                        const result = original.call(this);

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
                            // Bypass by returning false
                            return false;
                        }

                        return result;
                    }
                );
            }
        }

        // 2. Runtime.exec(String) / exec(String[])
        // 2. Runtime.exec() - used to execute shell commands for root detection
        const Runtime = safeUse("java.lang.Runtime", "bypass:root:runtime");
        if (Runtime) {
            // exec(String)
            const execStringRef = safeOverload(
                Runtime.exec,
                "bypass:Runtime.exec[String]",
                "java.lang.String"
            );
            if (execStringRef) {
                execStringRef.implementation = safeImplementation(
                    "bypass:Runtime.exec[String]",
                    execStringRef,
                    function (original, command: string) {
                        const rootCommands = ["su", "which su", "busybox", "id"];

                        if (rootCommands.some(cmd => command.includes(cmd))) {
                            createBypassEvent("bypass.root.command_execution", {
                                command: command,
                                detection_method: "Runtime.exec(String)",
                                action: "blocked"
                            });
                            // Return a fake process that indicates command not found
                            return original.call(this, "echo 'command not found'");
                        }

                        return original.call(this, command);
                    }
                );
            }

            // exec(String[])
            const execArrayRef = safeOverload(
                Runtime.exec,
                "bypass:Runtime.exec[String[]]",
                "[Ljava.lang.String;"
            );
            if (execArrayRef) {
                execArrayRef.implementation = safeImplementation(
                    "bypass:Runtime.exec[String[]]",
                    execArrayRef,
                    function (original, commands: string[]) {
                        const commandStr = commands.join(" ");
                        const rootCommands = ["su", "which", "busybox", "id"];

                        if (rootCommands.some(cmd => commandStr.includes(cmd))) {
                            createBypassEvent("bypass.root.command_execution", {
                                command: commandStr,
                                detection_method: "Runtime.exec(String[])",
                                action: "blocked"
                            });
                            const fake = ["echo", "command not found"];
                            return original.call(this, fake);
                        }

                        return original.call(this, commands);
                    }
                );
            }
        }

        // 3. Build.TAGS
        // 3. Build properties check
        const Build = safeUse("android.os.Build", "bypass:root:build");
        if (Build) {
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
        }

        // 4. PackageManager.getInstalledPackages(int)
        // 4. PackageManager - check for root apps
        const PackageManager = safeUse(
            "android.content.pm.PackageManager",
            "bypass:root:pm"
        );
        const ApplicationInfo = safeUse(
            "android.content.pm.ApplicationInfo",
            "bypass:root:appinfo"
        );
        if (PackageManager && ApplicationInfo) {
            const getInstalledPackagesRef = safeOverload(
                PackageManager.getInstalledPackages,
                "bypass:PackageManager.getInstalledPackages",
                "int"
            );
            if (getInstalledPackagesRef) {
                getInstalledPackagesRef.implementation = safeImplementation(
                    "bypass:PackageManager.getInstalledPackages",
                    getInstalledPackagesRef,
                    function (original, flags: number) {
                        const packages = original.call(this, flags);
                        const rootApps = [
                            "com.noshufou.android.su", "com.koushikdutta.superuser",
                            "eu.chainfire.supersu", "com.saurik.substrate",
                            "com.zachspong.temprootremovejb", "com.ramdroid.appquarantine",
                            "com.topjohnwu.magisk", "com.kingroot.kinguser"
                        ];

                        const list = Java.cast(packages, Java.use("java.util.List"));
                        for (let i = list.size() - 1; i >= 0; i--) {
                            const packageInfo = list.get(i);
                            const packageName = packageInfo.packageName.value;

                            if (rootApps.includes(packageName)) {
                                createBypassEvent("bypass.root.package_check", {
                                    package_name: packageName,
                                    detection_method: "PackageManager.getInstalledPackages()",
                                    action: "removed_from_list"
                                });
                                list.remove(i);
                            }
                        }

                        return list;
                    }
                );
            }
        }
    });
}

export function install_frida_detection_bypass() {
    devlog("Installing Frida detection bypass hooks");

    safePerform("bypass:install_frida_detection_bypass", () => {
        // 1. File.exists() for frida server / gadget paths
        // 1. File existence checks for frida-server and related files
        const File = safeUse("java.io.File", "bypass:frida:file");
        if (File) {
            const existsRef = File.exists;
            if (existsRef) {
                existsRef.implementation = safeImplementation(
                    "bypass:File.exists[frida]",
                    existsRef,
                    function (original) {
                        const path = this.getAbsolutePath();
                        const result = original.call(this);

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
                    }
                );
            }
        }

        // 2. Socket(String,int) for port 27042
        // 2. Port scanning for default Frida port (27042)
        const Socket = safeUse("java.net.Socket", "bypass:frida:socket");
        if (Socket) {
            const socketInitRef = safeOverload(
                Socket.$init,
                "bypass:Socket.$init[String,int]",
                "java.lang.String",
                "int"
            );
            if (socketInitRef) {
                socketInitRef.implementation = safeImplementation(
                    "bypass:Socket.$init[String,int]",
                    socketInitRef,
                    function (original, host: string, port: number) {
                        if (port === 27042) {
                            createBypassEvent("bypass.frida.port_check", {
                                host: host,
                                port: port,
                                detection_method: "Socket connection",
                                action: "connection_refused"
                            });
                            const ConnectException = safeUse(
                                "java.net.ConnectException",
                                "bypass:frida:ConnectException"
                            );
                            if (ConnectException) {
                                throw ConnectException.$new("Connection refused");
                            }
                        }
                        return original.call(this, host, port);
                    }
                );
            }
        }

        // 3. ActivityManager.getRunningAppProcesses()
        // 3. Process name checks
        const ActivityManager = safeUse(
            "android.app.ActivityManager",
            "bypass:frida:activitymanager"
        );
        if (ActivityManager) {
            const getRunningRef = ActivityManager.getRunningAppProcesses;
            if (getRunningRef) {
                getRunningRef.implementation = safeImplementation(
                    "bypass:ActivityManager.getRunningAppProcesses",
                    getRunningRef,
                    function (original) {
                        const processes = original.call(this);

                        if (processes) {
                            const ArrayList = Java.use("java.util.ArrayList");
                            const processArray = Java.cast(processes, ArrayList);
                            for (let i = processArray.size() - 1; i >= 0; i--) {
                                const process = processArray.get(i);
                                const processName = process.processName.value;

                                if (
                                    processName.includes("frida") ||
                                    processName.includes("gum") ||
                                    processName.includes("gmain") ||
                                    processName.includes("pool-frida")
                                ) {
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
                    }
                );
            }
        }

        // 4. Thread.getName()
        // 4. Thread name checks
        const Thread = safeUse("java.lang.Thread", "bypass:frida:thread");
        if (Thread) {
            const getNameRef = Thread.getName;
            if (getNameRef) {
                getNameRef.implementation = safeImplementation(
                    "bypass:Thread.getName",
                    getNameRef,
                    function (original) {
                        const name = original.call(this);

                        if (
                            name &&
                            (name.includes("frida") ||
                                name.includes("gum") ||
                                name.includes("pool-frida"))
                        ) {
                            createBypassEvent("bypass.frida.thread_check", {
                                original_name: name,
                                bypassed_name: "main",
                                detection_method: "Thread.getName()"
                            });
                            return "main";
                        }

                        return name;
                    }
                );
            }
        }
    });
}

export function install_debugger_detection_bypass() {
    devlog("Installing debugger detection bypass hooks");

    safePerform("bypass:install_debugger_detection_bypass", () => {
        // 1. Debug.isDebuggerConnected()
        const Debug = safeUse("android.os.Debug", "bypass:debug:Debug");
        if (Debug) {
            const isDebuggerConnectedRef = Debug.isDebuggerConnected;
            if (isDebuggerConnectedRef) {
                isDebuggerConnectedRef.implementation = safeImplementation(
                    "bypass:Debug.isDebuggerConnected",
                    isDebuggerConnectedRef,
                    function (original) {
                        const originalResult = original.call(this);
                        createBypassEvent("bypass.debugger.connection_check", {
                            original_result: originalResult,
                            bypassed_result: false,
                            detection_method: "Debug.isDebuggerConnected()"
                        });
                        return false;
                    }
                );
            }
        }

        // 2. ApplicationInfo.FLAG_DEBUGGABLE
        const ApplicationInfo = safeUse(
            "android.content.pm.ApplicationInfo",
            "bypass:debug:ApplicationInfo"
        );
        const PackageManager = safeUse(
            "android.content.pm.PackageManager",
            "bypass:debug:PackageManager"
        );
        if (ApplicationInfo && PackageManager) {
            const getApplicationInfoRef = safeOverload(
                PackageManager.getApplicationInfo,
                "bypass:PackageManager.getApplicationInfo",
                "java.lang.String",
                "int"
            );
            if (getApplicationInfoRef) {
                getApplicationInfoRef.implementation = safeImplementation(
                    "bypass:PackageManager.getApplicationInfo",
                    getApplicationInfoRef,
                    function (original, packageName: string, flags: number) {
                        const appInfo = original.call(this, packageName, flags);

                        if (
                            appInfo &&
                            (appInfo.flags.value &
                                ApplicationInfo.FLAG_DEBUGGABLE.value) !== 0
                        ) {
                            createBypassEvent("bypass.debugger.flag_check", {
                                package_name: packageName,
                                original_flags: appInfo.flags.value,
                                detection_method: "ApplicationInfo.FLAG_DEBUGGABLE",
                                action: "flag_removed"
                            });
                            appInfo.flags.value =
                                appInfo.flags.value &
                                ~ApplicationInfo.FLAG_DEBUGGABLE.value;
                        }

                        return appInfo;
                    }
                );
            }
        }

        // 3. /proc/self/status TracerPid via BufferedReader.readLine()
        // 3. Process status checks
        const BufferedReader = safeUse(
            "java.io.BufferedReader",
            "bypass:debug:BufferedReader"
        );
        if (BufferedReader) {
            const readLineRef = BufferedReader.readLine;
            if (readLineRef) {
                readLineRef.implementation = safeImplementation(
                    "bypass:BufferedReader.readLine",
                    readLineRef,
                    function (original) {
                        const line = original.call(this);

                        if (
                            line &&
                            line.includes("TracerPid:") &&
                            !line.includes("TracerPid:\t0")
                        ) {
                            createBypassEvent("bypass.debugger.tracer_check", {
                                original_line: line,
                                bypassed_line: "TracerPid:\t0",
                                detection_method: "/proc/self/status TracerPid",
                                action: "modified_output"
                            });
                            return "TracerPid:\t0";
                        }

                        return line;
                    }
                );
            }
        }
    });
}

export function install_emulator_detection_bypass() {
    devlog("Installing emulator detection bypass hooks");

    safePerform("bypass:install_emulator_detection_bypass", () => {
        // 1. Build properties that indicate emulator
        const Build = safeUse("android.os.Build", "bypass:emu:build");
        if (Build) {
            // Common emulator indicators
            const emulatorIndicators: Record<string, string[]> = {
                BRAND: ["generic", "Android"],
                DEVICE: ["generic", "generic_x86"],
                MODEL: ["Android SDK built for x86", "google_sdk"],
                PRODUCT: ["sdk", "google_sdk", "sdk_x86"],
                MANUFACTURER: ["Genymotion", "unknown"],
                HARDWARE: ["goldfish", "vbox86"]
            };

            Object.keys(emulatorIndicators).forEach(prop => {
                // @ts-ignore
                const originalValue = Build[prop].value;
                if (emulatorIndicators[prop].includes(originalValue)) {
                    const safeValue = prop === "BRAND" ? "samsung" : "SM-G973F";
                    // @ts-ignore
                    Build[prop].value = safeValue;
                    createBypassEvent("bypass.emulator.build_property", {
                        property: prop,
                        original_value: originalValue,
                        bypassed_value: safeValue,
                        detection_method: `Build.${prop}`
                    });
                }
            });
        }

        // 2. SystemProperties.get(String)
        const SystemProperties = safeUse(
            "android.os.SystemProperties",
            "bypass:emu:SystemProperties"
        );
        if (SystemProperties) {
            const getRef = safeOverload(
                SystemProperties.get,
                "bypass:SystemProperties.get[String]",
                "java.lang.String"
            );
            if (getRef) {
                getRef.implementation = safeImplementation(
                    "bypass:SystemProperties.get[String]",
                    getRef,
                    function (original, key: string) {
                        const value = original.call(this, key);

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
                    }
                );
            }
        }
    });
}

export function install_hook_detection_bypass() {
    devlog("Installing hook detection bypass hooks");

    safePerform("bypass:install_hook_detection_bypass", () => {
        // 1. Throwable.getStackTrace(): filter Xposed/Frida frames => should probably also ad LSPosed and other variants
        // 1. Xposed framework detection
        const Throwable = safeUse("java.lang.Throwable", "bypass:hook:Throwable");
        if (Throwable) {
            const getStackTraceRef = Throwable.getStackTrace;
            if (getStackTraceRef) {
                getStackTraceRef.implementation = safeImplementation(
                    "bypass:Throwable.getStackTrace",
                    getStackTraceRef,
                    function (original) {
                        const stack = original.call(this);
                        const filtered: any[] = [];

                        for (let i = 0; i < stack.length; i++) {
                            const frame = stack[i];
                            const className = frame.getClassName();

                            // Filter out Xposed, Frida, and other hooking framework traces
                            if (
                                !className.includes("de.robv.android.xposed") &&
                                !className.includes("com.android.internal.os.ZygoteInit") &&
                                !className.includes("frida") &&
                                !className.includes("gum")
                            ) {
                                filtered.push(frame);
                            } else {
                                createBypassEvent("bypass.hook.stack_trace", {
                                    filtered_class: className,
                                    detection_method: "StackTrace analysis",
                                    action: "filtered_frame"
                                });
                            }
                        }

                        return Java.array("java.lang.StackTraceElement", filtered);
                    }
                );
            }
        }

        // 2. System.mapLibraryName()
        // 2. Native method verification bypass
        const System = safeUse("java.lang.System", "bypass:hook:System");
        if (System) {
            const mapLibraryNameRef = System.mapLibraryName;
            if (mapLibraryNameRef) {
                mapLibraryNameRef.implementation = safeImplementation(
                    "bypass:System.mapLibraryName",
                    mapLibraryNameRef,
                    function (original, libname: string) {
                        const result = original.call(this, libname);

                        // Check if it's trying to verify native methods
                        if (libname.includes("frida") || libname.includes("substrate")) {
                            createBypassEvent("bypass.hook.library_check", {
                                library_name: libname,
                                detection_method: "System.mapLibraryName()",
                                action: "library_check_bypassed"
                            });
                        }

                        return result;
                    }
                );
            }
        }
    });
}

export function install_bypass_hooks(): void {
    devlog("\n");
    devlog("Installing anti-analysis bypass hooks");

    try {
        install_root_detection_bypass();
    } catch (error) {
        devlog(`[HOOK] Failed to install root detection bypass: ${error}`);
    }

    try {
        install_frida_detection_bypass();
    } catch (error) {
        devlog(`[HOOK] Failed to install Frida detection bypass: ${error}`);
    }

    try {
        install_debugger_detection_bypass();
    } catch (error) {
        devlog(`[HOOK] Failed to install debugger detection bypass: ${error}`);
    }

    try {
        install_emulator_detection_bypass();
    } catch (error) {
        devlog(`[HOOK] Failed to install emulator detection bypass: ${error}`);
    }

    try {
        install_hook_detection_bypass();
    } catch (error) {
        devlog(`[HOOK] Failed to install hook detection bypass: ${error}`);
    }

    log("[BYPASS] All anti-analysis bypass hooks installed");
}
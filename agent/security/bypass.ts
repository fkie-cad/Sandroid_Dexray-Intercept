import { log, devlog, am_send } from "../utils/logging.js"
import { Where } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"
import { safePerform, safeUse, safeOverload, safeImplementation, PropagateException } from "../utils/safe_java.js"

const PROFILE_HOOKING_TYPE: string = "BYPASS_DETECTION"

// PackageManager's legacy integer overload can delegate to the newer
// flags-object overload. Emit and alter the returned result only for the
// outer public call.
const activeInstalledPackagesDepth = new Map<number, number>();
const activeApplicationInfoDepth = new Map<number, number>();
const activeRuntimeExecDepth = new Map<number, number>();
const activeSocketConnectDepth = new Map<number, number>();

function createBypassEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function getRuntimeCommandTokens(
    commandValue: any,
    commandType: string
): string[] {
    if (!commandValue) {
        return [];
    }

    if (commandType === "java.lang.String") {
        return commandValue
            .toString()
            .trim()
            .split(/\s+/)
            .filter(token => token.length > 0);
    }

    const tokens: string[] = [];

    for (
        let tokenIndex = 0;
        tokenIndex < commandValue.length;
        tokenIndex++
    ) {
        const token = commandValue[tokenIndex];
        tokens.push(token === null ? "null" : token.toString());
    }

    return tokens;
}

function getCommandBasename(token: string): string {
    const separatorIndex = token.lastIndexOf("/");
    return separatorIndex >= 0
        ? token.substring(separatorIndex + 1)
        : token;
}

function isRootDetectionCommand(tokens: string[]): boolean {
    if (tokens.length === 0) {
        return false;
    }

    const executable = getCommandBasename(tokens[0]);

    if (
        executable === "su" ||
        executable === "busybox" ||
        executable === "id"
    ) {
        return true;
    }

    return (
        executable === "which" &&
        tokens.length > 1 &&
        getCommandBasename(tokens[1]) === "su"
    );
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

        // 1. File.exists() - common root and Frida artifact checks.
        // Root and Frida detection share one implementation so neither
        // category overwrites the other.
        const File = safeUse("java.io.File", "bypass:file");
        if (File) {
            const existsRef = safeOverload(
                File.exists,
                "bypass:File.exists"
            );
            if (existsRef) {
                existsRef.implementation = safeImplementation(
                    "bypass:File.exists",
                    existsRef,
                    function (original) {
                        const path = this.getAbsolutePath().toString();
                        const normalizedPath = path.replace(/\/+$/, "");
                        let result: boolean;
                        try {
                            result = original.call(this);
                        } catch (error) {
                            throw new PropagateException(error);
                        }

                        const rootPaths = [
                            "/system/bin/su", "/system/xbin/su", "/sbin/su",
                            "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
                            "/data/data/com.noshufou.android.su",
                            "/data/data/com.koushikdutta.superuser",
                            "/data/data/eu.chainfire.supersu",
                            "/system/xbin/busybox", "/system/bin/busybox",
                            "/system/app/RootCloak.apk",
                            "/dev/com.koushikdutta.superuser.daemon"
                        ];

                        const fridaPaths = [
                            "/data/local/tmp/frida-server",
                            "/data/local/tmp/re.frida.server",
                            "/system/lib/libfrida-gadget.so",
                            "/system/lib64/libfrida-gadget.so"
                        ];

                        if (rootPaths.includes(normalizedPath)) {
                            createBypassEvent("bypass.root.file_check", {
                                file_path: path,
                                original_result: result,
                                bypassed_result: false,
                                detection_method: "File.exists()"
                            });
                            return false;
                        }

                        if (fridaPaths.includes(normalizedPath)) {
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

        // 2. Runtime.exec() - used to execute shell commands for root detection.
        // Public overloads delegate internally to Runtime.exec(String[], String[], File).
        // Emit and substitute only for the outer public call.
        const Runtime = safeUse("java.lang.Runtime", "bypass:root:runtime");
        if (Runtime) {
            Runtime.exec.overloads.forEach(
                (overload: any, index: number) => {
                    const argumentTypes = overload.argumentTypes.map(
                        (type: any) => type.className
                    );
                    const commandType = argumentTypes[0];
                    const overloadSignature =
                        `exec(${argumentTypes.join(",")})`;

                    overload.implementation = safeImplementation(
                        `bypass:Runtime.${overloadSignature}`,
                        overload,
                        function (original, ...args: any[]) {
                            const threadId = Process.getCurrentThreadId();
                            const depth =
                                activeRuntimeExecDepth.get(threadId) || 0;
                            const isOutermost = depth === 0;

                            activeRuntimeExecDepth.set(
                                threadId,
                                depth + 1
                            );

                            try {
                                const commandTokens = getRuntimeCommandTokens(
                                    args[0],
                                    commandType
                                );
                                const command = commandTokens.join(" ");
                                const isRootCommand =
                                    isRootDetectionCommand(commandTokens);

                                if (isOutermost && isRootCommand) {
                                    createBypassEvent(
                                        "bypass.root.command_execution",
                                        {
                                            command: command,
                                            detection_method:
                                                `Runtime.${overloadSignature}`,
                                            action: "blocked",
                                            overload_index: index,
                                            overload_signature:
                                                overloadSignature,
                                            command_tokens: commandTokens
                                        }
                                    );

                                    const safeArgs = args.slice();

                                    if (
                                        commandType === "java.lang.String"
                                    ) {
                                        safeArgs[0] =
                                            "echo 'command not found'";
                                    } else {
                                        safeArgs[0] = Java.array(
                                            "java.lang.String",
                                            ["echo", "command not found"]
                                        );
                                    }

                                    return original.apply(this, safeArgs);
                                }

                                return original.apply(this, args);
                            } catch (error) {
                                throw new PropagateException(error);
                            } finally {
                                const remaining =
                                    activeRuntimeExecDepth.get(threadId)! - 1;

                                if (remaining <= 0) {
                                    activeRuntimeExecDepth.delete(threadId);
                                } else {
                                    activeRuntimeExecDepth.set(
                                        threadId,
                                        remaining
                                    );
                                }
                            }
                        }
                    );
                }
            );
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

        // 4. ApplicationPackageManager.getInstalledPackages(...)
        const ApplicationPackageManager = safeUse(
            "android.app.ApplicationPackageManager",
            "bypass:root:ApplicationPackageManager"
        );
        const PackageInfo = safeUse(
            "android.content.pm.PackageInfo",
            "bypass:root:PackageInfo"
        );

        if (ApplicationPackageManager && PackageInfo) {
            ApplicationPackageManager.getInstalledPackages.overloads.forEach(
                (overload: any, index: number) => {
                    overload.implementation = safeImplementation(
                        `bypass:ApplicationPackageManager.getInstalledPackages[${index}]`,
                        overload,
                        function (original, ...args: any[]) {
                            const threadId = Process.getCurrentThreadId();
                            const depth =
                                activeInstalledPackagesDepth.get(threadId) || 0;
                            const isOutermost = depth === 0;

                            activeInstalledPackagesDepth.set(
                                threadId,
                                depth + 1
                            );

                            try {
                                const packages = original.apply(this, args);

                                if (isOutermost && packages !== null) {
                                    const rootApps = [
                                        "com.noshufou.android.su",
                                        "com.koushikdutta.superuser",
                                        "eu.chainfire.supersu",
                                        "com.saurik.substrate",
                                        "com.zachspong.temprootremovejb",
                                        "com.ramdroid.appquarantine",
                                        "com.topjohnwu.magisk",
                                        "com.kingroot.kinguser"
                                    ];

                                    for (
                                        let listIndex = packages.size() - 1;
                                        listIndex >= 0;
                                        listIndex--
                                    ) {
                                        const rawPackageInfo =
                                            packages.get(listIndex);
                                        const packageInfo = Java.cast(
                                            rawPackageInfo,
                                            PackageInfo
                                        );
                                        const packageName =
                                            packageInfo.packageName.value.toString();

                                        if (rootApps.includes(packageName)) {
                                            createBypassEvent(
                                                "bypass.root.package_check",
                                                {
                                                    package_name: packageName,
                                                    detection_method:
                                                        "ApplicationPackageManager.getInstalledPackages()",
                                                    action: "removed_from_list"
                                                }
                                            );
                                            packages.remove(listIndex);
                                        }
                                    }
                                }

                                return packages;
                            } catch (error) {
                                throw new PropagateException(error);
                            } finally {
                                const remaining =
                                    activeInstalledPackagesDepth.get(threadId)! - 1;

                                if (remaining <= 0) {
                                    activeInstalledPackagesDepth.delete(threadId);
                                } else {
                                    activeInstalledPackagesDepth.set(
                                        threadId,
                                        remaining
                                    );
                                }
                            }
                        }
                    );
                }
            );
        }
    });
}


export function install_frida_detection_bypass() {
    devlog("Installing Frida detection bypass hooks");

    safePerform("bypass:install_frida_detection_bypass", () => {
        // 2. Socket constructors and connect() calls for port 27042.
        const Socket = safeUse("java.net.Socket", "bypass:frida:socket");
        const InetAddress = safeUse(
            "java.net.InetAddress",
            "bypass:frida:InetAddress"
        );
        const InetSocketAddress = safeUse(
            "java.net.InetSocketAddress",
            "bypass:frida:InetSocketAddress"
        );
        const ConnectException = safeUse(
            "java.net.ConnectException",
            "bypass:frida:ConnectException"
        );

        if (Socket && InetAddress && InetSocketAddress && ConnectException) {
            const constructorSignatures = [
                ["java.lang.String", "int"],
                [
                    "java.lang.String",
                    "int",
                    "java.net.InetAddress",
                    "int"
                ],
                ["java.lang.String", "int", "boolean"],
                ["java.net.InetAddress", "int"],
                [
                    "java.net.InetAddress",
                    "int",
                    "java.net.InetAddress",
                    "int"
                ],
                ["java.net.InetAddress", "int", "boolean"]
            ];

            constructorSignatures.forEach(signatures => {
                const constructorRef = safeOverload(
                    Socket.$init,
                    `bypass:Socket.$init[${signatures.join(",")}]`,
                    ...signatures
                );

                if (!constructorRef) {
                    return;
                }

                const connectionApi =
                    `Socket(${signatures.join(",")})`;

                constructorRef.implementation = safeImplementation(
                    `bypass:${connectionApi}`,
                    constructorRef,
                    function (original, ...args: any[]) {
                        let host: string | null = null;
                        const port = args[1];

                        try {
                            if (
                                signatures[0] === "java.lang.String"
                            ) {
                                host = args[0]
                                    ? args[0].toString()
                                    : null;
                            } else if (args[0]) {
                                const address = Java.cast(
                                    args[0],
                                    InetAddress
                                );
                                host = address.getHostAddress().toString();
                            }
                        } catch {
                            host = null;
                        }

                        if (port === 27042) {
                            createBypassEvent(
                                "bypass.frida.port_check",
                                {
                                    host: host,
                                    port: port,
                                    detection_method: "Socket connection",
                                    connection_api: connectionApi,
                                    action: "connection_refused"
                                }
                            );

                            throw new PropagateException(
                                ConnectException.$new(
                                    "Connection refused"
                                )
                            );
                        }

                        try {
                            return original.apply(this, args);
                        } catch (error) {
                            throw new PropagateException(error);
                        }
                    }
                );
            });

            Socket.connect.overloads.forEach(
                (overload: any, index: number) => {
                    const argumentTypes = overload.argumentTypes.map(
                        (type: any) => type.className
                    );
                    const connectionApi =
                        `Socket.connect(${argumentTypes.join(",")})`;

                    overload.implementation = safeImplementation(
                        `bypass:${connectionApi}`,
                        overload,
                        function (original, ...args: any[]) {
                            const threadId = Process.getCurrentThreadId();
                            const depth =
                                activeSocketConnectDepth.get(threadId) || 0;
                            const isOutermost = depth === 0;

                            activeSocketConnectDepth.set(
                                threadId,
                                depth + 1
                            );

                            try {
                                let host: string | null = null;
                                let port: number | null = null;

                                try {
                                    const endpoint = Java.cast(
                                        args[0],
                                        InetSocketAddress
                                    );
                                    host = endpoint
                                        .getHostString()
                                        .toString();
                                    port = endpoint.getPort();
                                } catch {
                                    // Non-InetSocketAddress endpoints are
                                    // not part of the port-27042 bypass.
                                }

                                if (
                                    isOutermost &&
                                    port === 27042
                                ) {
                                    createBypassEvent(
                                        "bypass.frida.port_check",
                                        {
                                            host: host,
                                            port: port,
                                            detection_method:
                                                "Socket connection",
                                            connection_api: connectionApi,
                                            action: "connection_refused"
                                        }
                                    );

                                    throw new PropagateException(
                                        ConnectException.$new(
                                            "Connection refused"
                                        )
                                    );
                                }

                                return original.apply(this, args);
                            } catch (error) {
                                throw error instanceof PropagateException
                                    ? error
                                    : new PropagateException(error);
                            } finally {
                                const remaining =
                                    activeSocketConnectDepth.get(threadId)! - 1;

                                if (remaining <= 0) {
                                    activeSocketConnectDepth.delete(threadId);
                                } else {
                                    activeSocketConnectDepth.set(
                                        threadId,
                                        remaining
                                    );
                                }
                            }
                        }
                    );
                }
            );
        }

        // 3. ActivityManager.getRunningAppProcesses()
        const ActivityManager = safeUse(
            "android.app.ActivityManager",
            "bypass:frida:activitymanager"
        );
        const RunningAppProcessInfo = safeUse(
            "android.app.ActivityManager$RunningAppProcessInfo",
            "bypass:frida:RunningAppProcessInfo"
        );

        if (ActivityManager && RunningAppProcessInfo) {
            const getRunningRef = safeOverload(
                ActivityManager.getRunningAppProcesses,
                "bypass:ActivityManager.getRunningAppProcesses"
            );

            if (getRunningRef) {
                getRunningRef.implementation = safeImplementation(
                    "bypass:ActivityManager.getRunningAppProcesses",
                    getRunningRef,
                    function (original) {
                        let processes;
                        try {
                            processes = original.call(this);
                        } catch (error) {
                            throw new PropagateException(error);
                        }

                        if (processes === null) {
                            return processes;
                        }

                        for (let index = processes.size() - 1; index >= 0; index--) {
                            const rawProcessInfo = processes.get(index);
                            const processInfo = Java.cast(
                                rawProcessInfo,
                                RunningAppProcessInfo
                            );
                            const processName =
                                processInfo.processName.value.toString();

                            if (
                                processName.includes("frida") ||
                                processName.includes("gum") ||
                                processName.includes("gmain") ||
                                processName.includes("pool-frida")
                            ) {
                                createBypassEvent("bypass.frida.process_check", {
                                    process_name: processName,
                                    detection_method:
                                        "ActivityManager.getRunningAppProcesses()",
                                    action: "removed_from_list"
                                });
                                processes.remove(index);
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
                        let name;
                        try {
                            name = original.call(this);
                        } catch (error) {
                            throw new PropagateException(error);
                        }

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
                        let originalResult;
                        try {
                            originalResult = original.call(this);
                        } catch (error) {
                            throw new PropagateException(error);
                        }

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
        const ApplicationPackageManager = safeUse(
            "android.app.ApplicationPackageManager",
            "bypass:debug:ApplicationPackageManager"
        );

        if (ApplicationInfo && ApplicationPackageManager) {
            ApplicationPackageManager.getApplicationInfo.overloads.forEach(
                (overload: any, index: number) => {
                    overload.implementation = safeImplementation(
                        `bypass:ApplicationPackageManager.getApplicationInfo[${index}]`,
                        overload,
                        function (original, ...args: any[]) {
                            const threadId = Process.getCurrentThreadId();
                            const depth =
                                activeApplicationInfoDepth.get(threadId) || 0;
                            const isOutermost = depth === 0;

                            activeApplicationInfoDepth.set(threadId, depth + 1);

                            try {
                                const rawAppInfo = original.apply(this, args);

                                if (isOutermost && rawAppInfo !== null) {
                                    const appInfo = Java.cast(
                                        rawAppInfo,
                                        ApplicationInfo
                                    );
                                    const originalFlags = appInfo.flags.value;

                                    if (
                                        (originalFlags &
                                            ApplicationInfo.FLAG_DEBUGGABLE.value) !==
                                        0
                                    ) {
                                        createBypassEvent(
                                            "bypass.debugger.flag_check",
                                            {
                                                package_name:
                                                    args[0] !== null
                                                        ? args[0].toString()
                                                        : null,
                                                original_flags: originalFlags,
                                                detection_method:
                                                    "ApplicationInfo.FLAG_DEBUGGABLE",
                                                action: "flag_removed"
                                            }
                                        );

                                        appInfo.flags.value =
                                            originalFlags &
                                            ~ApplicationInfo.FLAG_DEBUGGABLE.value;
                                    }
                                }

                                return rawAppInfo;
                            } catch (error) {
                                throw new PropagateException(error);
                            } finally {
                                const remaining =
                                    activeApplicationInfoDepth.get(threadId)! - 1;

                                if (remaining <= 0) {
                                    activeApplicationInfoDepth.delete(threadId);
                                } else {
                                    activeApplicationInfoDepth.set(
                                        threadId,
                                        remaining
                                    );
                                }
                            }
                        }
                    );
                }
            );
        }

        // 3. /proc/self/status TracerPid via BufferedReader.readLine()
        const BufferedReader = safeUse(
            "java.io.BufferedReader",
            "bypass:debug:BufferedReader"
        );

        if (BufferedReader) {
            const readLineRef = safeOverload(
                BufferedReader.readLine,
                "bypass:BufferedReader.readLine",
            );

            if (readLineRef) {
                readLineRef.implementation = safeImplementation(
                    "bypass:BufferedReader.readLine",
                    readLineRef,
                    function (original) {
                        let line;
                        try {
                            line = original.call(this);
                        } catch (error) {
                            throw new PropagateException(error);
                        }

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

        // 2. SystemProperties.get(String) and get(String, String)
        const SystemProperties = safeUse(
            "android.os.SystemProperties",
            "bypass:emu:SystemProperties"
        );

        if (SystemProperties) {
            SystemProperties.get.overloads.forEach(
                (overload: any, index: number) => {
                    const argumentTypes = overload.argumentTypes.map(
                        (type: any) => type.className
                    );
                    const overloadSignature =
                        `get(${argumentTypes.join(",")})`;

                    overload.implementation = safeImplementation(
                        `bypass:SystemProperties.${overloadSignature}`,
                        overload,
                        function (original, ...args: any[]) {
                            const key = args[0] ? args[0].toString() : "";
                            let value;

                            try {
                                value = original.apply(this, args);
                            } catch (error) {
                                throw new PropagateException(error);
                            }

                            if (
                                key === "ro.kernel.qemu" &&
                                value === "1"
                            ) {
                                createBypassEvent(
                                    "bypass.emulator.system_property",
                                    {
                                        property: key,
                                        original_value: value,
                                        bypassed_value: "0",
                                        detection_method:
                                            "SystemProperties.get()",
                                        overload_index: index,
                                        overload_signature:
                                            overloadSignature
                                    }
                                );
                                return "0";
                            }

                            if (
                                key === "ro.product.model" &&
                                value.includes("google_sdk")
                            ) {
                                createBypassEvent(
                                    "bypass.emulator.system_property",
                                    {
                                        property: key,
                                        original_value: value,
                                        bypassed_value: "SM-G973F",
                                        detection_method:
                                            "SystemProperties.get()",
                                        overload_index: index,
                                        overload_signature:
                                            overloadSignature
                                    }
                                );
                                return "SM-G973F";
                            }

                            return value;
                        }
                    );
                }
            );
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
                        let stack;
                        try {
                            stack = original.call(this);
                        } catch (error) {
                            throw new PropagateException(error);
                        }

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
                        let result;
                        try {
                            result = original.call(this, libname);
                        } catch (error) {
                            throw new PropagateException(error);
                        }

                        // Check if it's trying to verify native methods
                        if (
                            libname.includes("frida") ||
                            libname.includes("substrate")
                        ) {
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
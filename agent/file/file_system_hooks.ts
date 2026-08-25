import { devlog, am_send } from "../utils/logging.js"
import { buffer2ArrayBuffer, b2s, isPatternPresent, byteArray2JString, bytesToHex } from "../utils/misc.js"
import { show_verbose } from "../hooking_profile_loader.js"
import { deactivate_unlink } from "../hooking_profile_loader.js"
import { Java } from "../utils/javalib.js"
import {
    safePerform,
    safeUse,
    safeOverload,
    safeImplementation,
    PropagateException
} from "../utils/safe_java.js"
import { safeResolveExport, safeAttach, safeReplaceNoCallThrough } from "../utils/safe_native.js"
import { collectJavaStackTrace, collectNativeBacktrace } from "../utils/stacktrace.js"

const PROFILE_HOOKING_TYPE: string = "FILE_SYSTEM"

// ============================================================================
// IMPORTANT: We send the full buffer hex from TypeScript (no slicing here)
// because slice() on Java arrays in Frida causes app freezing/crashes.
// The Python side will truncate the hex string based on the length field.
// ============================================================================

var TraceFD = {};
var TraceFS = {};
var TraceFile = {};
var TraceSysFD = {};

var CONFIG = {
    // if TRUE enable data dump 
    printEnable: true,
    // if TRUE enable libc.so open/read/write hook
    printLibc: false,
    // if TRUE print the stack trace for each hook
    printStackTrace: false,
    // to filter the file path whose data want to be dumped in ASCII 
    dump_ascii_If_Path_contains: [".log", ".xml", ".prop"],
    // to filter the file path whose data want to be NOT dumped in hexdump (useful for big chunk and excessive reads) 
    dump_hex_If_Path_NOT_contains: [".png", "/proc/self/task", "/system/lib", "base.apk", "cacert", "jar", "dex"],
    // to filter the file path whose data want to be NOT dumped fron libc read/write (useful for big chunk and excessive reads) 
    dump_raw_If_Path_NOT_contains: [".png", "/proc/self/task", "/system/lib", "base.apk", "cacert"],
    // filter file access which is typically not of interest
    filter_out_access_to_these_files: ["anon_inode", "/dev/urandom", "/system/framework/", "/data/dalvik-cache/"],
    // Maximum length of data to display (bytes)
    max_output_length: 1024
}

function isFileFromInterest(file_string) {
    if (!file_string.startsWith("/proc") && !file_string.startsWith("/system/lib")) {
        return true
    } else if (file_string.endsWith("cgroup") || file_string.endsWith("primary.prof") || file_string.endsWith("cmdline") || file_string === "/proc" || file_string.startsWith("/proc/self/maps") || file_string.endsWith("jar.cur.prof")) {
        return false
    } else if (file_string.startsWith("/system/lib") || file_string.startsWith("[unknown") || (file_string.startsWith("/proc") && file_string.endsWith("maps"))) {
        return false
    }
    return true
}


function createFileSystemEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function bytesToHexSafe(bytes: number[] | null): string {
    if (!bytes || bytes.length === 0) return "";
    return bytesToHex(new Uint8Array(bytes));
}

function shouldSkipFile(filePath: string): boolean {
    // Check against filter_out_access_to_these_files
    for (const filter of CONFIG.filter_out_access_to_these_files) {
        if (filePath.includes(filter)) {
            return true;
        }
    }
    return !isFileFromInterest(filePath);
}

function hook_file_constructors(): void {
    const createdFiles: Set<string> = new Set();

    safePerform("file_system:constructors:install", () => {
        const File = safeUse("java.io.File", "file_system:constructors");
        if (!File) {
            return;
        }

        const constructors = [
            safeOverload(
                File.$init,
                "file_system:File.init(File,String)",
                "java.io.File",
                "java.lang.String"
            ),
            safeOverload(
                File.$init,
                "file_system:File.init(String)",
                "java.lang.String"
            ),
            safeOverload(
                File.$init,
                "file_system:File.init(String,String)",
                "java.lang.String",
                "java.lang.String"
            ),
            safeOverload(
                File.$init,
                "file_system:File.init(URI)",
                "java.net.URI"
            )
        ];

        function installConstructor(
            overload: any,
            context: string,
            variant: number,
            method: string,
            getDetails: (args: any[]) => any
        ): void {
            if (!overload) {
                return;
            }

            overload.implementation = safeImplementation(
                context,
                overload,
                function (original, ...args: any[]) {
                    let result;

                    try {
                        result = original.apply(this, args);
                    } catch (error) {
                        throw new PropagateException(error);
                    }

                    const filePath = this.getAbsolutePath().toString();

                    if (
                        !createdFiles.has(filePath) &&
                        filePath.length > 2 &&
                        !shouldSkipFile(filePath)
                    ) {
                        const java_stack_trace = collectJavaStackTrace();
                        createFileSystemEvent("file.create", {
                            operation: "File.new",
                            variant,
                            file_path: filePath,
                            method,
                            ...getDetails(args),
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        createdFiles.add(filePath);
                    }

                    TraceFile["f" + this.hashCode()] = filePath;

                    return result;
                }
            );
        }

        installConstructor(
            constructors[0],
            "file_system:File.init(File,String)",
            0,
            "java.io.File.init(File, String)",
            (args) => ({
                parent_path: args[0]
                    ? args[0].getAbsolutePath().toString()
                    : null,
                child_path: args[1].toString()
            })
        );

        installConstructor(
            constructors[1],
            "file_system:File.init(String)",
            1,
            "java.io.File.init(String)",
            () => ({})
        );

        installConstructor(
            constructors[2],
            "file_system:File.init(String,String)",
            2,
            "java.io.File.init(String, String)",
            (args) => ({
                parent_path: args[0].toString(),
                child_path: args[1].toString()
            })
        );

        installConstructor(
            constructors[3],
            "file_system:File.init(URI)",
            3,
            "java.io.File.init(URI)",
            () => ({})
        );
    });
}

function hook_file_input_stream_constructors(): void {
    const createdFileStreams: Set<string> = new Set();
    const constructorDepths = new Map<number, number>();

    safePerform("file_system:input_stream_constructors:install", () => {
        const FileInputStream = safeUse(
            "java.io.FileInputStream",
            "file_system:input_stream_constructors"
        );
        const FileDescriptor = safeUse(
            "java.io.FileDescriptor",
            "file_system:input_stream_constructors"
        );

        if (!FileInputStream || !FileDescriptor) {
            return;
        }

        function resolveFilePath(variant: number, args: any[]): string {
            if (variant === 0) {
                return args[0].getAbsolutePath().toString();
            }

            if (variant === 2) {
                return args[0].toString();
            }

            const descriptor = args[0];
            return TraceFD["fd" + descriptor.hashCode()] || "[unknown]";
        }

        function installConstructor(
            overload: any,
            context: string,
            variant: number,
            method: string,
            getDetails: (args: any[]) => any
        ): void {
            if (!overload) {
                return;
            }

            overload.implementation = safeImplementation(
                context,
                overload,
                function (original, ...args: any[]) {
                    const threadId = Process.getCurrentThreadId();
                    const depth = constructorDepths.get(threadId) || 0;
                    const isNested = depth > 0;
                    constructorDepths.set(threadId, depth + 1);

                    try {
                        let result;

                        try {
                            result = original.apply(this, args);
                        } catch (error) {
                            throw new PropagateException(error);
                        }

                        if (!isNested) {
                            try {
                                const filePath = resolveFilePath(variant, args);
                                const descriptor = Java.cast(
                                    this.getFD(),
                                    FileDescriptor
                                );
                                const deduplicationKey = `${variant}:${filePath}`;

                                if (
                                    !createdFileStreams.has(deduplicationKey) &&
                                    !shouldSkipFile(filePath)
                                ) {
                                    const java_stack_trace = collectJavaStackTrace();
                                    createFileSystemEvent("file.stream.create", {
                                        operation: "FileInputStream.new",
                                        variant,
                                        file_path: filePath,
                                        stream_type: "input",
                                        method,
                                        ...getDetails(args),
                                        ...(java_stack_trace
                                            ? { java_stack_trace }
                                            : {})
                                    });
                                    createdFileStreams.add(deduplicationKey);
                                }

                                TraceFS["fd" + this.hashCode()] = filePath;
                                TraceFD["fd" + descriptor.hashCode()] = filePath;
                            } catch (error) {
                                devlog(
                                    `FileInputStream constructor metadata failed: ${error}`
                                );
                            }
                        }

                        return result;
                    } finally {
                        if (depth === 0) {
                            constructorDepths.delete(threadId);
                        } else {
                            constructorDepths.set(threadId, depth);
                        }
                    }
                }
            );
        }

        installConstructor(
            safeOverload(
                FileInputStream.$init,
                "file_system:FileInputStream.init(File)",
                "java.io.File"
            ),
            "file_system:FileInputStream.init(File)",
            0,
            "java.io.FileInputStream.init(File)",
            () => ({})
        );

        installConstructor(
            safeOverload(
                FileInputStream.$init,
                "file_system:FileInputStream.init(FileDescriptor)",
                "java.io.FileDescriptor"
            ),
            "file_system:FileInputStream.init(FileDescriptor)",
            1,
            "java.io.FileInputStream.init(FileDescriptor)",
            () => ({})
        );

        installConstructor(
            safeOverload(
                FileInputStream.$init,
                "file_system:FileInputStream.init(String)",
                "java.lang.String"
            ),
            "file_system:FileInputStream.init(String)",
            2,
            "java.io.FileInputStream.init(String)",
            () => ({})
        );

        installConstructor(
            safeOverload(
                FileInputStream.$init,
                "file_system:FileInputStream.init(FileDescriptor,boolean)",
                "java.io.FileDescriptor",
                "boolean"
            ),
            "file_system:FileInputStream.init(FileDescriptor,boolean)",
            3,
            "java.io.FileInputStream.init(FileDescriptor, boolean)",
            (args) => ({
                close_descriptor: Boolean(args[1])
            })
        );
    });
}

function hook_file_input_stream_reads(): void {
    const readDepths = new Map<number, number>();

    safePerform("file_system:input_stream_reads:install", () => {
        const FileInputStream = safeUse(
            "java.io.FileInputStream",
            "file_system:input_stream_reads"
        );
        const FileDescriptor = safeUse(
            "java.io.FileDescriptor",
            "file_system:input_stream_reads"
        );

        if (!FileInputStream || !FileDescriptor) {
            return;
        }

        function resolveFilePath(stream: any): string {
            let filePath = TraceFS["fd" + stream.hashCode()];

            if (filePath != null) {
                return filePath;
            }

            const descriptor = Java.cast(stream.getFD(), FileDescriptor);
            filePath = TraceFD["fd" + descriptor.hashCode()];

            return filePath || "[unknown]";
        }

        function emitReadEvent(
            stream: any,
            variant: number,
            method: string,
            eventData: any
        ): void {
            let filePath = "[unknown]";

            try {
                filePath = resolveFilePath(stream);
            } catch (error) {
                devlog(`FileInputStream read path resolution failed: ${error}`);
            }

            if (shouldSkipFile(filePath)) {
                return;
            }

            const shouldDumpAscii = isPatternPresent(
                filePath,
                CONFIG.dump_ascii_If_Path_contains
            );
            const shouldDumpHex = !isPatternPresent(
                filePath,
                CONFIG.dump_hex_If_Path_NOT_contains
            );
            const java_stack_trace = collectJavaStackTrace();

            createFileSystemEvent("file.read", {
                operation: "FileInputStream.read",
                variant,
                file_path: filePath,
                method,
                ...eventData,
                data_hex: shouldDumpHex || shouldDumpAscii
                    ? eventData.data_hex
                    : null,
                should_dump_ascii: shouldDumpAscii,
                should_dump_hex: shouldDumpHex,
                ...(java_stack_trace ? { java_stack_trace } : {})
            });
        }

        function installRead(
            overload: any,
            context: string,
            variant: number,
            method: string,
            createEventData: (args: any[], result: number) => any
        ): void {
            if (!overload) {
                return;
            }

            overload.implementation = safeImplementation(
                context,
                overload,
                function (original, ...args: any[]) {
                    const threadId = Process.getCurrentThreadId();
                    const depth = readDepths.get(threadId) || 0;
                    const isNested = depth > 0;
                    readDepths.set(threadId, depth + 1);

                    try {
                        let result;

                        try {
                            result = original.apply(this, args);
                        } catch (error) {
                            throw new PropagateException(error);
                        }

                        if (!isNested) {
                            try {
                                emitReadEvent(
                                    this,
                                    variant,
                                    method,
                                    createEventData(args, result)
                                );
                            } catch (error) {
                                devlog(
                                    `FileInputStream read metadata failed: ${error}`
                                );
                            }
                        }

                        return result;
                    } finally {
                        if (depth === 0) {
                            readDepths.delete(threadId);
                        } else {
                            readDepths.set(threadId, depth);
                        }
                    }
                }
            );
        }

        installRead(
            safeOverload(
                FileInputStream.read,
                "file_system:FileInputStream.read()"
            ),
            "file_system:FileInputStream.read()",
            0,
            "java.io.FileInputStream.read()",
            (_args, result) => {
                const byteValue = result >= 0 ? result : null;

                return {
                    buffer_size: 1,
                    offset: 0,
                    length: 1,
                    bytes_read: byteValue === null ? 0 : 1,
                    byte_value: byteValue,
                    data_hex: byteValue === null
                        ? null
                        : bytesToHexSafe([byteValue])
                };
            }
        );

        installRead(
            safeOverload(
                FileInputStream.read,
                "file_system:FileInputStream.read(byte[])",
                "[B"
            ),
            "file_system:FileInputStream.read(byte[])",
            1,
            "java.io.FileInputStream.read(byte[])",
            (args, result) => {
                const buffer = Java.array("byte", args[0]);

                return {
                    buffer_size: args[0].length,
                    bytes_read: result,
                    data_hex: bytesToHexSafe(buffer)
                };
            }
        );

        installRead(
            safeOverload(
                FileInputStream.read,
                "file_system:FileInputStream.read(byte[],int,int)",
                "[B",
                "int",
                "int"
            ),
            "file_system:FileInputStream.read(byte[],int,int)",
            2,
            "java.io.FileInputStream.read(byte[], int, int)",
            (args, result) => {
                const buffer = Java.array("byte", args[0]);

                return {
                    buffer_size: args[0].length,
                    offset: args[1],
                    length: args[2],
                    bytes_read: result,
                    data_hex: bytesToHexSafe(buffer)
                };
            }
        );
    });
}

function hook_filesystem_accesses() {
    Java.perform(function () {

        var CLS = {
            FileOutputStream: Java.use("java.io.FileOutputStream"),
            FileDescriptor: Java.use("java.io.FileDescriptor")
        };
        var FileOuputStream = {
            new: [
                CLS.FileOutputStream.$init.overload("java.io.File"),
                CLS.FileOutputStream.$init.overload("java.io.File", "boolean"),
                CLS.FileOutputStream.$init.overload("java.io.FileDescriptor"),
                CLS.FileOutputStream.$init.overload("java.lang.String"),
                CLS.FileOutputStream.$init.overload("java.lang.String", "boolean")
            ],
            write: [
                CLS.FileOutputStream.write.overload("[B"),
                CLS.FileOutputStream.write.overload("int"),
                CLS.FileOutputStream.write.overload("[B", "int", "int"),
            ],
        };

        // ============= Hook implementation

        // =============== File Output Stream ============

        FileOuputStream.write[2].implementation = function (a0, a1, a2) {
            var fname = TraceFS["fd" + this.hashCode()];
            var fd = null;
            if (fname == null) {
                fd = Java.cast(this.getFD(), CLS.FileDescriptor);
                fname = TraceFD["fd" + fd.hashCode()]
            }
            if (fname == null) {
                devlog("FileOuputStream.write[2]: fd-->" + fd);
                fname = "[unknown]";
            }

            var result = FileOuputStream.write[2].call(this, a0, a1, a2);

            if (!shouldSkipFile(fname)) {
                // Determine content type for proper processing
                const shouldDumpAscii = isPatternPresent(fname, CONFIG.dump_ascii_If_Path_contains);
                const shouldDumpHex = !isPatternPresent(fname, CONFIG.dump_hex_If_Path_NOT_contains);
                const isLargeData = a2 > CONFIG.max_output_length;
                const java_stack_trace = collectJavaStackTrace();

                // Special handling for different file types
                const isApkDexJar = fname.endsWith(".apk") || fname.endsWith(".dex") || fname.endsWith(".jar");
                const isXmlFile = fname.endsWith(".xml");

                // Send full buffer hex (NO slicing here - Python will truncate using offset+length)
                // We avoid slice() because it causes app freezing on Java arrays in Frida
                createFileSystemEvent("file.write", {
                    operation: "FileOutputStream.write",
                    variant: 2,
                    file_path: fname,
                    buffer_size: a0.length,
                    offset: a1,
                    length: a2,
                    data_hex: (shouldDumpHex || shouldDumpAscii || isApkDexJar || isXmlFile) ? bytesToHexSafe(a0) : null,
                    should_dump_ascii: shouldDumpAscii,
                    should_dump_hex: shouldDumpHex,
                    is_large_data: isLargeData,
                    max_display_length: CONFIG.max_output_length,
                    file_type: isApkDexJar ? "binary" : (isXmlFile ? "xml" : "other"),
                    method: "java.io.FileOutputStream.write(byte[], int, int)",
                    ...(java_stack_trace ? { java_stack_trace } : {})
                });
            }

            return result;
        }
    });
}


function hook_filesystem_deletes(): void {
    var printedPaths: Set<string> = new Set();

    safePerform("file_system:delete:install", () => {
        const File = safeUse("java.io.File", "file_system:delete");
        if (!File) {
            return;
        }

        const deleteOverload = safeOverload(
            File.delete,
            "file_system:File.delete"
        );
        if (!deleteOverload) {
            return;
        }

        deleteOverload.implementation = safeImplementation(
            "file_system:File.delete",
            deleteOverload,
            function (original) {
                const path = this.getAbsolutePath();
                const shouldReport = path.endsWith(".jar") || path.endsWith(".dex");

                if (shouldReport) {
                    printedPaths.add(path); // suppresses the native unlink event generated by File.delete()
                }

                let result;
                try {
                    result = original.call(this);
                } catch (error) {
                    throw new PropagateException(error);
                }

                if (shouldReport) {
                    const java_stack_trace = collectJavaStackTrace();
                    createFileSystemEvent("file.delete.java", {
                        file_path: path,
                        success: result,
                        ...(deactivate_unlink ? { blocked: true } : {}),
                        ...(java_stack_trace ? { java_stack_trace } : {})
                    });
                }

                return result;
            }
        );
    });

    const unlinkPtr = safeResolveExport(null, "unlink", "file_system:unlink");

    if (!unlinkPtr) {
        return;
    }

    if (deactivate_unlink) {
        safeReplaceNoCallThrough(
            unlinkPtr,
            "file_system:unlink.block",
            "int",
            ["pointer"],
            function (pathname) {
                let filePath = "[unknown]";

                try {
                    filePath = pathname.readUtf8String() || "[unknown]";
                } catch (error) {
                    devlog(`file_system:unlink.block path resolution failed: ${error}`);
                }

                if (printedPaths.delete(filePath)) {
                    return 0;
                }

                try {
                    createFileSystemEvent("file.delete.native", {
                        file_path: filePath,
                        success: true,
                        blocked: true
                    });
                } catch (error) {
                    devlog(`file_system:unlink.block event creation failed: ${error}`);
                }

                return 0;
            },
            0
        );

        return;
    }

    safeAttach(unlinkPtr, "file_system:unlink", {
        onEnter(args: any) {
            this.file_path = args[0].readUtf8String() || "[unknown]";
        },
        onLeave(retval: any) {
            const filePath = this.file_path || "[unknown]";

            if (filePath.endsWith("flock") || printedPaths.delete(filePath)) {
                return;
            }

            const native_backtrace = collectNativeBacktrace(this.context);
            createFileSystemEvent("file.delete.native", {
                file_path: filePath,
                success: retval.toInt32() === 0,
                ...(native_backtrace ? { native_backtrace } : {})
            });
        }
    });
}

export function install_file_system_hooks() {
    devlog("\n")
    devlog("install filesystem hooks");

    try {
        hook_file_constructors();
    } catch (error) {
        devlog(`[HOOK] Failed to install file constructor hooks: ${error}`);
    }

    try {
        hook_file_input_stream_constructors();
    } catch (error) {
        devlog(`[HOOK] Failed to install FileInputStream constructor hooks: ${error}`);
    }

    try {
        hook_file_input_stream_reads();
    } catch (error) {
        devlog(`[HOOK] Failed to install FileInputStream read hooks: ${error}`);
    }

    try {
        hook_filesystem_accesses();
    } catch (error) {
        devlog(`[HOOK] Failed to install filesystem access hooks: ${error}`);
    }

    try {
        hook_filesystem_deletes();
    } catch (error) {
        devlog(`[HOOK] Failed to install filesystem delete hooks: ${error}`);
    }
}

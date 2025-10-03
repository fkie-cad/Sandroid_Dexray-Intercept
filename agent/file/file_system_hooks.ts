import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { buffer2ArrayBuffer, b2s, isPatternPresent, byteArray2JString, bytesToHex } from "../utils/misc.js"
import { show_verbose } from "../hooking_profile_loader.js"
import { deactivate_unlink } from "../hooking_profile_loader.js"
import { Java } from "../utils/javalib.js"

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

function hook_filesystem_accesses() {
    var createdFiles: Set<string> = new Set();
    var createdFileStreams: Set<string> = new Set();
    Java.perform(function () {

        var CLS = {
            File: Java.use("java.io.File"),
            FileInputStream: Java.use("java.io.FileInputStream"),
            FileOutputStream: Java.use("java.io.FileOutputStream"),
            String: Java.use("java.lang.String"),
            FileChannel: Java.use("java.nio.channels.FileChannel"),
            FileDescriptor: Java.use("java.io.FileDescriptor"),
            Thread: Java.use("java.lang.Thread"),
            StackTraceElement: Java.use("java.lang.StackTraceElement"),
            AndroidDbSQLite: Java.use("android.database.sqlite.SQLiteDatabase")
        };
        var File = {
            new: [
                CLS.File.$init.overload("java.io.File", "java.lang.String"),
                CLS.File.$init.overload("java.lang.String"),
                CLS.File.$init.overload("java.lang.String", "java.lang.String"),
                CLS.File.$init.overload("java.net.URI"),
            ]
        };
        var FileInputStream = {
            new: [
                CLS.FileInputStream.$init.overload("java.io.File"),
                CLS.FileInputStream.$init.overload("java.io.FileDescriptor"),
                CLS.FileInputStream.$init.overload("java.lang.String"),
            ],
            read: [
                CLS.FileInputStream.read.overload(),
                CLS.FileInputStream.read.overload("[B"),
                CLS.FileInputStream.read.overload("[B", "int", "int"),
            ],
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

        File.new[1].implementation = function (a0) {
            var file_path = a0;
            if (!createdFiles.has(file_path)) {
                if (file_path.length > 2 && !shouldSkipFile(file_path)) {
                    createFileSystemEvent("file.create", {
                        operation: "File.new",
                        variant: 1,
                        file_path: file_path,
                        method: "java.io.File.init(String)"
                    });
                    createdFiles.add(file_path);
                }
            }

            var ret = File.new[1].call(this, file_path);
            TraceFile["f" + this.hashCode()] = file_path;

            return ret;
        }
        File.new[2].implementation = function (a0, a1) {
            var file_path = a0 + "/" + a1;
            if (!createdFiles.has(file_path) && file_path.length > 3 && !shouldSkipFile(file_path)) {
                createFileSystemEvent("file.create", {
                    operation: "File.new",
                    variant: 2,
                    file_path: file_path,
                    parent_path: a0,
                    child_path: a1,
                    method: "java.io.File.init(String, String)"
                });
                createdFiles.add(file_path);
            }

            var ret = File.new[2].call(this, a0, a1);
            TraceFile["f" + this.hashCode()] = file_path;

            return ret;
        }

        FileInputStream.new[0].implementation = function (a0) {
            var file = Java.cast(a0, CLS.File);
            var fname = TraceFile["f" + file.hashCode()];

            if (fname == null) {
                var p = file.getAbsolutePath();
                if (p !== null)
                    fname = TraceFile["f" + file.hashCode()] = p;
            }
            if (fname == null) {
                devlog("FileInputStream.new[0]: p-->" + p);
                devlog("FileInputStream.new[0]: file-->" + file);
                fname = "[unknown]"
                const filePath = file.toString();

                if (isPatternPresent(filePath, ["/"])) {
                    fname = filePath;
                }
            }

            if (!shouldSkipFile(fname)) {
                if (!createdFileStreams.has(fname)) {
                    createFileSystemEvent("file.stream.create", {
                        operation: "FileInputStream.new",
                        variant: 0,
                        file_path: fname,
                        stream_type: "input",
                        method: "java.io.FileInputStream.init(File)"
                    });
                    createdFileStreams.add(fname)
                }
            }

            var fis = FileInputStream.new[0].call(this, a0)
            TraceFS["fd" + this.hashCode()] = fname;

            var fd = Java.cast(this.getFD(), CLS.FileDescriptor);

            TraceFD["fd" + fd.hashCode()] = fname;

            return fis;
        }

        FileInputStream.read[1].implementation = function (a0) {
            var fname = TraceFS["fd" + this.hashCode()];
            var fd = null;
            if (fname == null) {
                fd = Java.cast(this.getFD(), CLS.FileDescriptor);
                fname = TraceFD["fd" + fd.hashCode()]
            }
            if (fname == null) {
                devlog("FileInputStream.read[1]: fd-->" + fd);
                fname = "[unknown]"
            }

            var result = FileInputStream.read[1].call(this, a0);
            var b = Java.array('byte', a0);

            if (!shouldSkipFile(fname)) {
                // Determine content type for proper processing
                const shouldDumpAscii = isPatternPresent(fname, CONFIG.dump_ascii_If_Path_contains);
                const shouldDumpHex = !isPatternPresent(fname, CONFIG.dump_hex_If_Path_NOT_contains);

                // Send full buffer hex (NO slicing here - Python will truncate using bytes_read)
                // We avoid slice() because it causes app freezing on Java arrays in Frida
                createFileSystemEvent("file.read", {
                    operation: "FileInputStream.read",
                    variant: 1,
                    file_path: fname,
                    buffer_size: a0.length,
                    bytes_read: result,
                    data_hex: shouldDumpHex || shouldDumpAscii ? bytesToHexSafe(b) : null,
                    should_dump_ascii: shouldDumpAscii,
                    should_dump_hex: shouldDumpHex,
                    method: "java.io.FileInputStream.read(byte[])"
                });
            }

            return result;
        }
        FileInputStream.read[2].implementation = function (a0, a1, a2) {
            var fname = TraceFS["fd" + this.hashCode()];
            var fd = null;
            if (fname == null) {
                fd = Java.cast(this.getFD(), CLS.FileDescriptor);
                fname = TraceFD["fd" + fd.hashCode()]
            }
            if (fname == null) {
                devlog("FileInputStream.read[2]: fd-->" + fd);
                fname = "[unknown]"
            }

            var result = FileInputStream.read[2].call(this, a0, a1, a2);
            var b = Java.array('byte', a0);

            if (!shouldSkipFile(fname)) {
                // Determine content type for proper processing
                const shouldDumpAscii = isPatternPresent(fname, CONFIG.dump_ascii_If_Path_contains);
                const shouldDumpHex = !isPatternPresent(fname, CONFIG.dump_hex_If_Path_NOT_contains);

                // Send full buffer hex (NO slicing here - Python will truncate using offset+bytes_read)
                // We avoid slice() because it causes app freezing on Java arrays in Frida
                createFileSystemEvent("file.read", {
                    operation: "FileInputStream.read",
                    variant: 2,
                    file_path: fname,
                    buffer_size: a0.length,
                    offset: a1,
                    length: a2,
                    bytes_read: result,
                    data_hex: shouldDumpHex || shouldDumpAscii ? bytesToHexSafe(b) : null,
                    should_dump_ascii: shouldDumpAscii,
                    should_dump_hex: shouldDumpHex,
                    method: "java.io.FileInputStream.read(byte[], int, int)"
                });
            }

            return result;
        }

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
                    method: "java.io.FileOutputStream.write(byte[], int, int)"
                });
            }

            return result;
        }
    });
}


function hook_filesystem_deletes(): void {
    var printedPaths: Set<string> = new Set();

    Java.perform(() => {
        const File = Java.use("java.io.File");
        File.delete.implementation = function () {
            const path = this.getAbsolutePath();
            if (path.includes("jar") || path.endsWith("dex")) {
                createFileSystemEvent("file.delete.java", { file_path: path });
                printedPaths.add(path); // ensures that we don't print the same path multiple times
            }
            return true;
        };
    });

    var unlinkPtr: NativePointer | null = null;
    for (const module of Process.enumerateModules()) {
        try {
            unlinkPtr = module.findExportByName('unlink');
            if (unlinkPtr) break;
        } catch (e) {
            continue;
        }
    }

    if (unlinkPtr) {
        Interceptor.attach(unlinkPtr, {
            onEnter(args: any) {
                var ptr_to_file = ptr(args[0]);
                this.file_path = ptr_to_file.readUtf8String()
            },
            onLeave() {
                if (!this.file_path.endsWith("flock")) {
                    if (!printedPaths.has(this.file_path)) {
                        createFileSystemEvent("file.delete.native", {
                                        file_path: this.file_path
                                    });
                    }
                }
                
            }
        });
    }

    if (deactivate_unlink) {
        var unlink = new NativeFunction(unlinkPtr, 'int', []);
        Interceptor.replace(unlinkPtr, new NativeCallback(function () {
            am_send(PROFILE_HOOKING_TYPE, "unlink() encountered, skipping it.");
            return 0;
        }, 'int', []));
    }
}

export function install_file_system_hooks() {
    devlog("\n")
    devlog("install filesystem hooks");

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

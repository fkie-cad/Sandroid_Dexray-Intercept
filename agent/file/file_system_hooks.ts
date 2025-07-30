import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { hexdump_selfmade, buffer2ArrayBuffer, b2s, isPatternPresent, byteArray2JString } from "../utils/misc.js"
import { show_verbose } from "../hooking_profile_loader.js"
import { deactivate_unlink } from "../hooking_profile_loader.js"
import { Java } from "../utils/javalib.js"

const PROFILE_HOOKING_TYPE: string = "FILE_SYSTEM"

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
    max_output_length: 1024,
    // Color settings
    colors: {
        operation: '\x1b[1;35m',  // Bright magenta for operation names
        path: '\x1b[1;36m',       // Bright cyan for file paths
        parameter: '\x1b[1;33m',  // Bright yellow for parameters
        data: '\x1b[32m',         // Green for data content
        warning: '\x1b[1;31m',    // Bright red for warnings
        reset: '\x1b[0m'          // Reset color
    }
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

function prettyPrint(path, buffer, offset?, length?) {
    if (show_verbose) {
        // Determine maximum output length
        const maxLength = CONFIG.max_output_length || 1024;

        if (isPatternPresent(path, CONFIG.dump_ascii_If_Path_contains)) {
            let output = b2s(buffer);

            // Truncate if too long
            if (output.length > maxLength) {
                const truncated = output.substring(0, maxLength);
                return CONFIG.colors.data + truncated + CONFIG.colors.reset +
                    "\n" + CONFIG.colors.warning +
                    `[Output truncated, showing ${maxLength} of ${output.length} bytes]` +
                    CONFIG.colors.reset;
            }
            return CONFIG.colors.data + output + CONFIG.colors.reset;
        }
        else if (!isPatternPresent(path, CONFIG.dump_hex_If_Path_NOT_contains)) {
            // For hexdump, we need to limit based on buffer size
            let bufferToUse = buffer;
            let truncationMessage = "";

            // If buffer is too large, truncate it
            if (buffer.length > maxLength) {
                // Create a smaller buffer with limited size
                bufferToUse = new Uint8Array(buffer).slice(0, maxLength);
                truncationMessage = "\n" + CONFIG.colors.warning +
                    `[Output truncated, showing ${maxLength} of ${buffer.length} bytes]` +
                    CONFIG.colors.reset;
            }

            return CONFIG.colors.data + hexdump_selfmade(b2s(bufferToUse), 16) +
                CONFIG.colors.reset + truncationMessage;
        }
        return CONFIG.colors.warning + "[dump skipped by config]" + CONFIG.colors.reset;
    }
    return CONFIG.colors.warning + "[dump skipped by verbose level]" + CONFIG.colors.reset;
}

function createFileSystemEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
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
                if (file_path.length > 2 && isFileFromInterest(file_path)) {
                    am_send(PROFILE_HOOKING_TYPE,
                        CONFIG.colors.operation + "[Java::File.new.1]" + CONFIG.colors.reset +
                        " New file: " + CONFIG.colors.path + file_path + CONFIG.colors.reset + "\n");
                    createdFiles.add(file_path);
                }
            }

            var ret = File.new[1].call(this, file_path);
            TraceFile["f" + this.hashCode()] = file_path;

            return ret;
        }
        File.new[2].implementation = function (a0, a1) {
            var file_path = a0 + "/" + a1;
            if (!createdFiles.has(file_path) && file_path.length > 3 && isFileFromInterest(file_path)) {
                am_send(PROFILE_HOOKING_TYPE,
                    CONFIG.colors.operation + "[Java::File.new.2]" + CONFIG.colors.reset +
                    " New file: " + CONFIG.colors.path + file_path + CONFIG.colors.reset + "\n");
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

            if (isFileFromInterest(fname)) {
                if (!createdFileStreams.has(fname)) {
                    am_send(PROFILE_HOOKING_TYPE,
                        CONFIG.colors.operation + "[Java::FileInputStream.new.0]" + CONFIG.colors.reset +
                        " New input stream from file: " + CONFIG.colors.path + fname + CONFIG.colors.reset);
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

            var b = Java.array('byte', a0);

            if (isFileFromInterest(fname)) {
                am_send(PROFILE_HOOKING_TYPE,
                    CONFIG.colors.operation + "[Java::FileInputStream.read.1]" + CONFIG.colors.reset +
                    " Read from file, offset (" + CONFIG.colors.path + fname + CONFIG.colors.reset + ", " +
                    CONFIG.colors.parameter + a0 + CONFIG.colors.reset + "):\n" + prettyPrint(fname, b));
            }

            return FileInputStream.read[1].call(this, a0);
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

            var b = Java.array('byte', a0);

            if (isFileFromInterest(fname)) {
                am_send(PROFILE_HOOKING_TYPE,
                    CONFIG.colors.operation + "[Java::FileInputStream.read.2]" + CONFIG.colors.reset +
                    " Read from file, offset, len (" + CONFIG.colors.path + fname + CONFIG.colors.reset + ", " +
                    CONFIG.colors.parameter + a1 + CONFIG.colors.reset + ", " +
                    CONFIG.colors.parameter + a2 + CONFIG.colors.reset + ")\n" + prettyPrint(fname, b));
            }

            return FileInputStream.read[2].call(this, a0, a1, a2);
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

            if (isFileFromInterest(fname)) {
                var displayLen = Math.min(a2, CONFIG.max_output_length);
                var isTruncated = displayLen < a2;

                var message = CONFIG.colors.operation + "[Java::FileOuputStream.write.2]" + CONFIG.colors.reset +
                    " Write " + CONFIG.colors.parameter + a2 + CONFIG.colors.reset +
                    " bytes from offset " + CONFIG.colors.parameter + a1 + CONFIG.colors.reset +
                    " to " + CONFIG.colors.path + fname + CONFIG.colors.reset;

                if (isTruncated) {
                    message += " " + CONFIG.colors.warning +
                        "[Showing first " + displayLen + " of " + a2 + " bytes]" +
                        CONFIG.colors.reset;
                }
                message += ":\n";

                am_send(PROFILE_HOOKING_TYPE, message);

                if (fname.endsWith(".apk") || fname.endsWith(".dex") || fname.endsWith(".jar")) {
                    var arrayBuffer = buffer2ArrayBuffer(a0);
                    console.log(hexdump(arrayBuffer, {
                        offset: a1,
                        length: displayLen,
                        header: true,
                        ansi: true
                    }));
                }
                else if (fname.endsWith(".xml")) {
                    var result = Java.array('byte', a0);
                    const JString = Java.use('java.lang.String');
                    const fullStr = JString.$new(result);

                    const displayStr = fullStr.length() > displayLen ?
                        fullStr.substring(0, displayLen) +
                        CONFIG.colors.warning + "... [truncated]" + CONFIG.colors.reset :
                        fullStr;

                    am_send(PROFILE_HOOKING_TYPE, CONFIG.colors.data + displayStr + CONFIG.colors.reset);
                }
                else {
                    am_send(PROFILE_HOOKING_TYPE, prettyPrint(fname, a0));
                }
            }

            return FileOuputStream.write[2].call(this, a0, a1, a2);
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
    hook_filesystem_accesses();
    hook_filesystem_deletes();
}

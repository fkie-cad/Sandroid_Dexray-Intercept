package com.test.filee2e;

// JNI bridge for native unlink() trigger.
// Exercises the unlink hook in file_system_hooks.ts.
public class FileDeleteNative {
    static {
        System.loadLibrary("file_delete_native");
    }

    public static native int unlinkFile(String path);
}
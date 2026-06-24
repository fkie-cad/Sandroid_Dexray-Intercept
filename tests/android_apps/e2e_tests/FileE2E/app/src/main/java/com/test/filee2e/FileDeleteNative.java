package com.test.filee2e;

// JNI bridge for native unlink() trigger.
// Exercises the safeAttach hook on "unlink" in file_system_hooks.ts.
public class FileDeleteNative {
    static {
        System.loadLibrary("file_delete_native");
    }

    public static native void unlinkFile(String path);
}
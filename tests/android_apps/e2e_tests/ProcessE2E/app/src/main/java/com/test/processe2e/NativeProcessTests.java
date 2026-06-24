package com.test.processe2e;

import android.util.Log;

// Triggers native hooks in process.ts and nativelibrary.ts via NativeEntry:
//   fork()    -> process.fork.attempt, process.fork.result (parent only)
//   execve()  -> process.execve.attempt (child, before exec);
//               process.execve.result fires only on execve failure - on success
//               the child image is replaced and onLeave never returns
//   system()  -> process.system.call, process.system.result
//   dlopen()  -> native.library.load, native.library.loaded
//               android_dlopen_ext may also fire if the dynamic linker routes
//               through it internally on API 24+ for app-side dlopen calls
public class NativeProcessTests {

    private static final String TAG = "PROCESS_RUNTIME_E2E";
    private int passed = 0;
    private int failed = 0;

    public void runTests() {
        testNativeProcessOps();
        Log.i(TAG, "NativeProcessTests summary: " + passed + " passed, " + failed + " failed");
    }

    private void testNativeProcessOps() {
        try {
            NativeEntry.runNativeProcessTests();
            Log.i(TAG, "NativeEntry.runNativeProcessTests: ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "NativeEntry.runNativeProcessTests failed", t);
            failed++;
        }
    }
}
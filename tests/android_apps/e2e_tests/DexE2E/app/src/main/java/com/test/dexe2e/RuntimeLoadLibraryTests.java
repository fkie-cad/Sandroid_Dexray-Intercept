package com.test.dexe2e;

import android.content.Context;
import android.util.Log;

/**
 * Covers:
 *   load_library.ts -> install_runtime_library_hooks() ->
 *     Runtime.load(String)          - full filesystem path to .so
 *     Runtime.loadLibrary(String)   - bare library name
 *
 * Runtime.load / Runtime.loadLibrary are the instance-method equivalents of
 * System.load / System.loadLibrary. System delegates internally to Runtime,
 * but the hooks are on separate method objects so both sets need independent
 * triggering.
 *
 * By the time RuntimeLoadLibraryTests runs, libdexe2e_native.so is already
 * loaded by SystemLoadLibraryTests.test_system_load(). Both calls here are
 * linker no-ops but the Java methods are called so both hooks fire.
 *
 * Repeated runs in the same process: same "already opened" condition applies
 * as in SystemLoadLibraryTests - caught and treated as a pass for the same
 * reason. See SystemLoadLibraryTests class JSDoc for full explanation.
 *
 * Expected events:
 *   library.runtime.load_library   (method: "Runtime.loadLibrary(String)")
 *   library.runtime.load           (method: "Runtime.load(String)")
 */
public class RuntimeLoadLibraryTests {

    private static final String TAG = "DEX_RT_LOADLIB";

    private int passed = 0;
    private int failed = 0;
    private final Context context;

    public RuntimeLoadLibraryTests(Context context) {
        this.context = context;
    }

    private void pass(String name) {
        Log.i(TAG, "  PASS: " + name);
        passed++;
    }

    private void fail(String name, String reason) {
        Log.e(TAG, "  FAIL: " + name + " - " + reason);
        failed++;
    }

    public void runTests() {
        Log.i(TAG, "========================================");
        Log.i(TAG, "RuntimeLoadLibraryTests: starting");
        Log.i(TAG, "========================================");

        // loadLibrary must run before load so the library is mapped
        // and resolveNativeLibPath can find it in /proc/self/maps
        test_runtime_load_library();
        test_runtime_load();

        Log.i(TAG, "========================================");
        Log.i(TAG, "RuntimeLoadLibraryTests summary: " + passed + " passed, " + failed + " failed");
        Log.i(TAG, "========================================");
    }

    private void test_runtime_load_library() {
        Log.i(TAG, "");
        Log.i(TAG, "=== Runtime.loadLibrary(String) ===");

        try {
            // Library already loaded by SystemLoadLibraryTests - linker no-ops,
            // but the Java method call is made and the hook fires
            Runtime.getRuntime().loadLibrary("dexe2e_native");
            pass("Runtime.getRuntime().loadLibrary(\"dexe2e_native\")");
        } catch (Throwable t) {
            fail("Runtime.loadLibrary(\"dexe2e_native\")", t.toString());
        }
    }

    private void test_runtime_load() {
        Log.i(TAG, "");
        Log.i(TAG, "=== Runtime.load(String) ===");

        // Resolve the real filesystem path of the already-loaded library.
        // Works for both extracted and APK-embedded (non-extracted) cases.
        String libPath = DexTestUtils.resolveNativeLibPath(context, "dexe2e_native");
        if (libPath == null) {
            fail("resolveNativeLibPath(dexe2e_native)", "returned null");
            return;
        }
        Log.i(TAG, "Resolved library path: " + libPath);

        try {
            // Library is already loaded - linker no-ops, but the Java method
            // call is made and the hook fires
            Runtime.getRuntime().load(libPath);
            pass("Runtime.getRuntime().load(\"" + libPath + "\")");
        } catch (UnsatisfiedLinkError e) {
            if (e.getMessage() != null && e.getMessage().contains("already")) {
                // Same process reused between runs - see SystemLoadLibraryTests JSDoc
                pass("Runtime.getRuntime().load(\"" + libPath + "\") - already loaded in this process (hook fired)");
                Log.i(TAG, "Note: force-stop app between runs to reset linker state");
            } else {
                fail("Runtime.load(libPath)", e.toString());
            }
        } catch (Throwable t) {
            fail("Runtime.load(libPath)", t.toString());
        }
    }
}
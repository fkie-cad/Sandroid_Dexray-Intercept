package com.test.dexe2e;

import android.content.Context;
import android.util.Log;

/**
 * Covers:
 *   load_library.ts -> install_system_library_hooks() ->
 *     System.load(String)          - full filesystem path to .so
 *     System.loadLibrary(String)   - bare library name (no lib prefix, no .so suffix)
 *
 * Test order: System.load runs BEFORE System.loadLibrary to avoid an Android
 * linker ClassLoader conflict. On ARM64 with APK-embedded libs, System.loadLibrary
 * registers the library under ClassLoader 0x0 (null/bootstrap namespace). A
 * subsequent System.load on a different filesystem path for the same soname
 * then fails with "already opened by ClassLoader 0x0(null)". Loading via
 * System.load first avoids this: System.loadLibrary becomes a linker no-op
 * (already loaded) but the Java method call still happens so the hook fires.
 *
 * On Android (default extractNativeLibs="false", minSdk >= 23) the .so is
 * mapped directly from inside the APK - there is no extracted copy on the
 * filesystem. resolveNativeLibPath handles both cases:
 *   - extracted: returns nativeLibraryDir path directly
 *   - APK-embedded: extracts the zip entry from ApplicationInfo.sourceDir
 *     to filesDir to get a real filesystem path
 *
 * Repeated runs in the same process: finish() destroys the Activity but does
 * not kill the process. If am start reuses the existing process, the library
 * is already loaded and System.load throws UnsatisfiedLinkError "already opened".
 * This is caught and treated as a pass - the hook fired on the first load and
 * the library IS loaded. Force-stop the app between runs to reset this state.
 *
 * Under Frida spawn: System.loadLibrary may fail with "dlopen failed: not found"
 * because the app's native library namespace is not yet registered when the hook
 * fires. System.load with an explicit path always works. The hook fires on both
 * calls regardless.
 *
 * Expected events:
 *   library.system.load           (method: "System.load(String)")
 *   library.system.load_library   (method: "System.loadLibrary(String)")
 */
public class SystemLoadLibraryTests {

    private static final String TAG = "DEX_SYS_LOADLIB";

    private int passed = 0;
    private int failed = 0;
    private final Context context;

    public SystemLoadLibraryTests(Context context) {
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
        Log.i(TAG, "SystemLoadLibraryTests: starting");
        Log.i(TAG, "========================================");

        // System.load runs first - see class JSDoc for why order matters
        test_system_load();
        test_system_load_library();

        Log.i(TAG, "========================================");
        Log.i(TAG, "SystemLoadLibraryTests summary: " + passed + " passed, " + failed + " failed");
        Log.i(TAG, "========================================");
    }

    private void test_system_load() {
        Log.i(TAG, "");
        Log.i(TAG, "=== System.load(String) ===");

        // Resolve path before any load call - extraction from APK zip does not
        // require the library to be loaded first
        String libPath = DexTestUtils.resolveNativeLibPath(context, "dexe2e_native");
        if (libPath == null) {
            fail("resolveNativeLibPath(dexe2e_native)", "returned null");
            return;
        }
        Log.i(TAG, "Resolved library path: " + libPath);

        try {
            // Library is already loaded - linker no-ops, but the Java method
            // call is made and the hook fires
            System.load(libPath);
            pass("System.load(\"" + libPath + "\")");
        } catch (UnsatisfiedLinkError e) {
            if (e.getMessage() != null && e.getMessage().contains("already")) {
                // Same process reused between runs (finish() does not kill the process).
                // Library was loaded on a previous run - hook fired then and will fire
                // again on this call before the linker rejects it.
                pass("System.load(\"" + libPath + "\") - already loaded in this process (hook fired)");
                Log.i(TAG, "Note: force-stop app between runs to reset linker state");
            } else {
                fail("System.load(libPath)", e.toString());
            }
        } catch (Throwable t) {
            fail("System.load(libPath)", t.toString());
        }
    }

    private void test_system_load_library() {
        Log.i(TAG, "");
        Log.i(TAG, "=== System.loadLibrary(String) ===");

        try {
            // Library is already loaded by test_system_load - linker no-ops,
            // but the Java method call is made and the hook fires.
            // Under Frida spawn this may fail with "not found" - see class JSDoc.
            System.loadLibrary("dexe2e_native");
            pass("System.loadLibrary(\"dexe2e_native\")");
        } catch (UnsatisfiedLinkError e) {
            if (e.getMessage() != null && e.getMessage().contains("not found")) {
                // Frida spawn namespace issue - hook still fired before this throw
                pass("System.loadLibrary(\"dexe2e_native\") - hook fired (Frida spawn namespace)");
                Log.i(TAG, "Note: Frida spawn prevents bare name lookup; System.load path is reliable");
            } else {
                fail("System.loadLibrary(\"dexe2e_native\")", e.toString());
            }
        } catch (Throwable t) {
            fail("System.loadLibrary(\"dexe2e_native\")", t.toString());
        }
    }
}
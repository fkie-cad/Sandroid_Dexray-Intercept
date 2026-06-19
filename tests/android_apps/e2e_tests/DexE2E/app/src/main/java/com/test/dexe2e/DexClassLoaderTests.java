package com.test.dexe2e;

import android.content.Context;
import android.util.Log;
import dalvik.system.DexClassLoader;

import java.io.File;

/**
 * Covers:
 *   dex_unpacking.ts -> dex_api_unpacking() ->
 *     DexClassLoader.$init(String, String, String, ClassLoader)
 *
 * Also exercises the native OpenMemory/OpenCommon safeAttach hook in dumpDex()
 * which fires automatically when ART parses the DEX buffer.
 *
 * Expected events:
 *   dex.classloader.creation  (class_loader_type: "DexClassLoader")
 *   dex.file_copy
 *   dex.unpacking.detected    (from native hook)
 */
public class DexClassLoaderTests {

    private static final String TAG = "DEX_CLASS_LOADER";

    private int passed = 0;
    private int failed = 0;
    private final Context context;

    public DexClassLoaderTests(Context context) {
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
        Log.i(TAG, "DexClassLoaderTests: starting");
        Log.i(TAG, "========================================");

        test_dex_class_loader_init();

        Log.i(TAG, "========================================");
        Log.i(TAG, "DexClassLoaderTests summary: " + passed + " passed, " + failed + " failed");
        Log.i(TAG, "========================================");
    }

    private void test_dex_class_loader_init() {
        Log.i(TAG, "");
        Log.i(TAG, "=== DexClassLoader.$init(String, String, String, ClassLoader) ===");

        // Copy asset to writable location - classloader constructors require a real file path
        File dexFile = DexTestUtils.copyAsset(context, "test_classes.dex");
        if (dexFile == null) {
            fail("copyAsset(test_classes.dex)", "returned null");
            return;
        }
        Log.i(TAG, "DEX asset path: " + dexFile.getAbsolutePath());

        // optimizedDirectory must be writable; codeCacheDir is the standard choice
        File optimizedDir = context.getCodeCacheDir();

        try {
            DexClassLoader loader = new DexClassLoader(
                dexFile.getAbsolutePath(),
                optimizedDir.getAbsolutePath(),
                null,
                getClass().getClassLoader()
            );
            pass("DexClassLoader.$init created: " + loader.getClass().getSimpleName());

            // Verify the loaded DEX is usable by resolving the test class
            try {
                Class<?> payload = loader.loadClass("TestPayload");
                pass("loadClass(TestPayload) resolved: " + payload.getName());
            } catch (ClassNotFoundException e) {
                fail("loadClass(TestPayload)", e.getMessage());
            }
        } catch (Throwable t) {
            fail("DexClassLoader.$init", t.toString());
        }
    }
}
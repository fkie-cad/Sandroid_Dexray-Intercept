package com.test.dexe2e;

import android.content.Context;
import android.util.Log;
import dalvik.system.PathClassLoader;

import java.io.File;

/**
 * Covers:
 *   dex_unpacking.ts -> dex_api_unpacking() ->
 *     PathClassLoader.$init(String, ClassLoader)                  - 2-arg overload
 *     PathClassLoader.$init(String, String, ClassLoader)          - 3-arg overload
 *
 * Expected events per construction:
 *   dex.classloader.creation  (class_loader_type: "PathClassLoader")
 *   dex.file_copy
 *   dex.unpacking.detected    (from native hook)
 */
public class PathClassLoaderTests {

    private static final String TAG = "DEX_PATH_LOADER";

    private int passed = 0;
    private int failed = 0;
    private final Context context;

    public PathClassLoaderTests(Context context) {
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
        Log.i(TAG, "PathClassLoaderTests: starting");
        Log.i(TAG, "========================================");

        File dexFile = DexTestUtils.copyAsset(context, "test_classes.dex");
        if (dexFile == null) {
            fail("copyAsset(test_classes.dex)", "returned null");
            Log.i(TAG, "PathClassLoaderTests summary: " + passed + " passed, " + failed + " failed");
            return;
        }
        Log.i(TAG, "DEX asset path: " + dexFile.getAbsolutePath());

        test_path_class_loader_2arg(dexFile);
        test_path_class_loader_3arg(dexFile);

        Log.i(TAG, "========================================");
        Log.i(TAG, "PathClassLoaderTests summary: " + passed + " passed, " + failed + " failed");
        Log.i(TAG, "========================================");
    }

    private void test_path_class_loader_2arg(File dexFile) {
        Log.i(TAG, "");
        Log.i(TAG, "=== PathClassLoader.$init(String, ClassLoader) ===");

        try {
            PathClassLoader loader = new PathClassLoader(
                dexFile.getAbsolutePath(),
                getClass().getClassLoader()
            );
            pass("PathClassLoader.$init(2-arg) created: " + loader.getClass().getSimpleName());
        } catch (Throwable t) {
            fail("PathClassLoader.$init(2-arg)", t.toString());
        }
    }

    private void test_path_class_loader_3arg(File dexFile) {
        Log.i(TAG, "");
        Log.i(TAG, "=== PathClassLoader.$init(String, String, ClassLoader) ===");

        try {
            // librarySearchPath null is valid - no native lib search path needed
            PathClassLoader loader = new PathClassLoader(
                dexFile.getAbsolutePath(),
                null,
                getClass().getClassLoader()
            );
            pass("PathClassLoader.$init(3-arg) created: " + loader.getClass().getSimpleName());
        } catch (Throwable t) {
            fail("PathClassLoader.$init(3-arg)", t.toString());
        }
    }
}
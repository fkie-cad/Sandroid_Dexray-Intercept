package com.test.dexe2e;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import java.io.File;
import java.lang.reflect.Constructor;

/**
 * Covers:
 *   dex_unpacking.ts -> dex_api_unpacking() ->
 *     DelegateLastClassLoader.$init(String, ClassLoader)                     - 2-arg
 *     DelegateLastClassLoader.$init(String, String, ClassLoader)             - 3-arg
 *     DelegateLastClassLoader.$init(String, String, ClassLoader, boolean)    - 4-arg, API 29+
 *
 * DelegateLastClassLoader is not in the public Android SDK, so all three
 * constructors are accessed via reflection. This mirrors what the hook itself
 * sees at runtime - the class is always present on API 27+ regardless of
 * SDK visibility.
 *
 * Expected events per construction:
 *   dex.classloader.creation  (class_loader_type: "DelegateLastClassLoader")
 *   dex.file_copy
 *   dex.unpacking.detected    (from native hook)
 */
public class DelegateLastClassLoaderTests {

    private static final String TAG = "DEX_DELEGATE_LOADER";
    private static final String CLASS_NAME = "dalvik.system.DelegateLastClassLoader";

    private int passed = 0;
    private int failed = 0;
    private final Context context;

    public DelegateLastClassLoaderTests(Context context) {
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
        Log.i(TAG, "DelegateLastClassLoaderTests: starting");
        Log.i(TAG, "========================================");

        // DelegateLastClassLoader was added in API 27
        if (Build.VERSION.SDK_INT < 27) {
            Log.i(TAG, "Skipping - DelegateLastClassLoader requires API 27+ (device is API " + Build.VERSION.SDK_INT + ")");
            Log.i(TAG, "========================================");
            Log.i(TAG, "DelegateLastClassLoaderTests summary: " + passed + " passed, " + failed + " failed");
            Log.i(TAG, "========================================");
            return;
        }

        File dexFile = DexTestUtils.copyAsset(context, "test_classes.dex");
        if (dexFile == null) {
            fail("copyAsset(test_classes.dex)", "returned null");
            Log.i(TAG, "DelegateLastClassLoaderTests summary: " + passed + " passed, " + failed + " failed");
            return;
        }
        Log.i(TAG, "DEX asset path: " + dexFile.getAbsolutePath());

        Class<?> clazz = resolveClass();
        if (clazz == null) return;

        test_delegate_2arg(clazz, dexFile);
        test_delegate_3arg(clazz, dexFile);

        // 4-arg overload (String, String, ClassLoader, boolean) added in API 29
        if (Build.VERSION.SDK_INT >= 29) {
            test_delegate_4arg(clazz, dexFile);
        } else {
            Log.i(TAG, "Skipping 4-arg overload - requires API 29+ (device is API " + Build.VERSION.SDK_INT + ")");
        }

        Log.i(TAG, "========================================");
        Log.i(TAG, "DelegateLastClassLoaderTests summary: " + passed + " passed, " + failed + " failed");
        Log.i(TAG, "========================================");
    }

    private Class<?> resolveClass() {
        try {
            return Class.forName(CLASS_NAME);
        } catch (ClassNotFoundException e) {
            fail("Class.forName(DelegateLastClassLoader)", e.getMessage());
            return null;
        }
    }

    private void test_delegate_2arg(Class<?> clazz, File dexFile) {
        Log.i(TAG, "");
        Log.i(TAG, "=== DelegateLastClassLoader.$init(String, ClassLoader) ===");

        try {
            Constructor<?> ctor = clazz.getConstructor(String.class, ClassLoader.class);
            Object loader = ctor.newInstance(
                dexFile.getAbsolutePath(),
                getClass().getClassLoader()
            );
            pass("DelegateLastClassLoader.$init(2-arg) created: " + loader.getClass().getSimpleName());
        } catch (Throwable t) {
            fail("DelegateLastClassLoader.$init(2-arg)", t.toString());
        }
    }

    private void test_delegate_3arg(Class<?> clazz, File dexFile) {
        Log.i(TAG, "");
        Log.i(TAG, "=== DelegateLastClassLoader.$init(String, String, ClassLoader) ===");

        try {
            Constructor<?> ctor = clazz.getConstructor(String.class, String.class, ClassLoader.class);
            Object loader = ctor.newInstance(
                dexFile.getAbsolutePath(),
                null,                                // librarySearchPath - null is valid
                getClass().getClassLoader()
            );
            pass("DelegateLastClassLoader.$init(3-arg) created: " + loader.getClass().getSimpleName());
        } catch (Throwable t) {
            fail("DelegateLastClassLoader.$init(3-arg)", t.toString());
        }
    }

    private void test_delegate_4arg(Class<?> clazz, File dexFile) {
        Log.i(TAG, "");
        Log.i(TAG, "=== DelegateLastClassLoader.$init(String, String, ClassLoader, boolean) ===");

        try {
            Constructor<?> ctor = clazz.getConstructor(
                String.class, String.class, ClassLoader.class, boolean.class
            );
            Object loader = ctor.newInstance(
                dexFile.getAbsolutePath(),
                null,                                // librarySearchPath
                getClass().getClassLoader(),
                true                                 // resourceLoading
            );
            pass("DelegateLastClassLoader.$init(4-arg) created: " + loader.getClass().getSimpleName());
        } catch (Throwable t) {
            fail("DelegateLastClassLoader.$init(4-arg)", t.toString());
        }
    }
}
package com.test.dexe2e;

import android.content.Context;
import android.util.Log;
import dalvik.system.InMemoryDexClassLoader;

import java.nio.ByteBuffer;

/**
 * Covers:
 *   dex_unpacking.ts -> dex_api_unpacking() ->
 *     InMemoryDexClassLoader.$init(ByteBuffer, ClassLoader)
 *
 * The same test_classes.dex asset used by the file-path classloader tests
 * is read into a ByteBuffer here - no additional asset required.
 *
 * Expected events:
 *   dex.in_memory_loader   (buffer_size = DEX file size in bytes)
 *   dex.memory_dump        (file_name = /data/data/<pkg>/dump.dex)
 *   dex.dump_success       (bytes_written = buffer_size)
 *     OR dex.dump_error    (if remaining bytes > 0 after write)
 */
public class InMemoryDexClassLoaderTests {

    private static final String TAG = "DEX_INMEM_LOADER";

    private int passed = 0;
    private int failed = 0;
    private final Context context;

    public InMemoryDexClassLoaderTests(Context context) {
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
        Log.i(TAG, "InMemoryDexClassLoaderTests: starting");
        Log.i(TAG, "========================================");

        test_in_memory_dex_class_loader();
        test_in_memory_dex_class_loader_multi_buffer();

        Log.i(TAG, "========================================");
        Log.i(TAG, "InMemoryDexClassLoaderTests summary: " + passed + " passed, " + failed + " failed");
        Log.i(TAG, "========================================");
    }

    private void test_in_memory_dex_class_loader() {
        Log.i(TAG, "");
        Log.i(TAG, "=== InMemoryDexClassLoader.$init(ByteBuffer, ClassLoader) ===");

        // Read the DEX asset into a byte array, then wrap in a direct ByteBuffer.
        // A fresh buffer is required each time because the hook reads and
        // consumes the buffer's remaining bytes during the dump.
        byte[] dexBytes = DexTestUtils.readAssetBytes(context, "test_classes.dex");
        if (dexBytes == null) {
            fail("readAssetBytes(test_classes.dex)", "returned null");
            return;
        }
        Log.i(TAG, "DEX bytes read: " + dexBytes.length + " bytes");

        ByteBuffer buffer = ByteBuffer.wrap(dexBytes);

        try {
            InMemoryDexClassLoader loader = new InMemoryDexClassLoader(
                buffer,
                getClass().getClassLoader()
            );
            pass("InMemoryDexClassLoader.$init created: " + loader.getClass().getSimpleName());

            // Verify the in-memory DEX is usable
            try {
                Class<?> payload = loader.loadClass("TestPayload");
                pass("loadClass(TestPayload) resolved: " + payload.getName());
            } catch (ClassNotFoundException e) {
                fail("loadClass(TestPayload)", e.getMessage());
            }
        } catch (Throwable t) {
            fail("InMemoryDexClassLoader.$init", t.toString());
        }
    }

    private void test_in_memory_dex_class_loader_multi_buffer() {
        Log.i(TAG, "");
        Log.i(TAG, "=== InMemoryDexClassLoader.$init(ByteBuffer[], ClassLoader) ===");

        // Multi-buffer constructor added in API 27.
        // Not yet hooked in dex_unpacking.ts - trigger present for future hook coverage.
        if (android.os.Build.VERSION.SDK_INT < 27) {
            Log.i(TAG, "Skipping - multi-buffer constructor requires API 27+ (device is API "
                    + android.os.Build.VERSION.SDK_INT + ")");
            return;
        }

        byte[] dexBytes = DexTestUtils.readAssetBytes(context, "test_classes.dex");
        if (dexBytes == null) {
            fail("readAssetBytes(test_classes.dex) for multi-buffer", "returned null");
            return;
        }
        Log.i(TAG, "DEX bytes read for multi-buffer: " + dexBytes.length + " bytes");

        ByteBuffer buffer = ByteBuffer.wrap(dexBytes);

        try {
            InMemoryDexClassLoader loader = new InMemoryDexClassLoader(
                new ByteBuffer[]{ buffer },
                getClass().getClassLoader()
            );
            pass("InMemoryDexClassLoader.$init(ByteBuffer[], ClassLoader) created: "
                    + loader.getClass().getSimpleName());

            try {
                Class<?> payload = loader.loadClass("TestPayload");
                pass("loadClass(TestPayload) from multi-buffer loader resolved: " + payload.getName());
            } catch (ClassNotFoundException e) {
                fail("loadClass(TestPayload) from multi-buffer loader", e.getMessage());
            }
        } catch (Throwable t) {
            fail("InMemoryDexClassLoader.$init(ByteBuffer[], ClassLoader)", t.toString());
        }
    }
}
package com.test.dexe2e;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Shared helpers for DEX test modules.
 *
 * copyAsset - copies an asset file to the app's private files directory
 *   and returns the destination File. Multiple test classes need a
 *   writable file-system path for classloader constructors, so this
 *   lives here rather than being duplicated per test class.
 */
public class DexTestUtils {

    private static final String TAG = "DEX_E2E_UTILS";

    /**
     * Copy an asset to the app's private files directory.
     * Returns the destination File on success, null on failure.
     * Safe to call repeatedly - overwrites an existing copy each time.
     */
    public static File copyAsset(Context context, String assetName) {
        File dest = new File(context.getFilesDir(), assetName);
        try (InputStream is  = context.getAssets().open(assetName);
             FileOutputStream fos = new FileOutputStream(dest)) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = is.read(buf)) != -1) {
                fos.write(buf, 0, n);
            }
            return dest;
        } catch (IOException e) {
            Log.e(TAG, "copyAsset failed for " + assetName, e);
            return null;
        }
    }

    /**
     * Read an asset into a fresh byte array.
     * Used by InMemoryDexClassLoaderTests to get a ByteBuffer of the DEX.
     * Returns null on failure.
     */
    public static byte[] readAssetBytes(Context context, String assetName) {
        try (InputStream is = context.getAssets().open(assetName)) {
            byte[] bytes = new byte[is.available()];
            int total = 0;
            int n;
            while ((n = is.read(bytes, total, bytes.length - total)) != -1) {
                total += n;
                if (total == bytes.length) break;
            }
            return bytes;
        } catch (IOException e) {
            Log.e(TAG, "readAssetBytes failed for " + assetName, e);
            return null;
        }
    }
}
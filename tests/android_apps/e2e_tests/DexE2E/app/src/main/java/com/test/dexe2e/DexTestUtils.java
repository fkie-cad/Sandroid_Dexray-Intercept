package com.test.dexe2e;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Shared helpers for DEX test modules.
 *
 * copyAsset            - copies an asset file to the app's private files directory
 *                        and returns the destination File. Multiple test classes need
 *                        a writable file-system path for classloader constructors.
 *
 * readAssetBytes       - reads an asset into a byte array. Used by
 *                        InMemoryDexClassLoaderTests to get a ByteBuffer of the DEX.
 *
 * resolveNativeLibPath - resolves the on-disk path of a native library after it
 *                        has already been loaded via loadLibrary. Handles both the
 *                        extracted case (nativeLibraryDir) and the non-extracted case
 *                        (APK-embedded, Android default since API 23), where the .so
 *                        is mapped directly from inside the APK zip and has no
 *                        standalone filesystem path until we extract it ourselves.
 *
 *                        Must be called AFTER System.loadLibrary / Runtime.loadLibrary
 *                        has succeeded, because that guarantees the .so exists inside
 *                        the APK at the expected path.
 */
public class DexTestUtils {

    private static final String TAG = "DEX_E2E_UTILS";

    // --- Asset helpers --------------------------------------------------------

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

    // --- Native library path resolution ---------------------------------------

    /**
     * Resolve the filesystem path of a native library.
     *
     * Two cases handled:
     *
     *   1. extractNativeLibs="true" -> the .so was extracted to nativeLibraryDir
     *      at install time. File.exists() succeeds; return that path directly.
     *
     *   2. extractNativeLibs="false" (Android default for minSdk >= 23) -> the
     *      .so is mapped directly from inside the APK zip without extraction.
     *      /proc/self/maps shows base.apk entries but does NOT annotate individual
     *      .so names on Android 11+, so maps-scanning is unreliable. Instead:
     *      locate the APK via ApplicationInfo.sourceDir (always valid), find the
     *      zip entry for the correct ABI, and extract it to filesDir.
     *
     * Can be called before or after loadLibrary - extraction from the APK zip
     * does not require the library to be loaded first.
     *
     * @param context  app context
     * @param libName  bare library name without "lib" prefix and ".so" suffix
     * @return         absolute filesystem path, or null on failure
     */
    public static String resolveNativeLibPath(Context context, String libName) {
        String soName = "lib" + libName + ".so";

        // Fast path: extracted .so sitting in nativeLibraryDir
        File extracted = new File(context.getApplicationInfo().nativeLibraryDir, soName);
        if (extracted.exists()) {
            Log.i(TAG, "resolveNativeLibPath: found extracted at " + extracted.getAbsolutePath());
            return extracted.getAbsolutePath();
        }

        // Slow path: non-extracted - the .so is embedded in the APK.
        // Go directly to the APK zip via ApplicationInfo.sourceDir.
        Log.i(TAG, "resolveNativeLibPath: not in nativeLibraryDir, extracting from APK");
        return extractSoFromApk(context, soName);
    }

    /**
     * Extract a .so zip entry from the app's own APK to filesDir.
     *
     * Tries each ABI in Build.SUPPORTED_ABIS order - first match wins.
     * The destination file is overwritten on each call so the extracted
     * copy is always fresh.
     *
     * @param soName  full library filename, e.g. "libdexe2e_native.so"
     * @return        absolute path of the extracted file, or null on failure
     */
    private static String extractSoFromApk(Context context, String soName) {
        String apkPath = context.getApplicationInfo().sourceDir;
        File dest = new File(context.getFilesDir(), soName);

        for (String abi : android.os.Build.SUPPORTED_ABIS) {
            String entryPath = "lib/" + abi + "/" + soName;
            Log.i(TAG, "extractSoFromApk: trying " + entryPath + " in " + apkPath);

            try (ZipFile zf = new ZipFile(apkPath)) {
                ZipEntry entry = zf.getEntry(entryPath);
                if (entry == null) {
                    Log.i(TAG, "extractSoFromApk: entry not found for ABI " + abi);
                    continue;
                }
                try (InputStream is  = zf.getInputStream(entry);
                     FileOutputStream fos = new FileOutputStream(dest)) {
                    byte[] buf = new byte[4096];
                    int n;
                    while ((n = is.read(buf)) != -1) {
                        fos.write(buf, 0, n);
                    }
                }
                Log.i(TAG, "extractSoFromApk: extracted " + entry.getSize()
                        + " bytes to " + dest.getAbsolutePath());
                return dest.getAbsolutePath();
            } catch (IOException e) {
                Log.e(TAG, "extractSoFromApk: failed for ABI " + abi, e);
            }
        }

        Log.e(TAG, "extractSoFromApk: " + soName
                + " not found in " + apkPath + " for any supported ABI");
        return null;
    }
}
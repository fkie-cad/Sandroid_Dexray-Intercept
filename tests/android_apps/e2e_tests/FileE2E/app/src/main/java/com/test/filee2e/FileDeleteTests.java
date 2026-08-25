package com.test.filee2e;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;

// Triggers Java File.delete() and native unlink() hooks in file_system_hooks.ts.
//
// Hook status:
//   File.delete()  - implementation present; only fires for .jar and .dex paths
//   unlink()       - safeAttach on libc export "unlink"; implementation present
//                    Note: when deactivate_unlink is true, a safeReplace is also
//                    registered on the same address - attach + replace on the same
//                    target is undefined in Frida and must be resolved in the hook file.
public class FileDeleteTests {

    private static final String TAG = "FS_E2E";
    private final Context ctx;
    private int passed = 0;
    private int failed = 0;

    public FileDeleteTests(Context ctx) {
        this.ctx = ctx;
    }

    public void runTests() {
        testJavaDelete_dex();
        testJavaDelete_jar();
        testJavaDelete_jarSubstring();
        testNativeUnlink();

        Log.i(TAG, "FileDeleteTests summary: " + passed + " passed, " + failed + " failed");
    }

    // File.delete() on .dex path - hook fires for .dex suffix
    private void testJavaDelete_dex() {
        try {
            File f = new File(ctx.getFilesDir(), "delete_test.dex");
            FileOutputStream fos = new FileOutputStream(f);
            fos.write("dummy-dex".getBytes("UTF-8"));
            fos.close();

            boolean deleted = f.delete();
            boolean exists = f.exists();

            Log.i(TAG, "File.delete() .dex: deleted=" + deleted + ", exists=" + exists);
            if (deleted && !exists) {
                passed++;
            } else {
                Log.e(TAG, "File.delete() .dex did not remove the file");
                failed++;
            }
        } catch (Throwable t) {
            Log.e(TAG, "File.delete() .dex failed", t);
            failed++;
        }
    }

    // File.delete() on .jar path - hook fires for .jar suffix
    private void testJavaDelete_jar() {
        try {
            File f = new File(ctx.getFilesDir(), "delete_test.jar");
            FileOutputStream fos = new FileOutputStream(f);
            fos.write("dummy-jar".getBytes("UTF-8"));
            fos.close();

            boolean deleted = f.delete();
            boolean exists = f.exists();

            Log.i(TAG, "File.delete() .jar: deleted=" + deleted + ", exists=" + exists);
            if (deleted && !exists) {
                passed++;
            } else {
                Log.e(TAG, "File.delete() .jar did not remove the file");
                failed++;
            }
        } catch (Throwable t) {
            Log.e(TAG, "File.delete() .jar failed", t);
            failed++;
        }
    }

    // File.delete() on a non-jar path containing "jar"
    private void testJavaDelete_jarSubstring() {
        try {
            File f = new File(ctx.getFilesDir(), "delete_jar_marker.tmp");
            FileOutputStream fos = new FileOutputStream(f);
            fos.write("dummy-marker".getBytes("UTF-8"));
            fos.close();

            boolean deleted = f.delete();
            boolean exists = f.exists();

            Log.i(TAG, "File.delete() jar substring: deleted=" + deleted + ", exists=" + exists);
            if (deleted && !exists) {
                passed++;
            } else {
                Log.e(TAG, "File.delete() jar substring did not remove the file");
                failed++;
            }
        } catch (Throwable t) {
            Log.e(TAG, "File.delete() jar substring failed", t);
            failed++;
        }
    }

    public void runBlockedUnlinkTest() {
        try {
            File f = new File(ctx.getFilesDir(), "unlink_blocked.tmp");
            FileOutputStream fos = new FileOutputStream(f);
            fos.write("blocked-unlink-target".getBytes("UTF-8"));
            fos.close();

            int result = FileDeleteNative.unlinkFile(f.getAbsolutePath());
            boolean exists = f.exists();

            Log.i(TAG, "blocked native unlink: result=" + result + ", exists=" + exists);
            if (result == 0 && exists) {
                passed++;
            } else {
                Log.e(TAG, "blocked native unlink did not preserve the file");
                failed++;
            }
        } catch (Throwable t) {
            Log.e(TAG, "blocked native unlink failed", t);
            failed++;
        }

        Log.i(
            TAG,
            "FileDeleteTests blocked unlink summary: " +
            passed + " passed, " + failed + " failed"
        );
    }

    // native unlink() via JNI - triggers the unlink hook in file_system_hooks.ts
    private void testNativeUnlink() {
        try {
            File f = new File(ctx.getFilesDir(), "unlink_test.tmp");
            FileOutputStream fos = new FileOutputStream(f);
            fos.write("unlink-target".getBytes("UTF-8"));
            fos.close();

            int result = FileDeleteNative.unlinkFile(f.getAbsolutePath());
            boolean exists = f.exists();

            Log.i(TAG, "native unlink: result=" + result + ", exists=" + exists);
            if (result == 0 && !exists) {
                passed++;
            } else {
                Log.e(TAG, "native unlink did not remove the file");
                failed++;
            }
        } catch (Throwable t) {
            Log.e(TAG, "native unlink failed", t);
            failed++;
        }
    }
}

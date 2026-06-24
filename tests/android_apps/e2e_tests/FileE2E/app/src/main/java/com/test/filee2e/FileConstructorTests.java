package com.test.filee2e;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.net.URI;

// Triggers all four File.$init overloads declared in file_system_hooks.ts.
//
// Hook status per overload:
//   new[0] File(File, String)   - declared, NO implementation assigned
//   new[1] File(String)         - declared, implementation present
//   new[2] File(String, String) - declared, implementation present
//   new[3] File(URI)            - declared, NO implementation assigned
public class FileConstructorTests {

    private static final String TAG = "FS_E2E";
    private final Context ctx;
    private int passed = 0;
    private int failed = 0;

    public FileConstructorTests(Context ctx) {
        this.ctx = ctx;
    }

    public void runTests() {
        File baseDir = ctx.getFilesDir();

        testFile_String(baseDir);
        testFile_File_String(baseDir);
        testFile_String_String(baseDir);
        testFile_URI(baseDir);

        Log.i(TAG, "FileConstructorTests summary: " + passed + " passed, " + failed + " failed");
    }

    // hook new[1]: File(String) - implementation present
    private void testFile_String(File baseDir) {
        try {
            File f = new File(baseDir.getAbsolutePath() + "/ctor_string.log");
            Log.i(TAG, "File(String): " + f.getAbsolutePath());
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "File(String) failed", t);
            failed++;
        }
    }

    // hook new[0]: File(File, String) - NO implementation assigned in hook file
    private void testFile_File_String(File baseDir) {
        try {
            File f = new File(baseDir, "ctor_file_string.log");
            Log.i(TAG, "File(File,String): " + f.getAbsolutePath());
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "File(File,String) failed", t);
            failed++;
        }
    }

    // hook new[2]: File(String, String) - implementation present
    private void testFile_String_String(File baseDir) {
        try {
            File f = new File(baseDir.getAbsolutePath(), "ctor_str_str.log");
            Log.i(TAG, "File(String,String): " + f.getAbsolutePath());
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "File(String,String) failed", t);
            failed++;
        }
    }

    // hook new[3]: File(URI) - NO implementation assigned in hook file
    private void testFile_URI(File baseDir) {
        try {
            URI uri = new File(baseDir.getAbsolutePath() + "/ctor_uri.log").toURI();
            File f = new File(uri);
            Log.i(TAG, "File(URI): " + f.getAbsolutePath());
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "File(URI) failed", t);
            failed++;
        }
    }
}
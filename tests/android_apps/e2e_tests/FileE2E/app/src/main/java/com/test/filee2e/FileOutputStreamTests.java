package com.test.filee2e;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;

// Triggers all FileOutputStream constructor and write overloads declared in file_system_hooks.ts.
//
// Hook status per overload:
//   new[0] FileOutputStream(File)                - declared, NO implementation assigned
//   new[1] FileOutputStream(File, boolean)       - declared, NO implementation assigned
//   new[2] FileOutputStream(FileDescriptor)      - declared, NO implementation assigned
//   new[3] FileOutputStream(String)              - declared, NO implementation assigned
//   new[4] FileOutputStream(String, boolean)     - declared, NO implementation assigned
//   write[0] write(byte[])                       - declared, NO implementation assigned
//   write[1] write(int)                          - declared, NO implementation assigned
//   write[2] write(byte[], int, int)             - declared, implementation present
//
// Additional gap: none of the constructors populate TraceFS, so even write[2]
// will resolve the filename as "[unknown]" unless the path was registered via
// a File.$init hook first.
public class FileOutputStreamTests {

    private static final String TAG = "FS_E2E";
    private final Context ctx;
    private int passed = 0;
    private int failed = 0;

    public FileOutputStreamTests(Context ctx) {
        this.ctx = ctx;
    }

    public void runTests() {
        testFOS_File();
        testFOS_File_Boolean();
        testFOS_FileDescriptor();
        testFOS_String();
        testFOS_String_Boolean();
        testFOS_write_bytes();
        testFOS_write_int();
        testFOS_write_bytes_offset();

        Log.i(TAG, "FileOutputStreamTests summary: " + passed + " passed, " + failed + " failed");
    }

    // hook new[0]: FileOutputStream(File) - NO implementation assigned
    private void testFOS_File() {
        try {
            File f = new File(ctx.getFilesDir(), "fos_file.log");
            FileOutputStream fos = new FileOutputStream(f);
            fos.write("FOS-File".getBytes("UTF-8"), 0, 8);
            fos.close();
            Log.i(TAG, "FileOutputStream(File): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "FileOutputStream(File) failed", t);
            failed++;
        }
    }

    // hook new[1]: FileOutputStream(File, boolean) - NO implementation assigned
    private void testFOS_File_Boolean() {
        try {
            File f = new File(ctx.getFilesDir(), "fos_file_bool.log");
            FileOutputStream fos = new FileOutputStream(f, false);
            fos.write("FOS-File-Bool".getBytes("UTF-8"), 0, 13);
            fos.close();
            Log.i(TAG, "FileOutputStream(File,boolean): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "FileOutputStream(File,boolean) failed", t);
            failed++;
        }
    }

    // hook new[2]: FileOutputStream(FileDescriptor) - NO implementation assigned
    private void testFOS_FileDescriptor() {
        try {
            File f = new File(ctx.getFilesDir(), "fos_fd.log");
            FileOutputStream fos0 = new FileOutputStream(f);
            FileDescriptor fd = fos0.getFD();
            FileOutputStream fos = new FileOutputStream(fd);
            fos.write("FOS-FD".getBytes("UTF-8"), 0, 6);
            fos.close();
            fos0.close();
            Log.i(TAG, "FileOutputStream(FileDescriptor): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "FileOutputStream(FileDescriptor) failed", t);
            failed++;
        }
    }

    // hook new[3]: FileOutputStream(String) - NO implementation assigned
    private void testFOS_String() {
        try {
            File f = new File(ctx.getFilesDir(), "fos_string.log");
            FileOutputStream fos = new FileOutputStream(f.getAbsolutePath());
            fos.write("FOS-String".getBytes("UTF-8"), 0, 10);
            fos.close();
            Log.i(TAG, "FileOutputStream(String): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "FileOutputStream(String) failed", t);
            failed++;
        }
    }

    // hook new[4]: FileOutputStream(String, boolean) - NO implementation assigned
    private void testFOS_String_Boolean() {
        try {
            File f = new File(ctx.getFilesDir(), "fos_string_bool.log");
            FileOutputStream fos = new FileOutputStream(f.getAbsolutePath(), false);
            fos.write("FOS-String-Bool".getBytes("UTF-8"), 0, 15);
            fos.close();
            Log.i(TAG, "FileOutputStream(String,boolean): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "FileOutputStream(String,boolean) failed", t);
            failed++;
        }
    }

    // hook write[0]: write(byte[]) - NO implementation assigned
    private void testFOS_write_bytes() {
        try {
            File f = new File(ctx.getFilesDir(), "fos_write0.log");
            FileOutputStream fos = new FileOutputStream(f);
            fos.write("FOS-Write-Bytes".getBytes("UTF-8"));
            fos.close();
            Log.i(TAG, "FileOutputStream.write(byte[]): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "FileOutputStream.write(byte[]) failed", t);
            failed++;
        }
    }

    // hook write[1]: write(int) - NO implementation assigned
    private void testFOS_write_int() {
        try {
            File f = new File(ctx.getFilesDir(), "fos_write1.log");
            FileOutputStream fos = new FileOutputStream(f);
            fos.write((int) 'W');
            fos.close();
            Log.i(TAG, "FileOutputStream.write(int): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "FileOutputStream.write(int) failed", t);
            failed++;
        }
    }

    // hook write[2]: write(byte[], int, int) - implementation present
    // Note: filename resolves as "[unknown]" unless a File.$init hook ran first,
    // because no FileOutputStream constructor hook populates TraceFS.
    private void testFOS_write_bytes_offset() {
        try {
            File f = new File(ctx.getFilesDir(), "fos_write2.xml");
            FileOutputStream fos = new FileOutputStream(f);
            byte[] data = "<root><test>write2</test></root>".getBytes("UTF-8");
            fos.write(data, 0, data.length);
            fos.close();
            Log.i(TAG, "FileOutputStream.write(byte[],int,int): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "FileOutputStream.write(byte[],int,int) failed", t);
            failed++;
        }
    }
}
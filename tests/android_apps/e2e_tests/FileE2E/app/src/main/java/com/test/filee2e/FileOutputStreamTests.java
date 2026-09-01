package com.test.filee2e;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;

// Triggers public FileOutputStream constructors and write overloads.
//
// Public SDK constructor coverage:
//   new[0] FileOutputStream(File)
//   new[1] FileOutputStream(File, boolean)
//   new[2] FileOutputStream(FileDescriptor)
//   new[4] FileOutputStream(String)
//   new[5] FileOutputStream(String, boolean)
//
// Runtime-only constructor coverage:
//   new[3] FileOutputStream(FileDescriptor, boolean) is invoked internally by
//   FileOutputStream(FileDescriptor) on supported Android runtimes.
//
// Write coverage:
//   write[0] write(byte[])
//   write[1] write(int)
//   write[2] write(byte[], int, int)
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
        testFOS_write_large();

        Log.i(TAG, "FileOutputStreamTests summary: " + passed + " passed, " + failed + " failed");
    }

    // hook new[0]: FileOutputStream(File)
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

    // hook new[1]: FileOutputStream(File, boolean)
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

    // hook new[2]: FileOutputStream(FileDescriptor)
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

    // hook new[4]: FileOutputStream(String)
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

    // hook new[5]: FileOutputStream(String, boolean)
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

    // hook write[0]: FileOutputStream.write(byte[])
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

    // hook write[1]: FileOutputStream.write(int)
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

    // hook write[2]: FileOutputStream.write(byte[], int, int)
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

    // Large write for console preview truncation coverage
    private void testFOS_write_large() {
        try {
            File f = new File(ctx.getFilesDir(), "fos_large.bin");
            byte[] data = new byte[2048];

            for (int index = 0; index < data.length; index++) {
                data[index] = (byte) (index & 0xff);
            }

            FileOutputStream fos = new FileOutputStream(f);
            fos.write(data, 0, data.length);
            fos.close();

            long fileSize = f.length();
            Log.i(TAG, "FileOutputStream large write: " + fileSize + " bytes");

            if (fileSize == data.length) {
                passed++;
            } else {
                Log.e(
                    TAG,
                    "FileOutputStream large write has unexpected size: " +
                    fileSize
                );
                failed++;
            }
        } catch (Throwable t) {
            Log.e(TAG, "FileOutputStream large write failed", t);
            failed++;
        }
    }

}
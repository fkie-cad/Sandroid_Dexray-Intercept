package com.test.filee2e;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;

// Triggers all FileInputStream constructor and read overloads declared in file_system_hooks.ts.
//
// Hook status per overload:
//   new[0] FileInputStream(File)           - declared, implementation present
//   new[1] FileInputStream(FileDescriptor) - declared, NO implementation assigned
//   new[2] FileInputStream(String)         - declared, NO implementation assigned
//   read[0] read()                         - declared, NO implementation assigned
//   read[1] read(byte[])                   - declared, implementation present
//   read[2] read(byte[], int, int)         - declared, implementation present
public class FileInputStreamTests {

    private static final String TAG = "FS_E2E";
    private final Context ctx;
    private int passed = 0;
    private int failed = 0;

    public FileInputStreamTests(Context ctx) {
        this.ctx = ctx;
    }

    public void runTests() {
        testFIS_File();
        testFIS_String();
        testFIS_FileDescriptor();
        testFIS_read_noarg();
        testFIS_read_bytes();
        testFIS_read_bytes_offset();

        Log.i(TAG, "FileInputStreamTests summary: " + passed + " passed, " + failed + " failed");
    }

    private File prepareFile(String name, String content) throws Exception {
        File f = new File(ctx.getFilesDir(), name);
        FileOutputStream fos = new FileOutputStream(f);
        fos.write(content.getBytes("UTF-8"));
        fos.close();
        return f;
    }

    // hook new[0]: FileInputStream(File) - implementation present
    private void testFIS_File() {
        try {
            File f = prepareFile("fis_file.log", "FIS-File-Test");
            FileInputStream fis = new FileInputStream(f);
            fis.close();
            Log.i(TAG, "FileInputStream(File): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "FileInputStream(File) failed", t);
            failed++;
        }
    }

    // hook new[2]: FileInputStream(String) - NO implementation assigned
    private void testFIS_String() {
        try {
            File f = prepareFile("fis_string.log", "FIS-String-Test");
            FileInputStream fis = new FileInputStream(f.getAbsolutePath());
            fis.close();
            Log.i(TAG, "FileInputStream(String): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "FileInputStream(String) failed", t);
            failed++;
        }
    }

    // hook new[1]: FileInputStream(FileDescriptor) - NO implementation assigned
    private void testFIS_FileDescriptor() {
        try {
            File f = prepareFile("fis_fd.log", "FIS-FD-Test");
            // acquire a FileDescriptor from an existing stream, then wrap it
            FileInputStream fis0 = new FileInputStream(f);
            FileDescriptor fd = fis0.getFD();
            FileInputStream fis = new FileInputStream(fd);
            fis.close();
            fis0.close();
            Log.i(TAG, "FileInputStream(FileDescriptor): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "FileInputStream(FileDescriptor) failed", t);
            failed++;
        }
    }

    // hook read[0]: read() no-arg - NO implementation assigned
    private void testFIS_read_noarg() {
        try {
            File f = prepareFile("fis_read0.log", "X");
            FileInputStream fis = new FileInputStream(f);
            int b = fis.read();
            fis.close();
            Log.i(TAG, "FileInputStream.read() -> " + b);
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "FileInputStream.read() failed", t);
            failed++;
        }
    }

    // hook read[1]: read(byte[]) - implementation present
    private void testFIS_read_bytes() {
        try {
            File f = prepareFile("fis_read1.log", "ReadBytesTest");
            FileInputStream fis = new FileInputStream(f);
            byte[] buf = new byte[64];
            int n = fis.read(buf);
            fis.close();
            Log.i(TAG, "FileInputStream.read(byte[]) -> " + n + " bytes");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "FileInputStream.read(byte[]) failed", t);
            failed++;
        }
    }

    // hook read[2]: read(byte[], int, int) - implementation present
    private void testFIS_read_bytes_offset() {
        try {
            File f = prepareFile("fis_read2.log", "ReadBytesOffsetTest");
            FileInputStream fis = new FileInputStream(f);
            byte[] buf = new byte[128];
            int n = fis.read(buf, 4, 50);
            fis.close();
            Log.i(TAG, "FileInputStream.read(byte[],int,int) -> " + n + " bytes");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "FileInputStream.read(byte[],int,int) failed", t);
            failed++;
        }
    }
}
package com.test.filee2e;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;

// Triggers public FileInputStream constructors and read overloads declared in
// file_system_hooks.ts.
//
// Public SDK constructor coverage:
//   new[0] FileInputStream(File)
//   new[1] FileInputStream(FileDescriptor)
//   new[2] FileInputStream(String)
//
// Runtime-only constructor coverage:
//   new[3] FileInputStream(FileDescriptor, boolean) is invoked internally by
//   FileInputStream(FileDescriptor) on supported Android runtimes.
//
// Read coverage:
//   read[0] read()
//   read[1] read(byte[])
//   read[2] read(byte[], int, int)
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

    // hook new[0]: FileInputStream(File)
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

    // hook new[2]: FileInputStream(String)
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

    // hook new[1]: FileInputStream(FileDescriptor)
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

    // hook read[0]: read() no-arg
    private void testFIS_read_noarg() {
        try {
            File f = prepareFile("fis_read0.log", "X");
            FileInputStream fis = new FileInputStream(f);
            int b = fis.read();
            fis.close();

            Log.i(TAG, "FileInputStream.read() -> " + b);
            if (b == 'X') {
                passed++;
            } else {
                Log.e(TAG, "FileInputStream.read() returned unexpected byte: " + b);
                failed++;
            }
        } catch (Throwable t) {
            Log.e(TAG, "FileInputStream.read() failed", t);
            failed++;
        }
    }

    // hook read[1]: read(byte[])
    private void testFIS_read_bytes() {
        try {
            File f = prepareFile("fis_read1.log", "ReadBytesTest");
            FileInputStream fis = new FileInputStream(f);
            byte[] buf = new byte[64];
            int n = fis.read(buf);
            fis.close();

            Log.i(TAG, "FileInputStream.read(byte[]) -> " + n + " bytes");
            if (n == "ReadBytesTest".length()) {
                passed++;
            } else {
                Log.e(TAG, "FileInputStream.read(byte[]) returned unexpected length: " + n);
                failed++;
            }
        } catch (Throwable t) {
            Log.e(TAG, "FileInputStream.read(byte[]) failed", t);
            failed++;
        }
    }

    // hook read[2]: read(byte[], int, int)
    private void testFIS_read_bytes_offset() {
        try {
            File f = prepareFile("fis_read2.log", "ReadBytesOffsetTest");
            FileInputStream fis = new FileInputStream(f);
            byte[] buf = new byte[128];
            int n = fis.read(buf, 4, 50);
            fis.close();

            Log.i(TAG, "FileInputStream.read(byte[],int,int) -> " + n + " bytes");
            if (n == "ReadBytesOffsetTest".length()) {
                passed++;
            } else {
                Log.e(
                    TAG,
                    "FileInputStream.read(byte[],int,int) returned unexpected length: " + n
                );
                failed++;
            }
        } catch (Throwable t) {
            Log.e(TAG, "FileInputStream.read(byte[],int,int) failed", t);
            failed++;
        }
    }
}
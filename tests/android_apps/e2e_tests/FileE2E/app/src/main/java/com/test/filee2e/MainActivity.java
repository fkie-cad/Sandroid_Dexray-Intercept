package com.test.filee2e;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class MainActivity extends Activity {
    private static final String TAG = "FS_E2E";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        try {
            // Base directory for test files
            File baseDir = getFilesDir();

            // 1) File constructors: File(String) and File(String,String)
            File fileLog = new File(baseDir.getAbsolutePath() + "/test_e2e.log");
            File fileXml = new File(baseDir, "test_e2e.xml");
            File fileDex = new File(baseDir, "test_e2e.dex"); // will be used for delete()

            Log.i(TAG, "fileLog=" + fileLog.getAbsolutePath());
            Log.i(TAG, "fileXml=" + fileXml.getAbsolutePath());
            Log.i(TAG, "fileDex=" + fileDex.getAbsolutePath());

            // 2) FileOutputStream: write() variants

            // 2a) new FileOutputStream(String) + write(byte[])
            FileOutputStream fos1 = new FileOutputStream(fileLog.getAbsolutePath());
            byte[] logData = "Hello FileSystem E2E (log)\n".getBytes("UTF-8");
            fos1.write(logData);
            fos1.close();

            // 2b) new FileOutputStream(String, boolean append) + write(int)
            FileOutputStream fos2 = new FileOutputStream(fileLog.getAbsolutePath(), true);
            fos2.write((int) 'A');
            fos2.write((int) '\n');
            fos2.close();

            // 2c) new FileOutputStream(File) + write(byte[], int, int)
            FileOutputStream fos3 = new FileOutputStream(fileXml);
            byte[] xmlData = "<root><msg>FS E2E</msg></root>\n".getBytes("UTF-8");
            fos3.write(xmlData, 0, xmlData.length);
            fos3.close();

            // 3) FileInputStream: read(byte[]) and read(byte[], int, int)

            // 3a) read(byte[])
            FileInputStream fis1 = new FileInputStream(fileLog);
            byte[] buf1 = new byte[64];
            int read1 = fis1.read(buf1);
            Log.i(TAG, "read(byte[]) got " + read1 + " bytes from log");
            fis1.close();

            // 3b) read(byte[], int, int)
            FileInputStream fis2 = new FileInputStream(fileXml);
            byte[] buf2 = new byte[128];
            int read2 = fis2.read(buf2, 10, 50); // offset 10, len 50
            Log.i(TAG, "read(byte[],int,int) got " + read2 + " bytes from xml");
            fis2.close();

            // 4) Java delete() on .dex to trigger file.delete.java
            // Touch the file first
            if (!fileDex.exists()) {
                FileOutputStream fosDex = new FileOutputStream(fileDex);
                fosDex.write("dummy".getBytes("UTF-8"));
                fosDex.close();
            }
            boolean deleted = fileDex.delete();
            Log.i(TAG, "Deleted " + fileDex.getName() + ": " + deleted);

        } catch (Throwable t) {
            Log.e(TAG, "Error in FileSystemE2E test", t);
        }

        finish();
    }
}
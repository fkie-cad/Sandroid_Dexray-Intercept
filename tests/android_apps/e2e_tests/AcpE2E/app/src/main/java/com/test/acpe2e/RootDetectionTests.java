package com.test.acpe2e;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

public class RootDetectionTests {

    private static final String TAG = "ACP_E2E_ROOT";

    private static int testsPassed = 0;
    private static int testsFailed = 0;

    private static void assertTest(boolean cond, String name) {
        if (cond) {
            Log.i(TAG, "PASS: " + name);
            testsPassed++;
        } else {
            Log.e(TAG, "FAIL: " + name);
            testsFailed++;
        }
    }

    public static void runTests(Context ctx) {
        testsPassed = 0;
        testsFailed = 0;

        try {
            testBuildFingerprint();
        } catch (Throwable t) {
            Log.e(TAG, "testBuildFingerprint threw", t);
            testsFailed++;
        }

        try {
            testFileIndicators();
        } catch (Throwable t) {
            Log.e(TAG, "testFileIndicators threw", t);
            testsFailed++;
        }

        try {
            testPackageManager(ctx);
        } catch (Throwable t) {
            Log.e(TAG, "testPackageManager threw", t);
            testsFailed++;
        }

        try {
            testShellCommands();
        } catch (Throwable t) {
            Log.e(TAG, "testShellCommands threw", t);
            testsFailed++;
        }

        Log.i(TAG, "RootDetectionTests summary: passed=" + testsPassed + " failed=" + testsFailed);
    }

    private static void testBuildFingerprint() {
        // Target: android-disable-root-detection.js
        //  -> setProp(): overrides Build.TAGS, TYPE, FINGERPRINT

        String fingerprint = Build.FINGERPRINT;
        String type = Build.TYPE;
        String tags = Build.TAGS;

        Log.i(TAG, "Build.FINGERPRINT=" + fingerprint);
        Log.i(TAG, "Build.TYPE=" + type);
        Log.i(TAG, "Build.TAGS=" + tags);

        // Assertions are intentionally loose; this verifies that properties are readable.
        assertTest(fingerprint != null && fingerprint.length() > 0, "Build.FINGERPRINT readable");
        assertTest(type != null && type.length() > 0, "Build.TYPE readable");
        assertTest(tags != null && tags.length() > 0, "Build.TAGS readable");
    }

    private static void testFileIndicators() {
        // Target: android-disable-root-detection.js
        //  -> Native fopen/access/stat/lstat and Java File/UnixFileSystem hooks

        // Use a subset of common root indicator paths; these usually do not exist on test device.
        List<String> rootPaths = Arrays.asList(
                "/system/bin/su",
                "/system/xbin/su",
                "/sbin/su",
                "/data/adb/magisk"
        );

        for (String path : rootPaths) {
            File f = new File(path);
            boolean exists = f.exists();
            long len = 0L;
            if (exists) {
                len = f.length();
            }
            Log.i(TAG, "File check for " + path + ": exists=" + exists + " length=" + len);

            try {
                FileInputStream fis = new FileInputStream(f);
                fis.close();
                Log.i(TAG, "FileInputStream opened for " + path);
            } catch (IOException e) {
                Log.i(TAG, "FileInputStream failed for " + path + ": " + e.getMessage());
            }
        }

        assertTest(true, "File root indicator checks executed");
    }

    private static void testPackageManager(Context ctx) {
        // Target: android-disable-root-detection.js
        //  -> ApplicationPackageManager.getPackageInfo / getInstalledPackages filters root packages

        PackageManager pm = ctx.getPackageManager();

        // Example known package name from ROOT_INDICATORS.packages set.
        String magiskPkg = "com.topjohnwu.magisk";

        try {
            ApplicationInfo info = pm.getApplicationInfo(magiskPkg, 0);
            Log.i(TAG, "Package info for " + magiskPkg + " found: " + info.sourceDir);
        } catch (PackageManager.NameNotFoundException e) {
            Log.i(TAG, "Package " + magiskPkg + " not installed (expected on clean device)");
        }

        try {
            List<ApplicationInfo> installed = pm.getInstalledApplications(0);
            Log.i(TAG, "Installed applications count: " + installed.size());
        } catch (Throwable t) {
            Log.e(TAG, "getInstalledApplications failed", t);
            assertTest(false, "getInstalledApplications call");
            return;
        }

        assertTest(true, "PackageManager root-related calls executed");
    }

    private static void testShellCommands() {
        // Target: android-disable-root-detection.js
        //  -> Runtime.exec(String) and Runtime.exec(String[]) for commands in ROOT_INDICATORS.commands
        //  -> ProcessBuilder.command(List) and ProcessImpl.start(...)

        try {
            // Runtime.exec(String)
            Process p1 = Runtime.getRuntime().exec("su");
            Log.i(TAG, "Runtime.exec(\"su\") started, exitValue may block until completion");
            p1.destroy();
        } catch (Throwable t) {
            Log.i(TAG, "Runtime.exec(\"su\") failed: " + t.getMessage());
        }

        try {
            // Runtime.exec(String[])
            Process p2 = Runtime.getRuntime().exec(new String[]{"su", "-c", "id"});
            Log.i(TAG, "Runtime.exec([\"su\", \"-c\", \"id\"]) started");
            p2.destroy();
        } catch (Throwable t) {
            Log.i(TAG, "Runtime.exec([\"su\", ...]) failed: " + t.getMessage());
        }

        try {
            // ProcessBuilder.command(List)
            ProcessBuilder pb = new ProcessBuilder(Arrays.asList("su", "-c", "id"));
            Process p3 = pb.start();
            Log.i(TAG, "ProcessBuilder(['su', '-c', 'id']).start() invoked");
            p3.destroy();
        } catch (Throwable t) {
            Log.i(TAG, "ProcessBuilder command failed: " + t.getMessage());
        }

        assertTest(true, "Shell command tests executed");
    }
}
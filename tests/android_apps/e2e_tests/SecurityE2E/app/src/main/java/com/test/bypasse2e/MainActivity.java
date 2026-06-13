// tests/android_apps/e2e_tests/SecurityE2E/app/src/main/java/com/test/securitye2e/MainActivity.java
package com.test.securitye2e;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Debug;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.lang.reflect.Method;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;

public class MainActivity extends Activity {

    private static final String TAG = "BYPASS_E2E";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.i(TAG, "SecurityE2E started");

        try {
            Thread t = new Thread(() -> {
                try {
                    runRootBypassTests();
                    runFridaBypassTests();
                    runDebuggerBypassTests();
                    runEmulatorBypassTests();
                    runHookBypassTests();
                } catch (Throwable t1) {
                    Log.e(TAG, "Error in bypass tests", t1);
                } finally {
                    runOnUiThread(this::finish);
                }
            });
            t.start();
        } catch (Throwable t) {
            Log.e(TAG, "Error in SecurityE2E", t);
            finish();
        }
    }

    // ------------------------------------------------------------
    // Root detection bypass tests
    // ------------------------------------------------------------

    private void runRootBypassTests() {
        Log.i(TAG, "runRootBypassTests");
        try {
            List<String> rootPaths = Arrays.asList(
                    "/system/bin/su",
                    "/system/xbin/su",
                    "/sbin/su",
                    "/system/app/Superuser.apk",
                    "/system/app/SuperSU.apk",
                    "/data/data/com.noshufou.android.su",
                    "/data/data/com.koushikdutta.superuser",
                    "/data/data/eu.chainfire.supersu",
                    "/system/xbin/busybox",
                    "/system/bin/busybox",
                    "/system/app/RootCloak.apk",
                    "/dev/com.koushikdutta.superuser.daemon/"
            );
            for (String path : rootPaths) {
                try {
                    boolean exists = new File(path).exists();
                    Log.i(TAG, "File.exists(root path): " + path + " -> " + exists);
                } catch (Throwable t) {
                    Log.e(TAG, "File.exists failed for " + path, t);
                }
            }

            try {
                boolean exists = new File("/data/local/tmp/securitye2e_dummy").exists();
                Log.i(TAG, "File.exists(non-root path) -> " + exists);
            } catch (Throwable t) {
                Log.e(TAG, "File.exists failed for non-root path", t);
            }

            Runtime rt = Runtime.getRuntime();

            try {
                rt.exec("su");
            } catch (Throwable t) {
                Log.e(TAG, "Runtime.exec(\"su\") failed", t);
            }

            try {
                rt.exec("which su");
            } catch (Throwable t) {
                Log.e(TAG, "Runtime.exec(\"which su\") failed", t);
            }

            try {
                rt.exec(new String[]{"su", "-c", "id"});
            } catch (Throwable t) {
                Log.e(TAG, "Runtime.exec([\"su\",\"-c\",\"id\"]) failed", t);
            }

            try {
                rt.exec(new String[]{"busybox", "id"});
            } catch (Throwable t) {
                Log.e(TAG, "Runtime.exec([\"busybox\",\"id\"]) failed", t);
            }

            try {
                String tags = android.os.Build.TAGS;
                Log.i(TAG, "Build.TAGS: " + tags);
            } catch (Throwable t) {
                Log.e(TAG, "Reading Build.TAGS failed", t);
            }

            try {
                PackageManager pm = getPackageManager();
                if (pm != null) {
                    pm.getInstalledPackages(0);
                }
            } catch (Throwable t) {
                Log.e(TAG, "getInstalledPackages failed", t);
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runRootBypassTests", t);
        }
    }

    // ------------------------------------------------------------
    // Frida detection bypass tests
    // ------------------------------------------------------------

    private void runFridaBypassTests() {
        Log.i(TAG, "runFridaBypassTests");
        try {
            List<String> fridaPaths = Arrays.asList(
                    "/data/local/tmp/frida-server",
                    "/data/local/tmp/re.frida.server",
                    "/system/lib/libfrida-gadget.so",
                    "/system/lib64/libfrida-gadget.so"
            );
            for (String path : fridaPaths) {
                try {
                    boolean exists = new File(path).exists();
                    Log.i(TAG, "File.exists(frida path): " + path + " -> " + exists);
                } catch (Throwable t) {
                    Log.e(TAG, "File.exists failed for " + path, t);
                }
            }

            try {
                new Socket("127.0.0.1", 27042).close();
            } catch (Throwable t) {
                Log.e(TAG, "Socket(\"127.0.0.1\", 27042) failed", t);
            }

            try {
                ActivityManager am =
                        (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
                if (am != null) {
                    java.util.List<ActivityManager.RunningAppProcessInfo> list =
                            am.getRunningAppProcesses();
                    int count = list != null ? list.size() : 0;
                    Log.i(TAG, "Running app processes count: " + count);
                    if (list != null) {
                        for (ActivityManager.RunningAppProcessInfo info : list) {
                            Log.i(TAG, "Process: " + info.processName);
                        }
                    }
                }
            } catch (Throwable t) {
                Log.e(TAG, "getRunningAppProcesses failed", t);
            }

            try {
                Thread t = new Thread("frida-worker") {
                    @Override
                    public void run() {
                        try {
                            String name = getName();
                            Log.i(TAG, "Thread name (hooked): " + name);
                        } catch (Throwable e) {
                            Log.e(TAG, "Thread name retrieval failed", e);
                        }
                    }
                };
                t.start();
                t.join();
            } catch (Throwable t) {
                Log.e(TAG, "Thread name test failed", t);
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runFridaBypassTests", t);
        }
    }

    // ------------------------------------------------------------
    // Debugger detection bypass tests
    // ------------------------------------------------------------

    private void runDebuggerBypassTests() {
        Log.i(TAG, "runDebuggerBypassTests");
        try {
            try {
                boolean dbg = Debug.isDebuggerConnected();
                Log.i(TAG, "Debug.isDebuggerConnected(): " + dbg);
            } catch (Throwable t) {
                Log.e(TAG, "Debug.isDebuggerConnected failed", t);
            }

            try {
                PackageManager pm = getPackageManager();
                if (pm != null) {
                    ApplicationInfo info =
                            pm.getApplicationInfo(getPackageName(), 0);
                    if (info != null) {
                        boolean debuggable =
                                (info.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
                        Log.i(TAG, "ApplicationInfo.FLAG_DEBUGGABLE: " + debuggable);
                    }
                }
            } catch (Throwable t) {
                Log.e(TAG, "getApplicationInfo failed", t);
            }

            try {
                BufferedReader br = new BufferedReader(
                        new FileReader("/proc/self/status"));
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.startsWith("TracerPid:")) {
                        Log.i(TAG, "TracerPid line (hooked): " + line);
                        break;
                    }
                }
                br.close();
            } catch (Throwable t) {
                Log.e(TAG, "Reading /proc/self/status failed", t);
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runDebuggerBypassTests", t);
        }
    }

    // ------------------------------------------------------------
    // Emulator detection bypass tests
    // ------------------------------------------------------------

    private void runEmulatorBypassTests() {
        Log.i(TAG, "runEmulatorBypassTests");
        try {
            try {
                String brand = android.os.Build.BRAND;
                String device = android.os.Build.DEVICE;
                String model = android.os.Build.MODEL;
                String product = android.os.Build.PRODUCT;
                String manufacturer = android.os.Build.MANUFACTURER;
                String hardware = android.os.Build.HARDWARE;
                Log.i(TAG, "Build properties: BRAND=" + brand +
                        " DEVICE=" + device +
                        " MODEL=" + model +
                        " PRODUCT=" + product +
                        " MANUFACTURER=" + manufacturer +
                        " HARDWARE=" + hardware);
            } catch (Throwable t) {
                Log.e(TAG, "Reading Build.* properties failed", t);
            }

            try {
                Class<?> spClass = Class.forName("android.os.SystemProperties");
                Method get = spClass.getMethod("get", String.class);
                Object qemu = get.invoke(null, "ro.kernel.qemu");
                Object modelProp = get.invoke(null, "ro.product.model");
                Log.i(TAG, "SystemProperties.get(ro.kernel.qemu) = " + qemu);
                Log.i(TAG, "SystemProperties.get(ro.product.model) = " + modelProp);
            } catch (Throwable t) {
                Log.e(TAG, "SystemProperties.get emulator properties failed", t);
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runEmulatorBypassTests", t);
        }
    }

    // ------------------------------------------------------------
    // Hook detection bypass tests
    // ------------------------------------------------------------

    private void runHookBypassTests() {
        Log.i(TAG, "runHookBypassTests");
        try {
            try {
                Throwable th = new Throwable("bypass-e2e");
                StackTraceElement[] stack = th.getStackTrace();
                Log.i(TAG, "Throwable.getStackTrace length (hooked): " + stack.length);
                if (stack.length > 0) {
                    Log.i(TAG, "Stack[0]: " + stack[0].toString());
                }
            } catch (Throwable t) {
                Log.e(TAG, "Throwable.getStackTrace failed", t);
            }

            try {
                String mapped = System.mapLibraryName("frida");
                Log.i(TAG, "System.mapLibraryName(\"frida\") = " + mapped);
            } catch (Throwable t) {
                Log.e(TAG, "System.mapLibraryName failed", t);
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runHookBypassTests", t);
        }
    }
}
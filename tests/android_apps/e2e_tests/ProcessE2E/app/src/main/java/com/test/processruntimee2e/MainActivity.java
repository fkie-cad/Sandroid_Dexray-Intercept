// tests/android_apps/e2e_tests/ProcessE2E/app/src/main/java/com/test/processe2e/MainActivity.java
package com.test.processe2e;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class MainActivity extends Activity {

    private static final String TAG = "PROCESS_RUNTIME_E2E";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.i(TAG, "ProcessE2E started");

        try {
            Thread t = new Thread(() -> {
                try {
                    runJavaProcessTests();
                    runRuntimeExecTests();
                    runRuntimeLoadTests();
                    runReflectionTests();
                } catch (Throwable t1) {
                    Log.e(TAG, "Error in process/runtime tests", t1);
                } finally {
                    runOnUiThread(this::finish);
                }
            });
            t.start();
        } catch (Throwable t) {
            Log.e(TAG, "Error in ProcessE2E", t);
            finish();
        }
    }

    private void runJavaProcessTests() {
        Log.i(TAG, "runJavaProcessTests");
        try {
            int selfPid = android.os.Process.myPid();

            android.os.Process.sendSignal(selfPid, 0);

            android.os.Process.killProcess(0);
        } catch (Throwable t) {
            Log.e(TAG, "Error in runJavaProcessTests", t);
        }
    }

    private void runRuntimeExecTests() {
        Log.i(TAG, "runRuntimeExecTests");
        Runtime rt = Runtime.getRuntime();

        try {
            Process p1 = rt.exec("/system/bin/id");
            consumeProcessStreams(p1);

            String[] cmdArray = new String[]{"/system/bin/sh", "-c", "echo exec_array"};
            Process p2 = rt.exec(cmdArray);
            consumeProcessStreams(p2);

            String[] envp = new String[]{"E2E_ENV=1"};
            Process p3 = rt.exec("/system/bin/sh -c 'echo exec_envp'", envp);
            consumeProcessStreams(p3);

            String[] cmdArray2 = new String[]{"/system/bin/sh", "-c", "echo exec_array_envp"};
            Process p4 = rt.exec(cmdArray2, envp);
            consumeProcessStreams(p4);

            File dir = getFilesDir();
            Process p5 = rt.exec("/system/bin/sh -c 'pwd'", null, dir);
            consumeProcessStreams(p5);

            Process p6 = rt.exec(cmdArray2, null, dir);
            consumeProcessStreams(p6);
        } catch (Throwable t) {
            Log.e(TAG, "Error in runRuntimeExecTests", t);
        }
    }

    private void consumeProcessStreams(Process process) {
        if (process == null) {
            return;
        }
        CountDownLatch latch = new CountDownLatch(1);
        Thread t = new Thread(() -> {
            try (InputStream is = process.getInputStream()) {
                byte[] buf = new byte[256];
                int read;
                while ((read = is.read(buf)) != -1) {
                    if (read == 0) {
                        break;
                    }
                }
            } catch (Throwable ignored) {
            } finally {
                latch.countDown();
            }
        });
        t.start();

        try (InputStream es = process.getErrorStream()) {
            byte[] buf = new byte[256];
            int read;
            while ((read = es.read(buf)) != -1) {
                if (read == 0) {
                    break;
                }
            }
        } catch (Throwable ignored) {
        }

        try {
            latch.await(2, TimeUnit.SECONDS);
        } catch (Throwable ignored) {
        }

        try {
            OutputStream os = process.getOutputStream();
            os.close();
        } catch (Throwable ignored) {
        }

        try {
            process.destroy();
        } catch (Throwable ignored) {
        }
    }

    private void runRuntimeLoadTests() {
        Log.i(TAG, "runRuntimeLoadTests");
        Runtime rt = Runtime.getRuntime();

        try {
            System.loadLibrary("log");
        } catch (Throwable t) {
            Log.e(TAG, "System.loadLibrary(log) failed", t);
        }

        try {
            rt.loadLibrary("log");
        } catch (Throwable t) {
            Log.e(TAG, "Runtime.loadLibrary(log) failed", t);
        }

        String libName = System.mapLibraryName("log");

        String[] candidatePaths = new String[]{
                "/system/lib64/" + libName,
                "/system/lib/" + libName
        };

        for (String path : candidatePaths) {
            try {
                rt.load(path);
                break;
            } catch (Throwable t) {
                Log.w(TAG, "Runtime.load failed for path: " + path, t);
            }
        }

        try {
            NativeEntry.runNativeProcessTests();
        } catch (Throwable t) {
            Log.e(TAG, "NativeEntry.runNativeProcessTests failed", t);
        }
    }

    private void runReflectionTests() {
        Log.i(TAG, "runReflectionTests");
        try {
            Class<?> targetClass = Class.forName("com.test.processe2e.ReflectionTarget");

            java.lang.reflect.Method staticMethod = targetClass.getMethod(
                    "staticMethod", String.class, int.class);
            Object staticResult = staticMethod.invoke(null, "prefix-", 42);
            Log.i(TAG, "staticMethod result: " + staticResult);

            java.lang.reflect.Method instanceMethod = targetClass.getDeclaredMethod(
                    "instanceMethod", String.class);
            Object instance = targetClass.getConstructor(String.class).newInstance("base-");
            Object instanceResult = instanceMethod.invoke(instance, "suffix");
            Log.i(TAG, "instanceMethod result: " + instanceResult);

            ClassLoader loader = getClassLoader();
            Class<?> stringClass = loader.loadClass("java.lang.String");
            Class<?> selfClass = loader.loadClass("com.test.processe2e.MainActivity");
            Log.i(TAG, "Loaded via ClassLoader: " + stringClass.getName() + ", " + selfClass.getName());

            Class<?> selfViaForName = Class.forName(
                    "com.test.processe2e.MainActivity",
                    true,
                    getClassLoader()
            );
            Log.i(TAG, "Class.forName result: " + selfViaForName.getName());

            Method toStringMethod = Object.class.getMethod("toString");
            Object toStringResult = toStringMethod.invoke(this);
            Log.i(TAG, "Method.invoke on toString(): " + toStringResult);
        } catch (Throwable t) {
            Log.e(TAG, "Error in runReflectionTests", t);
        }
    }
}
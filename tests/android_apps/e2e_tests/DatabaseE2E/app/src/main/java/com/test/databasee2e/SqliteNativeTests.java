package com.test.databasee2e;

public final class SqliteNativeTests {

    static {
        // Loads libsqlite_native_tests.so
        System.loadLibrary("sqlite_native_tests");
    }

    /**
     * Explicitly initializes this class and loads the native library.
     *
     * The actual SQLite test calls remain in runTests(). DatabaseE2E invokes
     * this early so Frida's asynchronous module observer can finish installing
     * hooks before the test library's SQLite APIs are exercised.
     */
    public static void preload() {
        // Deliberately empty. Calling this method triggers class initialization.
    }

    // Native entry: Java_com_test_databasee2e_SqliteNativeTests_runTests
    // dbDir - absolute path to the app's databases directory
    public static native void runTests(String dbDir);

    private SqliteNativeTests() {}
}
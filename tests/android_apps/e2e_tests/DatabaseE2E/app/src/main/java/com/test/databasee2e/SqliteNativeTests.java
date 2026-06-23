package com.test.databasee2e;

public final class SqliteNativeTests {

    static {
        // Loads libsqlite_native_tests.so
        System.loadLibrary("sqlite_native_tests");
    }

    // Native entry: Java_com_test_databasee2e_SqliteNativeTests_runTests
    // dbDir - absolute path to the app's databases directory
    public static native void runTests(String dbDir);

    private SqliteNativeTests() {}
}
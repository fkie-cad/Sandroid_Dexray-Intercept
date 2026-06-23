#include <jni.h>
#include <android/log.h>
#include <string.h>
#include <stdlib.h>
#include "sqlite3.h"

#define LOG_TAG "SQLITE_NATIVE_E2E"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * SqliteNativeTests for hook_native_sqlite() in sql.ts.
 *
 * The SQLite amalgamation is compiled directly into libsqlite_native_tests.so.
 * hook_native_sqlite() filters modules whose name contains "sqlite"; this library
 * matches that filter, so sqlite3_bind_int and sqlite3_open16 compiled here are
 * hooked by the same mechanism that hooks libsqlite.so.
 *
 * Covered hook targets not reachable from the Java layer:
 *   sqlite3_open16  - UTF-16 database open
 *   sqlite3_bind_int - 32-bit integer bind; Android JNI bridge uses bind_int64
 */

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, name) do { \
    if (cond) { LOGI("  PASS: %s", name); tests_passed++; } \
    else       { LOGE("  FAIL: %s", name); tests_failed++; } \
} while (0)

/*
 * Test: sqlite3_open16
 * Constructs a UTF-16LE path and opens a database. The Android JNI bridge
 * never calls sqlite3_open16 from Java code.
 */
static void test_sqlite3_open16(JNIEnv *env, jstring dbDir) {
    LOGI("");
    LOGI("=== test_sqlite3_open16 ===");

    const jchar *dirChars = (*env)->GetStringChars(env, dbDir, NULL);
    if (!dirChars) {
        LOGE("GetStringChars failed");
        tests_failed++;
        return;
    }
    jsize dirLen    = (*env)->GetStringLength(env, dbDir);
    const char *suffix  = "/sqlite_open16_test.db";
    jsize suffixLen = (jsize) strlen(suffix);
    jsize totalLen  = dirLen + suffixLen;

    /* UTF-16LE path: ASCII suffix codepoints are identical in UTF-16LE */
    jchar *path16 = (jchar *) malloc((size_t)(totalLen + 1) * sizeof(jchar));
    if (!path16) {
        LOGE("malloc failed");
        (*env)->ReleaseStringChars(env, dbDir, dirChars);
        tests_failed++;
        return;
    }
    memcpy(path16, dirChars, (size_t)(dirLen * (jsize)sizeof(jchar)));
    (*env)->ReleaseStringChars(env, dbDir, dirChars);

    for (jsize i = 0; i < suffixLen; i++) {
        path16[dirLen + i] = (jchar)(unsigned char)suffix[i];
    }
    path16[totalLen] = 0;

    sqlite3 *db = NULL;
    int rc = sqlite3_open16(path16, &db);
    free(path16);

    TEST_ASSERT(rc == SQLITE_OK, "sqlite3_open16 returns SQLITE_OK");
    LOGI("sqlite3_open16 result: %d", rc);

    if (db) sqlite3_close(db);
}

/*
 * Test: sqlite3_bind_int
 * Binds a 32-bit integer explicitly. The Android JNI bridge always routes
 * Java integer bindings through sqlite3_bind_int64.
 */
static void test_sqlite3_bind_int(JNIEnv *env, jstring dbDir) {
    LOGI("");
    LOGI("=== test_sqlite3_bind_int ===");

    const char *dir = (*env)->GetStringUTFChars(env, dbDir, NULL);
    if (!dir) {
        LOGE("GetStringUTFChars failed");
        tests_failed++;
        return;
    }

    const char *filename = "/sqlite_bind_int_test.db";
    size_t pathLen = strlen(dir) + strlen(filename) + 1;
    char *path = (char *) malloc(pathLen);
    if (!path) {
        LOGE("malloc failed");
        (*env)->ReleaseStringUTFChars(env, dbDir, dir);
        tests_failed++;
        return;
    }
    strcpy(path, dir);
    strcat(path, filename);
    (*env)->ReleaseStringUTFChars(env, dbDir, dir);

    sqlite3 *db = NULL;
    int rc = sqlite3_open(path, &db);
    free(path);

    TEST_ASSERT(rc == SQLITE_OK, "sqlite3_open for bind_int test");
    if (rc != SQLITE_OK || !db) {
        LOGE("sqlite3_open failed: %d", rc);
        return;
    }

    char *errMsg = NULL;
    rc = sqlite3_exec(db,
            "DROP TABLE IF EXISTS bind_int_test;"
            "CREATE TABLE bind_int_test (id INTEGER PRIMARY KEY, val32 INTEGER);",
            NULL, NULL, &errMsg);
    if (rc != SQLITE_OK) {
        LOGE("CREATE TABLE failed: %s", errMsg ? errMsg : "unknown");
        sqlite3_free(errMsg);
        sqlite3_close(db);
        tests_failed++;
        return;
    }

    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(db,
            "INSERT INTO bind_int_test (val32) VALUES (?)",
            -1, &stmt, NULL);
    TEST_ASSERT(rc == SQLITE_OK, "sqlite3_prepare_v2 for bind_int");

    if (rc == SQLITE_OK && stmt) {
        rc = sqlite3_bind_int(stmt, 1, 42);
        TEST_ASSERT(rc == SQLITE_OK, "sqlite3_bind_int(stmt, 1, 42) returns SQLITE_OK");

        rc = sqlite3_step(stmt);
        TEST_ASSERT(rc == SQLITE_DONE, "sqlite3_step returns SQLITE_DONE");

        sqlite3_finalize(stmt);
    }

    sqlite3_close(db);
}

JNIEXPORT void JNICALL
Java_com_test_databasee2e_SqliteNativeTests_runTests(JNIEnv *env,
                                                      jclass  clazz,
                                                      jstring dbDir) {
    (void)clazz;

    tests_passed = 0;
    tests_failed = 0;

    LOGI("========================================");
    LOGI("SqliteNativeTests: starting");
    LOGI("========================================");

    LOGI(">> Running test_sqlite3_open16...");
    test_sqlite3_open16(env, dbDir);

    LOGI(">> Running test_sqlite3_bind_int...");
    test_sqlite3_bind_int(env, dbDir);

    LOGI("========================================");
    LOGI("SqliteNativeTests summary: %d passed, %d failed",
         tests_passed, tests_failed);
    LOGI("========================================");
}
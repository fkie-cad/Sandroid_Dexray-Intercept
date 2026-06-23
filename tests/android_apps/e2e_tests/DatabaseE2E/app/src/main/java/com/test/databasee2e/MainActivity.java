package com.test.databasee2e;

import android.app.Activity;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.DefaultDatabaseErrorHandler;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.util.Log;

import androidx.lifecycle.ProcessLifecycleOwner;
import androidx.room.Room;
import androidx.sqlite.db.SimpleSQLiteQuery;
import androidx.sqlite.db.SupportSQLiteQuery;

import java.io.File;
import java.util.List;

public class MainActivity extends Activity {

    private static final String TAG = "DATABASE_E2E";

    private static final String SQLITE_DB_NAME  = "sqlite_e2e.db";
    private static final String SQLITE_TABLE    = "e2e_table";
    private static final String WCDB_DB_NAME    = "wcdb_e2e.db";
    private static final String WCDB_TABLE      = "e2e_wcdb";
    private static final String SQLCIPHER_PASSWORD = "test_pass_123";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.i(TAG, "DatabaseE2E started");

        try {

            // 1) android.database.sqlite.SQLiteDatabase - all overloads
            try {
                runSqliteJavaTests();
                Log.i(TAG, "runSqliteJavaTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "runSqliteJavaTests failed", t);
            }

            // 1b) Native SQLite bind type coverage - REAL, BLOB, NULL, explicit TEXT
            try {
                runNativeBindTypeTests();
                Log.i(TAG, "runNativeBindTypeTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "runNativeBindTypeTests failed", t);
            }

            // 1c) Native SQLite open16 + bind_int - only reachable from native C code
            try {
                SqliteNativeTests.runTests(getDatabasePath("x").getParent());
                Log.i(TAG, "SqliteNativeTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "SqliteNativeTests failed", t);
            }
            
            // 2) androidx.room - builder, callbacks, DAO, LiveData, Flow, RawQuery
            try {
                runRoomTests();
                Log.i(TAG, "runRoomTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "runRoomTests failed", t);
            }

            // 3) net.sqlcipher.database - open, exec, transaction, pragma
            try {
                runSqlCipherTests();
                Log.i(TAG, "runSqlCipherTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "runSqlCipherTests failed", t);
            }

            // 4) Room + SQLCipher SupportFactory integration
            try {
                new RoomSqlCipherTests(this).runTests();
                Log.i(TAG, "RoomSqlCipherTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "RoomSqlCipherTests failed", t);
            }

            // 5) com.tencent.wcdb.database - all overloads
            try {
                runWcdbTests();
                Log.i(TAG, "runWcdbTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "runWcdbTests failed", t);
            }

        } catch (Throwable t) {
            Log.e(TAG, "Unexpected error in DatabaseE2E", t);
        } finally {
            Log.i(TAG, "DatabaseE2E finished");
            finish();
        }
    }

    // ----------------------------------------------------------------
    // android.database.sqlite.SQLiteDatabase
    // ----------------------------------------------------------------

    private void runSqliteJavaTests() {
        Log.i(TAG, "runSqliteJavaTests");
        SQLiteDatabase db = null;
        try {
            // openOrCreateDatabase(String, CursorFactory) via Context
            db = openOrCreateDatabase(SQLITE_DB_NAME, MODE_PRIVATE, null);
            Log.i(TAG, "openOrCreateDatabase(Context) OK: " + db.getPath());

            String dbPath = getDatabasePath(SQLITE_DB_NAME).getAbsolutePath();

            // openDatabase(String, CursorFactory, int)
            SQLiteDatabase db2 = SQLiteDatabase.openDatabase(
                    dbPath, null,
                    SQLiteDatabase.OPEN_READWRITE | SQLiteDatabase.CREATE_IF_NECESSARY
            );
            Log.i(TAG, "openDatabase(String,CursorFactory,int) OK");
            db2.close();

            // openDatabase(String, CursorFactory, int, DatabaseErrorHandler) - T3
            SQLiteDatabase db3 = SQLiteDatabase.openDatabase(
                    dbPath, null,
                    SQLiteDatabase.OPEN_READWRITE | SQLiteDatabase.CREATE_IF_NECESSARY,
                    new DefaultDatabaseErrorHandler()
            );
            Log.i(TAG, "openDatabase(String,CursorFactory,int,DatabaseErrorHandler) OK");
            db3.close();

            // openOrCreateDatabase(String, CursorFactory, DatabaseErrorHandler) - T4
            SQLiteDatabase db4 = SQLiteDatabase.openOrCreateDatabase(
                    dbPath, null,
                    new DefaultDatabaseErrorHandler()
            );
            Log.i(TAG, "openOrCreateDatabase(String,CursorFactory,DatabaseErrorHandler) OK");
            db4.close();

            // Schema setup
            db.execSQL("DROP TABLE IF EXISTS " + SQLITE_TABLE);
            db.execSQL("CREATE TABLE " + SQLITE_TABLE + " ("
                    + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    + "name TEXT,"
                    + "age INTEGER"
                    + ")");

            // execSQL(String, Object[])
            db.execSQL("INSERT INTO " + SQLITE_TABLE + "(name,age) VALUES (?,?)",
                    new Object[]{"Alice", 30});

            // insert(String, String, ContentValues)
            ContentValues cv = new ContentValues();
            cv.put("name", "Bob");
            cv.put("age", 40);
            long rowInsert = db.insert(SQLITE_TABLE, null, cv);
            Log.i(TAG, "insert rowId=" + rowInsert);

            // insertOrThrow(String, String, ContentValues)
            ContentValues cv2 = new ContentValues();
            cv2.put("name", "Charlie");
            cv2.put("age", 25);
            long rowInsertThrow = db.insertOrThrow(SQLITE_TABLE, null, cv2);
            Log.i(TAG, "insertOrThrow rowId=" + rowInsertThrow);

            // insertWithOnConflict(String, String, ContentValues, int)
            ContentValues cv3 = new ContentValues();
            cv3.put("name", "Alice");
            cv3.put("age", 31);
            long rowConflict = db.insertWithOnConflict(
                    SQLITE_TABLE, null, cv3, SQLiteDatabase.CONFLICT_REPLACE);
            Log.i(TAG, "insertWithOnConflict rowId=" + rowConflict);

            String[] columns = new String[]{"id", "name", "age"};

            // query(String, String[], String, String[], String, String, String)
            Cursor c1 = db.query(SQLITE_TABLE, columns, "name=?",
                    new String[]{"Alice"}, null, null, "id ASC");
            c1.close();

            // query(String, String[], String, String[], String, String, String, String)
            Cursor c2 = db.query(SQLITE_TABLE, columns, "age>=?",
                    new String[]{"30"}, null, null, "name ASC", "5");
            c2.close();

            // query(boolean, String, String[], String, String[], String, String, String, String)
            Cursor c3 = db.query(true, SQLITE_TABLE, columns, "age>?",
                    new String[]{"20"}, null, null, "age DESC", "10");
            c3.close();

            // query(boolean, ..., CancellationSignal)
            Cursor c4 = db.query(true, SQLITE_TABLE, columns, "age>?",
                    new String[]{"20"}, null, null, "age DESC", "5",
                    new CancellationSignal());
            c4.close();

            // queryWithFactory(CursorFactory, boolean, ...) 10-arg - T1 overload 1
            Cursor c5 = db.queryWithFactory(null, false, SQLITE_TABLE, columns,
                    "age>?", new String[]{"20"}, null, null, "id ASC", "5");
            Log.i(TAG, "queryWithFactory(10-arg) count=" + c5.getCount());
            c5.close();

            // queryWithFactory(CursorFactory, boolean, ..., CancellationSignal) 11-arg - T1 overload 2
            Cursor c6 = db.queryWithFactory(null, false, SQLITE_TABLE, columns,
                    "age>?", new String[]{"20"}, null, null, "id ASC", "5",
                    new CancellationSignal());
            Log.i(TAG, "queryWithFactory(11-arg) count=" + c6.getCount());
            c6.close();

            // rawQuery(String, String[])
            Cursor c7 = db.rawQuery(
                    "SELECT id,name,age FROM " + SQLITE_TABLE + " WHERE name LIKE ?",
                    new String[]{"A%"});
            c7.close();

            // rawQuery(String, String[], CancellationSignal)
            Cursor c8 = db.rawQuery(
                    "SELECT id,name,age FROM " + SQLITE_TABLE + " WHERE age>?",
                    new String[]{"10"}, new CancellationSignal());
            c8.close();

            // rawQueryWithFactory(CursorFactory, String, String[], String) - T2 overload 1
            Cursor c9 = db.rawQueryWithFactory(
                    null,
                    "SELECT id,name,age FROM " + SQLITE_TABLE + " WHERE name=?",
                    new String[]{"Alice"},
                    SQLITE_TABLE);
            Log.i(TAG, "rawQueryWithFactory(4-arg) count=" + c9.getCount());
            c9.close();

            // rawQueryWithFactory(CursorFactory, String, String[], String, CancellationSignal) - T2 overload 2
            Cursor c10 = db.rawQueryWithFactory(
                    null,
                    "SELECT id,name,age FROM " + SQLITE_TABLE + " WHERE age>?",
                    new String[]{"20"},
                    SQLITE_TABLE,
                    new CancellationSignal());
            Log.i(TAG, "rawQueryWithFactory(5-arg) count=" + c10.getCount());
            c10.close();

            // update(String, ContentValues, String, String[])
            ContentValues upd = new ContentValues();
            upd.put("age", 32);
            int rowsUpd = db.update(SQLITE_TABLE, upd, "name=?", new String[]{"Alice"});
            Log.i(TAG, "update rows=" + rowsUpd);

            // updateWithOnConflict(String, ContentValues, String, String[], int)
            ContentValues upd2 = new ContentValues();
            upd2.put("age", 33);
            int rowsUpdConf = db.updateWithOnConflict(
                    SQLITE_TABLE, upd2, "name=?",
                    new String[]{"Alice"}, SQLiteDatabase.CONFLICT_IGNORE);
            Log.i(TAG, "updateWithOnConflict rows=" + rowsUpdConf);

            // delete(String, String, String[])
            int rowsDel = db.delete(SQLITE_TABLE, "name=?", new String[]{"Charlie"});
            Log.i(TAG, "delete rows=" + rowsDel);

        } catch (Throwable t) {
            Log.e(TAG, "runSqliteJavaTests error", t);
        } finally {
            if (db != null) db.close();
        }
    }

    // Exercises sqlite3_bind_double, sqlite3_bind_blob, sqlite3_bind_null, sqlite3_bind_text.
    // sqlite3_bind_int is excluded: the Android SQLite JNI bridge routes all integer
    // bindings through sqlite3_bind_int64, making sqlite3_bind_int unreachable from Java.
    private void runNativeBindTypeTests() {
        Log.i(TAG, "runNativeBindTypeTests");
        SQLiteDatabase db = null;
        try {
            db = openOrCreateDatabase("bind_types_e2e.db", MODE_PRIVATE, null);

            // Table with all relevant column types
            db.execSQL("DROP TABLE IF EXISTS bind_type_test");
            db.execSQL("CREATE TABLE bind_type_test ("
                    + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    + "val_real REAL,"
                    + "val_blob BLOB,"
                    + "val_text TEXT,"
                    + "val_null TEXT"
                    + ")");

            // ContentValues path: triggers bind_double, bind_blob, bind_text, bind_null
            ContentValues cv = new ContentValues();
            cv.put("val_real",  3.14159);                    // sqlite3_bind_double
            cv.put("val_blob",  new byte[]{0x01, 0x02, 0x03, 0x04}); // sqlite3_bind_blob
            cv.put("val_text",  "bind_text_value");           // sqlite3_bind_text or bind_text16
            cv.putNull("val_null");                           // sqlite3_bind_null
            long rowId1 = db.insert("bind_type_test", null, cv);
            Log.i(TAG, "bind types insert rowId=" + rowId1);

            // execSQL Object[] path: same bind types via parameterized statement
            db.execSQL(
                    "INSERT INTO bind_type_test (val_real, val_blob, val_text, val_null)"
                    + " VALUES (?, ?, ?, ?)",
                    new Object[]{
                            2.71828,                          // sqlite3_bind_double
                            new byte[]{(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF}, // sqlite3_bind_blob
                            "another_text_value",             // sqlite3_bind_text or bind_text16
                            null                              // sqlite3_bind_null
                    }
            );
            Log.i(TAG, "bind types execSQL(Object[]) OK");

            // rawQuery to confirm rows are present
            Cursor c = db.rawQuery(
                    "SELECT id, val_real, val_blob, val_text, val_null FROM bind_type_test",
                    null);
            Log.i(TAG, "bind_type_test row count=" + c.getCount());
            c.close();

        } catch (Throwable t) {
            Log.e(TAG, "runNativeBindTypeTests error", t);
        } finally {
            if (db != null) db.close();
        }
    }


    // ----------------------------------------------------------------
    // androidx.room
    // ----------------------------------------------------------------

    private void runRoomTests() {
        Log.i(TAG, "runRoomTests");
        E2EDb db = null;
        try {
            // Delete database before building to ensure SupportSQLiteOpenHelper.Callback.onCreate fires
            getApplicationContext().deleteDatabase("room_e2e.db");
            db = Room.databaseBuilder(getApplicationContext(), E2EDb.class, "room_e2e.db")
                    .allowMainThreadQueries()
                    .build();

            UserDao dao = db.userDao();

            User alice = new User();
            alice.name = "Alice";
            alice.age = 30;
            long idAlice = dao.insert(alice);
            Log.i(TAG, "Inserted Alice id=" + idAlice);

            User bob = new User();
            bob.name = "Bob";
            bob.age = 40;
            long idBob = dao.insert(bob);
            Log.i(TAG, "Inserted Bob id=" + idBob);

            alice.id = (int) idAlice;
            alice.age = 31;
            int updCnt = dao.update(alice);
            Log.i(TAG, "Updated Alice rows=" + updCnt);

            List<User> older = dao.selectOlder(20);
            Log.i(TAG, "Users older than 20: " + older.size());

            // RoomDatabase.query(SupportSQLiteQuery)
            SupportSQLiteQuery rawQuery = new SimpleSQLiteQuery(
                    "SELECT * FROM e2e_user WHERE name LIKE ?",
                    new Object[]{"A%"});
            List<User> rawResult = dao.rawSelect(rawQuery);
            Log.i(TAG, "rawSelect count: " + rawResult.size());

            bob.id = (int) idBob;
            int delCnt = dao.delete(bob);
            Log.i(TAG, "Deleted Bob rows=" + delCnt);

            // LiveData.observe(LifecycleOwner, Observer) - T6
            // ProcessLifecycleOwner is always active; observe() call is the hook target
            dao.selectAllLive().observe(ProcessLifecycleOwner.get(), users ->
                    Log.i(TAG, "LiveData delivered users: " + users.size())
            );
            Log.i(TAG, "LiveData.observe called");

            // FlowCollector.emit - T7
            // Collection runs on Dispatchers.IO to avoid main-thread deadlock
            int flowCount = FlowTestHelper.collectFirst(db.flowUserDao());
            Log.i(TAG, "Flow collected count=" + flowCount);

        } catch (Throwable t) {
            Log.e(TAG, "runRoomTests error", t);
        } finally {
            if (db != null) db.close();
        }
    }

    // ----------------------------------------------------------------
    // net.sqlcipher.database
    // ----------------------------------------------------------------

    private void runSqlCipherTests() {
        Log.i(TAG, "runSqlCipherTests");
        try {
            net.sqlcipher.database.SQLiteDatabase.loadLibs(this);
            Log.i(TAG, "SQLCipher loadLibs OK");

            SqlCipherHelper helper = new SqlCipherHelper(this);

            net.sqlcipher.database.SQLiteDatabase db =
                    helper.getWritableDatabase(SQLCIPHER_PASSWORD);
            Log.i(TAG, "getWritableDatabase OK: " + db.getPath());

            helper.basicOps(db);

            db.beginTransaction();
            db.execSQL("INSERT INTO e2e_cipher (name, age) VALUES ('Charlie', 25)");
            db.setTransactionSuccessful();
            db.endTransaction();

            net.sqlcipher.database.SQLiteDatabase dbRead =
                    helper.getReadableDatabase(SQLCIPHER_PASSWORD);
            Log.i(TAG, "getReadableDatabase OK: " + dbRead.getPath());
            dbRead.close();

            File dbFile = getDatabasePath("sqlcipher_e2e_direct.db");
            if (dbFile.exists()) {
                //noinspection ResultOfMethodCallIgnored
                dbFile.delete();
            }

            // openOrCreateDatabase(File, String)
            net.sqlcipher.database.SQLiteDatabase dbFile1 =
                    net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase(
                            dbFile, SQLCIPHER_PASSWORD, null);
            Log.i(TAG, "openOrCreateDatabase(File,String) OK");
            dbFile1.execSQL("CREATE TABLE IF NOT EXISTS direct_table "
                    + "(id INTEGER PRIMARY KEY, value TEXT)");
            dbFile1.execSQL("INSERT INTO direct_table (id,value) VALUES (1,'direct')");
            dbFile1.close();

            // openOrCreateDatabase(String, char[], CursorFactory, DatabaseErrorHandler)
            net.sqlcipher.database.SQLiteDatabase dbPath =
                    net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase(
                            dbFile.getAbsolutePath(),
                            SQLCIPHER_PASSWORD.toCharArray(),
                            null,
                            null);
            Log.i(TAG, "openOrCreateDatabase(String,char[]) OK");
            dbPath.execSQL("INSERT INTO direct_table (id,value) VALUES (2,'path_char')");
            dbPath.close();

            // rawExecSQL
            net.sqlcipher.database.SQLiteDatabase dbPragma =
                    helper.getWritableDatabase(SQLCIPHER_PASSWORD);
            dbPragma.rawExecSQL("PRAGMA cipher_memory_security = OFF");
            dbPragma.close();

            // PRAGMA key via execSQL - triggers database.sqlcipher.pragma hook.
            // SQLCipher 4.x rejects this call on an already-open database (returns a result
            // set, must be called as a query). The hook fires before the original execSQL runs,
            // so the event is captured regardless of the throw.
            net.sqlcipher.database.SQLiteDatabase dbPragmaKey =
                    helper.getWritableDatabase(SQLCIPHER_PASSWORD);
            try {
                dbPragmaKey.execSQL("PRAGMA key='" + SQLCIPHER_PASSWORD + "'");
                Log.i(TAG, "PRAGMA key execSQL OK");
            } catch (Throwable t) {
                Log.i(TAG, "PRAGMA key execSQL threw (expected in SQLCipher 4.x): " + t.getMessage());
            } finally {
                dbPragmaKey.close();
            }

            db.close();
            Log.i(TAG, "SQLCipher primary DB closed");

        } catch (Throwable t) {
            Log.e(TAG, "runSqlCipherTests error", t);
        }
    }

    // ----------------------------------------------------------------
    // com.tencent.wcdb.database
    // ----------------------------------------------------------------

    private void runWcdbTests() {
        Log.i(TAG, "runWcdbTests");
        com.tencent.wcdb.database.SQLiteDatabase db = null;
        try {
            String path = getDatabasePath(WCDB_DB_NAME).getAbsolutePath();

            db = com.tencent.wcdb.database.SQLiteDatabase.openDatabase(
                    path, null,
                    com.tencent.wcdb.database.SQLiteDatabase.CREATE_IF_NECESSARY
                            | com.tencent.wcdb.database.SQLiteDatabase.OPEN_READWRITE);
            Log.i(TAG, "WCDB.openDatabase OK");

            com.tencent.wcdb.database.SQLiteDatabase db2 =
                    com.tencent.wcdb.database.SQLiteDatabase.openOrCreateDatabase(path, null);
            Log.i(TAG, "WCDB.openOrCreateDatabase OK");
            db2.close();

            db.execSQL("DROP TABLE IF EXISTS " + WCDB_TABLE);
            db.execSQL("CREATE TABLE " + WCDB_TABLE
                    + " (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, age INTEGER)");

            db.execSQL("INSERT INTO " + WCDB_TABLE + " (name,age) VALUES (?,?)",
                    new Object[]{"Alice", 30});

            ContentValues cv = new ContentValues();
            cv.put("name", "Bob");
            cv.put("age", 40);
            long rowInsert = db.insert(WCDB_TABLE, null, cv);
            Log.i(TAG, "WCDB.insert rowId=" + rowInsert);

            Cursor c = db.rawQuery(
                    "SELECT id,name,age FROM " + WCDB_TABLE + " WHERE age>?",
                    new String[]{"20"});
            Log.i(TAG, "WCDB.rawQuery count=" + c.getCount());
            c.close();

            ContentValues upd = new ContentValues();
            upd.put("age", 31);
            int rowsUpd = db.update(WCDB_TABLE, upd, "name=?", new String[]{"Alice"});
            Log.i(TAG, "WCDB.update rows=" + rowsUpd);

            int rowsDel = db.delete(WCDB_TABLE, "name=?", new String[]{"Bob"});
            Log.i(TAG, "WCDB.delete rows=" + rowsDel);

            db.beginTransaction();
            db.execSQL("INSERT INTO " + WCDB_TABLE + " (name,age) VALUES ('Charlie',25)");
            db.setTransactionSuccessful();
            db.endTransaction();

        } catch (Throwable t) {
            Log.e(TAG, "runWcdbTests error", t);
        } finally {
            if (db != null) db.close();
        }
    }
}
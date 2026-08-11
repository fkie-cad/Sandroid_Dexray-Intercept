package com.test.databasee2e;

import android.app.Activity;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.DefaultDatabaseErrorHandler;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteTransactionListener;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.util.Log;

import androidx.lifecycle.ProcessLifecycleOwner;
import androidx.room.Room;
import androidx.room.migration.Migration;
import androidx.sqlite.db.SupportSQLiteDatabase;
import androidx.sqlite.db.SimpleSQLiteQuery;
import androidx.sqlite.db.SupportSQLiteQuery;

import java.io.File;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
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

            // 2b) androidx.room - schema migration / RoomOpenHelper.onUpgrade
            try {
                runRoomUpgradeTests();
                Log.i(TAG, "runRoomUpgradeTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "runRoomUpgradeTests failed", t);
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

            // Direct RoomDatabase.query overload coverage.
            // DAO rawSelect above may route through RoomDatabase.query internally,
            // but these explicit calls ensure every public overload is exercised.

            // 1) RoomDatabase.query(SupportSQLiteQuery)
            SupportSQLiteQuery directSupportQuery = new SimpleSQLiteQuery(
                    "SELECT * FROM e2e_user WHERE age >= ?",
                    new Object[]{20}
            );
            Cursor supportQueryCursor = db.query(directSupportQuery);
            try {
                Log.i(TAG, "RoomDatabase.query(SupportSQLiteQuery) count="
                        + supportQueryCursor.getCount());
            } finally {
                supportQueryCursor.close();
            }

            // 2) RoomDatabase.query(SupportSQLiteQuery, CancellationSignal)
            SupportSQLiteQuery cancellableSupportQuery = new SimpleSQLiteQuery(
                    "SELECT * FROM e2e_user WHERE name = ?",
                    new Object[]{"Alice"}
            );
            Cursor cancellableQueryCursor = db.query(
                    cancellableSupportQuery,
                    new CancellationSignal()
            );
            try {
                Log.i(TAG, "RoomDatabase.query(SupportSQLiteQuery,CancellationSignal) count="
                        + cancellableQueryCursor.getCount());
            } finally {
                cancellableQueryCursor.close();
            }

            // 3) RoomDatabase.query(String, Object[])
            Cursor stringQueryCursor = db.query(
                    "SELECT * FROM e2e_user WHERE age < ?",
                    new Object[]{50}
            );
            try {
                Log.i(TAG, "RoomDatabase.query(String,Object[]) count="
                        + stringQueryCursor.getCount());
            } finally {
                stringQueryCursor.close();
            }

            // Direct RoomDatabase transaction lifecycle coverage.
            // No database mutation is needed; this explicitly exercises
            // beginTransaction(), setTransactionSuccessful(), and endTransaction().
            db.beginTransaction();
            try {
                db.setTransactionSuccessful();
                Log.i(TAG, "RoomDatabase direct transaction marked successful");
            } finally {
                db.endTransaction();
                Log.i(TAG, "RoomDatabase direct transaction ended");
            }

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
    // androidx.room migration / RoomOpenHelper.onUpgrade
    // ----------------------------------------------------------------

    private void runRoomUpgradeTests() {
        final String upgradeDbName = "room_upgrade_e2e.db";

        Log.i(TAG, "runRoomUpgradeTests");

        UpgradeDbV1 version1Database = null;
        UpgradeDbV2 version2Database = null;

        try {
            // Start from a known schema-v1 state on every E2E execution.
            getApplicationContext().deleteDatabase(upgradeDbName);

            // 1) Create version-1 database.
            version1Database = Room.databaseBuilder(
                            getApplicationContext(),
                            UpgradeDbV1.class,
                            upgradeDbName
                    )
                    .allowMainThreadQueries()
                    .build();

            // Force open/create before closing it, ensuring the on-disk schema
            // records user_version = 1 for the subsequent v2 open.
            version1Database.getOpenHelper().getWritableDatabase();
            version1Database.close();
            version1Database = null;

            Log.i(TAG, "Room upgrade E2E: version-1 database created");

            // 2) Reopen the same path as schema version 2 with an explicit
            // migration. This must invoke RoomOpenHelper.onUpgrade(..., 1, 2).
            Migration migration1To2 = new Migration(1, 2) {
                @Override
                public void migrate(SupportSQLiteDatabase database) {
                    database.execSQL(
                            "ALTER TABLE room_upgrade_user " +
                            "ADD COLUMN age INTEGER NOT NULL DEFAULT 0"
                    );
                    Log.i(TAG, "Room upgrade E2E migration 1->2 executed");
                }
            };

            version2Database = Room.databaseBuilder(
                            getApplicationContext(),
                            UpgradeDbV2.class,
                            upgradeDbName
                    )
                    .addMigrations(migration1To2)
                    .allowMainThreadQueries()
                    .build();

            // Force the v2 database open and migration execution.
            version2Database.getOpenHelper().getWritableDatabase();

            Log.i(TAG, "Room upgrade E2E: version-2 database opened");

        } catch (Throwable t) {
            Log.e(TAG, "runRoomUpgradeTests error", t);
        } finally {
            if (version1Database != null) {
                version1Database.close();
            }

            if (version2Database != null) {
                version2Database.close();
            }
        }
    }

    private File freshSqlCipherDatabaseFile(String name) {
        deleteDatabase(name);
        return getDatabasePath(name);
    }

    private void initializeAndCloseSqlCipherDatabase(
            net.sqlcipher.database.SQLiteDatabase database,
            String label
    ) {
        try {
            database.execSQL(
                    "CREATE TABLE IF NOT EXISTS overload_probe " +
                    "(id INTEGER PRIMARY KEY, label TEXT)"
            );
            Log.i(TAG, label + " OK: " + database.getPath());
        } finally {
            database.close();
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

            // SQLiteOpenHelper password overload coverage:
            // getWritableDatabase / getReadableDatabase with byte[] and char[].
            byte[] passwordBytes = net.sqlcipher.database.SQLiteDatabase.getBytes(
                    SQLCIPHER_PASSWORD.toCharArray()
            );
            char[] passwordChars = SQLCIPHER_PASSWORD.toCharArray();

            SqlCipherHelper helperWritableBytes = new SqlCipherHelper(this);
            net.sqlcipher.database.SQLiteDatabase dbWritableBytes =
                    helperWritableBytes.getWritableDatabase(passwordBytes);
            Log.i(TAG, "getWritableDatabase(byte[]) OK: " + dbWritableBytes.getPath());
            dbWritableBytes.close();

            SqlCipherHelper helperWritableChars = new SqlCipherHelper(this);
            net.sqlcipher.database.SQLiteDatabase dbWritableChars =
                    helperWritableChars.getWritableDatabase(passwordChars);
            Log.i(TAG, "getWritableDatabase(char[]) OK: " + dbWritableChars.getPath());
            dbWritableChars.close();

            SqlCipherHelper helperReadableBytes = new SqlCipherHelper(this);
            net.sqlcipher.database.SQLiteDatabase dbReadableBytes =
                    helperReadableBytes.getReadableDatabase(passwordBytes);
            Log.i(TAG, "getReadableDatabase(byte[]) OK: " + dbReadableBytes.getPath());
            dbReadableBytes.close();

            SqlCipherHelper helperReadableChars = new SqlCipherHelper(this);
            net.sqlcipher.database.SQLiteDatabase dbReadableChars =
                    helperReadableChars.getReadableDatabase(passwordChars);
            Log.i(TAG, "getReadableDatabase(char[]) OK: " + dbReadableChars.getPath());
            dbReadableChars.close();

            // File + String + CursorFactory
            File fileString3 = freshSqlCipherDatabaseFile("sqlcipher_file_string_3.db");
            initializeAndCloseSqlCipherDatabase(
                    net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase(
                            fileString3, SQLCIPHER_PASSWORD, null
                    ),
                    "openOrCreateDatabase(File,String,CursorFactory)"
            );

            // File + String + CursorFactory + SQLiteDatabaseHook
            File fileString4 = freshSqlCipherDatabaseFile("sqlcipher_file_string_4.db");
            initializeAndCloseSqlCipherDatabase(
                    net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase(
                            fileString4, SQLCIPHER_PASSWORD, null, null
                    ),
                    "openOrCreateDatabase(File,String,CursorFactory,SQLiteDatabaseHook)"
            );

            // File + String + CursorFactory + SQLiteDatabaseHook + DatabaseErrorHandler
            File fileString5 = freshSqlCipherDatabaseFile("sqlcipher_file_string_5.db");
            initializeAndCloseSqlCipherDatabase(
                    net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase(
                            fileString5, SQLCIPHER_PASSWORD, null, null, null
                    ),
                    "openOrCreateDatabase(File,String,CursorFactory,SQLiteDatabaseHook,DatabaseErrorHandler)"
            );

            // String + String password variants
            File pathString3File = freshSqlCipherDatabaseFile("sqlcipher_path_string_3.db");
            initializeAndCloseSqlCipherDatabase(
                    net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase(
                            pathString3File.getAbsolutePath(), SQLCIPHER_PASSWORD, null
                    ),
                    "openOrCreateDatabase(String,String,CursorFactory)"
            );

            File pathString4File = freshSqlCipherDatabaseFile("sqlcipher_path_string_4.db");
            initializeAndCloseSqlCipherDatabase(
                    net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase(
                            pathString4File.getAbsolutePath(), SQLCIPHER_PASSWORD, null, null
                    ),
                    "openOrCreateDatabase(String,String,CursorFactory,SQLiteDatabaseHook)"
            );

            File pathString5File = freshSqlCipherDatabaseFile("sqlcipher_path_string_5.db");
            initializeAndCloseSqlCipherDatabase(
                    net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase(
                            pathString5File.getAbsolutePath(), SQLCIPHER_PASSWORD, null, null, null
                    ),
                    "openOrCreateDatabase(String,String,CursorFactory,SQLiteDatabaseHook,DatabaseErrorHandler)"
            );

            // String + byte[] password variants
            File pathBytes3File = freshSqlCipherDatabaseFile("sqlcipher_path_bytes_3.db");
            initializeAndCloseSqlCipherDatabase(
                    net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase(
                            pathBytes3File.getAbsolutePath(), passwordBytes, null
                    ),
                    "openOrCreateDatabase(String,byte[],CursorFactory)"
            );

            File pathBytes4File = freshSqlCipherDatabaseFile("sqlcipher_path_bytes_4.db");
            initializeAndCloseSqlCipherDatabase(
                    net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase(
                            pathBytes4File.getAbsolutePath(), passwordBytes, null, null
                    ),
                    "openOrCreateDatabase(String,byte[],CursorFactory,SQLiteDatabaseHook)"
            );

            File pathBytes5File = freshSqlCipherDatabaseFile("sqlcipher_path_bytes_5.db");
            initializeAndCloseSqlCipherDatabase(
                    net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase(
                            pathBytes5File.getAbsolutePath(), passwordBytes, null, null, null
                    ),
                    "openOrCreateDatabase(String,byte[],CursorFactory,SQLiteDatabaseHook,DatabaseErrorHandler)"
            );

            // String + char[] password variants
            File pathChars3File = freshSqlCipherDatabaseFile("sqlcipher_path_chars_3.db");
            initializeAndCloseSqlCipherDatabase(
                    net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase(
                            pathChars3File.getAbsolutePath(), passwordChars, null
                    ),
                    "openOrCreateDatabase(String,char[],CursorFactory)"
            );

            File pathChars4File = freshSqlCipherDatabaseFile("sqlcipher_path_chars_4.db");
            initializeAndCloseSqlCipherDatabase(
                    net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase(
                            pathChars4File.getAbsolutePath(), passwordChars, null, null
                    ),
                    "openOrCreateDatabase(String,char[],CursorFactory,SQLiteDatabaseHook)"
            );

            File pathChars5File = freshSqlCipherDatabaseFile("sqlcipher_path_chars_5.db");
            initializeAndCloseSqlCipherDatabase(
                    net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase(
                            pathChars5File.getAbsolutePath(), passwordChars, null, null, null
                    ),
                    "openOrCreateDatabase(String,char[],CursorFactory,SQLiteDatabaseHook,DatabaseErrorHandler)"
            );

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

    private File freshWcdbDatabaseFile(String name) {
        deleteDatabase(name);
        return getDatabasePath(name);
    }

    private void initializeAndCloseWcdbDatabase(
            com.tencent.wcdb.database.SQLiteDatabase database,
            String label
    ) {
        try {
            database.execSQL(
                    "CREATE TABLE IF NOT EXISTS overload_probe " +
                    "(id INTEGER PRIMARY KEY, label TEXT)"
            );
            Log.i(TAG, label + " OK: " + database.getPath());
        } finally {
            database.close();
        }
    }


    private void runWcdbTests() {
        Log.i(TAG, "runWcdbTests");

        com.tencent.wcdb.database.SQLiteDatabase db = null;

        try {
            final int openFlags =
                    com.tencent.wcdb.database.SQLiteDatabase.CREATE_IF_NECESSARY
                            | com.tencent.wcdb.database.SQLiteDatabase.OPEN_READWRITE;
            final byte[] encryptedPassword =
                    "wcdb_e2e_pass".getBytes(StandardCharsets.UTF_8);

            // ------------------------------------------------------------
            // Existing WCDB CRUD / transaction coverage
            // ------------------------------------------------------------

            String path = getDatabasePath(WCDB_DB_NAME).getAbsolutePath();

            db = com.tencent.wcdb.database.SQLiteDatabase.openDatabase(
                    path,
                    null,
                    openFlags
            );
            Log.i(TAG, "WCDB.openDatabase(String,CursorFactory,int) OK");

            com.tencent.wcdb.database.SQLiteDatabase db2 =
                    com.tencent.wcdb.database.SQLiteDatabase.openOrCreateDatabase(
                            path,
                            null
                    );
            Log.i(TAG, "WCDB.openOrCreateDatabase(String,CursorFactory) OK");
            db2.close();

            db.execSQL("DROP TABLE IF EXISTS " + WCDB_TABLE);
            db.execSQL(
                    "CREATE TABLE " + WCDB_TABLE +
                    " (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, age INTEGER)"
            );

            db.execSQL(
                    "INSERT INTO " + WCDB_TABLE + " (name,age) VALUES (?,?)",
                    new Object[]{"Alice", 30}
            );

            ContentValues cv = new ContentValues();
            cv.put("name", "Bob");
            cv.put("age", 40);

            long rowInsert = db.insert(WCDB_TABLE, null, cv);
            Log.i(TAG, "WCDB.insert rowId=" + rowInsert);

            Cursor cursor = db.rawQuery(
                    "SELECT id,name,age FROM " + WCDB_TABLE + " WHERE age>?",
                    new Object[]{"20"}
            );
            Log.i(TAG, "WCDB.rawQuery(Object[]) count=" + cursor.getCount());
            cursor.close();

            // execSQL(String, Object[], CancellationSignal)
            com.tencent.wcdb.support.CancellationSignal execSignal =
                    new com.tencent.wcdb.support.CancellationSignal();

            db.execSQL(
                    "INSERT INTO " + WCDB_TABLE + " (name,age) VALUES (?,?)",
                    new Object[]{"CancelExec", 35},
                    execSignal
            );
            Log.i(TAG, "WCDB.execSQL(Object[],CancellationSignal) OK");

            // rawQuery(String, Object[], CancellationSignal)
            com.tencent.wcdb.support.CancellationSignal querySignal =
                    new com.tencent.wcdb.support.CancellationSignal();

            Cursor cancellationCursor = db.rawQuery(
                    "SELECT id,name,age FROM " + WCDB_TABLE + " WHERE age>=?",
                    new Object[]{"30"},
                    querySignal
            );
            Log.i(TAG, "WCDB.rawQuery(Object[],CancellationSignal) count="
                    + cancellationCursor.getCount());
            cancellationCursor.close();

            ContentValues upd = new ContentValues();
            upd.put("age", 31);

            int rowsUpd = db.update(
                    WCDB_TABLE,
                    upd,
                    "name=?",
                    new String[]{"Alice"}
            );
            Log.i(TAG, "WCDB.update rows=" + rowsUpd);

            int rowsDel = db.delete(
                    WCDB_TABLE,
                    "name=?",
                    new String[]{"Bob"}
            );
            Log.i(TAG, "WCDB.delete rows=" + rowsDel);

            // beginTransaction() no-argument overload
            db.beginTransaction();
            db.execSQL(
                    "INSERT INTO " + WCDB_TABLE + " (name,age) VALUES ('Charlie',25)"
            );
            db.setTransactionSuccessful();
            db.endTransaction();
            Log.i(TAG, "WCDB.beginTransaction() lifecycle OK");

            // beginTransaction(SQLiteTransactionListener, boolean) is private in
            // WCDB. Invoke it reflectively to exercise the runtime overload.
            try {
                SQLiteTransactionListener listener = new SQLiteTransactionListener() {
                    @Override
                    public void onBegin() {
                        Log.i(TAG, "WCDB transaction listener: onBegin");
                    }

                    @Override
                    public void onCommit() {
                        Log.i(TAG, "WCDB transaction listener: onCommit");
                    }

                    @Override
                    public void onRollback() {
                        Log.i(TAG, "WCDB transaction listener: onRollback");
                    }
                };

                Method beginTransactionWithListener =
                        com.tencent.wcdb.database.SQLiteDatabase.class.getDeclaredMethod(
                                "beginTransaction",
                                SQLiteTransactionListener.class,
                                boolean.class
                        );

                beginTransactionWithListener.setAccessible(true);
                beginTransactionWithListener.invoke(db, listener, false);

                db.execSQL(
                        "INSERT INTO " + WCDB_TABLE +
                        " (name,age) VALUES ('ReflectiveListener',26)"
                );
                db.setTransactionSuccessful();
                db.endTransaction();

                Log.i(TAG, "WCDB.beginTransaction(listener,false) reflective lifecycle OK");
            } catch (Throwable t) {
                Log.w(
                        TAG,
                        "WCDB.beginTransaction(listener,false) reflective call failed: " +
                                t.getClass().getSimpleName() + " - " + t.getMessage()
                );
            }

            // ------------------------------------------------------------
            // openDatabase(...) overload matrix: 5 overloads
            // ------------------------------------------------------------

            File openPlain3 = freshWcdbDatabaseFile("wcdb_open_plain_3.db");
            initializeAndCloseWcdbDatabase(
                    com.tencent.wcdb.database.SQLiteDatabase.openDatabase(
                            openPlain3.getAbsolutePath(),
                            null,
                            openFlags
                    ),
                    "WCDB.openDatabase(String,CursorFactory,int)"
            );

            File openPlain4 = freshWcdbDatabaseFile("wcdb_open_plain_4.db");
            initializeAndCloseWcdbDatabase(
                    com.tencent.wcdb.database.SQLiteDatabase.openDatabase(
                            openPlain4.getAbsolutePath(),
                            null,
                            openFlags,
                            null
                    ),
                    "WCDB.openDatabase(String,CursorFactory,int,DatabaseErrorHandler)"
            );

            File openPlain5 = freshWcdbDatabaseFile("wcdb_open_plain_5.db");
            initializeAndCloseWcdbDatabase(
                    com.tencent.wcdb.database.SQLiteDatabase.openDatabase(
                            openPlain5.getAbsolutePath(),
                            null,
                            openFlags,
                            null,
                            1
                    ),
                    "WCDB.openDatabase(String,CursorFactory,int,DatabaseErrorHandler,int)"
            );

            File openEncrypted6 = freshWcdbDatabaseFile("wcdb_open_encrypted_6.db");
            initializeAndCloseWcdbDatabase(
                    com.tencent.wcdb.database.SQLiteDatabase.openDatabase(
                            openEncrypted6.getAbsolutePath(),
                            encryptedPassword,
                            null,
                            null,
                            openFlags,
                            null
                    ),
                    "WCDB.openDatabase(String,byte[],SQLiteCipherSpec,CursorFactory,int,DatabaseErrorHandler)"
            );

            File openEncrypted7 = freshWcdbDatabaseFile("wcdb_open_encrypted_7.db");
            initializeAndCloseWcdbDatabase(
                    com.tencent.wcdb.database.SQLiteDatabase.openDatabase(
                            openEncrypted7.getAbsolutePath(),
                            encryptedPassword,
                            null,
                            null,
                            openFlags,
                            null,
                            1
                    ),
                    "WCDB.openDatabase(String,byte[],SQLiteCipherSpec,CursorFactory,int,DatabaseErrorHandler,int)"
            );

            // ------------------------------------------------------------
            // openOrCreateDatabase(...) overload matrix: 12 overloads
            // ------------------------------------------------------------

            File createFile2 = freshWcdbDatabaseFile("wcdb_create_file_2.db");
            initializeAndCloseWcdbDatabase(
                    com.tencent.wcdb.database.SQLiteDatabase.openOrCreateDatabase(
                            createFile2,
                            null
                    ),
                    "WCDB.openOrCreateDatabase(File,CursorFactory)"
            );

            File createFile5Cipher = freshWcdbDatabaseFile("wcdb_create_file_cipher_5.db");
            initializeAndCloseWcdbDatabase(
                    com.tencent.wcdb.database.SQLiteDatabase.openOrCreateDatabase(
                            createFile5Cipher,
                            encryptedPassword,
                            null,
                            null,
                            null
                    ),
                    "WCDB.openOrCreateDatabase(File,byte[],SQLiteCipherSpec,CursorFactory,DatabaseErrorHandler)"
            );

            File createFile6Cipher = freshWcdbDatabaseFile("wcdb_create_file_cipher_6.db");
            initializeAndCloseWcdbDatabase(
                    com.tencent.wcdb.database.SQLiteDatabase.openOrCreateDatabase(
                            createFile6Cipher,
                            encryptedPassword,
                            null,
                            null,
                            null,
                            1
                    ),
                    "WCDB.openOrCreateDatabase(File,byte[],SQLiteCipherSpec,CursorFactory,DatabaseErrorHandler,int)"
            );

            File createFile4 = freshWcdbDatabaseFile("wcdb_create_file_4.db");
            initializeAndCloseWcdbDatabase(
                    com.tencent.wcdb.database.SQLiteDatabase.openOrCreateDatabase(
                            createFile4,
                            encryptedPassword,
                            null,
                            null
                    ),
                    "WCDB.openOrCreateDatabase(File,byte[],CursorFactory,DatabaseErrorHandler)"
            );

            File createFile5 = freshWcdbDatabaseFile("wcdb_create_file_5.db");
            initializeAndCloseWcdbDatabase(
                    com.tencent.wcdb.database.SQLiteDatabase.openOrCreateDatabase(
                            createFile5,
                            encryptedPassword,
                            null,
                            null,
                            1
                    ),
                    "WCDB.openOrCreateDatabase(File,byte[],CursorFactory,DatabaseErrorHandler,int)"
            );

            File createPath2 = freshWcdbDatabaseFile("wcdb_create_path_2.db");
            initializeAndCloseWcdbDatabase(
                    com.tencent.wcdb.database.SQLiteDatabase.openOrCreateDatabase(
                            createPath2.getAbsolutePath(),
                            null
                    ),
                    "WCDB.openOrCreateDatabase(String,CursorFactory)"
            );

            File createPath3Flags = freshWcdbDatabaseFile("wcdb_create_path_flags_3.db");
            initializeAndCloseWcdbDatabase(
                    com.tencent.wcdb.database.SQLiteDatabase.openOrCreateDatabase(
                            createPath3Flags.getAbsolutePath(),
                            null,
                            openFlags
                    ),
                    "WCDB.openOrCreateDatabase(String,CursorFactory,int)"
            );

            File createPath3Handler = freshWcdbDatabaseFile("wcdb_create_path_handler_3.db");
            initializeAndCloseWcdbDatabase(
                    com.tencent.wcdb.database.SQLiteDatabase.openOrCreateDatabase(
                            createPath3Handler.getAbsolutePath(),
                            null,
                            null
                    ),
                    "WCDB.openOrCreateDatabase(String,CursorFactory,DatabaseErrorHandler)"
            );

            File createPath3Boolean = freshWcdbDatabaseFile("wcdb_create_path_boolean_3.db");
            initializeAndCloseWcdbDatabase(
                    com.tencent.wcdb.database.SQLiteDatabase.openOrCreateDatabase(
                            createPath3Boolean.getAbsolutePath(),
                            null,
                            false
                    ),
                    "WCDB.openOrCreateDatabase(String,CursorFactory,boolean)"
            );

            File createPath6Cipher = freshWcdbDatabaseFile("wcdb_create_path_cipher_6.db");
            initializeAndCloseWcdbDatabase(
                    com.tencent.wcdb.database.SQLiteDatabase.openOrCreateDatabase(
                            createPath6Cipher.getAbsolutePath(),
                            encryptedPassword,
                            null,
                            null,
                            null,
                            1
                    ),
                    "WCDB.openOrCreateDatabase(String,byte[],SQLiteCipherSpec,CursorFactory,DatabaseErrorHandler,int)"
            );

            File createPath4 = freshWcdbDatabaseFile("wcdb_create_path_4.db");
            initializeAndCloseWcdbDatabase(
                    com.tencent.wcdb.database.SQLiteDatabase.openOrCreateDatabase(
                            createPath4.getAbsolutePath(),
                            encryptedPassword,
                            null,
                            null
                    ),
                    "WCDB.openOrCreateDatabase(String,byte[],CursorFactory,DatabaseErrorHandler)"
            );

            File createPath5 = freshWcdbDatabaseFile("wcdb_create_path_5.db");
            initializeAndCloseWcdbDatabase(
                    com.tencent.wcdb.database.SQLiteDatabase.openOrCreateDatabase(
                            createPath5.getAbsolutePath(),
                            encryptedPassword,
                            null,
                            null,
                            1
                    ),
                    "WCDB.openOrCreateDatabase(String,byte[],CursorFactory,DatabaseErrorHandler,int)"
            );

        } catch (Throwable t) {
            Log.e(TAG, "runWcdbTests error", t);
        } finally {
            if (db != null) {
                db.close();
            }
        }
    }
}
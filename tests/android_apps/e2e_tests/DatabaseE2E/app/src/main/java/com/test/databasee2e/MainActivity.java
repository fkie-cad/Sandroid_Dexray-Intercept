// tests/android_apps/e2e_tests/DatabaseE2E/app/src/main/java/com/test/databasee2e/MainActivity.java
package com.test.databasee2e;

import android.app.Activity;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.util.Log;

import androidx.room.Room;
import androidx.sqlite.db.SimpleSQLiteQuery;
import androidx.sqlite.db.SupportSQLiteQuery;

import java.io.File;
import java.util.List;

public class MainActivity extends Activity {

    private static final String TAG = "DATABASE_E2E";

    private static final String SQLITE_DB_NAME = "sqlite_e2e.db";
    private static final String SQLITE_TABLE = "e2e_table";

    private static final String WCDB_DB_NAME = "wcdb_e2e.db";
    private static final String WCDB_TABLE = "e2e_wcdb";

    private static final String SQLCIPHER_PASSWORD = "test_pass_123";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.i(TAG, "DatabaseE2E started");

        try {
            try {
                runSqliteJavaTests();
            } catch (Throwable t1) {
                Log.e(TAG, "runSqliteJavaTests failed", t1);
            }

            try {
                runRoomTests();
            } catch (Throwable t1) {
                Log.e(TAG, "runRoomTests failed", t1);
            }

            try {
                runSqlCipherTests();
            } catch (Throwable t1) {
                Log.e(TAG, "runSqlCipherTests failed", t1);
            }

            try {
                runWcdbTests();
            } catch (Throwable t1) {
                Log.e(TAG, "runWcdbTests failed", t1);
            }

        } catch (Throwable t) {
            Log.e(TAG, "Error in DatabaseE2E", t);
        } finally {
            finish();
        }
    }

    // ------------------------------------------------------------
    // 1) Java SQLite tests (SqliteJavaE2E)
    // ------------------------------------------------------------

    private void runSqliteJavaTests() {
        Log.i(TAG, "runSqliteJavaTests");
        SQLiteDatabase db = null;
        try {
            // 1) openOrCreateDatabase via Context -> triggers SQLiteDatabase.openOrCreateDatabase hooks
            db = openOrCreateDatabase(SQLITE_DB_NAME, MODE_PRIVATE, null);
            Log.i(TAG, "openOrCreateDatabase via Context OK: " + db.getPath());

            // 2) Static openDatabase(String, CursorFactory, int)
            String dbPath = getDatabasePath(SQLITE_DB_NAME).getAbsolutePath();
            SQLiteDatabase db2 = SQLiteDatabase.openDatabase(
                    dbPath,
                    null,
                    SQLiteDatabase.OPEN_READWRITE | SQLiteDatabase.CREATE_IF_NECESSARY
            );
            Log.i(TAG, "SQLiteDatabase.openDatabase(String,CursorFactory,int) OK: " + db2.getPath());
            db2.close();

            // 3) CREATE TABLE via execSQL(String)
            db.execSQL("DROP TABLE IF EXISTS " + SQLITE_TABLE);
            db.execSQL("CREATE TABLE " + SQLITE_TABLE + " (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "name TEXT," +
                    "age INTEGER" +
                    ")");

            // 4) execSQL(String, Object[])
            db.execSQL("INSERT INTO " + SQLITE_TABLE + "(name, age) VALUES (?,?)",
                    new Object[]{"Alice", 30});

            // 5) insert(String, String, ContentValues)
            ContentValues cv = new ContentValues();
            cv.put("name", "Bob");
            cv.put("age", 40);
            long rowIdInsert = db.insert(SQLITE_TABLE, null, cv);
            Log.i(TAG, "insert(...) rowId=" + rowIdInsert);

            // 6) insertOrThrow(String, String, ContentValues)
            ContentValues cv2 = new ContentValues();
            cv2.put("name", "Charlie");
            cv2.put("age", 25);
            long rowIdInsertThrow = db.insertOrThrow(SQLITE_TABLE, null, cv2);
            Log.i(TAG, "insertOrThrow(...) rowId=" + rowIdInsertThrow);

            // 7) insertWithOnConflict(String, String, ContentValues, int)
            ContentValues cv3 = new ContentValues();
            cv3.put("name", "Alice"); // duplicate name for conflict
            cv3.put("age", 31);
            long rowIdConflict = db.insertWithOnConflict(
                    SQLITE_TABLE,
                    null,
                    cv3,
                    SQLiteDatabase.CONFLICT_REPLACE
            );
            Log.i(TAG, "insertWithOnConflict(...) rowId=" + rowIdConflict);

            String[] columns = new String[]{"id", "name", "age"};
            String[] whereArgsNameAlice = new String[]{"Alice"};

            // 8) query(String, String[], String, String[], String, String, String)
            Cursor c1 = db.query(
                    SQLITE_TABLE,
                    columns,
                    "name=?",
                    whereArgsNameAlice,
                    null,
                    null,
                    "id ASC"
            );
            c1.close();

            // 9) query(boolean distinct, String, String[], String, String[], String, String, String, String)
            Cursor c2 = db.query(
                    true,
                    SQLITE_TABLE,
                    columns,
                    "age>?",
                    new String[]{"20"},
                    null,
                    null,
                    "age DESC",
                    "10"
            );
            c2.close();

            // 10) query(boolean distinct, ..., CancellationSignal)
            Cursor c3 = db.query(
                    true,
                    SQLITE_TABLE,
                    columns,
                    "age>?",
                    new String[]{"20"},
                    null,
                    null,
                    "age DESC",
                    "5",
                    new CancellationSignal()
            );
            c3.close();

            // 11) query(String, String[], String, String[], String, String, String, String)
            Cursor c4 = db.query(
                    SQLITE_TABLE,
                    columns,
                    "age>=?",
                    new String[]{"30"},
                    null,
                    null,
                    "name ASC",
                    "5"
            );
            c4.close();

            // 12) rawQuery(String, String[])
            Cursor c5 = db.rawQuery(
                    "SELECT id, name, age FROM " + SQLITE_TABLE + " WHERE name LIKE ?",
                    new String[]{"A%"}
            );
            c5.close();

            // 13) rawQuery(String, String[], CancellationSignal)
            Cursor c6 = db.rawQuery(
                    "SELECT id, name, age FROM " + SQLITE_TABLE + " WHERE age > ?",
                    new String[]{"10"},
                    new CancellationSignal()
            );
            c6.close();

            // 14) update(String, ContentValues, String, String[])
            ContentValues upd = new ContentValues();
            upd.put("age", 32);
            int rowsUpd = db.update(SQLITE_TABLE, upd, "name=?", new String[]{"Alice"});
            Log.i(TAG, "update(...) rows=" + rowsUpd);

            // 15) updateWithOnConflict(String, ContentValues, String, String[], int)
            ContentValues upd2 = new ContentValues();
            upd2.put("age", 33);
            int rowsUpdConf = db.updateWithOnConflict(
                    SQLITE_TABLE,
                    upd2,
                    "name=?",
                    new String[]{"Alice"},
                    SQLiteDatabase.CONFLICT_IGNORE
            );
            Log.i(TAG, "updateWithOnConflict(...) rows=" + rowsUpdConf);

            // 16) delete(String, String, String[])
            int rowsDel = db.delete(SQLITE_TABLE, "name=?", new String[]{"Charlie"});
            Log.i(TAG, "delete(...) rows=" + rowsDel);

        } catch (Throwable t) {
            Log.e(TAG, "Error in runSqliteJavaTests", t);
        } finally {
            if (db != null) {
                db.close();
            }
        }
    }

    // ------------------------------------------------------------
    // 2) Room tests (RoomE2E)
    // ------------------------------------------------------------

    private void runRoomTests() {
        Log.i(TAG, "runRoomTests");
        E2EDb db = null;

        try {
            // 1) Room.databaseBuilder -> database.room.builder
            db = Room.databaseBuilder(
                    getApplicationContext(),
                    E2EDb.class,
                    "room_e2e.db"
            )
                    .allowMainThreadQueries()  // for E2E simplicity
                    .build();

            UserDao dao = db.userDao();

            // 2) Insert operations -> database.room.dao
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

            // 3) Update -> database.room.dao
            alice.id = (int) idAlice;
            alice.age = 31;
            int updCnt = dao.update(alice);
            Log.i(TAG, "Updated Alice rows=" + updCnt);

            // 4) Query -> database.room.dao
            List<User> older = dao.selectOlder(20);
            Log.i(TAG, "Users older than 20: " + older.size());

            // 5) RawQuery -> RoomDatabase.query(SupportSQLiteQuery)
            SupportSQLiteQuery rawQuery = new SimpleSQLiteQuery(
                    "SELECT * FROM e2e_user WHERE name LIKE ?",
                    new Object[]{"A%"}
            );
            List<User> rawResult = dao.rawSelect(rawQuery);
            Log.i(TAG, "RawQuery result count: " + rawResult.size());

            // 6) Delete -> database.room.dao
            bob.id = (int) idBob;
            int delCnt = dao.delete(bob);
            Log.i(TAG, "Deleted Bob rows=" + delCnt);

        } catch (Throwable t) {
            Log.e(TAG, "Error in runRoomTests", t);
        } finally {
            if (db != null) {
                db.close();
            }
        }
    }

    // ------------------------------------------------------------
    // 3) SQLCipher tests (SqlCipherE2E)
    // ------------------------------------------------------------

    private void runSqlCipherTests() {
        Log.i(TAG, "runSqlCipherTests");

        try {
            // 1) Load SQLCipher native libs
            net.sqlcipher.database.SQLiteDatabase.loadLibs(this);
            Log.i(TAG, "SQLCipher loadLibs OK");

            // 2) Helper-based usage (triggers SQLiteOpenHelper.getWritableDatabase(String))
            SqlCipherHelper helper = new SqlCipherHelper(this);

            // 3) getWritableDatabase(String)
            net.sqlcipher.database.SQLiteDatabase db =
                    helper.getWritableDatabase(SQLCIPHER_PASSWORD);
            Log.i(TAG, "getWritableDatabase(String) OK: " + db.getPath());

            // Basic operations: execSQL, rawQuery
            helper.basicOps(db);

            // Transactions
            db.beginTransaction();
            db.execSQL("INSERT INTO e2e_cipher (name, age) VALUES ('Charlie', 25)");
            db.setTransactionSuccessful();
            db.endTransaction();

            // 4) getReadableDatabase(String)
            net.sqlcipher.database.SQLiteDatabase dbRead =
                    helper.getReadableDatabase(SQLCIPHER_PASSWORD);
            Log.i(TAG, "getReadableDatabase(String) OK: " + dbRead.getPath());
            dbRead.close();

            // 5) Direct openOrCreateDatabase(File, String)
            File dbFile = getDatabasePath("sqlcipher_e2e_direct.db");
            if (dbFile.exists()) {
                // For a clean slate on each run
                boolean ignored = dbFile.delete();
            }
            
            net.sqlcipher.database.SQLiteDatabase dbDirectFile =
                    net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase(
                            dbFile,
                            SQLCIPHER_PASSWORD,
                            null
                    );
            Log.i(TAG, "openOrCreateDatabase(File,String) OK: " + dbFile.getAbsolutePath());

            // Use IF NOT EXISTS to keep repeated runs clean
            dbDirectFile.execSQL("CREATE TABLE IF NOT EXISTS direct_table (" +
                    "id INTEGER PRIMARY KEY, " +
                    "value TEXT" +
                    ")");
            dbDirectFile.execSQL("INSERT INTO direct_table (id, value) VALUES (1, 'direct')");
            dbDirectFile.close();

            // 6) Direct openOrCreateDatabase(String, char[])
            net.sqlcipher.database.SQLiteDatabase dbDirectPath =
                    net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase(
                            dbFile.getAbsolutePath(),
                            SQLCIPHER_PASSWORD.toCharArray(),
                            null,
                            null
                    );
            Log.i(TAG, "openOrCreateDatabase(String,char[]) OK: " + dbFile.getAbsolutePath());
            dbDirectPath.execSQL("INSERT INTO direct_table (id, value) VALUES (2, 'path_char')");
            dbDirectPath.close();

            // 7) rawExecSQL (e.g., PRAGMA key or other commands)
            net.sqlcipher.database.SQLiteDatabase dbPragma =
                    helper.getWritableDatabase(SQLCIPHER_PASSWORD);
            dbPragma.rawExecSQL("PRAGMA cipher_memory_security = OFF");
            dbPragma.close();

            // 8) Close helper database
            db.close();
            Log.i(TAG, "Closed primary SQLCipher DB");

        } catch (Throwable t) {
            Log.e(TAG, "Error in runSqlCipherTests", t);
        }
    }

    // ------------------------------------------------------------
    // 4) WCDB tests (WcdbE2E)
    // ------------------------------------------------------------

    private void runWcdbTests() {
        Log.i(TAG, "runWcdbTests");

        com.tencent.wcdb.database.SQLiteDatabase db = null;
        try {
            File dbFile = getDatabasePath(WCDB_DB_NAME);
            String path = dbFile.getAbsolutePath();

            // 1) openDatabase(String, CursorFactory, int)
            db = com.tencent.wcdb.database.SQLiteDatabase.openDatabase(
                    path,
                    null,
                    com.tencent.wcdb.database.SQLiteDatabase.CREATE_IF_NECESSARY
                            | com.tencent.wcdb.database.SQLiteDatabase.OPEN_READWRITE
            );
            Log.i(TAG, "WCDB.openDatabase OK: " + path);

            // 2) openOrCreateDatabase(String, CursorFactory)
            com.tencent.wcdb.database.SQLiteDatabase db2 =
                    com.tencent.wcdb.database.SQLiteDatabase.openOrCreateDatabase(path, null);
            Log.i(TAG, "WCDB.openOrCreateDatabase OK: " + path);
            db2.close();

            // 3) execSQL(String)
            db.execSQL("DROP TABLE IF EXISTS " + WCDB_TABLE);
            db.execSQL("CREATE TABLE " + WCDB_TABLE + " (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "name TEXT," +
                    "age INTEGER" +
                    ")");

            // 4) execSQL(String, Object[])
            db.execSQL("INSERT INTO " + WCDB_TABLE + " (name, age) VALUES (?,?)",
                    new Object[]{"Alice", 30});

            // 5) insert(String, String, ContentValues)
            ContentValues cv = new ContentValues();
            cv.put("name", "Bob");
            cv.put("age", 40);
            long rowInsert = db.insert(WCDB_TABLE, null, cv);
            Log.i(TAG, "WCDB.insert(...) rowId=" + rowInsert);

            // 6) rawQuery(String, String[])
            Cursor c = db.rawQuery(
                    "SELECT id, name, age FROM " + WCDB_TABLE + " WHERE age > ?",
                    new String[]{"20"}
            );
            Log.i(TAG, "WCDB.rawQuery count=" + c.getCount());
            c.close();

            // 7) update(String, ContentValues, String, String[])
            ContentValues upd = new ContentValues();
            upd.put("age", 31);
            int rowsUpd = db.update(WCDB_TABLE, upd, "name=?", new String[]{"Alice"});
            Log.i(TAG, "WCDB.update(...) rows=" + rowsUpd);

            // 8) delete(String, String, String[])
            int rowsDel = db.delete(WCDB_TABLE, "name=?", new String[]{"Bob"});
            Log.i(TAG, "WCDB.delete(...) rows=" + rowsDel);

            // 9) Transactions
            db.beginTransaction();
            db.execSQL("INSERT INTO " + WCDB_TABLE + " (name, age) VALUES ('Charlie', 25)");
            db.setTransactionSuccessful();
            db.endTransaction();

        } catch (Throwable t) {
            Log.e(TAG, "Error in runWcdbTests", t);
        } finally {
            if (db != null) {
                db.close();
            }
        }
    }
}
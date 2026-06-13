// tests/android_apps/e2e_tests/DatabaseE2E/app/src/main/java/com/test/databasee2e/SqlCipherHelper.java
package com.test.databasee2e;

import android.content.Context;
import android.database.Cursor;
import android.util.Log;

import net.sqlcipher.database.SQLiteDatabase;
import net.sqlcipher.database.SQLiteOpenHelper;

public class SqlCipherHelper extends SQLiteOpenHelper {
    private static final String TAG = "SQLCIPHER_E2E_HELPER";
    private static final String DB_NAME = "sqlcipher_e2e.db";
    private static final int DB_VERSION = 1;

    public SqlCipherHelper(Context context) {
        super(context, DB_NAME, null, DB_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        Log.i(TAG, "onCreate called");
        db.execSQL("CREATE TABLE e2e_cipher (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "name TEXT," +
                "age INTEGER" +
                ")");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        Log.i(TAG, "onUpgrade called: " + oldVersion + " -> " + newVersion);
        db.execSQL("DROP TABLE IF EXISTS e2e_cipher");
        onCreate(db);
    }

    public void basicOps(SQLiteDatabase db) {
        db.execSQL("INSERT INTO e2e_cipher (name, age) VALUES ('Alice', 30)");
        db.execSQL("INSERT INTO e2e_cipher (name, age) VALUES ('Bob', 40)");

        Cursor c = db.rawQuery(
                "SELECT id, name, age FROM e2e_cipher WHERE age > ?",
                new String[]{"20"}
        );
        Log.i(TAG, "Rows in e2e_cipher: " + c.getCount());
        c.close();
    }
}
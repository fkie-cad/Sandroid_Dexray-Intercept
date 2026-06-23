package com.test.databasee2e;

import android.content.Context;
import android.util.Log;

import androidx.room.Room;

import net.sqlcipher.database.SQLiteDatabase;
import net.sqlcipher.database.SupportFactory;

// Triggers Room+SQLCipher integration hooks:
//   database.room.builder
//   net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase(File, String)
//   net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase(String, String)
//   database.sqlcipher.pragma  (PRAGMA key path, SQLCipher 4.x native key injection)
//   database.room.callback     (onCreate / onOpen)
public class RoomSqlCipherTests {

    private static final String TAG = "ROOM_SQLCIPHER_E2E";
    private static final String DB_NAME = "room_encrypted_e2e.db";
    private static final String PASSWORD = "room_cipher_pass";

    private final Context context;

    public RoomSqlCipherTests(Context context) {
        this.context = context;
    }

    public void runTests() {
        E2EEncryptedDb db = null;
        try {
            SQLiteDatabase.loadLibs(context);

            // SupportFactory wires SQLCipher as the Room open helper backend
            byte[] passphrase = SQLiteDatabase.getBytes(PASSWORD.toCharArray());
            SupportFactory factory = new SupportFactory(passphrase);

            // Room.databaseBuilder with SQLCipher factory - triggers:
            //   database.room.builder
            //   net.sqlcipher openOrCreateDatabase hooks (internal to SupportFactory)
            //   database.room.callback onCreate/onOpen
            // Delete before building to ensure onCreate fires each run
            context.deleteDatabase(DB_NAME);
            db = Room.databaseBuilder(
                            context,
                            E2EEncryptedDb.class,
                            DB_NAME
                    )
                    .openHelperFactory(factory)
                    .allowMainThreadQueries()
                    .build();

            UserDao dao = db.userDao();

            User user = new User();
            user.name = "CipherUser";
            user.age = 99;
            long id = dao.insert(user);
            Log.i(TAG, "insert OK id=" + id);

            java.util.List<User> results = dao.selectOlder(0);
            Log.i(TAG, "selectOlder count=" + results.size());

        } catch (Throwable t) {
            Log.e(TAG, "RoomSqlCipherTests failed", t);
        } finally {
            if (db != null) {
                db.close();
            }
        }
    }
}
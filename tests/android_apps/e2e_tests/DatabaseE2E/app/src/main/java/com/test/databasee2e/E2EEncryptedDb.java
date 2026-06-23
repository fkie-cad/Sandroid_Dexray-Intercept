package com.test.databasee2e;

import androidx.room.Database;
import androidx.room.RoomDatabase;

// Separate Room database class for Room+SQLCipher integration tests
@Database(entities = {User.class}, version = 1, exportSchema = false)
public abstract class E2EEncryptedDb extends RoomDatabase {
    public abstract UserDao userDao();
}
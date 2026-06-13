// tests/android_apps/e2e_tests/DatabaseE2E/app/src/main/java/com/test/databasee2e/E2EDb.java
package com.test.databasee2e;

import androidx.room.Database;
import androidx.room.RoomDatabase;

@Database(entities = {User.class}, version = 1, exportSchema = false)
public abstract class E2EDb extends RoomDatabase {
    public abstract UserDao userDao();
}
package com.test.databasee2e;

import androidx.room.Database;
import androidx.room.RoomDatabase;

@Database(
        entities = {UpgradeUserV1.class},
        version = 1,
        exportSchema = false
)
public abstract class UpgradeDbV1 extends RoomDatabase {
}
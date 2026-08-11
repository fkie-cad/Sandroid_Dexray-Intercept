package com.test.databasee2e;

import androidx.room.Database;
import androidx.room.RoomDatabase;

@Database(
        entities = {UpgradeUserV2.class},
        version = 2,
        exportSchema = false
)
public abstract class UpgradeDbV2 extends RoomDatabase {
}
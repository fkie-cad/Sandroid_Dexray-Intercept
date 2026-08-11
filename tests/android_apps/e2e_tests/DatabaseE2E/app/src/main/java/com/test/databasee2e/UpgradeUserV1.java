package com.test.databasee2e;

import androidx.room.Entity;
import androidx.room.PrimaryKey;

@Entity(tableName = "room_upgrade_user")
public class UpgradeUserV1 {

    @PrimaryKey
    public int id;

    public String name;
}
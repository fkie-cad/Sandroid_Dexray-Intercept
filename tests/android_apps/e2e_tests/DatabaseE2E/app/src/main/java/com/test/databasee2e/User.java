// tests/android_apps/e2e_tests/DatabaseE2E/app/src/main/java/com/test/databasee2e/User.java
package com.test.databasee2e;

import androidx.room.Entity;
import androidx.room.PrimaryKey;

@Entity(tableName = "e2e_user")
public class User {

    @PrimaryKey(autoGenerate = true)
    public int id;

    public String name;

    public int age;
}
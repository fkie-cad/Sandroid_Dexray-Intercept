// tests/android_apps/e2e_tests/DatabaseE2E/app/src/main/java/com/test/databasee2e/UserDao.java
package com.test.databasee2e;

import androidx.room.Dao;
import androidx.room.Delete;
import androidx.room.Insert;
import androidx.room.Query;
import androidx.room.RawQuery;
import androidx.room.Update;
import androidx.sqlite.db.SupportSQLiteQuery;

import java.util.List;

@Dao
public interface UserDao {

    @Insert
    long insert(User user);

    @Update
    int update(User user);

    @Delete
    int delete(User user);

    @Query("SELECT * FROM e2e_user WHERE age > :minAge")
    List<User> selectOlder(int minAge);

    @RawQuery
    List<User> rawSelect(SupportSQLiteQuery query);
}
package com.test.databasee2e

import androidx.room.Dao
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

// Separate Kotlin DAO required - Room Flow return types are not supported in Java DAOs
@Dao
interface FlowUserDao {
    @Query("SELECT * FROM e2e_user")
    fun selectAllFlow(): Flow<List<User>>
}
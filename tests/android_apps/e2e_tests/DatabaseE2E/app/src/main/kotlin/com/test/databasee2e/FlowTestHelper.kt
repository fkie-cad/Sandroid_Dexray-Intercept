package com.test.databasee2e

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking

// Utility for triggering FlowCollector.emit from Java test code.
// runBlocking on Dispatchers.IO avoids main-thread deadlock with Room's
// internal coroutine dispatcher.
object FlowTestHelper {

    @JvmStatic
    fun collectFirst(dao: FlowUserDao): Int {
        return runBlocking(Dispatchers.IO) {
            dao.selectAllFlow().first().size
        }
    }
}
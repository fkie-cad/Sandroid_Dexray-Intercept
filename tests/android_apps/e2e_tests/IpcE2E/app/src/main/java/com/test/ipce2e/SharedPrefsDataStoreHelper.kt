package com.test.ipce2e

import android.content.Context
import android.util.Log
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

private const val TAG = "IPC_E2E"

// DataStore extension on Context for this E2E app
val Context.ipcE2eDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "ipc_e2e_datastore"
)

object SharedPrefsDataStoreHelper {

    /**
     * Runs DataStore tests to exercise shared_prefs.ts datastore hooks:
     *
     * 8) stringPreferencesKey/intPreferencesKey/booleanPreferencesKey ->
     *    shared_prefs.ts: Preferences$Key.$init(String)
     *    -> PROFILE_HOOKING_TYPE="IPC_SHARED-PREF", event_type="datastore_prefs.key_init"
     *
     * 9) dataStore.updateData { ... } ->
     *    shared_prefs.ts: DataStore.updateData[...] overloads
     *    -> event_type="datastore.update" (if hook is correctly attached)
     *
     * 10) dataStore.edit { prefs[...] = ... } ->
     *     shared_prefs.ts: DataStore.updateData[...] + MutablePreferences.get(Key)
     *     -> event_type="datastore.update" + "datastore_prefs.get" (if hook works)
     *
     * 11) dataStore.data.first() + prefs[key] reads ->
     *     shared_prefs.ts: DataStore.getData + Preferences.get(Key)
     *     -> event_type="datastore.get" + "datastore_prefs.get"
     *
     * 12) GlobalScope.launch(Dispatchers.IO) + dataStore.edit { ... } ->
     *     exercises DataStore writes from a dispatched coroutine context instead of
     *     the surrounding runBlocking coroutine
     *     -> expected to hit the same datastore.update path if hooks are generic
     *
     * 13) GlobalScope.launch(Dispatchers.IO) + dataStore.data.first() ->
     *     exercises DataStore reads from a dispatched coroutine context instead of
     *     the surrounding runBlocking coroutine
     *     -> expected to hit the same datastore.get path if hooks are generic
     *
     * CompletableDeferred is used for 12/13 so the short-lived E2E app waits for
     * the launched coroutine work to finish before MainActivity exits.
     */
    @JvmStatic
    fun runDataStoreTests(context: Context) = runBlocking {
        val dataStore = context.ipcE2eDataStore

        // 8) Preferences key initialization
        val stringKey = stringPreferencesKey("ds_string")
        val intKey = intPreferencesKey("ds_int")
        val boolKey = booleanPreferencesKey("ds_bool")

        // 9) Explicit call to DataStore.updateData(...)
        //    We return the incoming state unchanged; this is purely to hit the method.
        dataStore.updateData { prefs ->
            // No modifications, just return the same Preferences instance
            prefs
        }

        // 10) Write values using edit { } (typical API) ->
        //     Internally uses updateData and accesses MutablePreferences
        dataStore.edit { prefs ->
            prefs[stringKey] = "ds_hello"
            prefs[intKey] = 456
            prefs[boolKey] = true
        }

        // 11) Read values via data flow ->
        //     Exercises DataStore.getData and Preferences.get(Key)
        val prefs = dataStore.data.first()

        val dsString = prefs[stringKey] ?: "missing"
        val dsInt = prefs[intKey] ?: -1
        val dsBool = prefs[boolKey] ?: false

        Log.i(TAG, "DataStore E2E: ds_string=$dsString, ds_int=$dsInt, ds_bool=$dsBool")

        // 12) DataStore write from a dispatched coroutine context.
        //     This complements the runBlocking path above and checks whether
        //     shared_prefs.ts datastore hooks still fire when the caller uses
        //     a more typical asynchronous coroutine launch.
        val coroutineStringKey = stringPreferencesKey("ds_coroutine_string")
        val coroutineIntKey = intPreferencesKey("ds_coroutine_int")

        val writeDone = CompletableDeferred<Unit>()

        GlobalScope.launch(Dispatchers.IO) {
            try {
                dataStore.edit { coroutinePrefs ->
                    coroutinePrefs[coroutineStringKey] = "coroutine_hello"
                    coroutinePrefs[coroutineIntKey] = 789
                }

                Log.i(TAG, "DataStore GlobalScope write: ds_coroutine_string=coroutine_hello, ds_coroutine_int=789")
            } catch (t: Throwable) {
                Log.e(TAG, "DataStore GlobalScope write failed", t)
            } finally {
                writeDone.complete(Unit)
            }
        }

        writeDone.await()

        // 13) DataStore read from a dispatched coroutine context.
        //     Exercises DataStore.getData and Preferences.get(Key) outside the
        //     direct runBlocking call path.
        val readDone = CompletableDeferred<Unit>()

        GlobalScope.launch(Dispatchers.IO) {
            try {
                val coroutinePrefs = dataStore.data.first()

                val dsCoroutineString = coroutinePrefs[coroutineStringKey] ?: "missing"
                val dsCoroutineInt = coroutinePrefs[coroutineIntKey] ?: -1

                Log.i(
                    TAG,
                    "DataStore GlobalScope read: " +
                        "ds_coroutine_string=$dsCoroutineString, " +
                        "ds_coroutine_int=$dsCoroutineInt"
                )
            } catch (t: Throwable) {
                Log.e(TAG, "DataStore GlobalScope read failed", t)
            } finally {
                readDone.complete(Unit)
            }
        }

        readDone.await()
    }
}
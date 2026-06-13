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
import kotlinx.coroutines.flow.first
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
    }
}
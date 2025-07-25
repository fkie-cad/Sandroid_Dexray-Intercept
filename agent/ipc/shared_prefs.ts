import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"

const PROFILE_HOOKING_TYPE: string = "IPC_SHARED-PREF"

/**
 * 
 * Some parts are taken from https://github.com/Areizen/Android-Malware-Sandbox/tree/master/plugins/shared_preferences_plugin
 * 
 */


  
  

function hook_shared_preferences(){
    Java.perform(function() {
    var sharedPrefs = Java.use('android.app.SharedPreferencesImpl');
  
    sharedPrefs.$init.overload('java.io.File', 'int').implementation = function(file, mode) {
      var result = this.$init(file, mode);
      var obj = {"event_type": "Java::SharedPreferencesImpl$EditorImpl.$init", "method": "SharedPreferencesImpl.$init('java.lang.String', 'int')", "file": file.getAbsolutePath(), "mode": mode};
      am_send(PROFILE_HOOKING_TYPE,"[Java::SharedPreferencesImpl$EditorImpl] SharedPref File : " + JSON.stringify(obj)); 
      return result;
    }
  
    Java.use('android.app.SharedPreferencesImpl$EditorImpl').putString.overload('java.lang.String', 'java.lang.String').implementation = function(k, v) {
      var obj = {"event_type": "Java::SharedPreferencesImpl$EditorImpl.putString", "method":"SharedPreferences.Editor.putString('java.lang.String', 'java.lang.String')", "file": 'NULL', "value": k+" = "+v};
      am_send(PROFILE_HOOKING_TYPE,"[Java::SharedPreferencesImpl$EditorImpl] SharedPref Content : " + JSON.stringify(obj)); 
      return this.putString(k, v);
    }




  console.log("Starting DataStore hooks...");

        // Hook the DataStore class
        const DataStore = Java.use("androidx.datastore.core.DataStore");

        // Hook updateData
        DataStore.updateData.overload("kotlin.coroutines.Continuation").implementation = function (continuation) {
          console.log("DataStore.updateData() called");
          const result = this.updateData(continuation);

          // Log the result if possible
          result.then((data: any) => {
            //console.log(`Updated DataStore data: ${data}`);
            var obj = {"event_type": "Java::androidx.datastore.core.DataStore.updateData", "method":"updateData('kotlin.coroutines.Continuation')", "data": data};
            am_send(PROFILE_HOOKING_TYPE,"[Java::androidx.datastore.core.DataStore] updateData : " + JSON.stringify(obj));
          });

          return result;
        };

        // Hook data (flow)
        DataStore.getData.overload().implementation = function () {
          console.log("DataStore.getData() called");
          const flow = this.getData();

          // Hook into the flow to log emitted data
          flow.collect((data: any) => {
            //console.log(`Data emitted from DataStore: ${data}`);
            var obj = {"event_type": "Java::androidx.datastore.core.DataStore.getData", "method":"getData()", "data": data};
            am_send(PROFILE_HOOKING_TYPE,"[Java::androidx.datastore.core.DataStore] getData : " + JSON.stringify(obj));
          });

          return flow;
        };

        // Hook Preferences DataStore (key-value)
        const Preferences = Java.use("androidx.datastore.preferences.core.Preferences");
        Preferences.get.overload("androidx.datastore.preferences.core.Preferences$Key").implementation = function (key) {
          //console.log(`Preferences.get() called for key: ${key}`);
          const value = this.get(key);

          //console.log(`Value for key '${key}': ${value}`);
          var obj = {"event_type": "Java::androidx.datastore.core.DataStore.Preferences.get()", "method":"get()", "Value for key ": key+" = "+value};
          am_send(PROFILE_HOOKING_TYPE,"[Java::androidx.datastore.core.DataStore.Preferences] .get() : " + JSON.stringify(obj));
          return value;
        };

        // Hook Preferences.Key class
        const PreferencesKey = Java.use("androidx.datastore.preferences.core.Preferences$Key");
        PreferencesKey.$init.overload("java.lang.String").implementation = function (key) {
          //console.log(`Preferences.Key initialized with key: ${key}`);
          var obj = {"event_type": "Java::androidx.datastore.dataStore.core.Preferences$Key", "method":"$init", "Preferences.Key initialized with key ": key};
          am_send(PROFILE_HOOKING_TYPE,"[Java::androidx.datastore.core.Preferences$Key] .$init (constructor) : " + JSON.stringify(obj));
          return this.$init(key);
        };

        // Hook Proto DataStore (typed objects)
        const ProtoDataStore = Java.use("androidx.datastore.core.DataStore");
        ProtoDataStore.updateData.overload("kotlin.coroutines.Continuation").implementation = function (continuation) {
          console.log("Proto DataStore updateData called");
          const result = this.updateData(continuation);

          result.then((data: any) => {
            //console.log(`Proto DataStore updated data: ${data}`);
            var obj = {"event_type": "Java::androidx.datastore.dataStore", "method":"updateData", "Proto DataStore updated data ": data};
          am_send(PROFILE_HOOKING_TYPE,"[Java::androidx.datastore.core.Preferences$Key] .updateData : " + JSON.stringify(obj));
          });

          return result;
        };



      });

}




export function install_shared_prefs_hooks(){
    devlog("\n")
    devlog("install shared preferences hooks");
    hook_shared_preferences();

}
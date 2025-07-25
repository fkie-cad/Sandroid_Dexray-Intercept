import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Where } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"

const PROFILE_HOOKING_TYPE: string = "CRYPTO_ENCODING"

/**
 *  https://github.com/dpnishant/appmon/blob/master/scripts/Android/Crypto/Hash.js
 * Some parts are taken from https://github.com/Areizen/Android-Malware-Sandbox/tree/master/plugins/base64_plugin
 * 
 */

function hook_base64(){
    var base64 = Java.use('android.util.Base64');
    var threadef = Java.use('java.lang.Thread');
    var threadinstance = threadef.$new();

    base64.decode.overload('java.lang.String', 'int').implementation = function(str, flag) {
        var result = this.decode(str, flag);
        if (result.length != 0) {
            var stack = threadinstance.currentThread().getStackTrace();
            var obj = {"event_type": "Java::android.util.Base64", "method" : "Base64.decode('java.lang.String', 'int')", 'decoded_content:':result.buffer, 'stack': Where(stack)};
            am_send(PROFILE_HOOKING_TYPE, JSON.stringify(obj) +":\n ");
        }
        return result;
    }
    base64.decode.overload('[B', 'int').implementation = function(input, flag) {
        var result = this.decode(input, flag);
        if (result.length != 0) {
            var stack = threadinstance.currentThread().getStackTrace();
            var obj = {"event_type": "Java::android.util.Base64", "method" : "Base64.decode('[B', 'int')", 'decoded_content:':result.buffer, 'stack': Where(stack)};
            am_send(PROFILE_HOOKING_TYPE, JSON.stringify(obj) +":\n ");
        }
        return result;
    }
    base64.decode.overload('[B', 'int', 'int', 'int').implementation = function(input, offset, len, flags){
        var result = this.decode(input, offset, len, flags);
        if (result.length != 0) {
            var stack = threadinstance.currentThread().getStackTrace();
            var obj = {"event_type": "Java::android.util.Base64", "method" : "Base64.decode('[B', 'int', 'int', 'int')", 'decoded_content:':result.buffer , 'stack': Where(stack)};
            am_send(PROFILE_HOOKING_TYPE, JSON.stringify(obj) +":\n ");
        }
        return result;
    }
    base64.encode.overload('[B', 'int').implementation = function(input, flags) {
        var result = this.encode(input, flags);
        if (input.length != 0) {
            var stack = threadinstance.currentThread().getStackTrace();
            var obj = {"event_type": "Java::android.util.Base64", "method" : "Base64.encode('[B', 'int')", 'content':input.buffer,'stack': Where(stack)};
            am_send(PROFILE_HOOKING_TYPE, JSON.stringify(obj) +":\n ");
        }
        return result;
    }
    base64.encode.overload('[B', 'int', 'int', 'int').implementation = function(input, offset, len, flags){
        var result = this.encode(input, offset, len, flags);
        if (input.length != 0) {
            var stack = threadinstance.currentThread().getStackTrace();
            var obj = {"event_type": "Java::android.util.Base64", "method" : "Base64.encode('[B', 'int', 'int', 'int')", 'content':input.buffer,'stack': Where(stack)};
            am_send(PROFILE_HOOKING_TYPE, JSON.stringify(obj) +":\n ");
        }
        return result;
    }
    base64.encodeToString.overload('[B', 'int', 'int', 'int').implementation = function(input, offset, len, flags){
        var result = this.encodeToString(input, offset, len, flags);
        if (input.length != 0) {
            var stack = threadinstance.currentThread().getStackTrace();
            var obj = {"event_type": "Java::android.util.Base64", "method" : "Base64.encodeToString('[B', 'int', 'int', 'int')",'content':input.buffer,'stack': Where(stack)};
            am_send(PROFILE_HOOKING_TYPE, JSON.stringify(obj) +":\n" );
        }
        return result;
    }
    base64.encodeToString.overload('[B', 'int').implementation = function(input, flags){
        var result = this.encodeToString(input, flags);
        if (input.length != 0) {
            var stack = threadinstance.currentThread().getStackTrace();
            var obj = {"event_type": "Java::android.util.Base64", "method" : "Base64.encodeToString('[B', 'int')",'content':input.buffer,'stack': Where(stack)};
            am_send(PROFILE_HOOKING_TYPE, JSON.stringify(obj) +":\n ");
        }
        return result;
    }

}




export function install_encodings_hooks(){
    devlog("\n")
    devlog("install encodings hooks");
    hook_base64();

}
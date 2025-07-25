export function log(str: string) {
    var message: { [key: string]: string } = {}
    message["profileType"] = "console"
    const now = new Date().toISOString();
    message["timestamp"] = now
    message["console"] = str
    send(message)
}


export function devlog(str: string) {
    var message: { [key: string]: string } = {}
    message["profileType"] = "console_dev"
    message["console_dev"] = str
    const now = new Date().toISOString();
    message["timestamp"] = now
    send(message)
}


var CACHE_LOG = "";
var CACHE_LOG_TEL = "";
export function am_send(hooking_type: string, str: string, data?: ArrayBuffer) {
    if (hooking_type === "IPC_BINDER" || hooking_type === "PROCESS_NATIVE_LIB"){
        if(str.toString() == CACHE_LOG.toString()) return; // Let's hide duplicate logs...
    }else if(hooking_type === "TELEPHONY"){
        if(str.toString() == CACHE_LOG_TEL.toString()) return; // Let's hide duplicate logs...
    }
    
    var message: { [key: string]: string } = {}
    message["profileType"] = hooking_type
    message["profileContent"] = str
    const now = new Date().toISOString();
    message["timestamp"] = now
    if (data === undefined){
        send(message)
    }else{
        send(message,data)
    }
    
}
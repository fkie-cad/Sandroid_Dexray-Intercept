import { enable_stacktrace } from "../hooking_profile_loader.js";

function getStackTrace(context?: CpuContext): string {
    try {
        if (context) {
            // Resolve each frame defensively and silently: logging sits below the
            // error-reporting layer (error_utils -> logging), so it must NOT route
            // through safe_native/hookError — that would be a logging->safe_native->
            // error_utils->logging cycle, and a failed resolution would recurse back
            // into getStackTrace. A bad frame degrades to a placeholder instead of
            // losing the whole trace.
            return Thread.backtrace(context, Backtracer.ACCURATE)
                .map(addr => {
                    try {
                        const s = DebugSymbol.fromAddress(addr);
                        return `${s.address} ${s.name || '<unknown>'} (${s.moduleName || '<unknown module>'})`;
                    } catch (e) {
                        return `<unresolved frame ${addr}>`;
                    }
                })
                .join('\n');
        } else {
            // Fallback: show current module information
            const modules = Process.enumerateModules();
            const moduleInfo = modules.slice(0, 3).map(m => `${m.name}: ${m.base}`).join('\n');
            return `Stack trace context unavailable\nLoaded modules:\n${moduleInfo}`;
        }
    } catch (e) {
        return `<stacktrace unavailable: ${e}>`;
    }
}

export function log(str: string, context?: CpuContext) {
    var message: { [key: string]: string } = {}
    message["profileType"] = "console"
    const now = new Date().toISOString();
    message["timestamp"] = now
    message["console"] = str
    
    if (enable_stacktrace) {
        message["stacktrace"] = escapeJsonString(getStackTrace(context));
    }
    
    send(message)
}


export function devlog(str: string, context?: CpuContext) {
    var message: { [key: string]: string } = {}
    message["profileType"] = "console_dev"
    message["console_dev"] = str
    const now = new Date().toISOString();
    message["timestamp"] = now
    
    if (enable_stacktrace) {
        message["stacktrace"] = escapeJsonString(getStackTrace(context));
    }
    
    send(message)
}


var CACHE_LOG = "";
var CACHE_LOG_TEL = "";
function escapeJsonString(str: string): string {
    return str.replace(/\\/g, '\\\\')
              .replace(/"/g, '\\"')
              .replace(/\n/g, '\\n')
              .replace(/\r/g, '\\r')
              .replace(/\t/g, '\\t')
              .replace(/\x08/g, '\\b')
              .replace(/\f/g, '\\f');
}

export function am_send(hooking_type: string, str: string, data?: ArrayBuffer, context?: CpuContext) {
    if (hooking_type === "IPC_BINDER" || hooking_type === "PROCESS_NATIVE_LIB"){
        if(str.toString() == CACHE_LOG.toString()) return; // Let's hide duplicate logs...
    }else if(hooking_type === "TELEPHONY"){
        if(str.toString() == CACHE_LOG_TEL.toString()) return; // Let's hide duplicate logs...
    }
    
    var message: { [key: string]: string } = {}
    message["profileType"] = hooking_type
    //message["profileContent"] = escapeJsonString(str)
    message["profileContent"] = str
    const now = new Date().toISOString();
    message["timestamp"] = now
    
    if (enable_stacktrace) {
        console.log("Stacktrace enabled, adding stacktrace to message");
        message["stacktrace"] = escapeJsonString(getStackTrace(context));
    }
    
    if (data === undefined){
        send(message)
    }else{
        send(message,data)
    }
    
}
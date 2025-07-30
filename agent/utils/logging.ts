import { enable_stacktrace } from "../hooking_profile_loader.js";

function getStackTrace(context?: CpuContext): string {
    try {
        if (context) {
            return Thread.backtrace(context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress)
                .map(s => `${s.address} ${s.name || '<unknown>'} (${s.moduleName || '<unknown module>'})`)
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
    message["console"] = escapeJsonString(str)
    
    if (enable_stacktrace) {
        message["stacktrace"] = escapeJsonString(getStackTrace(context));
    }
    
    send(message)
}


export function devlog(str: string, context?: CpuContext) {
    var message: { [key: string]: string } = {}
    message["profileType"] = "console_dev"
    message["console_dev"] = escapeJsonString(str)
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
    message["profileContent"] = escapeJsonString(str)
    const now = new Date().toISOString();
    message["timestamp"] = now
    
    if (enable_stacktrace) {
        message["stacktrace"] = escapeJsonString(getStackTrace(context));
    }
    
    if (data === undefined){
        send(message)
    }else{
        send(message,data)
    }
    
}
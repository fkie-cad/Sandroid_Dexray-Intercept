import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd, java_stack_trace } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"

const PROFILE_HOOKING_TYPE: string = "REFELCTION"

const PROFILE_HOOKING_TYPE2: string = "RUNTIME_EXEC"

/**
 * 
/**
 * https://github.com/dpnishant/appmon/tree/master/scripts/Android
 * https://github.com/Ch0pin/medusa/blob/master/modules/runtime/runtime.med
 */

function hook_runtime(){
    type SendData = {
        time: Date;
        txnType: string;
        lib: string;
        method: string;
        artifact: { name: string; value: string; argSeq: number }[];
    };
    
    function processArgs(command: any, envp: any, dir: any) {
        const output: { [key: string]: string } = {};
        if (command) {
            output.command = command;
        }
        if (envp) {
            output.envp = envp;
        }
        if (dir) {
            output.dir = dir;
        }
        return output;
    }
    
    function createPayload(
        txnType: string,
        lib: string,
        method: string,
        args: { [key: string]: any }
    ): SendData {
        const send_data: SendData = {
            time: new Date(),
            txnType,
            lib,
            method,
            artifact: [],
        };
    
        for (const key in args) {
            send_data.artifact.push({
                name: key.charAt(0).toUpperCase() + key.slice(1),
                value: args[key] ? args[key].toString() : 'null',
                argSeq: Object.keys(args).indexOf(key),
            });
        }
    
        return send_data;
    }
    
    function sendHookEvent(event: any) {
        for (const key in event) {
            if (event[key] === null || event[key] === '') {
                delete event[key];
            }
        }
        am_send(PROFILE_HOOKING_TYPE2, JSON.stringify(event));
    }
    
    Java.perform(() => {
        const Runtime = Java.use('java.lang.Runtime');
    
        const execOverload = (
            command: any,
            envp: any,
            dir: any,
            overloadIndex: number
        ) => {
            const args = processArgs(command, envp, dir);
            const send_data = createPayload(
                'Runtime Command Execution',
                'java.lang.Runtime',
                'exec',
                args
            );
            sendHookEvent(send_data);
            return Runtime.exec.overloads[overloadIndex].apply(
                Runtime.exec,
                arguments
            );
        };
    
        for (let i = 0; i < 6; i++) {
            if (Runtime.exec.overloads[i]) {
                Runtime.exec.overloads[i].implementation = function (
                    command: any,
                    envp: any,
                    dir: any
                ) {
                    return execOverload(command, envp, dir, i);
                };
            }
        }
    
        const loadLibraryOverload = (libname: any, overloadIndex: number) => {
            const send_data = createPayload(
                'Runtime Load Library',
                'java.lang.Runtime',
                'loadLibrary',
                { libname }
            );
            sendHookEvent(send_data);
            return Runtime.loadLibrary.overloads[overloadIndex].apply(
                Runtime.loadLibrary,
                arguments
            );
        };
    
        for (let i = 0; i < 2; i++) {
            if (Runtime.loadLibrary.overloads[i]) {
                Runtime.loadLibrary.overloads[i].implementation = function (
                    libname: any
                ) {
                    return loadLibraryOverload(libname, i);
                };
            }
        }
    
        const loadOverload = (filename: any, overloadIndex: number) => {
            const send_data = createPayload(
                'Runtime Load Library',
                'java.lang.Runtime',
                'load',
                { filename }
            );
            sendHookEvent(send_data);
            return Runtime.load.overloads[overloadIndex].apply(
                Runtime.load,
                arguments
            );
        };
    
        for (let i = 0; i < 2; i++) {
            if (Runtime.load.overloads[i]) {
                Runtime.load.overloads[i].implementation = function (
                    filename: any
                ) {
                    return loadOverload(filename, i);
                };
            }
        }
    });
    

}

function trace_reflection(){
    Java.perform(() => {
        const internalClasses: string[] = ["android.", "com.android", "java.lang", "java.io"];
    
        const classDef = Java.use('java.lang.Class');
        const classLoaderDef = Java.use('java.lang.ClassLoader');
        const Method = Java.use('java.lang.reflect.Method');
    
        const forName = classDef.forName.overload('java.lang.String', 'boolean', 'java.lang.ClassLoader');
        const loadClass = classLoaderDef.loadClass.overload('java.lang.String', 'boolean');
        const getMethod = classDef.getMethod.overload('java.lang.String', '[Ljava.lang.Class;');
        const getDeclaredMethod = classDef.getDeclaredMethod.overload('java.lang.String', '[Ljava.lang.Class;');
        const invoke = Method.invoke.overload('java.lang.Object', '[Ljava.lang.Object;');

    
        getMethod.implementation = function (a: string, b: any) {
            const method = getMethod.call(this, a, b);
            am_send(PROFILE_HOOKING_TYPE,`[Reflection::Class.getMethod] Retrieving public method: ${a} (${method.toGenericString()})`);
            return method;
        }

        getDeclaredMethod.implementation = function (a: string, b: any) {
            const method = getMethod.call(this, a, b);
            am_send(PROFILE_HOOKING_TYPE,`[Reflection::Class.getDeclaredMethod] Retrieving (non-)public method: ${a} (${method.toGenericString()})`);
            return method;
        }
    
        forName.implementation = function (class_name: string, flag: boolean, class_loader: any) {
            let isGood = true;
            for (let i = 0; i < internalClasses.length; i++) {
                if (class_name.startsWith(internalClasses[i])) {
                    isGood = false;
                }
            }
            if (isGood) {
                am_send(PROFILE_HOOKING_TYPE,`[Reflection::Class.forName] Loads and initializes the class: ${class_name}`);
            }
            return forName.call(this, class_name, flag, class_loader);
        }
    
        loadClass.implementation = function (class_name: string, resolve: boolean) {
            let isGood = true;
            for (let i = 0; i < internalClasses.length; i++) {
                if (class_name.startsWith(internalClasses[i])) {
                    isGood = false;
                }
            }
            if (isGood) {
                am_send(PROFILE_HOOKING_TYPE,`[Reflection::ClassLoader.loadClass] Loads the class but does not initialize it:  ${class_name}`);
            }
            return loadClass.call(this, class_name, resolve);
        }

        invoke.implementation = function(instance: any, args: any) {
            const result = invoke.call(this, instance, args);

            if (args) {
                //console.log(`Arguments: ${args.map(arg => arg.toString()).join(', ')}`);
                am_send(PROFILE_HOOKING_TYPE,`[Reflection::reflect.Method.invoke] Invoking method: ${instance} (Arguments: ${args.map(arg => arg.toString()).join(', ')}, Result: ${result})`);
            }else{
                am_send(PROFILE_HOOKING_TYPE,`[Reflection::reflect.Method.invoke] Invoking method: ${instance} (Result: ${result})`);
            }
    
            // Return the original result
            return result;
        };
    });
    
}


function trace_reflection_old(){
    /** based on 
      * https://codeshare.frida.re/@dzonerzy/dereflector/
      * https://gitee.com/zstorm/frida-snippets#hook-reflection
      */

     Java.perform(function() {

        var internalClasses = ["android.", "org."];
        var classDef = Java.use('java.lang.Class');
        var classLoaderDef = Java.use('java.lang.ClassLoader');
        var loadClass = classLoaderDef.loadClass.overload('java.lang.String', 'boolean');
        var forName = classDef.forName.overload('java.lang.String', 'boolean', 'java.lang.ClassLoader');
        var reflect = Java.use('java.lang.reflect.Method')
        var member = Java.use('java.lang.reflect.Member')
        var dalvik = Java.use("dalvik.system.DexFile")
        var dalvik2 = Java.use("dalvik.system.DexClassLoader")
        var url = Java.use("java.net.URL")
        var obj = Java.use("java.lang.Object")
        var fo = Java.use("java.io.FileOutputStream")
        var ThreadDef = Java.use('java.lang.Thread');
        var ThreadObj = ThreadDef.$new();
    
    
        obj.getClass.implementation = function(){
            var o = this.getClass()
            return this.getClass()
        }
    
        member.getName.implementation = function(){
            am_send(PROFILE_HOOKING_TYPE,'Getname -> ' + this.getName())
            return this.getName()
        }
        classDef.getMethods.implementation = function(){
            var o = this.getMethods()
            //am_send(PROFILE_HOOKING_TYPE,o)
            return this.getMethods()
        }
        reflect.invoke.implementatition = function(a,b){
            // java.lang.reflect.Method#invoke(Object obj, Object... args, boolean bool)
            am_send(PROFILE_HOOKING_TYPE,"invoke catched -> " + a)
            this.invoke(a,b)
        }
        
       
        dalvik.loadDex.implementation = function(a,b,c){
            am_send(PROFILE_HOOKING_TYPE,"[+] loadDex Catched -> " + a)
            //java_stack_trace
            return dalvik.loadDex(a,b,c)
            
        }
        dalvik2.$init.implementation = function (a,b,c,d) {
            am_send(PROFILE_HOOKING_TYPE,"[+] DexClassLoader Catched -> " + a)
            //java_stack_trace
            this.$init(a,b,c,d)
        }
        forName.implementation = function(class_name, flag, class_loader) {
            var isGood = true;
            for (var i = 0; i < internalClasses.length; i++) {
                if (class_name.startsWith(internalClasses[i])) {
                    isGood = false;
                }
            }
            if (isGood) {
                am_send(PROFILE_HOOKING_TYPE,"Reflection => forName => " + class_name);
                //java_stack_trace
            }
            return forName.call(this, class_name, flag, class_loader);
        }
        loadClass.implementation = function(class_name, resolve) {
            var isGood = true;
            for (var i = 0; i < internalClasses.length; i++) {
                if (class_name.startsWith(internalClasses[i])) {
                    isGood = false;
                }
            }
            if (isGood) {
                am_send(PROFILE_HOOKING_TYPE,"Reflection => loadClass => " + class_name);
            }
            return loadClass.call(this, class_name, resolve);
        }
       
    });
}






export function install_runtime_hooks(){
    devlog("\n")
    devlog("install runtime hooks");
    hook_runtime();
    trace_reflection()

}


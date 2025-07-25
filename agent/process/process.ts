import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"

/**
 * 
/**
 * https://github.com/dpnishant/appmon/tree/master/scripts/Android
 * 
 */
 const PROFILE_HOOKING_TYPE: string = "PROCESS_CREATION"

 function hook_java_process_creation() {
    Java.perform(() => {
        try {
            const Process = Java.use('android.os.Process');

            const sendHookEvent = (event: any) => {
                for (const key in event) {
                    if (event[key] === null || event[key] === '') {
                        delete event[key];
                    }
                }
                am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
            };

            if (Process.start) {
                Process.start.implementation = function (
                    processClass: any, niceName: string, uid: number,
                    gid: number, gids: any, debugFlags: number, mountExternal: number,
                    targetSdkVersion: number, seInfo: string, abi: string,
                    instructionSet: string, appDataDir: string, zygoteArgs: any
                ) {
                    const send_data = {
                        event_type: "Process",
                        lib: 'android.os.Process',
                        method: 'start',
                        time: new Date(),
                        artifact: [
                            {
                                name: "Process Class",
                                value: processClass.toString(),
                                argSeq: 0
                            },
                            {
                                name: "Nice Name",
                                value: niceName,
                                argSeq: 1
                            },
                            {
                                name: "uid",
                                value: uid.toString(),
                                argSeq: 2
                            },
                            {
                                name: "gid",
                                value: gid.toString(),
                                argSeq: 3
                            },
                            {
                                name: "gids",
                                value: gids.toString(),
                                argSeq: 4
                            },
                            {
                                name: "Debug Flags",
                                value: debugFlags.toString(),
                                argSeq: 5
                            },
                            {
                                name: "Mount External",
                                value: mountExternal.toString(),
                                argSeq: 6
                            },
                            {
                                name: "Target Sdk Version",
                                value: targetSdkVersion.toString(),
                                argSeq: 7
                            },
                            {
                                name: "SElinux Info",
                                value: seInfo,
                                argSeq: 8
                            },
                            {
                                name: "abi",
                                value: abi,
                                argSeq: 9
                            },
                            {
                                name: "Instruction Set",
                                value: instructionSet,
                                argSeq: 10
                            },
                            {
                                name: "Application Data Directory",
                                value: appDataDir,
                                argSeq: 11
                            },
                            {
                                name: "Zygote Args",
                                value: zygoteArgs.toString(),
                                argSeq: 12
                            }
                        ]
                    };

                    sendHookEvent(send_data);

                    return this.start.apply(this, arguments);
                };
            }
        } catch (error) {
            am_send(PROFILE_HOOKING_TYPE, `Error: ${(error as Error).toString()}`);
        }
    });
}



function hook_native_process_creation(){


}




export function install_process_hooks(){
    devlog("\n")
    devlog("install process hooks");
    hook_java_process_creation();

}


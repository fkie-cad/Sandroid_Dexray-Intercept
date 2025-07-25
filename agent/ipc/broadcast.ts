import { log, devlog, am_send } from "../utils/logging.js"
import { Java } from "../utils/javalib.js"

const PROFILE_HOOKING_TYPE: string = "IPC_BROADCAST"

/*
based on the work of https://github.com/dpnishant/appmon/blob/master/scripts/Android/IPC/IPC.js
*/

function hook_broadcasts() {
    Java.perform(() => {
        try {
            const ContextWrapper = Java.use('android.content.ContextWrapper');

            const sendHookEvent = (event: any) => {
                for (const key in event) {
                    if (event[key] === null || event[key] === '') {
                        delete event[key];
                    }
                }
                am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
            };

            if (ContextWrapper.sendBroadcast) {
                ContextWrapper.sendBroadcast.overload('android.content.Intent').implementation = function (intent: any) {
                    const send_data = {
                        event_type: "Broadcast Sent",
                        lib: 'android.content.ContextWrapper',
                        method: 'sendBroadcast',
                        time: new Date(),
                        artifact: [
                            {
                                name: "Intent (Stringified)",
                                value: intent.toString(),
                                argSeq: 0
                            },
                            {
                                name: "Intent Extras",
                                value: intent ? intent.getExtras() ? intent.getExtras().toString() : "null" : "null",
                                argSeq: 1
                            },
                            {
                                name: "Intent Flags",
                                value: intent.getFlags().toString(),
                                argSeq: 2
                            }
                        ]
                    };
                    sendHookEvent(send_data);
                    return this.sendBroadcast.overload('android.content.Intent').apply(this, arguments);
                };

                ContextWrapper.sendBroadcast.overload('android.content.Intent', 'java.lang.String').implementation = function (intent: any, receiverPermission: string) {
                    const send_data = {
                        event_type: "Broadcast Sent",
                        lib: 'android.content.ContextWrapper',
                        method: 'sendBroadcast',
                        time: new Date(),
                        artifact: [
                            {
                                name: "Intent (Stringified)",
                                value: intent.toString(),
                                argSeq: 0
                            },
                            {
                                name: "Intent Extras",
                                value: intent.getExtras().toString(),
                                argSeq: 1
                            },
                            {
                                name: "Intent Flags",
                                value: intent.getFlags().toString(),
                                argSeq: 2
                            },
                            {
                                name: "Receiver Permission",
                                value: receiverPermission.toString(),
                                argSeq: 3
                            }
                        ]
                    };
                    sendHookEvent(send_data);
                    return this.sendBroadcast.overload('android.content.Intent', 'java.lang.String').apply(this, arguments);
                };
            }

            if (ContextWrapper.sendStickyBroadcast) {
                ContextWrapper.sendStickyBroadcast.overload('android.content.Intent').implementation = function (intent: any) {
                    const send_data = {
                        event_type: "Sticky Broadcast Sent",
                        class: 'android.content.ContextWrapper',
                        method: 'sendStickyBroadcast',
                        time: new Date(),
                        artifact: [
                            {
                                name: "Intent (Stringified)",
                                value: intent.toString(),
                                argSeq: 0
                            },
                            {
                                name: "Intent Extras",
                                value: intent.getExtras().toString(),
                                argSeq: 1
                            },
                            {
                                name: "Intent Flags",
                                value: intent.getFlags().toString(),
                                argSeq: 2
                            }
                        ]
                    };
                    sendHookEvent(send_data);
                    return this.sendStickyBroadcast.overload('android.content.Intent').apply(this, arguments);
                };
            }

            if (ContextWrapper.startActivity) {
                ContextWrapper.startActivity.overload('android.content.Intent').implementation = function (intent: any) {
                    const send_data = {
                        event_type: "Activity Started",
                        class: 'android.content.ContextWrapper',
                        method: 'startActivity',
                        artifact: [
                            {
                                name: "Intent (Stringified)",
                                value: intent.toString(),
                                argSeq: 0
                            }
                        ]
                    };
                    sendHookEvent(send_data);
                    return this.startActivity.overload('android.content.Intent').apply(this, arguments);
                };

                ContextWrapper.startActivity.overload('android.content.Intent', 'android.os.Bundle').implementation = function (intent: any, bundle: any) {
                    const send_data = {
                        event_type: "Activity Started",
                        lib: 'android.content.ContextWrapper',
                        method: 'startActivity',
                        artifact: [
                            {
                                name: "Intent (Stringified)",
                                value: intent.toString(),
                                argSeq: 0
                            },
                            {
                                name: "Bundle",
                                value: bundle.toString(),
                                argSeq: 1
                            }
                        ]
                    };
                    sendHookEvent(send_data);
                    return this.startActivity.overload('android.content.Intent', 'android.os.Bundle').apply(this, arguments);
                };
            }

            if (ContextWrapper.startService) {
                ContextWrapper.startService.implementation = function (service: any) {
                    const send_data = {
                        event_type: "Service Started",
                        class: 'android.content.ContextWrapper',
                        method: 'startService',
                        artifact: [
                            {
                                name: "Service",
                                value: service.toUri(0).toString(),
                                argSeq: 0
                            }
                        ]
                    };
                    sendHookEvent(send_data);
                    return this.startService.apply(this, arguments);
                };
            }

            if (ContextWrapper.stopService) {
                ContextWrapper.stopService.implementation = function (name: any) {
                    const send_data = {
                        event_type: "Service Stopped",
                        class: 'android.content.ContextWrapper',
                        method: 'stopService',
                        artifact: [
                            {
                                name: "Service Intent URL",
                                value: name.toUri(0),
                                argSeq: 0
                            }
                        ]
                    };
                    sendHookEvent(send_data);
                    return this.stopService.apply(this, arguments);
                };
            }

            if (ContextWrapper.registerReceiver) {
                ContextWrapper.registerReceiver.overload('android.content.BroadcastReceiver', 'android.content.IntentFilter').implementation = function (receiver: any, filter: any) {
                    return this.registerReceiver.apply(this, arguments);
                };

                ContextWrapper.registerReceiver.overload('android.content.BroadcastReceiver', 'android.content.IntentFilter', 'java.lang.String', 'android.os.Handler').implementation = function (receiver: any, filter: any, broadcastPermission: string, scheduler: any) {
                    return this.registerReceiver.apply(this, arguments);
                };
            }
        } catch (error) {
            am_send(PROFILE_HOOKING_TYPE, `Error: ${(error as Error).toString()}`);
        }
    });
}


export function install_broadcast_hooks(){
    devlog("\n")
    devlog("install broadcast hooks");
    hook_broadcasts();

}
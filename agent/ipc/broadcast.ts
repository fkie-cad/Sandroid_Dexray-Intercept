import { log, devlog, am_send } from "../utils/logging.js"
import { Where } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"
import { hook_config } from "../hooking_profile_loader.js"

const PROFILE_HOOKING_TYPE: string = "IPC_BROADCAST"
const HOOK_NAME = 'broadcast_hooks'

function createBroadcastEvent(eventType: string, data: any): void {
    // Check if hook is enabled at runtime
    if (!hook_config[HOOK_NAME]) {
        return;
    }
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function getStackTrace() {
    const threadDef = Java.use('java.lang.Thread');
    const threadInstance = threadDef.$new();
    return Where(threadInstance.currentThread().getStackTrace());
}

/*
based on the work of https://github.com/dpnishant/appmon/blob/master/scripts/Android/IPC/IPC.js
*/

function hook_broadcasts() {
    Java.perform(() => {
        try {
            const ContextWrapper = Java.use('android.content.ContextWrapper');

            const getIntentInfo = (intent: any) => {
                const intentData: any = {};
                
                try {
                    intentData.intent_string = intent.toString();
                    
                    const component = intent.getComponent();
                    if (component) {
                        intentData.component = component.getClassName();
                    }
                    
                    const action = intent.getAction();
                    if (action) {
                        intentData.action = action;
                    }
                    
                    const data = intent.getData();
                    if (data) {
                        intentData.data_uri = data.toString();
                    }
                    
                    const extras = intent.getExtras();
                    if (extras) {
                        intentData.extras = extras.toString();
                    }
                    
                    intentData.flags = intent.getFlags();
                } catch (e) {
                    intentData.error = `Error extracting intent: ${e}`;
                }
                
                return intentData;
            };

            if (ContextWrapper.sendBroadcast) {
                ContextWrapper.sendBroadcast.overload('android.content.Intent').implementation = function (intent: any) {
                    const intentInfo = getIntentInfo(intent);
                    
                    createBroadcastEvent("broadcast.sent", {
                        class: 'android.content.ContextWrapper',
                        method: 'sendBroadcast',
                        intent: intentInfo,
                        stack_trace: getStackTrace()
                    });
                    
                    return this.sendBroadcast.overload('android.content.Intent').apply(this, arguments);
                };

                ContextWrapper.sendBroadcast.overload('android.content.Intent', 'java.lang.String').implementation = function (intent: any, receiverPermission: string) {
                    const intentInfo = getIntentInfo(intent);
                    
                    createBroadcastEvent("broadcast.sent", {
                        class: 'android.content.ContextWrapper',
                        method: 'sendBroadcast',
                        intent: intentInfo,
                        receiver_permission: receiverPermission,
                        stack_trace: getStackTrace()
                    });
                    
                    return this.sendBroadcast.overload('android.content.Intent', 'java.lang.String').apply(this, arguments);
                };
            }

            if (ContextWrapper.sendStickyBroadcast) {
                ContextWrapper.sendStickyBroadcast.overload('android.content.Intent').implementation = function (intent: any) {
                    const intentInfo = getIntentInfo(intent);
                    
                    createBroadcastEvent("broadcast.sticky_sent", {
                        class: 'android.content.ContextWrapper',
                        method: 'sendStickyBroadcast',
                        intent: intentInfo,
                        stack_trace: getStackTrace()
                    });
                    
                    return this.sendStickyBroadcast.overload('android.content.Intent').apply(this, arguments);
                };
            }

            if (ContextWrapper.startActivity) {
                ContextWrapper.startActivity.overload('android.content.Intent').implementation = function (intent: any) {
                    const intentInfo = getIntentInfo(intent);
                    
                    createBroadcastEvent("activity.started", {
                        class: 'android.content.ContextWrapper',
                        method: 'startActivity',
                        intent: intentInfo,
                        stack_trace: getStackTrace()
                    });
                    
                    return this.startActivity.overload('android.content.Intent').apply(this, arguments);
                };

                ContextWrapper.startActivity.overload('android.content.Intent', 'android.os.Bundle').implementation = function (intent: any, bundle: any) {
                    const intentInfo = getIntentInfo(intent);
                    
                    createBroadcastEvent("activity.started", {
                        class: 'android.content.ContextWrapper',
                        method: 'startActivity',
                        intent: intentInfo,
                        bundle: bundle ? bundle.toString() : null,
                        stack_trace: getStackTrace()
                    });
                    
                    return this.startActivity.overload('android.content.Intent', 'android.os.Bundle').apply(this, arguments);
                };
            }

            if (ContextWrapper.startService) {
                ContextWrapper.startService.implementation = function (service: any) {
                    const intentInfo = getIntentInfo(service);
                    
                    createBroadcastEvent("service.started", {
                        class: 'android.content.ContextWrapper',
                        method: 'startService',
                        service: intentInfo,
                        stack_trace: getStackTrace()
                    });
                    
                    return this.startService.apply(this, arguments);
                };
            }

            if (ContextWrapper.stopService) {
                ContextWrapper.stopService.implementation = function (name: any) {
                    const intentInfo = getIntentInfo(name);
                    
                    createBroadcastEvent("service.stopped", {
                        class: 'android.content.ContextWrapper',
                        method: 'stopService',
                        service: intentInfo,
                        stack_trace: getStackTrace()
                    });
                    
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
            createBroadcastEvent("broadcast.error", {
                error: (error as Error).toString(),
                stack_trace: getStackTrace()
            });
        }
    });
}


export function install_broadcast_hooks(){
    devlog("\n")
    devlog("install broadcast hooks");

    try {
        hook_broadcasts();
    } catch (error) {
        devlog(`[HOOK] Failed to install broadcast hooks: ${error}`);
    }
}
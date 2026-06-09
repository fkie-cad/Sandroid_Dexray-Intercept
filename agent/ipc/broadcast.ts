import { log, devlog, am_send } from "../utils/logging.js"
import { Where } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"
import { safePerform, safeUse, safeOverload, safeImplementation } from "../utils/safe_java.js"

const PROFILE_HOOKING_TYPE: string = "IPC_BROADCAST"

function createBroadcastEvent(eventType: string, data: any): void {
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
    safePerform("broadcast:hook_broadcasts", () => {
        const ContextWrapper = safeUse(
            'android.content.ContextWrapper',
            "broadcast:hook_broadcasts"
        );
        if (!ContextWrapper) return;

        const getIntentInfo = (intent: any) => {
            const intentData: any = {};
            try {
                intentData.intent_string = intent.toString();
                const component = intent.getComponent();
                if (component) intentData.component = component.getClassName();
                const action = intent.getAction();
                if (action) intentData.action = action;
                const data = intent.getData();
                if (data) intentData.data_uri = data.toString();
                const extras = intent.getExtras();
                if (extras) intentData.extras = extras.toString();
                intentData.flags = intent.getFlags();
            } catch (e) {
                intentData.error = `Error extracting intent: ${e}`;
            }
            return intentData;
        };

        if (ContextWrapper.sendBroadcast) {
            const sendBroadcast1 = safeOverload(
                ContextWrapper.sendBroadcast,
                "broadcast:ContextWrapper.sendBroadcast",
                'android.content.Intent'
            );
            if (sendBroadcast1) {
                sendBroadcast1.implementation = safeImplementation(
                    "broadcast:ContextWrapper.sendBroadcast[Intent]",
                    sendBroadcast1,
                    function(original, intent: any) {
                        const intentInfo = getIntentInfo(intent);
                        createBroadcastEvent("broadcast.sent", {
                            class: 'android.content.ContextWrapper',
                            method: 'sendBroadcast',
                            intent: intentInfo,
                            stack_trace: getStackTrace()
                        });
                        return original.call(this, intent);
                    }
                );
            }

            const sendBroadcast2 = safeOverload(
                ContextWrapper.sendBroadcast,
                "broadcast:ContextWrapper.sendBroadcast",
                'android.content.Intent', 'java.lang.String'
            );
            if (sendBroadcast2) {
                sendBroadcast2.implementation = safeImplementation(
                    "broadcast:ContextWrapper.sendBroadcast[Intent,String]",
                    sendBroadcast2,
                    function(original, intent: any, receiverPermission: string) {
                        const intentInfo = getIntentInfo(intent);
                        createBroadcastEvent("broadcast.sent", {
                            class: 'android.content.ContextWrapper',
                            method: 'sendBroadcast',
                            intent: intentInfo,
                            receiver_permission: receiverPermission,
                            stack_trace: getStackTrace()
                        });
                        return original.call(this, intent, receiverPermission);
                    }
                );
            }
        }

        if (ContextWrapper.sendStickyBroadcast) {
            const sendSticky = safeOverload(
                ContextWrapper.sendStickyBroadcast,
                "broadcast:ContextWrapper.sendStickyBroadcast",
                'android.content.Intent'
            );
            if (sendSticky) {
                sendSticky.implementation = safeImplementation(
                    "broadcast:ContextWrapper.sendStickyBroadcast[Intent]",
                    sendSticky,
                    function(original, intent: any) {
                        const intentInfo = getIntentInfo(intent);
                        createBroadcastEvent("broadcast.sticky_sent", {
                            class: 'android.content.ContextWrapper',
                            method: 'sendStickyBroadcast',
                            intent: intentInfo,
                            stack_trace: getStackTrace()
                        });
                        return original.call(this, intent);
                    }
                );
            }
        }

        if (ContextWrapper.startActivity) {
            const startActivity1 = safeOverload(
                ContextWrapper.startActivity,
                "broadcast:ContextWrapper.startActivity",
                'android.content.Intent'
            );
            if (startActivity1) {
                startActivity1.implementation = safeImplementation(
                    "broadcast:ContextWrapper.startActivity[Intent]",
                    startActivity1,
                    function(original, intent: any) {
                        const intentInfo = getIntentInfo(intent);
                        createBroadcastEvent("activity.started", {
                            class: 'android.content.ContextWrapper',
                            method: 'startActivity',
                            intent: intentInfo,
                            stack_trace: getStackTrace()
                        });
                        return original.call(this, intent);
                    }
                );
            }

            const startActivity2 = safeOverload(
                ContextWrapper.startActivity,
                "broadcast:ContextWrapper.startActivity",
                'android.content.Intent', 'android.os.Bundle'
            );
            if (startActivity2) {
                startActivity2.implementation = safeImplementation(
                    "broadcast:ContextWrapper.startActivity[Intent,Bundle]",
                    startActivity2,
                    function(original, intent: any, bundle: any) {
                        const intentInfo = getIntentInfo(intent);
                        createBroadcastEvent("activity.started", {
                            class: 'android.content.ContextWrapper',
                            method: 'startActivity',
                            intent: intentInfo,
                            bundle: bundle ? bundle.toString() : null,
                            stack_trace: getStackTrace()
                        });
                        return original.call(this, intent, bundle);
                    }
                );
            }
        }

        if (ContextWrapper.startService) {
            const startServiceRef = ContextWrapper.startService;
            startServiceRef.implementation = safeImplementation(
                "broadcast:ContextWrapper.startService",
                startServiceRef,
                function(original, service: any) {
                    const intentInfo = getIntentInfo(service);
                    createBroadcastEvent("service.started", {
                        class: 'android.content.ContextWrapper',
                        method: 'startService',
                        service: intentInfo,
                        stack_trace: getStackTrace()
                    });
                    return original.call(this, service);
                }
            );
        }

        if (ContextWrapper.stopService) {
            const stopServiceRef = ContextWrapper.stopService;
            stopServiceRef.implementation = safeImplementation(
                "broadcast:ContextWrapper.stopService",
                stopServiceRef,
                function(original, name: any) {
                    const intentInfo = getIntentInfo(name);
                    createBroadcastEvent("service.stopped", {
                        class: 'android.content.ContextWrapper',
                        method: 'stopService',
                        service: intentInfo,
                        stack_trace: getStackTrace()
                    });
                    return original.call(this, name);
                }
            );
        }

        if (ContextWrapper.registerReceiver) {
            const registerReceiver1 = safeOverload(
                ContextWrapper.registerReceiver,
                "broadcast:ContextWrapper.registerReceiver",
                'android.content.BroadcastReceiver', 'android.content.IntentFilter'
            );
            if (registerReceiver1) {
                registerReceiver1.implementation = safeImplementation(
                    "broadcast:ContextWrapper.registerReceiver[BroadcastReceiver,IntentFilter]",
                    registerReceiver1,
                    function(original, receiver: any, filter: any) {
                        return original.call(this, receiver, filter);
                    }
                );
            }

            const registerReceiver2 = safeOverload(
                ContextWrapper.registerReceiver,
                "broadcast:ContextWrapper.registerReceiver",
                'android.content.BroadcastReceiver', 'android.content.IntentFilter',
                'java.lang.String', 'android.os.Handler'
            );
            if (registerReceiver2) {
                registerReceiver2.implementation = safeImplementation(
                    "broadcast:ContextWrapper.registerReceiver[BroadcastReceiver,IntentFilter,String,Handler]",
                    registerReceiver2,
                    function(original, receiver: any, filter: any, broadcastPermission: string, scheduler: any) {
                        return original.call(this, receiver, filter, broadcastPermission, scheduler);
                    }
                );
            }
        }
    });
}

export function install_broadcast_hooks(){
    devlog("\n");
    devlog("install broadcast hooks");

    try {
        hook_broadcasts();
    } catch (error) {
        devlog(`[HOOK] Failed to install broadcast hooks: ${error}`);
    }
}
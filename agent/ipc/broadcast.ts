import { devlog, am_send } from "../utils/logging.js"
import { toNullableInt, getIdentityHash } from "../utils/misc.js"
import { safePerform, safeUse, safeOverload, safeImplementation } from "../utils/safe_java.js"
import { collectJavaStackTrace } from "../utils/stacktrace.js"

const PROFILE_HOOKING_TYPE: string = "IPC_BROADCAST"

function createBroadcastEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
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
                const data = intent.getDataString();
                if (data) intentData.data_uri = data;
                const extras = intent.getExtras();
                if (extras) intentData.extras = extras.toString();
                intentData.flags = intent.getFlags();
            } catch (e) {
                intentData.error = `Error extracting intent: ${e}`;
            }
            return intentData;
        };

        const getReceiverInfo = (receiver: any) => {
            const receiverData: any = {};
            try {
                if (!receiver) {
                    receiverData.is_null = true;
                    return receiverData;
                }

                try {
                    receiverData.receiver_identity = getIdentityHash(receiver);
                } catch (_) {}

                try {
                    if (receiver.$className) {
                        receiverData.receiver_class = String(receiver.$className);
                    }
                } catch (_) {}

                if (!receiverData.receiver_class) {
                    try {
                        const cls = receiver.getClass();
                        if (cls) receiverData.receiver_class = String(cls.getName());
                    } catch (_) {}
                }

                try {
                    receiverData.receiver_string = String(receiver.toString());
                } catch (_) {}
            } catch (e) {
                receiverData.error = `Error extracting receiver: ${e}`;
            }
            return receiverData;
        };

        const getIntentFilterActions = (filter: any): string[] => {
            const actions: string[] = [];
            if (!filter) return actions;

            try {
                const count = filter.countActions();
                for (let i = 0; i < count; i++) {
                    actions.push(String(filter.getAction(i)));
                }
            } catch (_) {}

            return actions;
        };

        const handleRegisterReceiverResult = (
            receiver: any,
            filter: any,
            result: any,
            extraData: any = {}
        ): void => {
            const actions = getIntentFilterActions(filter);
            const java_stack_trace = collectJavaStackTrace();

            if (!receiver) {
                createBroadcastEvent("broadcast.sticky_query", {
                    source_class: 'android.content.ContextWrapper',
                    method: 'registerReceiver',
                    actions,
                    sticky_intent: result ? getIntentInfo(result) : null,
                    ...extraData,
                    ...(java_stack_trace ? { java_stack_trace } : {})
                });
                return;
            }

            createBroadcastEvent("receiver.registered", {
                source_class: 'android.content.ContextWrapper',
                method: 'registerReceiver',
                ...getReceiverInfo(receiver),
                actions,
                ...extraData,
                ...(java_stack_trace ? { java_stack_trace } : {})
            });
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
                        const java_stack_trace = collectJavaStackTrace();
                        createBroadcastEvent("broadcast.sent", {
                            source_class: 'android.content.ContextWrapper',
                            method: 'sendBroadcast',
                            intent: intentInfo,
                            ...(java_stack_trace ? { java_stack_trace } : {})
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
                        const java_stack_trace = collectJavaStackTrace();
                        createBroadcastEvent("broadcast.sent", {
                            source_class: 'android.content.ContextWrapper',
                            method: 'sendBroadcast',
                            intent: intentInfo,
                            receiver_permission: receiverPermission,
                            ...(java_stack_trace ? { java_stack_trace } : {})
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
                        const java_stack_trace = collectJavaStackTrace();
                        createBroadcastEvent("broadcast.sticky_sent", {
                            source_class: 'android.content.ContextWrapper',
                            method: 'sendStickyBroadcast',
                            intent: intentInfo,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return original.call(this, intent);
                    }
                );
            }
        }

        if (ContextWrapper.sendOrderedBroadcast) {
            const sendOrdered1 = safeOverload(
                ContextWrapper.sendOrderedBroadcast,
                "broadcast:ContextWrapper.sendOrderedBroadcast",
                'android.content.Intent', 'java.lang.String'
            );
            if (sendOrdered1) {
                sendOrdered1.implementation = safeImplementation(
                    "broadcast:ContextWrapper.sendOrderedBroadcast[Intent,String]",
                    sendOrdered1,
                    function(original, intent: any, receiverPermission: string) {
                        const intentInfo = getIntentInfo(intent);
                        const java_stack_trace = collectJavaStackTrace();
                        createBroadcastEvent("broadcast.ordered_sent", {
                            source_class: 'android.content.ContextWrapper',
                            method: 'sendOrderedBroadcast',
                            intent: intentInfo,
                            receiver_permission: receiverPermission,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return original.call(this, intent, receiverPermission);
                    }
                );
            }

            const sendOrdered2 = safeOverload(
                ContextWrapper.sendOrderedBroadcast,
                "broadcast:ContextWrapper.sendOrderedBroadcast",
                'android.content.Intent', 'java.lang.String',
                'android.content.BroadcastReceiver', 'android.os.Handler',
                'int', 'java.lang.String', 'android.os.Bundle'
            );
            if (sendOrdered2) {
                sendOrdered2.implementation = safeImplementation(
                    "broadcast:ContextWrapper.sendOrderedBroadcast[Intent,String,BroadcastReceiver,Handler,int,String,Bundle]",
                    sendOrdered2,
                    function(original, intent: any, receiverPermission: string,
                            resultReceiver: any, scheduler: any,
                            initialCode: number, initialData: string, initialExtras: any) {
                        const intentInfo = getIntentInfo(intent);
                        const normalizedInitialCode = toNullableInt(initialCode);
                        const java_stack_trace = collectJavaStackTrace();

                        createBroadcastEvent("broadcast.ordered_sent", {
                            source_class: 'android.content.ContextWrapper',
                            method: 'sendOrderedBroadcast',
                            intent: intentInfo,
                            receiver_permission: receiverPermission,
                            initial_code: normalizedInitialCode,
                            initial_data: initialData,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });

                        return original.call(this, intent, receiverPermission, resultReceiver,
                            scheduler, initialCode, initialData, initialExtras);
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
                            source_class: 'android.content.ContextWrapper',
                            method: 'startActivity',
                            intent: intentInfo
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
                            source_class: 'android.content.ContextWrapper',
                            method: 'startActivity',
                            intent: intentInfo,
                            bundle: bundle ? bundle.toString() : null
                        });
                        return original.call(this, intent, bundle);
                    }
                );
            }
        }

        // Activity.startActivity is a separate override - calls from Activity subclasses
        // never reach ContextWrapper.startActivity; both layers must be hooked
        const Activity = safeUse('android.app.Activity', "broadcast:hook_broadcasts");
        if (Activity && Activity.startActivity) {
            const activityStart1 = safeOverload(
                Activity.startActivity,
                "broadcast:Activity.startActivity",
                'android.content.Intent'
            );
            if (activityStart1) {
                activityStart1.implementation = safeImplementation(
                    "broadcast:Activity.startActivity[Intent]",
                    activityStart1,
                    function(original, intent: any) {
                        const intentInfo = getIntentInfo(intent);
                        createBroadcastEvent("activity.started", {
                            source_class: 'android.app.Activity',
                            method: 'startActivity',
                            intent: intentInfo
                        });
                        return original.call(this, intent);
                    }
                );
            }

            const activityStart2 = safeOverload(
                Activity.startActivity,
                "broadcast:Activity.startActivity",
                'android.content.Intent', 'android.os.Bundle'
            );
            if (activityStart2) {
                activityStart2.implementation = safeImplementation(
                    "broadcast:Activity.startActivity[Intent,Bundle]",
                    activityStart2,
                    function(original, intent: any, bundle: any) {
                        const intentInfo = getIntentInfo(intent);
                        createBroadcastEvent("activity.started", {
                            source_class: 'android.app.Activity',
                            method: 'startActivity',
                            intent: intentInfo,
                            bundle: bundle ? bundle.toString() : null
                        });
                        return original.call(this, intent, bundle);
                    }
                );
            }
        }

        if (Activity && Activity.startActivityForResult) {
            const startForResult1 = safeOverload(
                Activity.startActivityForResult,
                "broadcast:Activity.startActivityForResult",
                'android.content.Intent', 'int'
            );
            if (startForResult1) {
                startForResult1.implementation = safeImplementation(
                    "broadcast:Activity.startActivityForResult[Intent,int]",
                    startForResult1,
                    function(original, intent: any, requestCode: number) {
                        const intentInfo = getIntentInfo(intent);
                        createBroadcastEvent("activity.started_for_result", {
                            source_class: 'android.app.Activity',
                            method: 'startActivityForResult',
                            intent: intentInfo,
                            request_code: requestCode
                        });
                        return original.call(this, intent, requestCode);
                    }
                );
            }

            const startForResult2 = safeOverload(
                Activity.startActivityForResult,
                "broadcast:Activity.startActivityForResult",
                'android.content.Intent', 'int', 'android.os.Bundle'
            );
            if (startForResult2) {
                startForResult2.implementation = safeImplementation(
                    "broadcast:Activity.startActivityForResult[Intent,int,Bundle]",
                    startForResult2,
                    function(original, intent: any, requestCode: number, options: any) {
                        const intentInfo = getIntentInfo(intent);
                        createBroadcastEvent("activity.started_for_result", {
                            source_class: 'android.app.Activity',
                            method: 'startActivityForResult',
                            intent: intentInfo,
                            request_code: requestCode,
                            options: options ? options.toString() : null
                        });
                        return original.call(this, intent, requestCode, options);
                    }
                );
            }
        }

        // startForegroundService is available from API 26; hook mirrors startService
        if (ContextWrapper.startForegroundService) {
            const startFgService = safeOverload(
                ContextWrapper.startForegroundService,
                "broadcast:ContextWrapper.startForegroundService",
                'android.content.Intent'
            );
            if (startFgService) {
                startFgService.implementation = safeImplementation(
                    "broadcast:ContextWrapper.startForegroundService[Intent]",
                    startFgService,
                    function(original, service: any) {
                        const intentInfo = getIntentInfo(service);
                        const java_stack_trace = collectJavaStackTrace();
                        createBroadcastEvent("service.foreground_started", {
                            source_class: 'android.content.ContextWrapper',
                            method: 'startForegroundService',
                            intent: intentInfo,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return original.call(this, service);
                    }
                );
            }
        }

        // Service.startForeground - promotes a running service to foreground status.
        // Two overloads: 2-arg (int, Notification) below API 34,
        // 3-arg (int, Notification, int) on API 34+ where a foreground service type is required.
        const Service = safeUse('android.app.Service', "broadcast:hook_broadcasts");
        if (Service && Service.startForeground) {
            const startFg2 = safeOverload(
                Service.startForeground,
                "broadcast:Service.startForeground",
                'int', 'android.app.Notification'
            );
            if (startFg2) {
                startFg2.implementation = safeImplementation(
                    "broadcast:Service.startForeground[int,Notification]",
                    startFg2,
                    function(original, id: number, notification: any) {
                        const java_stack_trace = collectJavaStackTrace();
                        createBroadcastEvent("service.foreground_promoted", {
                            source_class: 'android.app.Service',
                            method: 'startForeground',
                            notification_id: id,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return original.call(this, id, notification);
                    }
                );
            }

            const startFg3 = safeOverload(
                Service.startForeground,
                "broadcast:Service.startForeground",
                'int', 'android.app.Notification', 'int'
            );
            if (startFg3) {
                startFg3.implementation = safeImplementation(
                    "broadcast:Service.startForeground[int,Notification,int]",
                    startFg3,
                    function(original, id: number, notification: any, fgServiceType: number) {
                        const java_stack_trace = collectJavaStackTrace();
                        createBroadcastEvent("service.foreground_promoted", {
                            source_class: 'android.app.Service',
                            method: 'startForeground',
                            notification_id: id,
                            foreground_service_type: fgServiceType,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return original.call(this, id, notification, fgServiceType);
                    }
                );
            }
        }

        if (ContextWrapper.startService) {
            const startServiceOverload = safeOverload(
                ContextWrapper.startService,
                "broadcast:ContextWrapper.startService",
                'android.content.Intent'
            );
            if (startServiceOverload) {
                startServiceOverload.implementation = safeImplementation(
                    "broadcast:ContextWrapper.startService[Intent]",
                    startServiceOverload,
                    function(original, service: any) {
                        const intentInfo = getIntentInfo(service);
                        const java_stack_trace = collectJavaStackTrace();
                        createBroadcastEvent("service.started", {
                            source_class: 'android.content.ContextWrapper',
                            method: 'startService',
                            intent: intentInfo,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return original.call(this, service);
                    }
                );
            }
        }

        if (ContextWrapper.stopService) {
            const stopServiceOverload = safeOverload(
                ContextWrapper.stopService,
                "broadcast:ContextWrapper.stopService",
                'android.content.Intent'
            );
            if (stopServiceOverload) {
                stopServiceOverload.implementation = safeImplementation(
                    "broadcast:ContextWrapper.stopService[Intent]",
                    stopServiceOverload,
                    function(original, name: any) {
                        const intentInfo = getIntentInfo(name);
                        const java_stack_trace = collectJavaStackTrace();
                        createBroadcastEvent("service.stopped", {
                            source_class: 'android.content.ContextWrapper',
                            method: 'stopService',
                            intent: intentInfo,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return original.call(this, name);
                    }
                );
            }
        }

        if (ContextWrapper.bindService) {
            const bindServiceOverload = safeOverload(
                ContextWrapper.bindService,
                "broadcast:ContextWrapper.bindService",
                'android.content.Intent', 'android.content.ServiceConnection', 'int'
            );
            if (bindServiceOverload) {
                bindServiceOverload.implementation = safeImplementation(
                    "broadcast:ContextWrapper.bindService[Intent,ServiceConnection,int]",
                    bindServiceOverload,
                    function(original, service: any, conn: any, flags: number) {
                        const intentInfo = getIntentInfo(service);
                        const java_stack_trace = collectJavaStackTrace();
                        createBroadcastEvent("service.bound", {
                            source_class: 'android.content.ContextWrapper',
                            method: 'bindService',
                            intent: intentInfo,
                            flags: flags,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return original.call(this, service, conn, flags);
                    }
                );
            }
        }

        if (ContextWrapper.unbindService) {
            const unbindServiceOverload = safeOverload(
                ContextWrapper.unbindService,
                "broadcast:ContextWrapper.unbindService",
                'android.content.ServiceConnection'
            );
            if (unbindServiceOverload) {
                unbindServiceOverload.implementation = safeImplementation(
                    "broadcast:ContextWrapper.unbindService[ServiceConnection]",
                    unbindServiceOverload,
                    function(original, conn: any) {
                        const java_stack_trace = collectJavaStackTrace();
                        createBroadcastEvent("service.unbound", {
                            source_class: 'android.content.ContextWrapper',
                            method: 'unbindService',
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return original.call(this, conn);
                    }
                );
            }
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
                        const result = original.call(this, receiver, filter);
                        handleRegisterReceiverResult(receiver, filter, result);
                        return result;
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
                        const result = original.call(this, receiver, filter, broadcastPermission, scheduler);
                        handleRegisterReceiverResult(receiver, filter, result, {
                            receiver_permission: broadcastPermission
                        });
                        return result;
                    }
                );
            }

            // 3-arg overload - required on API 33+ with RECEIVER_EXPORTED / RECEIVER_NOT_EXPORTED flag
            const registerReceiver3 = safeOverload(
                ContextWrapper.registerReceiver,
                "broadcast:ContextWrapper.registerReceiver",
                'android.content.BroadcastReceiver', 'android.content.IntentFilter', 'int'
            );
            if (registerReceiver3) {
                registerReceiver3.implementation = safeImplementation(
                    "broadcast:ContextWrapper.registerReceiver[BroadcastReceiver,IntentFilter,int]",
                    registerReceiver3,
                    function(original, receiver: any, filter: any, flags: number) {
                        const result = original.call(this, receiver, filter, flags);
                        handleRegisterReceiverResult(receiver, filter, result, {
                            flags: flags
                        });
                        return result;
                    }
                );
            }

            // 5-arg overload - flag-bearing version of BroadcastReceiver, IntentFilter, String, Handler
            const registerReceiver5 = safeOverload(
                ContextWrapper.registerReceiver,
                "broadcast:ContextWrapper.registerReceiver",
                'android.content.BroadcastReceiver', 'android.content.IntentFilter',
                'java.lang.String', 'android.os.Handler', 'int'
            );
            if (registerReceiver5) {
                registerReceiver5.implementation = safeImplementation(
                    "broadcast:ContextWrapper.registerReceiver[BroadcastReceiver,IntentFilter,String,Handler,int]",
                    registerReceiver5,
                    function(original, receiver: any, filter: any, broadcastPermission: string, scheduler: any, flags: number) {
                        const result = original.call(this, receiver, filter, broadcastPermission, scheduler, flags);
                        handleRegisterReceiverResult(receiver, filter, result, {
                            receiver_permission: broadcastPermission,
                            flags: flags
                        });
                        return result;
                    }
                );
            }
        }

        if (ContextWrapper.unregisterReceiver) {
            const unregisterReceiver1 = safeOverload(
                ContextWrapper.unregisterReceiver,
                "broadcast:ContextWrapper.unregisterReceiver",
                'android.content.BroadcastReceiver'
            );
            if (unregisterReceiver1) {
                unregisterReceiver1.implementation = safeImplementation(
                    "broadcast:ContextWrapper.unregisterReceiver[BroadcastReceiver]",
                    unregisterReceiver1,
                    function(original, receiver: any) {
                        const receiverInfo = getReceiverInfo(receiver);

                        const result = original.call(this, receiver);

                        const java_stack_trace = collectJavaStackTrace();
                        createBroadcastEvent("receiver.unregistered", {
                            source_class: 'android.content.ContextWrapper',
                            method: 'unregisterReceiver',
                            ...receiverInfo,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });

                        return result;
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
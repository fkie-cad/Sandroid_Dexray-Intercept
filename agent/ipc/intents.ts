import { log, devlog, am_send } from "../utils/logging.js"
import { Where } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"

const PROFILE_HOOKING_TYPE: string = "IPC_INTENT"

function createIntentEvent(eventType: string, data: any): void {
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


function extractIntentData(intent: any): any {
    const intentData: any = {};
    
    try {
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
        
        const type = intent.getType();
        if (type) {
            intentData.mime_type = type;
        }
        
        const flags = intent.getFlags();
        if (flags) {
            intentData.flags = flags;
        }
        
        const extras = intent.getExtras();
        if (extras) {
            const extrasData: any = {};
            const keys = extras.keySet().iterator();
            
            while (keys.hasNext()) {
                const key = keys.next();
                let value = extras.get(key);
                let type = "null";
                
                if (value) {
                    try {
                        type = value.getClass().getSimpleName();
                        if (value.getClass().isArray()) {
                            value = Java.use('org.json.JSONArray').$new(value);
                        }
                        value = value.toString();
                    } catch (error) {
                        value = `<error extracting value: ${error}>`;
                    }
                }
                
                extrasData[key] = {
                    type: type,
                    value: value
                };
            }
            
            intentData.extras = extrasData;
        }
        
        intentData.intent_string = intent.toString();
        
    } catch (error) {
        intentData.error = `Error extracting intent: ${error}`;
    }
    
    return intentData;
}

function hookGetData(this: any): any {
    const intentData = extractIntentData(this);
    
    createIntentEvent("intent.data_accessed", {
        intent: intentData,
        method: 'getData',
        stack_trace: getStackTrace()
    });
    
    return this.getData();
}

function hookGetIntent(this: any): any {
    const intent = this.getIntent();
    const intentData = extractIntentData(intent);
    
    createIntentEvent("intent.accessed", {
        intent: intentData,
        method: 'getIntent',
        stack_trace: getStackTrace()
    });
    
    return intent;
}


function intent_hooks(){
setTimeout(() => {
    Java.perform(() => {
        const Intent = Java.use("android.content.Intent");
        Intent.getData.implementation = hookGetData;
        // const Activity = Java.use("android.app.Activity");
        // Activity.getIntent.implementation = hookGetIntent;
    });
}, 0);
}


export function install_intent_hooks(){
    devlog("\n")
    devlog("install intent hooks");

    try {
        intent_hooks();
    } catch (error) {
        devlog(`[HOOK] Failed to install intent hooks: ${error}`);
    }
}
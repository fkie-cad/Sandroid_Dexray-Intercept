import { log, devlog, am_send } from "../utils/logging.js"
import { Java } from "../utils/javalib.js"
import { safePerform, safeUse, safeImplementation } from "../utils/safe_java.js"
import { collectJavaStackTrace } from "../utils/stacktrace.js"

const PROFILE_HOOKING_TYPE: string = "IPC_INTENT"

// Guards against any getData() firing triggered by our own intent extraction,
// regardless of which hook initiated the extraction
let _inIntentExtraction = false;

function createIntentEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
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
        
        // getDataString() returns the URI as a plain String without calling getData(),
        // avoiding re-entry into the Intent.getData hook
        const dataStr = intent.getDataString();
        if (dataStr) {
            intentData.data_uri = dataStr;
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
                let valueType = "null";
                
                if (value) {
                    try {
                        valueType = value.getClass().getSimpleName();
                        if (value.getClass().isArray()) {
                            value = Java.use('org.json.JSONArray').$new(value);
                        }
                        value = value.toString();
                    } catch (error) {
                        value = `<error extracting value: ${error}>`;
                    }
                }
                
                extrasData[key] = {
                    type: valueType,
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

function hookGetData(this: any, original: any): any {
    if (_inIntentExtraction) {
        return original.call(this);
    }
    const result = original.call(this);
    // Only emit when getData() returned an actual URI.
    // Framework lifecycle calls on intents with no data URI produce null
    // and are not security-relevant, suppressing them eliminates all
    // cross-hook and lifecycle artifacts without affecting genuine events.
    if (result === null) {
        return result;
    }
    _inIntentExtraction = true;
    try {
        const intentData = extractIntentData(this);
        const java_stack_trace = collectJavaStackTrace();
        createIntentEvent("intent.data_accessed", {
            intent: intentData,
            method: 'getData',
            ...(java_stack_trace ? { java_stack_trace } : {})
        });
    } finally {
        _inIntentExtraction = false;
    }
    return result;
}

function hookGetIntent(this: any, original: any): any {
    _inIntentExtraction = true;
    let intent: any;
    try {
        intent = original.call(this);
        const intentData = extractIntentData(intent);
        const java_stack_trace = collectJavaStackTrace();
        createIntentEvent("intent.accessed", {
            intent: intentData,
            source_class: this.$className,
            method: 'getIntent',
            ...(java_stack_trace ? { java_stack_trace } : {})
        });
    } finally {
        _inIntentExtraction = false;
    }
    return intent;
}

function intent_hooks() {
    safePerform("intents:intent_hooks", () => {
        const Intent = safeUse("android.content.Intent", "intents:intent_hooks");
        if (Intent) {
            const getDataRef = Intent.getData;
            getDataRef.implementation = safeImplementation(
                "intents:Intent.getData",
                getDataRef,
                hookGetData
            );
        }

        // const Activity = Java.use("android.app.Activity");
        // Activity.getIntent.implementation = hookGetIntent;

        const Activity = safeUse("android.app.Activity", "intents:intent_hooks");
        if (Activity) {
            const getIntentRef = Activity.getIntent;
            getIntentRef.implementation = safeImplementation(
                "intents:Activity.getIntent",
                getIntentRef,
                hookGetIntent
            );
        }
    });
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
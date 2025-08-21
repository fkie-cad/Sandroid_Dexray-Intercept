TypeScript API Reference
========================

This section documents the TypeScript/JavaScript API for creating custom Frida hooks in Dexray Intercept.

.. important::
   **Always run** ``npm run build`` or ``frida-compile`` after modifying TypeScript hooks to compile them to JavaScript for use by the Python frontend.

Core Architecture
-----------------

Hook Structure
^^^^^^^^^^^^^^

All hooks follow a standardized structure for consistency and integration:

.. code-block:: typescript

   import { log, devlog, am_send } from "../utils/logging.js"
   import { Where } from "../utils/misc.js" 
   import { Java } from "../utils/javalib.js"

   // Profile type identifier for this hook category
   const PROFILE_HOOKING_TYPE: string = "MY_CATEGORY"

   // Event creation helper
   function createMyEvent(eventType: string, data: any): void {
       const event = {
           event_type: eventType,
           timestamp: Date.now(),
           ...data
       };
       am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
   }

   // Main hook installation function
   export function install_my_hooks(): void {
       devlog("Installing my custom hooks");
       
       Java.perform(() => {
           // Hook implementation goes here
       });
   }

Essential Components
^^^^^^^^^^^^^^^^^^^^

**Required Imports:**

.. code-block:: typescript

   import { log, devlog, am_send } from "../utils/logging.js"     // Logging utilities
   import { Where, bytesToHex } from "../utils/misc.js"          // Helper functions  
   import { Java } from "../utils/javalib.js"                    // Java runtime access

**Profile Type Constants:**

Every hook category must define a unique profile type identifier:

.. code-block:: typescript

   const PROFILE_HOOKING_TYPE: string = "CRYPTO_AES"        // Crypto hooks
   const PROFILE_HOOKING_TYPE: string = "WEB"               // Network hooks
   const PROFILE_HOOKING_TYPE: string = "BYPASS_DETECTION"  // Bypass hooks
   const PROFILE_HOOKING_TYPE: string = "MY_CUSTOM_HOOKS"   // Your custom category

**Event Creation Pattern:**

.. code-block:: typescript

   function createCustomEvent(eventType: string, data: any): void {
       const event = {
           event_type: eventType,           // Specific event identifier
           timestamp: Date.now(),           // Event timestamp
           ...data                          // Custom event data
       };
       am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
   }

Logging and Communication
-------------------------

Logging Functions
^^^^^^^^^^^^^^^^^

.. code-block:: typescript

   // Standard logging (always visible)
   log("Hook installed successfully");

   // Development logging (only visible in verbose mode)
   devlog("Detailed debug information");

   // Send structured data to Python
   am_send(PROFILE_HOOKING_TYPE, JSON.stringify(eventData));

**Usage Guidelines:**
   - Use ``log()`` for important status messages
   - Use ``devlog()`` for detailed debugging information
   - Always use ``am_send()`` to send structured event data

Message Format
^^^^^^^^^^^^^^

Messages sent via ``am_send()`` must follow the structured format:

.. code-block:: typescript

   const eventData = {
       event_type: "specific.event.identifier",  // Required: dot-separated event type
       timestamp: Date.now(),                    // Required: event timestamp
       // Custom fields based on event type
       field1: "value1",
       field2: 42,
       binary_data: bytesToHex(byteArray)       // Convert binary to hex
   };
   
   am_send(PROFILE_HOOKING_TYPE, JSON.stringify(eventData));

Java Runtime Integration
------------------------

Basic Java Hooking
^^^^^^^^^^^^^^^^^^^

.. code-block:: typescript

   export function install_basic_hooks(): void {
       Java.perform(() => {
           try {
               // Get Java class
               const MyClass = Java.use("com.example.MyClass");
               
               // Hook method with overload
               MyClass.sensitiveMethod.overload("java.lang.String").implementation = function(param) {
                   // Log the hook activation
                   devlog("sensitiveMethod called with: " + param);
                   
                   // Create event
                   createCustomEvent("method.called", {
                       method_name: "sensitiveMethod",
                       parameter: param,
                       class_name: "com.example.MyClass"
                   });
                   
                   // Call original method
                   return this.sensitiveMethod(param);
               };
               
           } catch (error) {
               devlog("Error in hook installation: " + error);
           }
       });
   }

Method Overloading
^^^^^^^^^^^^^^^^^^

Handle multiple method signatures:

.. code-block:: typescript

   Java.perform(() => {
       const Cipher = Java.use("javax.crypto.Cipher");
       
       // Hook multiple overloads
       Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
           createCryptoEvent("cipher.init.key", {
               mode: mode,
               key_algorithm: key.getAlgorithm()
           });
           return this.init(mode, key);
       };
       
       Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(mode, key, params) {
           createCryptoEvent("cipher.init.key_params", {
               mode: mode,
               key_algorithm: key.getAlgorithm(),
               params_class: params.$className
           });
           return this.init(mode, key, params);
       };
   });

Exception Handling
^^^^^^^^^^^^^^^^^^

Robust error handling in hooks:

.. code-block:: typescript

   Java.perform(() => {
       try {
           const TargetClass = Java.use("com.example.TargetClass");
           
           TargetClass.riskyMethod.implementation = function() {
               try {
                   // Pre-hook logic
                   createCustomEvent("risky.method.start", {});
                   
                   // Call original with error handling
                   const result = this.riskyMethod();
                   
                   // Post-hook logic
                   createCustomEvent("risky.method.success", { result: result });
                   return result;
                   
               } catch (methodError) {
                   // Handle method-specific errors
                   createCustomEvent("risky.method.error", { 
                       error: methodError.toString() 
                   });
                   throw methodError; // Re-throw to maintain app behavior
               }
           };
           
       } catch (hookError) {
           devlog("Failed to install hook: " + hookError);
       }
   });

Utility Functions
-----------------

Binary Data Handling
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: typescript

   import { bytesToHex } from "../utils/misc.js"

   // Convert byte array to hex string
   function processBytes(byteArray: number[]): string {
       if (!byteArray || byteArray.length === 0) {
           return "";
       }
       return bytesToHex(new Uint8Array(byteArray));
   }

   // Safe byte array processing
   function bytesToHexSafe(bytes: number[] | null): string {
       if (!bytes || bytes.length === 0) return "";
       try {
           return bytesToHex(new Uint8Array(bytes));
       } catch (error) {
           devlog("Error converting bytes to hex: " + error);
           return "[conversion_error]";
       }
   }

Stack Trace Collection
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: typescript

   import { Where } from "../utils/misc.js"

   Java.perform(() => {
       const Thread = Java.use('java.lang.Thread');
       const threadInstance = Thread.$new();
       
       MyClass.trackedMethod.implementation = function() {
           const stack = threadInstance.currentThread().getStackTrace();
           
           createCustomEvent("method.with.stack", {
               method: "trackedMethod",
               stack_trace: Where(stack)  // Convert stack to readable format
           });
           
           return this.trackedMethod();
       };
   });

String Processing
^^^^^^^^^^^^^^^^^

.. code-block:: typescript

   // Safe string extraction from various types
   function extractStringValue(obj: any): string {
       if (!obj) return "";
       
       try {
           if (typeof obj === 'string') return obj;
           if (obj.toString) return obj.toString();
           return JSON.stringify(obj);
       } catch (error) {
           return "[extraction_error]";
       }
   }

   // Extract plaintext from hex data
   function extractPlaintext(hexData: string): string | null {
       if (!hexData) return null;
       try {
           const bytes = hexData.match(/.{2}/g)?.map(byte => parseInt(byte, 16)) || [];
           // Only printable ASCII characters
           return String.fromCharCode(...bytes.filter(b => b >= 32 && b <= 126));
       } catch {
           return null;
       }
   }

Event Types and Patterns
-------------------------

Cryptographic Events
^^^^^^^^^^^^^^^^^^^^

.. code-block:: typescript

   // Key generation/creation events
   createCryptoEvent("crypto.key.creation", {
       algorithm: "AES",
       key_length: keyBytes.length,
       key_hex: bytesToHexSafe(keyBytes)
   });

   // Encryption/decryption operations  
   createCryptoEvent("crypto.cipher.operation", {
       algorithm: cipher.getAlgorithm(),
       operation_mode: opMode,
       key_hex: bytesToHexSafe(keyBytes),
       iv_hex: bytesToHexSafe(ivBytes),
       input_hex: bytesToHexSafe(inputBytes),
       output_hex: bytesToHexSafe(outputBytes),
       input_length: inputBytes.length,
       output_length: outputBytes.length
   });

Network Events
^^^^^^^^^^^^^^

.. code-block:: typescript

   // HTTP requests
   createNetworkEvent("http.request", {
       url: requestUrl,
       method: requestMethod,
       headers: headersObj,
       body_preview: bodyPreview,
       library: "OkHttp"
   });

   // Socket connections
   createNetworkEvent("socket.connect", {
       host: targetHost,
       port: targetPort,
       protocol: "TCP",
       local_port: localPort
   });

Bypass Events
^^^^^^^^^^^^^

.. code-block:: typescript

   // Detection bypass events
   createBypassEvent("bypass.root.file_check", {
       file_path: filePath,
       original_result: originalResult,
       bypassed_result: bypassedResult,
       detection_method: "File.exists()"
   });

   // Evasion technique events
   createBypassEvent("bypass.frida.process_check", {
       process_name: processName,
       detection_method: "ActivityManager.getRunningAppProcesses()",
       action: "removed_from_list"
   });

Hook Integration
----------------

Hook Loader Integration
^^^^^^^^^^^^^^^^^^^^^^^

To integrate new hooks into the main system, modify ``agent/hooking_profile_loader.ts``:

**1. Add Import:**

.. code-block:: typescript

   import { install_my_custom_hooks } from "./custom/my_hooks.js"

**2. Add to Hook Configuration:**

.. code-block:: typescript

   export let hook_config: HookConfig = {
       // ... existing hooks ...
       'my_custom_hooks': false,
   };

**3. Add to Installation Function:**

.. code-block:: typescript

   function load_profile_hooks() {
       // ... existing installations ...
       install_hook_conditionally('my_custom_hooks', install_my_custom_hooks);
   }

CLI Integration
^^^^^^^^^^^^^^^

To add CLI support for your hooks, modify ``src/dexray_intercept/ammm.py``:

**1. Add to Hook Groups (optional):**

.. code-block:: python

   if parsed_args.hooks_custom:
       hook_config.update({
           'my_custom_hooks': True
       })

**2. Add Individual Hook Support:**

.. code-block:: python

   individual_hooks = {
       # ... existing hooks ...
       'enable_my_custom': 'my_custom_hooks'
   }

**3. Add CLI Arguments:**

.. code-block:: python

   hooks.add_argument("--enable-my-custom", action="store_true", 
                      help="Enable my custom hooks")

Parser Integration
^^^^^^^^^^^^^^^^^^

Create a Python parser for your custom events in ``src/dexray_intercept/parsers/``:

**1. Create Parser File:**

.. code-block:: python

   # src/dexray_intercept/parsers/my_custom.py
   from .base import BaseParser
   from ..models.events import Event

   class MyCustomParser(BaseParser):
       def parse_json_data(self, data: dict, timestamp: str):
           event = MyCustomEvent(data.get('event_type'), timestamp)
           # Parse custom fields
           event.custom_field = data.get('custom_field')
           return event

**2. Register in Parser Factory:**

.. code-block:: python

   # src/dexray_intercept/parsers/factory.py
   from .my_custom import MyCustomParser

   def _register_default_parsers(self):
       # ... existing parsers ...
       self._parsers["MY_CUSTOM_HOOKS"] = MyCustomParser()

Advanced Patterns
-----------------

Dynamic Hook Installation
^^^^^^^^^^^^^^^^^^^^^^^^^

Install hooks based on runtime conditions:

.. code-block:: typescript

   export function install_dynamic_hooks(): void {
       Java.perform(() => {
           try {
               // Check if target class exists
               const TargetClass = Java.use("com.example.TargetClass");
               
               // Install hook only if conditions are met
               if (checkInstallConditions()) {
                   installTargetHooks(TargetClass);
               } else {
                   devlog("Conditions not met, skipping hook installation");
               }
               
           } catch (error) {
               // Class doesn't exist, skip gracefully
               devlog("Target class not found, skipping hooks: " + error);
           }
       });
   }

   function checkInstallConditions(): boolean {
       // Custom logic to determine if hooks should be installed
       return true;
   }

State Management
^^^^^^^^^^^^^^^^

Maintain state across hook invocations:

.. code-block:: typescript

   // Global state for hook category
   interface SessionInfo {
       id: number;
       algorithm?: string;
       keyData?: number[];
   }

   const activeSessions = new Map<number, SessionInfo>();

   export function install_stateful_hooks(): void {
       Java.perform(() => {
           const CipherClass = Java.use("javax.crypto.Cipher");
           
           // Initialize state
           CipherClass.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
               const sessionId = this.hashCode();
               const keyBytes = key.getEncoded();
               
               activeSessions.set(sessionId, {
                   id: sessionId,
                   algorithm: key.getAlgorithm(),
                   keyData: keyBytes
               });
               
               return this.init(mode, key);
           };
           
           // Use state
           CipherClass.doFinal.overload("[B").implementation = function(inputBytes) {
               const result = this.doFinal(inputBytes);
               const sessionId = this.hashCode();
               const session = activeSessions.get(sessionId);
               
               if (session) {
                   createCryptoEvent("cipher.operation", {
                       algorithm: session.algorithm,
                       key_hex: bytesToHexSafe(session.keyData),
                       input_hex: bytesToHexSafe(inputBytes),
                       output_hex: bytesToHexSafe(result)
                   });
                   
                   // Clean up session
                   activeSessions.delete(sessionId);
               }
               
               return result;
           };
       });
   }

Multi-Method Hooking
^^^^^^^^^^^^^^^^^^^^

Hook multiple related methods systematically:

.. code-block:: typescript

   export function install_comprehensive_hooks(): void {
       Java.perform(() => {
           const FileClass = Java.use("java.io.File");
           
           // Define methods to hook
           const methodsToHook = [
               { name: 'exists', args: [] },
               { name: 'canRead', args: [] },
               { name: 'canWrite', args: [] },
               { name: 'delete', args: [] }
           ];
           
           methodsToHook.forEach(methodInfo => {
               try {
                   const method = methodInfo.args.length > 0 
                       ? FileClass[methodInfo.name].overload(...methodInfo.args)
                       : FileClass[methodInfo.name];
                   
                   method.implementation = function(...args) {
                       const filePath = this.getAbsolutePath();
                       const result = method.apply(this, args);
                       
                       createFileEvent(`file.${methodInfo.name}`, {
                           file_path: filePath,
                           method: methodInfo.name,
                           result: result,
                           arguments: args
                       });
                       
                       return result;
                   };
               } catch (error) {
                   devlog(`Failed to hook ${methodInfo.name}: ${error}`);
               }
           });
       });
   }

Performance Considerations
--------------------------

Efficient Hook Design
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: typescript

   export function install_optimized_hooks(): void {
       Java.perform(() => {
           const TargetClass = Java.use("com.example.TargetClass");
           
           // Pre-compute expensive operations
           const stringClass = Java.use("java.lang.String");
           const threadClass = Java.use("java.lang.Thread");
           const currentThread = threadClass.currentThread();
           
           TargetClass.frequentMethod.implementation = function(param) {
               // Minimal processing in hot path
               const startTime = Date.now();
               const result = this.frequentMethod(param);
               
               // Only create event if necessary
               if (shouldLogEvent(param)) {
                   createOptimizedEvent("frequent.method", {
                       parameter: param,
                       execution_time: Date.now() - startTime
                   });
               }
               
               return result;
           };
       });
   }

   function shouldLogEvent(param: any): boolean {
       // Custom logic to reduce event volume
       return param && param.toString().length > 10;
   }

Memory Management
^^^^^^^^^^^^^^^^^

.. code-block:: typescript

   // Limit state storage size
   const MAX_SESSION_COUNT = 1000;
   const activeSessions = new Map<number, SessionInfo>();

   function cleanupOldSessions(): void {
       if (activeSessions.size > MAX_SESSION_COUNT) {
           // Remove oldest entries
           const entries = Array.from(activeSessions.entries());
           const toRemove = entries.slice(0, entries.length - MAX_SESSION_COUNT);
           toRemove.forEach(([key]) => activeSessions.delete(key));
       }
   }

Best Practices
--------------

**Hook Design:**
   1. Always wrap hooks in try-catch blocks
   2. Use descriptive event type names (e.g., ``crypto.key.creation``)
   3. Include relevant context in event data
   4. Call original methods to maintain app functionality

**Error Handling:**
   1. Gracefully handle missing classes/methods
   2. Log errors using ``devlog()`` for debugging
   3. Don't break app execution due to hook failures
   4. Validate data before processing

**Performance:**
   1. Minimize processing in frequently called methods
   2. Use conditional event creation for high-volume hooks
   3. Clean up state periodically to prevent memory leaks
   4. Pre-compute expensive operations when possible

**Integration:**
   1. Follow naming conventions for consistency
   2. Document hook behavior and event formats
   3. Add CLI support for user control
   4. Create corresponding Python parsers

Testing Hooks
--------------

Local Testing
^^^^^^^^^^^^^

.. code-block:: bash

   # Compile hooks
   npm run build

   # Test with target app
   ammm --enable-my-custom com.test.app

   # Use verbose mode for debugging
   ammm -v --enable-my-custom com.test.app

Development Workflow
^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Development cycle
   1. Edit TypeScript hook file
   2. npm run build                    # Compile to JavaScript
   3. ammm --enable-my-custom app      # Test with target
   4. Check JSON output for events
   5. Iterate and refine

Example: Complete Custom Hook
-----------------------------

Here's a complete example of a custom hook implementation:

**TypeScript Hook** (``agent/custom/android_id.ts``):

.. code-block:: typescript

   import { log, devlog, am_send } from "../utils/logging.js"
   import { Java } from "../utils/javalib.js"

   const PROFILE_HOOKING_TYPE: string = "ANDROID_ID_ACCESS"

   function createAndroidIdEvent(eventType: string, data: any): void {
       const event = {
           event_type: eventType,
           timestamp: Date.now(),
           ...data
       };
       am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
   }

   export function install_android_id_hooks(): void {
       devlog("Installing Android ID access hooks");
       
       Java.perform(() => {
           try {
               const Settings = Java.use("android.provider.Settings$Secure");
               
               Settings.getString.overload("android.content.ContentResolver", "java.lang.String").implementation = function(resolver, name) {
                   const result = this.getString(resolver, name);
                   
                   if (name === "android_id") {
                       createAndroidIdEvent("android_id.access", {
                           setting_name: name,
                           android_id: result,
                           access_method: "Settings.Secure.getString"
                       });
                   }
                   
                   return result;
               };
               
               log("Android ID hooks installed successfully");
               
           } catch (error) {
               devlog("Error installing Android ID hooks: " + error);
           }
       });
   }

**Python Parser** (``src/dexray_intercept/parsers/android_id.py``):

.. code-block:: python

   from .base import BaseParser
   from ..models.events import Event

   class AndroidIdEvent(Event):
       def __init__(self, event_type: str, timestamp: str):
           super().__init__(event_type, timestamp)
           self.setting_name = None
           self.android_id = None
           self.access_method = None
       
       def get_event_data(self):
           return {
               "event_type": self.event_type,
               "setting_name": self.setting_name,
               "android_id": self.android_id,
               "access_method": self.access_method
           }

   class AndroidIdParser(BaseParser):
       def parse_json_data(self, data: dict, timestamp: str):
           event = AndroidIdEvent(data.get('event_type'), timestamp)
           event.setting_name = data.get('setting_name')
           event.android_id = data.get('android_id')
           event.access_method = data.get('access_method')
           return event

**Integration Steps:**

1. **Add to Hook Loader** (``agent/hooking_profile_loader.ts``):

.. code-block:: typescript

   import { install_android_id_hooks } from "./custom/android_id.js"
   
   export let hook_config: HookConfig = {
       // ... existing hooks ...
       'android_id_hooks': false,
   };
   
   function load_profile_hooks() {
       // ... existing installations ...
       install_hook_conditionally('android_id_hooks', install_android_id_hooks);
   }

2. **Register Parser** (``src/dexray_intercept/parsers/factory.py``):

.. code-block:: python

   from .android_id import AndroidIdParser
   
   def _register_default_parsers(self):
       # ... existing parsers ...
       self._parsers["ANDROID_ID_ACCESS"] = AndroidIdParser()

3. **Add CLI Support** (``src/dexray_intercept/ammm.py``):

.. code-block:: python

   individual_hooks = {
       # ... existing hooks ...
       'enable_android_id': 'android_id_hooks'
   }
   
   hooks.add_argument("--enable-android-id", action="store_true", 
                      help="Enable Android ID access monitoring")

4. **Build and Test**:

.. code-block:: bash

   npm run build
   ammm --enable-android-id com.test.app

This creates a complete hook system that monitors Android ID access, parses the events in Python, and integrates with the CLI system.

Next Steps
----------

- Review existing hooks in ``agent/`` directories for more examples
- Study the Python API for event processing: :doc:`python-api`  
- Learn about the development workflow: :doc:`../development/index`
- Explore advanced hook patterns in the source code
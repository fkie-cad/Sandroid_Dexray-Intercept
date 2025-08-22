Creating Custom Hooks
====================

This guide provides step-by-step instructions for creating custom hooks to monitor specific Android behaviors not covered by the built-in hook categories.

.. important::
   You only need to write a new **custom hook** when you’re adding a new feature to **dexray-intercept** itself.  
   For one-off tweaks, pass your script with ``--custom-script <path/to/script.js>`` and it will be loaded *in addition to* dexray-intercept’s built-in hooks.


Overview
--------

Creating a custom hook involves several coordinated steps:

1. **Design the hook** - Determine what to monitor and event structure
2. **Implement TypeScript hooks** - Write Frida instrumentation code
3. **Create Python parsers** - Process events in Python
4. **Integrate with CLI** - Add command-line support
5. **Test and validate** - Ensure functionality works correctly

This guide walks through creating a complete hook category from scratch.

Example: Android Clipboard Monitoring
-------------------------------------

We'll create a comprehensive clipboard monitoring hook as a practical example.

Step 1: Design the Hook
^^^^^^^^^^^^^^^^^^^^^^^

**Target Behavior:** Monitor clipboard access (read/write operations)

**Target APIs:**
   - ``android.content.ClipboardManager.getPrimaryClip()``
   - ``android.content.ClipboardManager.setPrimaryClip()``
   - ``android.content.ClipData`` operations

**Event Types to Generate:**
   - ``clipboard.read`` - When app reads clipboard content
   - ``clipboard.write`` - When app writes to clipboard
   - ``clipboard.clear`` - When app clears clipboard

**Event Data Structure:**

.. code-block:: json

   {
     "event_type": "clipboard.read",
     "timestamp": "2024-08-20T10:30:00.000Z",
     "clip_label": "Copied text",
     "clip_text": "Hello World",
     "clip_type": "text/plain",
     "item_count": 1,
     "source_app": "com.example.app"
   }

Step 2: Implement TypeScript Hook
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Create the hook file at ``agent/clipboard/clipboard_monitor.ts``:

.. code-block:: typescript

   import { log, devlog, am_send } from "../utils/logging.js"
   import { Where } from "../utils/misc.js"
   import { Java } from "../utils/javalib.js"

   // Profile type identifier - must be unique
   const PROFILE_HOOKING_TYPE: string = "CLIPBOARD_MONITOR"

   /**
    * Create clipboard monitoring event
    * @param eventType Specific clipboard event type
    * @param data Event-specific data
    */
   function createClipboardEvent(eventType: string, data: any): void {
       const event = {
           event_type: eventType,
           timestamp: Date.now(),
           ...data
       };
       am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
   }

   /**
    * Extract text content from ClipData safely
    * @param clipData Android ClipData object
    * @returns Text content or null
    */
   function extractClipText(clipData: any): string | null {
       try {
           if (!clipData) return null;
           
           const itemCount = clipData.getItemCount();
           if (itemCount === 0) return null;
           
           const firstItem = clipData.getItemAt(0);
           if (!firstItem) return null;
           
           const text = firstItem.getText();
           return text ? text.toString() : null;
       } catch (error) {
           devlog("Error extracting clip text: " + error);
           return null;
       }
   }

   /**
    * Install clipboard monitoring hooks
    */
   export function install_clipboard_monitor_hooks(): void {
       devlog("Installing clipboard monitoring hooks");
       
       Java.perform(() => {
           try {
               // Hook ClipboardManager
               const ClipboardManager = Java.use("android.content.ClipboardManager");
               
               // Monitor clipboard reads
               ClipboardManager.getPrimaryClip.implementation = function() {
                   const clipData = this.getPrimaryClip();
                   
                   if (clipData) {
                       const clipText = extractClipText(clipData);
                       const description = clipData.getDescription();
                       
                       createClipboardEvent("clipboard.read", {
                           clip_label: description ? description.getLabel().toString() : "",
                           clip_text: clipText || "",
                           clip_type: description ? description.getMimeType(0).toString() : "unknown",
                           item_count: clipData.getItemCount(),
                           operation: "read"
                       });
                   }
                   
                   return clipData;
               };
               
               // Monitor clipboard writes
               ClipboardManager.setPrimaryClip.implementation = function(clip) {
                   const clipText = extractClipText(clip);
                   const description = clip.getDescription();
                   
                   createClipboardEvent("clipboard.write", {
                       clip_label: description ? description.getLabel().toString() : "",
                       clip_text: clipText || "",
                       clip_type: description ? description.getMimeType(0).toString() : "unknown",
                       item_count: clip.getItemCount(),
                       operation: "write"
                   });
                   
                   return this.setPrimaryClip(clip);
               };
               
               // Monitor clipboard clearing (if available)
               try {
                   ClipboardManager.clearPrimaryClip.implementation = function() {
                       createClipboardEvent("clipboard.clear", {
                           operation: "clear"
                       });
                       
                       return this.clearPrimaryClip();
                   };
               } catch (error) {
                   devlog("clearPrimaryClip not available on this Android version");
               }
               
               log("Clipboard monitoring hooks installed successfully");
               
           } catch (error) {
               devlog("Error installing clipboard hooks: " + error);
           }
       });
   }

   /**
    * Install comprehensive clipboard hooks (main export function)
    */
   export function install_clipboard_hooks(): void {
       devlog("Installing comprehensive clipboard hooks");
       install_clipboard_monitor_hooks();
   }

Step 3: Create Python Parser
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Create parser at ``src/dexray_intercept/parsers/clipboard.py``:

.. code-block:: python

   #!/usr/bin/env python3
   # -*- coding: utf-8 -*-

   from typing import Optional
   from .base import BaseParser
   from ..models.events import Event


   class ClipboardEvent(Event):
       """Event representing clipboard operations"""
       
       def __init__(self, event_type: str, timestamp: str):
           super().__init__(event_type, timestamp)
           self.clip_label = None
           self.clip_text = None
           self.clip_type = None
           self.item_count = None
           self.operation = None
           
       def get_event_data(self):
           data = {
               "event_type": self.event_type,
               "operation": self.operation,
               "timestamp": self.timestamp
           }
           
           # Add optional fields if present
           if self.clip_label:
               data["clip_label"] = self.clip_label
           if self.clip_text:
               data["clip_text"] = self.clip_text
           if self.clip_type:
               data["clip_type"] = self.clip_type
           if self.item_count is not None:
               data["item_count"] = self.item_count
               
           return data


   class ClipboardParser(BaseParser):
       """Parser for clipboard monitoring events"""
       
       def parse_json_data(self, data: dict, timestamp: str) -> Optional[ClipboardEvent]:
           """Parse JSON data into ClipboardEvent"""
           event_type = data.get('event_type', 'clipboard.unknown')
           
           event = ClipboardEvent(event_type, timestamp)
           
           # Map fields from hook data
           event.clip_label = data.get('clip_label', '')
           event.clip_text = data.get('clip_text', '')
           event.clip_type = data.get('clip_type', 'unknown')
           event.item_count = data.get('item_count', 0)
           event.operation = data.get('operation', 'unknown')
           
           # Add metadata for analysis
           self._add_clipboard_metadata(event, data)
           
           return event
       
       def _add_clipboard_metadata(self, event: ClipboardEvent, data: dict):
           """Add clipboard-specific metadata"""
           
           # Categorize clipboard operations
           operation_descriptions = {
               'clipboard.read': 'Application read clipboard content',
               'clipboard.write': 'Application wrote to clipboard',
               'clipboard.clear': 'Application cleared clipboard'
           }
           
           description = operation_descriptions.get(event.event_type, f'Unknown clipboard operation: {event.event_type}')
           event.add_metadata('description', description)
           
           # Add privacy sensitivity metadata
           if event.clip_text and len(event.clip_text) > 0:
               event.add_metadata('contains_data', True)
               event.add_metadata('data_length', len(event.clip_text))
               
               # Detect potentially sensitive content
               sensitive_indicators = ['password', 'token', 'key', 'secret', 'credential']
               if any(indicator in event.clip_text.lower() for indicator in sensitive_indicators):
                   event.add_metadata('potentially_sensitive', True)
                   event.add_metadata('sensitivity_level', 'high')
               else:
                   event.add_metadata('sensitivity_level', 'medium')
           else:
               event.add_metadata('contains_data', False)
               event.add_metadata('sensitivity_level', 'low')
           
           # Add operation category
           event.add_metadata('category', 'privacy')
           event.add_metadata('subcategory', 'clipboard_access')

Step 4: Integrate with Hook Loader
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**4a. Add to Hook Loader** (``agent/hooking_profile_loader.ts``):

.. code-block:: typescript

   // Add import at the top
   import { install_clipboard_hooks } from "./clipboard/clipboard_monitor.js"

   // Add to hook configuration
   export let hook_config: HookConfig = {
       // ... existing hooks ...
       'clipboard_monitor_hooks': false,
   };

   // Add to installation function
   function load_profile_hooks() {
       // ... existing installations ...
       install_hook_conditionally('clipboard_monitor_hooks', install_clipboard_hooks);
   }

**4b. Register Parser** (``src/dexray_intercept/parsers/factory.py``):

.. code-block:: python

   # Add import
   from .clipboard import ClipboardParser

   def _register_default_parsers(self):
       # ... existing parsers ...
       self._parsers["CLIPBOARD_MONITOR"] = ClipboardParser()

Step 5: Add CLI Support
^^^^^^^^^^^^^^^^^^^^^^^

Modify ``src/dexray_intercept/ammm.py``:

.. code-block:: python

   # Add to hook groups (optional - create privacy group)
   if parsed_args.hooks_privacy:
       hook_config.update({
           'clipboard_monitor_hooks': True,
           # other privacy-related hooks
       })

   # Add to individual hooks mapping
   individual_hooks = {
       # ... existing hooks ...
       'enable_clipboard_monitor': 'clipboard_monitor_hooks'
   }

   # Add CLI argument
   hooks.add_argument("--enable-clipboard-monitor", action="store_true", 
                      help="Enable clipboard access monitoring")

   # Optional: Add to hook groups
   hooks.add_argument("--hooks-privacy", required=False, action="store_const", const=True, default=False,
                      help="Enable privacy-related hooks (clipboard, etc.)")

Step 6: Build and Test
^^^^^^^^^^^^^^^^^^^^^^

**6a. Compile TypeScript:**

.. code-block:: bash

   # Compile hooks to JavaScript
   npm run build

   # Verify compilation
   grep -n "install_clipboard_hooks" src/dexray_intercept/profiling.js

**6b. Test with Target App:**

.. code-block:: bash

   # Test with verbose output
   dexray-intercept -v --enable-clipboard-monitor com.android.chrome

   # Test specific clipboard operations in the app:
   # 1. Copy text from webpage
   # 2. Paste in address bar  
   # 3. Clear clipboard (if supported)

**6c. Validate JSON Output:**

.. code-block:: bash

   # Check generated events
   cat profile_com.android.chrome_*.json | jq '.CLIPBOARD_MONITOR'

   # Expected output:
   [
     {
       "event_type": "clipboard.write",
       "operation": "write",
       "clip_text": "Hello World",
       "clip_type": "text/plain",
       "item_count": 1,
       "timestamp": "2024-08-20T10:30:00.000Z"
     }
   ]

Step 7: Create Unit Tests
^^^^^^^^^^^^^^^^^^^^^^^^^

Create ``tests/test_clipboard_parser.py``:

.. code-block:: python

   import unittest
   from datetime import datetime
   from dexray_intercept.parsers.clipboard import ClipboardParser, ClipboardEvent

   class TestClipboardParser(unittest.TestCase):
       def setUp(self):
           self.parser = ClipboardParser()
           self.timestamp = "2024-08-20T10:30:00.000Z"
       
       def test_parse_clipboard_write(self):
           """Test parsing clipboard write event"""
           test_data = {
               'event_type': 'clipboard.write',
               'clip_text': 'Hello World',
               'clip_type': 'text/plain',
               'item_count': 1,
               'operation': 'write'
           }
           
           event = self.parser.parse_json_data(test_data, self.timestamp)
           
           self.assertIsInstance(event, ClipboardEvent)
           self.assertEqual(event.event_type, 'clipboard.write')
           self.assertEqual(event.clip_text, 'Hello World')
           self.assertEqual(event.operation, 'write')
       
       def test_parse_clipboard_read(self):
           """Test parsing clipboard read event"""
           test_data = {
               'event_type': 'clipboard.read',
               'clip_text': 'Sensitive password: 12345',
               'operation': 'read'
           }
           
           event = self.parser.parse_json_data(test_data, self.timestamp)
           
           self.assertEqual(event.event_type, 'clipboard.read')
           self.assertTrue(event.metadata.get('potentially_sensitive', False))
           self.assertEqual(event.metadata.get('sensitivity_level'), 'high')
       
       def test_empty_clipboard(self):
           """Test parsing empty clipboard operation"""
           test_data = {
               'event_type': 'clipboard.clear',
               'operation': 'clear'
           }
           
           event = self.parser.parse_json_data(test_data, self.timestamp)
           
           self.assertEqual(event.operation, 'clear')
           self.assertFalse(event.metadata.get('contains_data', True))

   if __name__ == '__main__':
       unittest.main()

Step 8: Documentation
^^^^^^^^^^^^^^^^^^^^^

**8a. Update User Documentation** (``docs/user-guide/hook-configuration.rst``):

.. code-block:: rst

   Clipboard Monitoring (``--enable-clipboard-monitor``)
   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

   Monitors clipboard access operations including read, write, and clear operations.

   **What it captures:**
      - Clipboard content (text, images, etc.)
      - Content types and labels
      - Operation timing and frequency
      - Potentially sensitive data detection

   **Use cases:**
      - Privacy analysis of data sharing
      - Detecting clipboard-based data exfiltration
      - Monitoring sensitive information exposure

   **Example usage:**

   .. code-block:: bash

      # Monitor clipboard access
      dexray-intercept --enable-clipboard-monitor com.social.app

      # Combine with other privacy hooks
      dexray-intercept --hooks-privacy com.banking.app

   **Example events:**

   .. code-block:: json

      {
        "event_type": "clipboard.write",
        "clip_text": "Hello World",
        "clip_type": "text/plain",
        "operation": "write",
        "metadata": {
          "sensitivity_level": "medium",
          "contains_data": true
        }
      }

**8b. Update CLI Documentation** (``docs/user-guide/cli-usage.rst``):

.. code-block:: rst

   .. option:: --enable-clipboard-monitor

      Enable clipboard access monitoring.

      .. code-block:: bash

         dexray-intercept --enable-clipboard-monitor com.example.app

Advanced Hook Patterns
-----------------------

Conditional Hook Installation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Install hooks only when target conditions are met:

.. code-block:: typescript

   export function install_conditional_hooks(): void {
       Java.perform(() => {
           try {
               // Check if target API is available
               const Build = Java.use("android.os.Build");
               const sdkVersion = Build.VERSION.SDK_INT.value;
               
               if (sdkVersion >= 28) {
                   install_android_p_plus_hooks();
               } else {
                   install_legacy_android_hooks();
               }
               
           } catch (error) {
               devlog("Conditional installation failed: " + error);
           }
       });
   }

State Management Between Hooks
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Maintain state across multiple hook invocations:

.. code-block:: typescript

   // Global state for tracking clipboard sessions
   interface ClipboardSession {
       startTime: number;
       operationCount: number;
       lastOperation: string;
   }

   const clipboardSessions = new Map<string, ClipboardSession>();

   function trackClipboardSession(appPackage: string, operation: string): void {
       const session = clipboardSessions.get(appPackage) || {
           startTime: Date.now(),
           operationCount: 0,
           lastOperation: ''
       };
       
       session.operationCount++;
       session.lastOperation = operation;
       
       clipboardSessions.set(appPackage, session);
       
       // Create session tracking event
       createClipboardEvent("clipboard.session", {
           app_package: appPackage,
           operation_count: session.operationCount,
           session_duration: Date.now() - session.startTime,
           last_operation: operation
       });
   }

Multi-API Hooking Pattern
^^^^^^^^^^^^^^^^^^^^^^^^^

Hook multiple related APIs systematically:

.. code-block:: typescript

   export function install_comprehensive_clipboard_hooks(): void {
       Java.perform(() => {
           // Primary clipboard API
           hookClipboardManager();
           
           // Clipboard service API (if available)
           hookClipboardService();
           
           // Text selection APIs that interact with clipboard
           hookTextSelection();
           
           // Intent-based clipboard operations
           hookClipboardIntents();
       });
   }

   function hookClipboardManager(): void {
       // Implementation for ClipboardManager hooks
   }

   function hookClipboardService(): void {
       try {
           const IClipboard = Java.use("android.content.IClipboard");
           // Hook service-level operations
       } catch (error) {
           devlog("IClipboard not available: " + error);
       }
   }

Error Handling and Robustness
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: typescript

   export function install_robust_hooks(): void {
       Java.perform(() => {
           const hookTargets = [
               { 
                   className: "android.content.ClipboardManager",
                   methods: ["getPrimaryClip", "setPrimaryClip", "clearPrimaryClip"]
               },
               {
                   className: "android.content.IClipboard",
                   methods: ["getPrimaryClip", "setPrimaryClip"]
               }
           ];
           
           hookTargets.forEach(target => {
               try {
                   const targetClass = Java.use(target.className);
                   
                   target.methods.forEach(methodName => {
                       try {
                           installMethodHook(targetClass, methodName);
                       } catch (methodError) {
                           devlog(`Method ${methodName} not available: ${methodError}`);
                       }
                   });
                   
               } catch (classError) {
                   devlog(`Class ${target.className} not available: ${classError}`);
               }
           });
       });
   }

Testing Strategies
------------------

Unit Testing Hooks
^^^^^^^^^^^^^^^^^^

Test individual hook functionality:

.. code-block:: bash

   # Test hook with specific app
   dexray-intercept --enable-my-hook com.test.app

   # Verify events are generated
   python3 -c "
   import json
   with open('profile_com.test.app_*.json') as f:
       data = json.load(f)
       events = data.get('MY_HOOK_CATEGORY', [])
       print(f'Generated {len(events)} events')
       for event in events[:3]:
           print(f'Event: {event[\"event_type\"]}')
   "

Integration Testing
^^^^^^^^^^^^^^^^^^^

Test hook interaction with other components:

.. code-block:: python

   # tests/integration/test_clipboard_integration.py
   import unittest
   from dexray_intercept import AppProfiler
   from dexray_intercept.parsers.factory import parser_factory

   class TestClipboardIntegration(unittest.TestCase):
       def test_parser_registration(self):
           """Test that clipboard parser is registered"""
           parser = parser_factory.get_parser("CLIPBOARD_MONITOR")
           self.assertIsNotNone(parser)
       
       def test_hook_config_integration(self):
           """Test hook configuration integration"""
           from dexray_intercept.ammm import parse_hook_config
           from argparse import Namespace
           
           args = Namespace()
           args.enable_clipboard_monitor = True
           # Set other args to False...
           
           config = parse_hook_config(args)
           self.assertTrue(config.get('clipboard_monitor_hooks', False))

Performance Testing
^^^^^^^^^^^^^^^^^^^

Validate hook performance impact:

.. code-block:: python

   def test_clipboard_hook_performance():
       """Test that clipboard hooks don't significantly impact performance"""
       import time
       
       # Baseline measurement
       start = time.time()
       run_app_without_hooks()
       baseline_time = time.time() - start
       
       # With hooks measurement
       start = time.time()
       run_app_with_clipboard_hooks()
       hook_time = time.time() - start
       
       # Performance impact should be minimal
       performance_impact = (hook_time - baseline_time) / baseline_time
       assert performance_impact < 0.1  # Less than 10% impact

Common Pitfalls and Solutions
-----------------------------

**Issue: Hook Not Installing**

.. code-block:: typescript

   // Problem: Class not found
   const MyClass = Java.use("com.example.MyClass");  // May throw

   // Solution: Defensive loading
   try {
       const MyClass = Java.use("com.example.MyClass");
       // Install hooks
   } catch (error) {
       devlog("MyClass not available: " + error);
       return; // Skip gracefully
   }

**Issue: Method Overloads Not Working**

.. code-block:: typescript

   // Problem: Incorrect overload specification
   MyClass.myMethod.overload("String").implementation = ...  // Wrong

   // Solution: Use correct Java type names
   MyClass.myMethod.overload("java.lang.String").implementation = ...

**Issue: Events Not Appearing in JSON**

.. code-block:: bash

   # Debug steps:
   # 1. Check TypeScript compilation
   npm run build && grep -n "my_hook" src/dexray_intercept/profiling.js
   
   # 2. Check parser registration
   python3 -c "from dexray_intercept.parsers.factory import parser_factory; print(parser_factory.get_parser('MY_CATEGORY'))"
   
   # 3. Check hook configuration
   dexray-intercept -v --enable-my-hook com.test.app  # Look for "[HOOK] Enabled: my_hook"

**Issue: App Crashes with Hooks**

.. code-block:: typescript

   // Problem: Unhandled exceptions in hooks
   MyClass.sensitiveMethod.implementation = function() {
       // This might throw and crash the app
       const result = this.sensitiveMethod();
       processResult(result);  // May fail
       return result;
   };

   // Solution: Comprehensive error handling
   MyClass.sensitiveMethod.implementation = function() {
       try {
           const result = this.sensitiveMethod();
           try {
               processResult(result);
           } catch (processingError) {
               devlog("Result processing failed: " + processingError);
           }
           return result;
       } catch (methodError) {
           devlog("Method execution failed: " + methodError);
           throw methodError; // Re-throw to maintain app behavior
       }
   };

Next Steps
----------

After creating your custom hook:

1. **Test thoroughly** with multiple target applications
2. **Document the hook** in user guides and API reference
3. **Create examples** showing practical usage scenarios
4. **Consider contributing** the hook back to the project
5. **Monitor performance** impact on target applications

For more advanced patterns and integration:

- Study existing hooks in the ``agent/`` directory
- Review the :doc:`../api/typescript-api` for detailed API reference
- Check the :doc:`building` guide for development workflow
- See :doc:`contributing` for submission guidelines
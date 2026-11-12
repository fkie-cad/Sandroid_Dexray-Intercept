Creating Custom Hooks
====================

This guide provides step-by-step instructions for creating custom hooks to monitor specific Android behaviors not covered by the built-in hook categories.

.. important::
   This guide describes adding hooks to Dexray Intercept itself. For a
   standalone Frida script, use ``--custom-script <path/to/script.js>``;
   it is loaded alongside the built-in hooks.


Overview
--------

Creating a custom hook involves several coordinated steps:

1. **Design the hook** - Determine what to monitor and event structure
2. **Implement TypeScript hooks** - Write Frida instrumentation code
3. **Update Python event processing** - Extend an existing model and parser,
   or create new ones
4. **Integrate with CLI** - Add command-line support
5. **Test and validate** - Ensure functionality works correctly

This guide walks through adding a hook to an existing category.

Example: Adding Clipboard Monitoring
------------------------------------

This example walks through adding clipboard monitoring to the ``services``
category. Clipboard support already exists in Dexray Intercept; the steps
below reconstruct its integration as a guide for adding another hook.

Step 1: Design the Hook
^^^^^^^^^^^^^^^^^^^^^^^

First decide whether the behavior fits an existing category or needs a new one.
Clipboard access is an Android system-service operation, so it belongs under
``agent/services/``. An unrelated behavior may justify a separate category.

For this example:

- **Agent file:** ``agent/services/clipboard.ts``
- **Target APIs:** ``ClipboardManager.setPrimaryClip()`` and
  ``ClipboardManager.getPrimaryClip()``
- **Hook configuration key:** ``clipboard_hooks``
- **Profile category:** ``CLIPBOARD``
- **Event types:** ``clipboard.set_primary_clip`` and
  ``clipboard.get_primary_clip``
- **Test application:** ``ServicesE2E``

Decide which fields each event needs and whether the existing Python event model
and parser can represent them. The clipboard events use ``ServiceEvent`` and
``ServiceParser``.

For example, a clipboard write can produce:

.. code-block:: json

   {
     "event_type": "clipboard.set_primary_clip",
     "timestamp": "2026-11-12T12:06:41.725Z",
     "event_description": "Clipboard data written",
     "library": "android.content.ClipboardManager",
     "method": "setPrimaryClip",
     "content_type": "text",
     "content": "services-e2e-clipboard",
     "item_index": 0,
     "total_items": 1,
     "content_length": 22
   }

Step 2: Implement the TypeScript Hook
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Create ``agent/services/clipboard.ts``. The hook uses the ``CLIPBOARD`` profile
type and sends structured events to the Python frontend:

.. code-block:: typescript

   import { devlog, am_send } from "../utils/logging.js"
   import {
       safePerform,
       safeUse,
       safeImplementation,
       PropagateException
   } from "../utils/safe_java.js"
   import { collectJavaStackTrace } from "../utils/stacktrace.js"

   const PROFILE_HOOKING_TYPE: string = "CLIPBOARD"

   function createClipboardEvent(eventType: string, data: any): void {
       const event = {
           event_type: eventType,
           timestamp: Date.now(),
           ...data
       };
       am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
   }

Install the hooks inside ``safePerform()`` and resolve the Android class with
``safeUse()``. The following excerpt shows the read hook:

.. code-block:: typescript

   function hook_clipboard() {
       safePerform("clipboard:hook_clipboard", () => {
           const ClipboardManager = safeUse(
               "android.content.ClipboardManager",
               "clipboard:hook_clipboard"
           );
           if (!ClipboardManager) return;

           // The setPrimaryClip hook is also installed here.

           const getPrimaryClipRef = ClipboardManager.getPrimaryClip;
           if (getPrimaryClipRef) {
               getPrimaryClipRef.implementation = safeImplementation(
                   "clipboard:ClipboardManager.getPrimaryClip",
                   getPrimaryClipRef,
                   function (original) {
                       const java_stack_trace = collectJavaStackTrace();
                       let result;

                       try {
                           result = original.call(this);
                       } catch (error) {
                           throw new PropagateException(error);
                       }

                       try {
                           createClipboardEvent("clipboard.get_primary_clip", {
                               library: "android.content.ClipboardManager",
                               method: "getPrimaryClip",
                               has_clip: result !== null,
                               item_count: result ? result.getItemCount() : 0,
                               ...(java_stack_trace
                                   ? { java_stack_trace }
                                   : {})
                           });
                       } catch (error) {
                           try {
                               devlog(`Clipboard read event failed: ${error}`);
                           } catch {
                               // Preserve the original result.
                           }
                       }

                       return result;
                   }
               );
           }
       });
   }

``PropagateException`` passes an exception from the original call back to the
application without triggering the wrapper's fallback call. Errors while
creating the read event are handled separately so the original result can be
returned.

The write hook in the same file extracts clipboard-item details and emits
``clipboard.set_primary_clip``. See ``agent/services/clipboard.ts`` for the
complete read and write implementations.

Export the installer for the hook loader:

.. code-block:: typescript

   export function install_clipboard_hooks() {
       devlog("\n");
       devlog("install clipboard hooks");

       try {
           hook_clipboard();
       } catch (error) {
           devlog(`[HOOK] Failed to install clipboard hooks: ${error}`);
       }
   }

For more on safe helpers and propagation, see
:ref:`hook-error-handling`.

Step 3: Update Python Event Processing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Clipboard events use the existing ``ServiceEvent`` model and
``ServiceParser``. When adding a hook, check whether its fields fit an existing
model and parser or require new ones.

**3a. Event model**

In ``src/dexray_intercept/models/events.py``, add the event attributes to
``ServiceEvent.__init__()``:

.. code-block:: python

   self.item_count = None
   self.has_clip = None

Include them in the ``fields`` list in ``ServiceEvent.get_event_data()`` so
they are serialized:

.. code-block:: python

   'item_count', 'has_clip',

The clipboard-write event uses additional fields such as ``content_type``,
``content``, ``item_index``, ``total_items``, and ``content_length``.

**3b. Parser**

In ``src/dexray_intercept/parsers/services.py``, add the fields to the
``field_mapping`` in ``ServiceParser.parse_json_data()``:

.. code-block:: python

   'item_count': 'item_count',
   'has_clip': 'has_clip',

Add descriptions for the new event types in
``ServiceParser._add_event_description()``:

.. code-block:: python

   elif event_type.startswith('clipboard.'):
       if event_type == 'clipboard.set_primary_clip':
           event.event_description = 'Clipboard data written'
       elif event_type == 'clipboard.get_primary_clip':
           event.event_description = 'Clipboard data read'

**3c. Console formatting**

In ``src/dexray_intercept/formatters/console.py``, check how the event is
displayed. ``ConsoleFormatter.format_event()`` routes ``ServiceEvent`` objects
to ``_format_service_event()``, where clipboard events have their own branch:

.. code-block:: python

   elif event.event_type.startswith('clipboard.'):
       lines.append(
           f"\n[*] [Clipboard] {event.event_description or event.event_type}:"
       )
       if event.content_type:
           lines.append(f"[*] Content Type: {event.content_type}")
       if event.content:
           content = truncate_string(event.content, 100)
           lines.append(f"[*] Content: {content}")
       if event.item_count is not None:
           lines.append(f"[*] Items: {event.item_count}")

Add or adjust formatting when new event fields should appear in terminal
output. Formatting is separate from JSON serialization.

Step 4: Register the Hook and Parser
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**4a. Agent hook loader**

In ``agent/hooking_profile_loader.ts``, import the installer:

.. code-block:: typescript

   import { install_clipboard_hooks } from "./services/clipboard.js"

Add the default configuration key to ``hook_config``:

.. code-block:: typescript

   'clipboard_hooks': false,

Add the conditional installation to ``load_profile_hooks()``:

.. code-block:: typescript

   install_hook_conditionally('clipboard_hooks', install_clipboard_hooks);

**4b. Python hook manager**

In ``src/dexray_intercept/services/hook_manager.py``, add the key to the
defaults in ``_init_hook_config()``:

.. code-block:: python

   'clipboard_hooks': False,

Also include it in the ``services`` entry of the ``hook_groups`` mapping in
``enable_hook_group()``:

.. code-block:: python

   'services': [
       'bluetooth_hooks', 'camera_hooks', 'clipboard_hooks',
       'location_hooks', 'telephony_hooks'
   ],

**4c. Parser factory**

In ``src/dexray_intercept/parsers/factory.py``, register the emitted profile
type with its parser:

.. code-block:: python

   self._parsers["CLIPBOARD"] = ServiceParser()

For a new parser, import it into the factory and register an instance under
the profile type emitted by the agent.

Step 5: Add CLI Support
^^^^^^^^^^^^^^^^^^^^^^^

Update ``src/dexray_intercept/ammm.py`` so users can select the hook.

**5a. Add it to the services group** in ``parse_hook_config()``:

.. code-block:: python

   if parsed_args.hooks_services:
       hook_config.update({
           'bluetooth_hooks': True,
           'camera_hooks': True,
           'clipboard_hooks': True,
           'location_hooks': True,
           'telephony_hooks': True
       })

Also add ``clipboard_hooks`` to the list enabled by ``--hooks-all``.

**5b. Add individual selection** to the ``individual_hooks`` mapping:

.. code-block:: python

   'enable_clipboard': 'clipboard_hooks',

Define the corresponding CLI argument:

.. code-block:: python

   hooks.add_argument(
       "--enable-clipboard",
       action="store_true",
       help="Enable clipboard hooks"
   )

**5c. Add interactive selection** by including ``clipboard_hooks`` in the
``services`` group's ``hooks`` list in ``interactive_hook_selection()``:

.. code-block:: python

   'hooks': [
       'bluetooth_hooks', 'camera_hooks', 'clipboard_hooks',
       'location_hooks', 'telephony_hooks'
   ]

A hook in a new category also needs its own group option and configuration
mapping. Update the help description for any group whose contents change.

Step 6: Build and Test the Hook
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

After modifying the agent, compile it from the repository root:

.. code-block:: bash
   
   # Compile hooks to JavaScript
   npm run build

   # Verify compilation
   grep -n "install_clipboard_hooks" src/dexray_intercept/profiling.js

Add triggers for the hooked APIs to the corresponding category test app. For
clipboard monitoring, ``ServicesE2E`` uses ``ClipboardTestActivity``:

- ``setPrimaryClip()`` is called during activity creation.
- ``getPrimaryClip()`` is called after the activity receives window focus.

Build and install the test app:

.. code-block:: bash

    cd tests/android_apps/e2e_tests/ServicesE2E
    ./gradlew assembleDebug
    adb install -r app/build/outputs/apk/debug/app-debug.apk

Start logcat in a separate terminal:

.. code-block:: bash

   adb logcat -v threadtime \
     -s 'SERVICES_E2E:*' 'SERVICES_CLIPBOARD:*' 'AndroidRuntime:E'

Run the app without hooks to establish a baseline:

.. code-block:: bash

   adb shell am force-stop com.test.servicese2e
   adb shell am start -n com.test.servicese2e/.MainActivity

Then run it with clipboard monitoring:

.. code-block:: bash

   adb shell am force-stop com.test.servicese2e
   dexray-intercept -s -v --enable-clipboard com.test.servicese2e

Compare the clipboard activity's logcat output with the baseline. After the
activity finishes, press Ctrl+C to write the profile. Replace the filename
below with the one generated by your run:

.. code-block:: bash

   PROFILE="profile_com.test.servicese2e_<timestamp>.json"
   jq '.CLIPBOARD[] | select(
     .event_type == "clipboard.set_primary_clip" or
     .event_type == "clipboard.get_primary_clip"
   )' "$PROFILE"

Check that the expected events and fields are present. For more on category
test apps and their prerequisites, see :doc:`index`.

Step 7: Test Event Processing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Test the parser and serialized event fields as well as the agent hook:

- Use a unit test to check ``ServiceParser`` with representative clipboard
  event data.
- Use an integration test to check parser selection through ``ParserFactory``
  and event serialization.
- Test relevant failure paths and confirm that instrumentation preserves
  application behavior.

The **Testing Strategies** section below contains clipboard parser examples
that can be adapted for these checks.

Step 8: Update Documentation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Update the user guides to describe how to enable the hook, what it captures,
and what its output looks like.

**8a. Hook configuration**

In ``docs/user-guide/hook-configuration.rst``, add the individual option to the
system-service hooks and describe the captured behavior:

.. code-block:: rst

   - ``--enable-clipboard`` - Monitor clipboard reads and writes

   Clipboard events include content type and content for writes, and item
   count and clipboard availability for reads.

**8b. CLI usage**

In ``docs/user-guide/cli-usage.rst``, document the individual option:

.. code-block:: rst

   .. option:: --enable-clipboard

      Enable clipboard access monitoring.

      .. code-block:: bash

         dexray-intercept --enable-clipboard com.example.app

Include the hook in the ``--hooks-services`` description when documenting the
group.

**8c. Output format**

In ``docs/user-guide/output-formats.rst``, add an example based on an observed
``CLIPBOARD`` event:

.. code-block:: json

   {
     "event_type": "clipboard.get_primary_clip",
     "timestamp": "2026-11-12T12:06:41.815Z",
     "event_description": "Clipboard data read",
     "library": "android.content.ClipboardManager",
     "method": "getPrimaryClip",
     "item_count": 1,
     "has_clip": true
   }

Document relevant prerequisites and limitations as well. For example,
``ServicesE2E`` performs clipboard reads from a focused activity.

Advanced Hook Patterns
-----------------------

Conditional Hook Installation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Some hooks target APIs or overloads available only on certain Android
versions. Check the runtime version and resolve the overload safely before
installing the hook.

For example, ``agent/dex/dex_unpacking.ts`` checks for an API 29+ constructor:

.. code-block:: typescript

   const BuildVersion = safeUse(
       "android.os.Build$VERSION",
       "dex:dex_api_unpacking"
   );

   if (BuildVersion && BuildVersion.SDK_INT.value > 28) {
       const delegateInit4 = safeOverload(
           DelegateLastClassLoader.$init,
           "dex:DelegateLastClassLoader.$init",
           "java.lang.String",
           "java.lang.String",
           "java.lang.ClassLoader",
           "boolean"
       );

       if (delegateInit4) {
           // Install the implementation using safeImplementation().
       }
   }

This excerpt runs inside a ``safePerform()`` callback, after resolving
``DelegateLastClassLoader``. See the DEX hook file for the complete
implementation.

State Management Between Hooks
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Maintain state across multiple hook invocations:

The following example illustrates the pattern; choose suitable state keys and
cleanup rules for the hook being implemented.

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

The helper functions below illustrate the structure and must be implemented for
the APIs being monitored.

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

.. _hook-error-handling:

Error Handling and Exception Propagation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Hooks run inside the target process. Error handling aims to isolate hook
failures, allow unrelated hooks to install, and preserve application behavior.

Java Hook Installation
""""""""""""""""""""""

Use the helpers in ``agent/utils/safe_java.ts``:

- ``safePerform()`` enters the Java runtime for hook installation. During
  synchronous startup, it uses ``safePerformNow()``.
- ``safeUse()`` resolves a class using the default class loader.
  ``safeUseFromClassLoader()`` resolves it through a specified class loader.
- ``safeOverload()`` resolves a method overload by its Java signatures.

Class and overload resolution return ``null`` on failure. Check each result
before installing the hook. Keep unrelated installation units separate: a
failure within one callback can prevent its remaining statements from running.

Normally, ``Java.perform()`` may defer its callback until the Java runtime is
ready. If the callback runs after ``safePerform()`` has returned, an exception
inside it cannot be caught by the outer ``safePerform()`` call.

To contain unexpected installation errors, place a ``try/catch`` inside the
callback. For example:

.. code-block:: typescript

    import { safePerform, safeUse, safeOverload } from "../utils/safe_java.js";
    import { devlog } from "../utils/logging.js";

    safePerform("example:install", () => {
        try {
            const File = safeUse("java.io.File", "example:install");
            if (!File) return;

            const deleteOverload = safeOverload(
                File.delete,
                "example:File.delete"
            );
            if (!deleteOverload) return;

            // Install the implementation using safeImplementation().
        } catch (error) {
            devlog(`[HOOK] Failed to install File.delete hook: ${error}`);
        }
    });

This boundary protects the installation callback; ``safeImplementation()``
separately handles errors when the installed hook executes. For independent
hooks, use separate installation callbacks or separate error boundaries so one
failure does not skip the others.

For callbacks scheduled with ``setTimeout()`` or ``setImmediate()``, use
``safeDeferred()``. It wraps the deferred callback with its own error boundary,
as demonstrated by the delayed native read-hook installation in
``agent/network/sockets.ts``.

Java Hook Execution
"""""""""""""""""""

``safeImplementation()`` wraps a hook body. If hook logic fails, it logs the
failure and calls the original method with the original arguments.

If the original method itself throws, wrap that exception in
``PropagateException``. The wrapper then rethrows the original cause rather
than logging it as a hook failure or calling the original again.

The following excerpt is adapted from the ``FileInputStream.read`` hooks in
``agent/file/file_system_hooks.ts``:

.. code-block:: typescript

   let result;

   try {
       result = original.apply(this, args);
   } catch (error) {
       throw new PropagateException(error);
   }

   try {
       emitReadEvent(
           this,
           variant,
           method,
           createEventData(args, result)
       );
   } catch (error) {
       devlog(`FileInputStream read metadata failed: ${error}`);
   }

   return result;

.. important::
   ``safeImplementation()`` does not track whether the original method was
   already called. If post-call hook logic throws out of the wrapper, its
   fallback calls the original again. Catch post-call processing errors
   locally and return the original result.

Native Hook Installation
""""""""""""""""""""""""

Use the helpers in ``agent/utils/safe_native.ts`` to discover native functions:

- ``safeResolveExport()`` resolves an export by module and name, or searches
  globally when the module name is ``null``. It returns ``null`` on failure.
- ``safeEnumerateModuleExports()`` and ``safeEnumerateModuleSymbols()`` list a
  module's exports and symbols. The SQLite hooks use both to discover
  ``sqlite3_*`` functions.
- ``safeEnumerateMatches()`` searches using a Frida resolver query. The DEX
  hooks use it to find mangled ART symbols; ``stripModulePrefix()`` extracts
  the symbol name from a match.
- ``safeNativeFunction()`` creates a callable native function. Check for
  ``null`` before using it, and provide the correct function signature.

Native Hook Execution
"""""""""""""""""""""

Use ``safeAttach()`` when you already have a function address, or
``safeAttachExport()`` to resolve and attach to an export in one step. These
helpers isolate errors in ``onEnter`` and ``onLeave`` callbacks; the original
native function continues to run.

The following excerpt is adapted from the ``fork()`` hook in
``agent/process/process.ts``:

.. code-block:: typescript

   safeAttachExport(null, "fork", "process:fork", {
       onEnter() {
           createProcessEvent("process.fork.attempt", {
               native_function: "fork",
               caller_pid: Process.id
           });
       },
       onLeave(retval) {
           const pid = retval.toInt32();
           createProcessEvent("process.fork.result", {
               native_function: "fork",
               caller_pid: Process.id,
               child_pid: pid,
               success: pid >= 0
           });
       }
   });

If ``onLeave`` depends on state set in ``onEnter``, account for that state
being absent when ``onEnter`` fails.

For native replacements:

- ``safeReplace()`` provides a callable original function to the replacement.
  If replacement logic throws, the wrapper attempts to call the original.
  Catch errors after a successful original call locally to avoid calling it
  again. The SQLite hooks use typed replacements for values that require
  ABI-specific handling.
- ``safeReplaceNoCallThrough()`` intentionally replaces behavior without
  calling the original. It returns a configured fallback value if replacement
  logic throws. The file hooks use it for ``--deactivate-unlink``.

The return and argument types supplied to a native replacement must match the
target function's ABI.

Diagnostics
"""""""""""

The helpers use ``hookError()`` and ``hookPropagate()`` from
``agent/utils/error_utils.ts`` to send contextual diagnostic messages through
``devlog()``. These messages are normally visible with ``-v``:

- ``[HOOK ERROR]`` - A helper encountered a hook installation or execution
  error.
- ``[HOOK PROPAGATE]`` - An exception from the original Java call was
  deliberately propagated. This does not by itself indicate a hook failure.

These helper diagnostics are console messages, not structured profile events.

Testing Strategies
------------------

For category E2E app setup, baseline runs, instrumented runs, and profile
inspection, see :doc:`index`.

Unit Testing
^^^^^^^^^^^^

Test a parser independently with representative event data. For example, the
clipboard hooks use ``ServiceParser``:

.. code-block:: python

   import unittest

   from dexray_intercept.models.events import ServiceEvent
   from dexray_intercept.parsers.services import ServiceParser


   class TestClipboardParser(unittest.TestCase):
       def test_parse_clipboard_write(self):
           parser = ServiceParser()
           data = {
               "event_type": "clipboard.set_primary_clip",
               "library": "android.content.ClipboardManager",
               "method": "setPrimaryClip",
               "content_type": "text",
               "content": "services-e2e-clipboard",
               "item_index": 0,
               "total_items": 1,
               "content_length": 22,
           }

           event = parser.parse_json_data(
               data, "2026-11-12T12:06:41.725Z"
           )

           self.assertIsInstance(event, ServiceEvent)
           self.assertEqual(event.event_type, "clipboard.set_primary_clip")
           self.assertEqual(event.content, "services-e2e-clipboard")
           self.assertEqual(event.content_length, 22)
           self.assertEqual(event.event_description, "Clipboard data written")


   if __name__ == "__main__":
       unittest.main()

Integration Testing
^^^^^^^^^^^^^^^^^^^

Test parser selection, JSON parsing, and event serialization together:

.. code-block:: python

   import json
   import unittest

   from dexray_intercept.parsers.factory import parser_factory


   class TestClipboardIntegration(unittest.TestCase):
       def test_factory_parsing_and_serialization(self):
           parser = parser_factory.get_parser("CLIPBOARD")
           self.assertIsNotNone(parser)

           raw_data = json.dumps({
               "event_type": "clipboard.get_primary_clip",
               "library": "android.content.ClipboardManager",
               "method": "getPrimaryClip",
               "item_count": 1,
               "has_clip": True,
           })

           event = parser.parse(raw_data, "2026-11-12T12:06:41.815Z")
           serialized = event.to_dict()

           self.assertEqual(
               serialized["event_type"], "clipboard.get_primary_clip"
           )
           self.assertEqual(serialized["item_count"], 1)
           self.assertTrue(serialized["has_clip"])
           self.assertEqual(
               serialized["event_description"], "Clipboard data read"
           )


   if __name__ == "__main__":
       unittest.main()

This checks the Python processing path. Use the category E2E applications to
validate the Frida hook in an Android process.

Performance Testing
^^^^^^^^^^^^^^^^^^^

Validate hook performance by comparing repeated runs of the same workload
with and without hooks. For example:

.. code-block:: python

   from statistics import median


   def test_clipboard_hook_performance():
       """Compare clipboard-hook performance against the baseline."""

       # Implement these helpers for the app under test. Each returns the
       # duration of the same workload in seconds.
       baseline_runs = [run_app_without_hooks() for _ in range(3)]
       hooked_runs = [run_app_with_clipboard_hooks() for _ in range(3)]

       baseline_time = median(baseline_runs)
       hook_time = median(hooked_runs)

       assert baseline_time > 0
       performance_impact = (hook_time - baseline_time) / baseline_time

       # Example threshold; choose one appropriate to the workload.
       assert performance_impact < 0.10

The ``run_app_*()`` calls are placeholders for functions that measure the same
workload and check application behavior in both runs.

See :doc:`index` for a tested ``FileE2E`` measurement script. Use the same
device, inputs, and test configuration for baseline and instrumented runs.

Common Pitfalls and Solutions
-----------------------------

**Issue: Hook Not Installing**

A target class may be absent on a particular Android version or application.
A direct ``Java.use()`` call can throw and stop the remaining installation
logic in that callback:

.. code-block:: typescript

   // Problem: class resolution may throw.
   const MyClass = Java.use("com.example.MyClass");
   // Install hooks on MyClass.

Use ``safeUse()`` instead and check its result before installing the hooks:

.. code-block:: typescript

   // Solution: log the failure and skip this class if unavailable.
   const MyClass = safeUse("com.example.MyClass", "example:install");
   if (!MyClass) return;

   // Install hooks on MyClass.

Both snippets are intended to run inside a Java installation callback.
``safeUse()`` returns ``null`` on failure and emits a diagnostic visible with
``-v``.

**Issue: Method Overloads Not Working**

Java method signatures must use the correct type names. For example,
``String`` is not the Java signature for ``java.lang.String``.

.. code-block:: typescript

   // Problem: incorrect Java type name.
   const overload = MyClass.myMethod.overload("String");

   // Solution: resolve the overload using its full Java type name.
   const method = safeOverload(
       MyClass.myMethod,
       "example:MyClass.myMethod",
       "java.lang.String"
   );

   if (method) {
       // Install the hook using safeImplementation().
   }

``safeOverload()`` logs a resolution failure and returns ``null`` when the
method or requested overload is unavailable.

**Issue: Events Not Appearing in JSON**

Check the agent build, hook selection, test trigger, and parser registration:

.. code-block:: bash

   # Compile the agent and check for the hook installer
   npm run build
   grep -n "install_clipboard_hooks" src/dexray_intercept/profiling.js

   # Check the profile category's parser registration
   python3 -c \
     "from dexray_intercept.parsers.factory import parser_factory; print(parser_factory.get_parser('CLIPBOARD'))"

   # Run the test app with clipboard hooks and diagnostics enabled
   dexray-intercept -s -v --enable-clipboard com.test.servicese2e

After the test finishes, stop profiling and inspect the generated profile:

.. code-block:: bash

   PROFILE="profile_com.test.servicese2e_<timestamp>.json"
   jq '.CLIPBOARD // []' "$PROFILE"

Also check logcat to confirm that the test app invoked the target APIs. A hook
listed as enabled in diagnostic output does not by itself prove that every
target method was available or invoked.

**Issue: App Crashes with Hooks**

.. code-block:: typescript

   import {
       safeOverload,
       safeImplementation,
       PropagateException
   } from "../utils/safe_java.js";
   import { devlog } from "../utils/logging.js";

   // Problem: post-call processing can throw and affect the application.
   MyClass.sensitiveMethod.implementation = function (value: string) {
       const result = this.sensitiveMethod(value);
       processResult(result);
       return result;
   };

   // Solution: select the overload and isolate original and hook errors.
   const sensitiveMethod = safeOverload(
       MyClass.sensitiveMethod,
       "example:sensitiveMethod",
       "java.lang.String"
   );

   if (sensitiveMethod) {
       sensitiveMethod.implementation = safeImplementation(
           "example:sensitiveMethod",
           sensitiveMethod,
           function (original, value: string) {
               let result;

               try {
                   result = original.call(this, value);
               } catch (error) {
                   throw new PropagateException(error);
               }

               try {
                   processResult(result);
               } catch (error) {
                   try {
                       devlog(`Result processing failed: ${error}`);
                   } catch {
                       // Preserve the original result if logging fails.
                   }
               }

               return result;
           }
       );
   }

``MyClass`` and ``processResult()`` represent the target class and
hook-specific processing. For the full error-handling strategy, see
:ref:`hook-error-handling`.

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
- Review the development workflow: :doc:`index`
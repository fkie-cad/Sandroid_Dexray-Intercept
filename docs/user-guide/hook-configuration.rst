Hook Configuration Guide
========================

This guide explains the different hook categories, what they monitor, and how to configure them for optimal analysis results.

Understanding Hooks
-------------------

**Hooks** are Frida-based instrumentation points that intercept specific Android API calls and operations. Each hook category focuses on a particular aspect of application behavior.

**Key Principles:**

- **All hooks are disabled by default** for performance reasons
- **Hooks can be enabled individually or by category**  
- **Multiple hook categories can be combined**
- **Custom hooks can supplement built-in functionality**

Hook Categories
---------------

Cryptographic Hooks (``--hooks-crypto``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Monitors encryption, decryption, and key management operations.

**Individual Hooks:**
   - ``--enable-aes`` - AES encryption/decryption operations
   - ``--enable-keystore`` - Android Keystore operations  
   - ``--enable-encodings`` - Base64, URL encoding/decoding

**What it captures:**
   - Cryptographic keys and initialization vectors
   - Plaintext and ciphertext data
   - Encryption algorithms and modes
   - Key generation and storage operations

**Use cases:**
   - Analyzing malware encryption schemes
   - Auditing data protection mechanisms  
   - Investigating key management practices

**Example events:**

.. code-block:: json

   {
     "event_type": "crypto.key.creation",
     "algorithm": "AES",
     "key_length": 32,
     "key_hex": "a1b2c3d4e5f6...",
     "timestamp": "2024-08-20T10:30:00Z"
   }

Network Hooks (``--hooks-network``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Monitors all network communications including HTTP/HTTPS, WebSockets, and raw sockets.

**Individual Hooks:**
   - ``--enable-web`` - HTTP/HTTPS, Retrofit, Volley, OkHttp, WebSockets
   - ``--enable-sockets`` - Raw TCP/UDP socket operations

**What it captures:**
   - HTTP requests and responses with headers
   - WebSocket messages and connections
   - Socket connections and data transfers
   - SSL/TLS certificate information

**Use cases:**
   - Analyzing C2 communications in malware
   - Auditing API usage and data transmission
   - Investigating network-based exfiltration

**Example events:**

.. code-block:: json

   {
     "event_type": "http.request",
     "url": "https://api.example.com/data",
     "method": "POST", 
     "headers": {"Content-Type": "application/json"},
     "body_preview": "{\"user_id\": 12345}",
     "timestamp": "2024-08-20T10:30:15Z"
   }

File Hooks (``--hooks-file``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Monitors file construction, stream creation, read operations, write operations,
and file deletion.

**Individual Hook:**
   - ``--enable-filesystem`` - File construction, stream, read, write, and
     deletion monitoring

   - ``--deactivate-unlink`` - Prevent native ``unlink()`` deletion while
     reporting success to the target application

.. warning::
   ``--deactivate-unlink`` changes target behavior. Use it only when preserving
   deleted files or dropped artifacts is required.

**What it captures:**
   - File paths and constructor variants
   - Input and output stream creation
   - Read and write operations, including offsets and lengths
   - File deletion results
   - Native ``unlink()`` operations

**Use cases:**
   - Tracking malware file modifications
   - Investigating dropped files and payloads
   - Analyzing application file access patterns

**Example events:**

.. code-block:: json

   {
     "event_type": "file.write",
     "file_path": "/data/data/com.example.app/files/config.json",
     "method": "java.io.FileOutputStream.write(byte[], int, int)",
     "offset": 0,
     "length": 256,
     "bytes_written": 256,
     "timestamp": "2024-08-20T10:30:30Z"
   }

Database Hooks (``--hooks-database``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Monitors Java and native database activity.

**Individual Hook:**
   - ``--enable-sql`` - Database operation monitoring

**What it captures:**
   - SQLite queries and data-modification operations
   - Room, SQLCipher, and WCDB activity when the corresponding libraries are
     present
   - Native SQLite opens, prepared statements, execution, and bind values

**Use cases:**
   - Tracking locally stored application data
   - Investigating encrypted or protected databases
   - Inspecting SQL queries and database modifications

Inter-Process Communication (``--hooks-ipc``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Monitors communication between Android components and processes.

**Individual Hooks:**
   - ``--enable-intents`` - Intent passing between components
   - ``--enable-broadcasts`` - Broadcast receiver operations
   - ``--enable-binder`` - Low-level binder communication
   - ``--enable-shared-prefs`` - SharedPreferences access

**What it captures:**
   - Intent actions, extras, and target components
   - Broadcast messages and receivers
   - Binder transaction data
   - Preference key-value operations

**Use cases:**
   - Analyzing inter-app communication
   - Tracking privilege escalation attempts
   - Investigating data sharing mechanisms

**Example events:**

.. code-block:: json

   {
     "event_type": "intent.send",
     "action": "android.intent.action.SEND",
     "target_component": "com.example.receiver/.DataReceiver",
     "extras": {"android.intent.extra.TEXT": "sensitive data"},
     "timestamp": "2024-08-20T10:30:45Z"
   }

Process Hooks (``--hooks-process``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Monitors process APIs, runtime activity, reflection, and Java or native library
loading.

**Individual Hooks:**
   - ``--enable-process`` - Android process APIs and native process activity
   - ``--enable-runtime`` - Runtime execution, shutdown behavior, and reflection
   - ``--enable-library-loading`` - Java ``System`` and ``Runtime``
     library-loading APIs
   - ``--enable-native-libs`` - Native linker-level library loading

**What it captures:**
   - Process signals, termination, identity changes, and process-group activity
   - ``/proc`` scanning through Android process APIs
   - Native ``fork()``, ``execve()``, and ``system()`` activity
   - Runtime command execution, shutdown hooks, and exit behavior
   - Reflection and class-loading activity
   - Java and native library-loading activity

**Use cases:**
   - Detecting packed or encrypted malware
   - Analyzing code injection techniques
   - Tracking dynamic loading behavior

**Example events:**

.. code-block:: json

   {
     "event_type": "runtime.exec",
     "timestamp": "2026-11-11T11:25:18.874Z",
     "command": "/system/bin/id",
     "event_description": "Runtime command execution",
     "overload_index": 0,
     "metadata": {
       "library": "java.lang.Runtime",
       "method": "exec"
     }
   }

DEX Hooks (``--hooks-dex``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Monitors DEX loading, unpacking, and in-memory DEX processing.

**Individual Hook:**
   - ``--enable-dex-unpacking`` - ART DEX detection and Java class-loader
     monitoring

**What it captures:**
   - File-backed DEX class-loader creation
   - In-memory DEX loader metadata
   - Native DEX loading detected through ART runtime hooks
   - DEX payload metadata and captured artifacts when available

**Use cases:**
   - Detecting packed, encrypted, or dynamically loaded code
   - Recovering DEX artifacts for further analysis
   - Tracking class-loader-based code loading

System Service Hooks (``--hooks-services``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Monitors access to Android system services and hardware.

**Individual Hooks:**
   - ``--enable-location`` - GPS and location services
   - ``--enable-camera`` - Camera access and usage
   - ``--enable-telephony`` - Phone and SMS operations
   - ``--enable-bluetooth`` - Bluetooth operations
   - ``--enable-clipboard`` - Clipboard access

**What it captures:**
   - Location coordinates and providers
   - Camera capture events and parameters
   - Phone calls and SMS messages
   - Bluetooth device scanning and connections
   - Clipboard read/write operations

**Use cases:**
   - Analyzing privacy-sensitive operations
   - Tracking hardware access patterns
   - Investigating data collection behavior

**Example events:**

.. code-block:: json

   {
     "event_type": "location.access",
     "provider": "gps",
     "latitude": 37.7749,
     "longitude": -122.4194,
     "accuracy": 10.0,
     "timestamp": "2024-08-20T10:31:15Z"
   }

Anti-Analysis Bypass Hooks (``--hooks-bypass``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Bypasses common anti-analysis detection techniques used by malware and security-conscious applications.

**Individual Hook:**
   - ``--enable-bypass`` - All bypass techniques

**Device Profiles:**
   - ``--bypass-device-profile <profile>`` - Apply a built-in coherent Android
     ``Build`` identity
   - ``--bypass-device-profile-file <file>`` - Apply a custom validated
     ``Build`` identity from JSON

   Either option enables bypass hooks automatically and is useful when an
   application uses multiple ``Build`` properties to detect emulator
   environments.

**Detection Methods Bypassed:**
   - **Root Detection** - su binary checks, root app detection, build tag analysis
   - **Frida Detection** - frida-server detection, port scanning, process/thread name checks
   - **Debugger Detection** - debug flag checks, tracer detection
   - **Emulator Detection** - hardware property checks, system characteristics
   - **Hook Detection** - stack trace analysis, library verification

**What it captures:**
   - Detection attempts and bypass actions
   - Original vs. modified return values
   - Detection methods used by applications
   - Evasion technique classification

**Use cases:**
   - Analyzing sophisticated malware with evasion capabilities
   - Bypassing app protection mechanisms for security research
   - Understanding anti-analysis techniques

**Example events:**

.. code-block:: json

   {
     "event_type": "bypass.root.file_check",
     "bypass_category": "root_detection",
     "detection_method": "File.exists()",
     "file_path": "/system/bin/su", 
     "original_result": true,
     "bypassed_result": false,
     "timestamp": "2024-08-20T10:31:30Z"
   }

JNI Tracing (``--hooks-jni``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Traces JNI calls made by native libraries in the target process.

**Configuration Options:**
   - ``--jni-lib <pattern>`` - Limit tracing to matching library paths
   - ``--jni-backtrace <none|fuzzy|accurate>`` - Select native backtrace mode
   - ``--jni-include <regex>`` / ``--jni-exclude <regex>`` - Filter JNI method
     names
   - ``--jni-include-export <substring>`` /
     ``--jni-exclude-export <substring>`` - Filter native exports
   - ``--jni-hide-data`` - Do not decode strings and buffers
   - ``--jni-ignore-env`` - Do not trace ``JNIEnv`` calls
   - ``--jni-ignore-vm`` - Do not trace ``JavaVM`` calls

**What it captures:**
   - JNI environment and Java VM calls
   - Native library tracking
   - JNI method, field, string, array, reference, exception, and registration
     activity
   - Decoded arguments and return values where supported

**Example usage:**

.. code-block:: bash

   # Trace JNI activity in all native libraries
   dexray-intercept -s --hooks-jni com.example.app

   # Limit tracing to libraries matching a path fragment
   dexray-intercept -s --hooks-jni \
     --jni-lib "libtarget.so" \
     com.example.app

Configuration Strategies
------------------------

Performance-Optimized Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Start with minimal hooks and add as needed:

.. code-block:: bash

   # Lightweight network monitoring
   dexray-intercept --enable-web com.example.app
   
   # Add crypto if encryption is detected
   dexray-intercept --enable-web --enable-aes com.example.app

Comprehensive Analysis Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For complete behavioral analysis:

.. code-block:: bash

   # Full monitoring with bypass (resource intensive)
   dexray-intercept --hooks-all --hooks-bypass com.suspicious.app

Targeted Analysis Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Focus on specific behavior categories:

.. code-block:: bash

   # Banking app analysis - focus on crypto and network
   dexray-intercept --hooks-crypto --hooks-network --enable-fritap com.banking.app
   
   # Malware analysis - include bypass and process monitoring  
   dexray-intercept --hooks-bypass --hooks-process --hooks-network malware.apk

Custom Analysis Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Combine built-in hooks with custom scripts:

.. code-block:: bash

   # Custom hooks + built-in categories
   dexray-intercept --custom-script ./app_specific.js --hooks-crypto com.target.app

Hook Interactions
-----------------

**Compatible Combinations:**
   - Most hook categories can be safely combined
   - ``--hooks-bypass`` complements all other categories
   - friTap (``--enable-fritap``) works well with ``--hooks-network``

**Potential Conflicts:**
   - Heavy hook combinations may impact app performance
   - Some apps may detect extensive instrumentation

**Recommended Combinations:**

.. code-block:: bash

   # Malware analysis
   dexray-intercept --hooks-bypass --hooks-crypto --hooks-network --hooks-process app.malware
   
   # General security audit
   dexray-intercept --hooks-crypto --hooks-network --hooks-ipc com.example.app
   
   # Privacy analysis
   dexray-intercept --hooks-services --hooks-network --hooks-file com.social.app

Dynamic Hook Management
-----------------------

Hooks can be managed programmatically using the Python API:

.. code-block:: python

   from dexray_intercept import AppProfiler
   
   # Start with minimal hooks
   profiler = AppProfiler(session, hook_config={'web_hooks': True})
   profiler.start_profiling()
   
   # Enable additional hooks at runtime
   profiler.enable_hook('aes_hooks', True)
   profiler.enable_hook('bypass_hooks', True)
   
   # Check currently enabled hooks
   enabled = profiler.get_enabled_hooks()
   print(f"Active hooks: {enabled}")

Custom Hook Integration
-----------------------

Custom Frida scripts can be loaded alongside built-in hooks:

**Custom Script Example:**

.. code-block:: javascript

   // my_custom_hooks.js
   Java.perform(function() {
       // Custom hook implementation
       var MyClass = Java.use("com.example.MyClass");
       MyClass.sensitiveMethod.implementation = function() {
           // Send structured message to Dexray
           send({
               "profileType": "CUSTOM_SCRIPT",
               "profileContent": {
                   "script_name": "my_custom_hooks.js",
                   "event_type": "sensitive_method_called",
                   "data": "method intercepted"
               },
               "timestamp": new Date().toISOString()
           });
           
           return this.sensitiveMethod();
       };
   });

**Usage:**

.. code-block:: bash

   dexray-intercept --custom-script ./my_custom_hooks.js --hooks-crypto com.target.app

Best Practices
--------------

**Hook Selection:**
   1. Start with targeted hook categories based on analysis goals
   2. Add ``--hooks-bypass`` for potentially evasive applications  
   3. Use ``--hooks-all`` only when comprehensive coverage is needed
   4. Monitor performance impact and adjust accordingly

**Performance:**
   1. Avoid unnecessary hooks to maintain app responsiveness
   2. Use verbose mode (``-v``) only for debugging
   3. Consider system resources when enabling multiple categories

**Security:**
   1. Always use ``--hooks-bypass`` for malware analysis
   2. Combine network hooks with friTap for complete network visibility
   3. Enable stack traces (``--enable-full-stacktrace``) for detailed analysis

**Data Management:**
   1. Regularly clean up old profile files and friTap captures
   2. Use descriptive output directories for organized analysis
   3. Consider data retention policies for sensitive analysis results

Next Steps
----------

- Learn about output formats: :doc:`output-formats`
- Explore the Python API: :doc:`../api/python-api`
- Create custom hooks: :doc:`../development/creating-hooks`
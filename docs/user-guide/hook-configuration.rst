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

File System Hooks (``--hooks-filesystem``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Monitors file operations and database access.

**Individual Hooks:**
   - ``--enable-filesystem`` - File read/write/delete operations
   - ``--enable-database`` - SQLite database operations

**What it captures:**
   - File paths and operations (read, write, delete, move)
   - Database queries and modifications
   - File content previews (configurable)
   - Permission changes and directory operations

**Use cases:**
   - Tracking malware file modifications
   - Analyzing data storage patterns
   - Investigating sensitive file access

**Example events:**

.. code-block:: json

   {
     "event_type": "file.write",
     "file_path": "/data/data/com.example.app/files/config.json",
     "size": 256,
     "content_preview": "{\"api_key\": \"...\"}",
     "timestamp": "2024-08-20T10:30:30Z"
   }

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

Monitors process creation, library loading, and dynamic code execution.

**Individual Hooks:**
   - ``--enable-dex-unpacking`` - DEX file unpacking detection
   - ``--enable-java-dex`` - Java DEX loading (may crash apps)
   - ``--enable-native-libs`` - Native library loading
   - ``--enable-process`` - Process creation and management
   - ``--enable-runtime`` - Runtime behavior and reflection

**What it captures:**
   - Dynamically loaded DEX files and libraries
   - Process spawn events and parameters
   - Reflection API usage
   - Native library paths and symbols

**Use cases:**
   - Detecting packed or encrypted malware
   - Analyzing code injection techniques
   - Tracking dynamic loading behavior

**Example events:**

.. code-block:: json

   {
     "event_type": "dex.unpacking",
     "dex_path": "/data/app/com.example.app/classes.dex",
     "unpacked": true,
     "orig_location": "/system/framework/core.jar",
     "timestamp": "2024-08-20T10:31:00Z"
   }

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

Configuration Strategies
------------------------

Performance-Optimized Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Start with minimal hooks and add as needed:

.. code-block:: bash

   # Lightweight network monitoring
   ammm --enable-web com.example.app
   
   # Add crypto if encryption is detected
   ammm --enable-web --enable-aes com.example.app

Comprehensive Analysis Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For complete behavioral analysis:

.. code-block:: bash

   # Full monitoring with bypass (resource intensive)
   ammm --hooks-all --hooks-bypass com.suspicious.app

Targeted Analysis Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Focus on specific behavior categories:

.. code-block:: bash

   # Banking app analysis - focus on crypto and network
   ammm --hooks-crypto --hooks-network --enable-fritap com.banking.app
   
   # Malware analysis - include bypass and process monitoring  
   ammm --hooks-bypass --hooks-process --hooks-network malware.apk

Custom Analysis Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Combine built-in hooks with custom scripts:

.. code-block:: bash

   # Custom hooks + built-in categories
   ammm --custom-script ./app_specific.js --hooks-crypto com.target.app

Hook Interactions
-----------------

**Compatible Combinations:**
   - Most hook categories can be safely combined
   - ``--hooks-bypass`` complements all other categories
   - friTap (``--enable-fritap``) works well with ``--hooks-network``

**Potential Conflicts:**
   - ``--enable-java-dex`` may crash certain applications
   - Heavy hook combinations may impact app performance
   - Some apps may detect extensive instrumentation

**Recommended Combinations:**

.. code-block:: bash

   # Malware analysis
   ammm --hooks-bypass --hooks-crypto --hooks-network --hooks-process app.malware
   
   # General security audit
   ammm --hooks-crypto --hooks-network --hooks-ipc com.example.app
   
   # Privacy analysis
   ammm --hooks-services --hooks-network --hooks-filesystem com.social.app

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

   ammm --custom-script ./my_custom_hooks.js --hooks-crypto com.target.app

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
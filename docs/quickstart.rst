Quick Start Guide
=================

This guide will help you perform your first analysis with Dexray Intercept in minutes.

Prerequisites
-------------

Before starting, ensure you have:

✅ **Completed installation** (see :doc:`installation`)  
✅ **Rooted Android device** connected via USB  
✅ **Target app** installed on the device  
✅ **USB debugging** enabled  

First Analysis
--------------

1. Basic App Monitoring
^^^^^^^^^^^^^^^^^^^^^^^

Start with the simplest command to attach to a running app:

.. code-block:: bash

   # Attach to running app by package name
   dexray-intercept com.example.app

   # Or attach to running app by process ID
   dexray-intercept 1234

.. note::
   By default, **all hooks are disabled** for performance. You'll see basic process attachment info but no detailed monitoring.

2. Enable Specific Hook Categories
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Enable hook categories based on what you want to monitor:

.. code-block:: bash

   # Monitor cryptographic operations
   dexray-intercept --hooks-crypto com.example.app

   # Monitor network communications
   dexray-intercept --hooks-network com.example.app

   # Monitor multiple categories
   dexray-intercept --hooks-crypto --hooks-network --hooks-filesystem com.example.app

3. Comprehensive Analysis
^^^^^^^^^^^^^^^^^^^^^^^^^

For complete behavioral analysis:

.. code-block:: bash

   # Enable all available hooks
   dexray-intercept --hooks-all com.example.app

   # Include anti-analysis bypass
   dexray-intercept --hooks-all --hooks-bypass com.example.app

Common Scenarios
---------------

Scenario 1: Malware Analysis
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For analyzing potentially malicious apps with evasion techniques:

.. code-block:: bash

   # Spawn app with full monitoring and bypass techniques
   dexray-intercept -s --hooks-all --hooks-bypass --enable-fritap suspicious.malware

   # Enable verbose output for detailed analysis
   dexray-intercept -s --hooks-all --hooks-bypass -v suspicious.malware

**What this does:**
   - ``-s`` spawns the app (vs attaching to running process)
   - ``--hooks-all`` enables comprehensive monitoring
   - ``--hooks-bypass`` bypasses anti-analysis detection
   - ``--enable-fritap`` extracts TLS keys and captures network traffic
   - ``-v`` shows verbose output for detailed debugging

Scenario 2: Network Traffic Analysis
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Focus on network communications and TLS inspection:

.. code-block:: bash

   # Network monitoring with TLS key extraction
   dexray-intercept -s --hooks-network --enable-fritap com.banking.app

   # Specify custom output directory for network captures
   dexray-intercept -s --hooks-network --enable-fritap --fritap-output-dir ./network_logs com.banking.app

Scenario 3: Cryptographic Analysis  
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Analyze encryption/decryption operations:

.. code-block:: bash

   # Monitor crypto operations with stack traces
   dexray-intercept -s --hooks-crypto --enable-full-stacktrace com.encrypted.app

Scenario 4: Custom Hook Analysis
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Load your own custom Frida scripts alongside built-in hooks:

.. code-block:: bash

   # Load custom script with built-in hooks
   dexray-intercept --custom-script ./my_hooks.js --hooks-crypto com.example.app

   # Load multiple custom scripts  
   dexray-intercept --custom-script ./script1.js --custom-script ./script2.js com.example.app

Understanding the Output
------------------------

Terminal Output
^^^^^^^^^^^^^^

Real-time events appear in the terminal with color-coded categories:

.. code-block:: text

   [*] attaching to app: com.example.app
   [*] enabled hooks: aes_hooks, web_hooks
   [*] starting app profiling
   [*] press Ctrl+C to stop the profiling ...

   [CRYPTO] AES key creation: algorithm=AES, key_length=32
   [WEB] HTTP request: GET https://api.example.com/data
   [CUSTOM] my_script.js: Custom hook triggered
   [BYPASS] Root detection bypassed: File.exists() -> /system/bin/su

JSON Profile Output
^^^^^^^^^^^^^^^^^^^

When you stop profiling (Ctrl+C), a JSON profile is generated:

.. code-block:: json

   {
     "CRYPTO_AES": [
       {
         "event_type": "crypto.key.creation",
         "algorithm": "AES",
         "key_length": 32,
         "timestamp": "2024-08-20T10:30:00.000Z"
       }
     ],
     "WEB": [
       {
         "event_type": "http.request", 
         "url": "https://api.example.com/data",
         "method": "GET",
         "timestamp": "2024-08-20T10:30:15.000Z"
       }
     ],
     "BYPASS_DETECTION": [
       {
         "event_type": "bypass.root.file_check",
         "bypass_category": "root_detection",
         "file_path": "/system/bin/su",
         "original_result": true,
         "bypassed_result": false,
         "timestamp": "2024-08-20T10:30:05.000Z"
       }
     ],
     "_metadata": {
       "created_at": "2024-08-20T10:30:00.000Z",
       "total_events": 3,
       "version": "2.0"
     }
   }

Hook Categories Reference
-------------------------

Quick reference for available hook categories:

**Cryptography**
   - ``--hooks-crypto`` - AES, encodings, keystore operations
   - ``--enable-aes`` - AES encryption/decryption only
   - ``--enable-keystore`` - Android keystore operations

**Network**
   - ``--hooks-network`` - HTTP/HTTPS, WebSocket, socket communications
   - ``--enable-web`` - Web traffic (HTTP/HTTPS, Retrofit, Volley)
   - ``--enable-sockets`` - Raw socket communications

**File System**
   - ``--hooks-filesystem`` - File operations, database access
   - ``--enable-filesystem`` - File read/write/delete operations
   - ``--enable-database`` - SQLite database operations

**Inter-Process Communication**
   - ``--hooks-ipc`` - Intents, broadcasts, binder, shared preferences
   - ``--enable-intents`` - Intent passing between components
   - ``--enable-broadcasts`` - Broadcast receiver operations

**Process Monitoring**
   - ``--hooks-process`` - DEX unpacking, native libraries, runtime
   - ``--enable-dex-unpacking`` - Dynamic DEX loading detection
   - ``--enable-native-libs`` - Native library loading

**System Services**
   - ``--hooks-services`` - Location, camera, telephony, clipboard
   - ``--enable-location`` - GPS/location access
   - ``--enable-camera`` - Camera usage

**Anti-Analysis Bypass**
   - ``--hooks-bypass`` - Root, Frida, debugger, emulator detection bypass
   - ``--enable-bypass`` - Enable all bypass techniques

Best Practices
--------------

**Performance Optimization**
   .. code-block:: bash
   
      # Start with minimal hooks and add as needed
      dexray-intercept --enable-web --enable-aes com.example.app
      
      # Avoid --hooks-all for performance-sensitive analysis
      dexray-intercept --hooks-crypto --hooks-network com.example.app

**Security Considerations**
   .. code-block:: bash
   
      # Always use bypass hooks for evasive malware
      dexray-intercept --hooks-bypass --hooks-crypto suspicious.apk
      
      # Use fritap for complete network analysis
      dexray-intercept --enable-fritap --hooks-network banking.app

**Debugging Issues**
   .. code-block:: bash
   
      # Use verbose mode for troubleshooting
      dexray-intercept -v --hooks-crypto com.problematic.app
      
      # Enable stack traces to see call origins
      dexray-intercept --enable-full-stacktrace --hooks-crypto com.example.app

Stopping Analysis
-----------------

To stop profiling and generate the final JSON report:

1. **Press Ctrl+C** in the terminal
2. Wait for the JSON profile to be generated
3. Check the terminal for the output file location

.. code-block:: text

   ^C
   [*] interrupt received - stopping profiling
   [*] fritap finished successfully
   [*] TLS keys saved to: ./fritap_output/dexray_tlskeys_com.example.app_20240820_103000.log
   [*] Traffic capture saved to: ./fritap_output/dexray_unfiltered_traffic_com.example.app_20240820_103000.pcap
   [*] Profile saved to: profile_com.example.app_2024-08-20_10-30-45.json

Next Steps
----------

Now that you've performed your first analysis:

1. **Explore the JSON output** - Import into your analysis tools
2. **Read the User Guide** - :doc:`user-guide/index` for advanced usage
3. **Check the API Reference** - :doc:`api/index` for programmatic usage
4. **Learn Hook Development** - :doc:`development/index` for creating custom hooks

If you encounter any issues, consult the :doc:`troubleshooting` guide.
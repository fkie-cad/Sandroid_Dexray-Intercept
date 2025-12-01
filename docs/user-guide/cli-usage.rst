Command Line Usage
==================

The ``dexray-intercept`` (or ``ammm``) command is the primary interface for Dexray Intercept. This section covers all command-line options and usage patterns.

Basic Syntax
------------

.. code-block:: bash

   dexray-intercept [OPTIONS] <target>

Where ``<target>`` can be:
   - **Package name**: ``com.example.app``
   - **Process ID**: ``1234``
   - **App name**: ``"My Banking App"``

Core Options
------------

Target and Connection
^^^^^^^^^^^^^^^^^^^^^

.. option:: <target>

   **Required.** The target application to analyze.
   
   Examples:
   
   .. code-block:: bash
   
      dexray-intercept com.banking.app          # Package name
      dexray-intercept 1234                     # Process ID  
      dexray-intercept "Banking App"            # App display name

.. option:: -s, --spawn

   Spawn the application instead of attaching to a running process.
   
   .. code-block:: bash
   
      dexray-intercept -s com.example.app

   .. note::
      Spawning gives you control from app startup, useful for analyzing initialization behavior.

.. option:: -fg, --foreground

   Attach to the currently foreground (visible) application.
   
   .. code-block:: bash
   
      dexray-intercept -fg

.. option:: -H <ip:port>, --host <ip:port>

   Connect to a remote Frida device.
   
   .. code-block:: bash
   
      dexray-intercept -H 192.168.1.100:27042 com.example.app

Device and Server Management
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. option:: -l, --list-devices

   List all connected Frida devices and exit. Useful for identifying device IDs when multiple devices are connected.

   .. code-block:: bash

      dexray-intercept -l

      # Output:
      # Connected Frida devices:
      #
      #   ID               NAME                    TYPE
      #   ---------------  ----------------------  ----
      #   local            Local System            local
      #   emulator-5554    Android Emulator 5554   usb
      #   192.168.1.5:5555 Samsung Galaxy S21      usb
      #
      # Usage: dexray-intercept -d <device_id> <app_name>

.. option:: -d <device_id>, --device <device_id>

   Connect to a specific device by its ID. Use ``-l`` to list available device IDs.

   .. code-block:: bash

      # Connect to specific emulator
      dexray-intercept -d emulator-5554 com.example.app

      # Connect to specific physical device
      dexray-intercept --device HVA12345 --hooks-all com.banking.app

   .. tip::
      Device IDs typically match the output of ``adb devices`` for USB-connected devices.

.. option:: -f, --frida

   Install and run frida-server on the target device.

   .. code-block:: bash

      dexray-intercept -f  # Install frida-server and exit

.. option:: --enable_spawn_gating

   Enable spawn gating to catch newly spawned processes.

   .. code-block:: bash

      dexray-intercept --enable_spawn_gating com.example.app

   .. warning::
      This may catch unrelated processes spawned during analysis.

Output and Debugging
^^^^^^^^^^^^^^^^^^^^^

.. option:: -v, --verbose

   Enable verbose output for detailed debugging information.
   
   .. code-block:: bash
   
      dexray-intercept -v --hooks-crypto com.example.app

.. option:: -st, --enable-full-stacktrace

   Enable full stack traces showing call origins in binary code.
   
   .. code-block:: bash
   
      dexray-intercept -st --hooks-crypto com.example.app

Network Analysis
^^^^^^^^^^^^^^^^

.. option:: --enable-fritap

   Enable friTap for TLS key extraction and traffic capture.
   
   .. code-block:: bash
   
      dexray-intercept --enable-fritap --hooks-network com.example.app

.. option:: --fritap-output-dir <directory>

   Specify directory for friTap output files (default: ``./fritap_output``).
   
   .. code-block:: bash
   
      dexray-intercept --enable-fritap --fritap-output-dir ./network_logs com.example.app

Custom Scripts
^^^^^^^^^^^^^^

.. option:: --custom-script <path>

   Load custom Frida script alongside built-in hooks. Can be used multiple times.
   
   .. code-block:: bash
   
      # Single custom script
      dexray-intercept --custom-script ./my_hooks.js com.example.app
      
      # Multiple custom scripts
      dexray-intercept --custom-script ./script1.js --custom-script ./script2.js com.example.app

Hook Selection
--------------

Hook Groups
^^^^^^^^^^^

.. option:: --hooks-all

   Enable all available hooks for comprehensive analysis.
   
   .. code-block:: bash
   
      dexray-intercept --hooks-all com.example.app

.. option:: --hooks-crypto

   Enable cryptographic hooks (AES, encodings, keystore).
   
   .. code-block:: bash
   
      dexray-intercept --hooks-crypto com.example.app

.. option:: --hooks-network  

   Enable network communication hooks (web traffic, sockets).
   
   .. code-block:: bash
   
      dexray-intercept --hooks-network com.example.app

.. option:: --hooks-filesystem

   Enable file system hooks (file operations, database access).
   
   .. code-block:: bash
   
      dexray-intercept --hooks-filesystem com.example.app

.. option:: --hooks-ipc

   Enable Inter-Process Communication hooks (intents, broadcasts, binder, shared preferences).
   
   .. code-block:: bash
   
      dexray-intercept --hooks-ipc com.example.app

.. option:: --hooks-process

   Enable process monitoring hooks (native libraries, runtime, DEX unpacking).
   
   .. code-block:: bash
   
      dexray-intercept --hooks-process com.example.app

.. option:: --hooks-services

   Enable system service hooks (bluetooth, camera, clipboard, location, telephony).
   
   .. code-block:: bash
   
      dexray-intercept --hooks-services com.example.app

.. option:: --hooks-bypass

   Enable anti-analysis bypass hooks (root, frida, debugger, emulator detection).
   
   .. code-block:: bash
   
      dexray-intercept --hooks-bypass com.example.app

Individual Hooks
^^^^^^^^^^^^^^^^

For fine-grained control, you can enable specific individual hooks:

**Cryptographic Hooks**

.. option:: --enable-aes

   Enable AES encryption/decryption monitoring.

.. option:: --enable-keystore

   Enable Android keystore operation monitoring.

.. option:: --enable-encodings

   Enable encoding/decoding operation monitoring.

**Network Hooks**

.. option:: --enable-web

   Enable web traffic monitoring (HTTP/HTTPS, Retrofit, Volley, WebSockets).

.. option:: --enable-sockets

   Enable raw socket communication monitoring.

**File System Hooks**

.. option:: --enable-filesystem

   Enable file system operation monitoring.

.. option:: --enable-database

   Enable database operation monitoring.

**Process Hooks**

.. option:: --enable-dex-unpacking

   Enable DEX unpacking detection.

.. option:: --enable-java-dex

   Enable Java DEX loading hooks.
   
   .. warning::
      This hook may crash certain applications.

.. option:: --enable-native-libs

   Enable native library loading monitoring.

.. option:: --enable-process

   Enable process creation monitoring.

.. option:: --enable-runtime

   Enable runtime operation monitoring.

**IPC Hooks**

.. option:: --enable-shared-prefs

   Enable shared preferences monitoring.

.. option:: --enable-binder

   Enable binder communication monitoring.

.. option:: --enable-intents

   Enable intent passing monitoring.

.. option:: --enable-broadcasts

   Enable broadcast receiver monitoring.

**Service Hooks**

.. option:: --enable-bluetooth

   Enable Bluetooth API monitoring.

.. option:: --enable-camera

   Enable camera usage monitoring.

.. option:: --enable-clipboard

   Enable clipboard access monitoring.

.. option:: --enable-location

   Enable location/GPS access monitoring.

.. option:: --enable-telephony

   Enable telephony API monitoring.

**Bypass Hooks**

.. option:: --enable-bypass

   Enable all anti-analysis bypass techniques.

Usage Examples
--------------

Basic Analysis
^^^^^^^^^^^^^^

.. code-block:: bash

   # Attach to running app with minimal monitoring
   dexray-intercept com.example.app

   # Spawn app with crypto monitoring
   dexray-intercept -s --enable-aes com.banking.app

Comprehensive Analysis
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Full monitoring with anti-analysis bypass
   dexray-intercept -s --hooks-all --hooks-bypass suspicious.malware

   # Verbose analysis with stack traces
   dexray-intercept -sv --enable-full-stacktrace --hooks-crypto com.example.app

Network Analysis
^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Network monitoring with TLS key extraction
   dexray-intercept -s --hooks-network --enable-fritap com.banking.app

   # Custom network analysis directory
   dexray-intercept --enable-fritap --fritap-output-dir ./analysis_2024 --hooks-network com.example.app

Custom Analysis
^^^^^^^^^^^^^^^

.. code-block:: bash

   # Load custom hooks with built-in crypto monitoring  
   dexray-intercept --custom-script ./my_analysis.js --hooks-crypto com.target.app

   # Multiple custom scripts with comprehensive monitoring
   dexray-intercept --custom-script ./script1.js --custom-script ./script2.js --hooks-all com.example.app

Remote Analysis
^^^^^^^^^^^^^^^

.. code-block:: bash

   # Connect to remote device
   dexray-intercept -H 192.168.1.100:27042 --hooks-crypto com.example.app

   # Remote analysis with spawn gating
   dexray-intercept -H 10.0.0.5:27042 --enable_spawn_gating --hooks-all com.example.app

Performance Considerations
--------------------------

**Hook Selection Strategy**

Start with minimal hooks and add categories as needed:

.. code-block:: bash

   # Start minimal
   dexray-intercept --enable-web com.example.app
   
   # Add crypto if needed
   dexray-intercept --enable-web --enable-aes com.example.app
   
   # Avoid --hooks-all unless necessary
   dexray-intercept --hooks-crypto --hooks-network com.example.app  # Preferred
   dexray-intercept --hooks-all com.example.app                     # Heavy

**Resource Usage**

- ``--hooks-all`` can significantly impact app performance
- ``--enable-full-stacktrace`` adds overhead but provides valuable debugging info
- ``--verbose`` generates substantial output for complex apps

**Memory Considerations**

- Large apps with many events may require increased system memory
- friTap network captures can grow large for traffic-heavy applications
- Consider using specific hook categories rather than ``--hooks-all``

Error Handling
--------------

Common exit codes:

- ``0`` - Successful completion
- ``1`` - General error
- ``2`` - Frida connection error or invalid arguments

For troubleshooting specific errors, see the :doc:`../troubleshooting` section.
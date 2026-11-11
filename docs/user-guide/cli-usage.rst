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

   The target application or process to analyze. It is required unless using a
   standalone option such as ``--list-devices``.
   
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

.. option:: --component <package/.Activity>

   Spawn and instrument an explicit Android activity component. Requires
   ``-s`` / ``--spawn`` and a package name as the positional target.

   .. code-block:: bash

      dexray-intercept -s --component .MainActivity com.example.app

   Dexray Intercept installs the selected hooks before resuming the component.

   .. note::
      ``--component`` cannot be combined with ``--enable_spawn_gating``,
      ``--enable-fritap``, or ``--host``.

.. option:: -H <ip:port>, --host <ip:port>

   Connect to a remote Frida device.
   
   .. code-block:: bash
   
      dexray-intercept -H 192.168.1.100:27042 com.example.app

.. option:: -d <device_id>, --device <device_id>

   Connect to a specific Frida device.

   .. code-block:: bash

      dexray-intercept -d emulator-5554 com.example.app

.. option:: -l, --list-devices

   List available Frida devices and exit.

   .. code-block:: bash

      dexray-intercept --list-devices

Device and Server Management
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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

.. option:: --non-interactive

   Disable the interactive hook-selection prompt when no built-in hook option is
   supplied. This is useful for automated or custom-script-only runs.

   .. code-block:: bash

      dexray-intercept -s --non-interactive \
        --custom-script ./my_hooks.js \
        com.example.app

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

Bypass Device Profiles
^^^^^^^^^^^^^^^^^^^^^^

.. option:: --bypass-device-profile <profile>

   Apply a built-in coherent Android ``Build`` identity for emulator-detection
   bypass. This option enables bypass hooks automatically.

   .. code-block:: bash

      dexray-intercept -s \
        --bypass-device-profile google_pixel_8 \
        com.example.app

.. option:: --bypass-device-profile-file <file>

   Apply a custom Android ``Build`` identity from a JSON profile file. This
   option enables bypass hooks automatically.

   .. code-block:: bash

      dexray-intercept -s \
        --bypass-device-profile-file ./device-profile.json \
        com.example.app

   ``--bypass-device-profile`` and ``--bypass-device-profile-file`` cannot be
   combined.

Hook Selection
--------------

Hook Groups
^^^^^^^^^^^

.. option:: --hooks-all

   Enable all standard hook categories for comprehensive analysis. JNI tracing is
   not included.
   
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

.. option:: --hooks-file

   Enable file hooks for file construction, streams, reads, writes, and
   deletion.

   .. code-block:: bash

      dexray-intercept --hooks-file com.example.app

.. option:: --hooks-database

   Enable database hooks for SQLite, Room, SQLCipher, WCDB, and native SQLite
   operations.

   .. code-block:: bash

      dexray-intercept --hooks-database com.example.app

.. option:: --hooks-ipc

   Enable Inter-Process Communication hooks (intents, broadcasts, binder, shared preferences).
   
   .. code-block:: bash
   
      dexray-intercept --hooks-ipc com.example.app

.. option:: --hooks-process

   Enable process monitoring hooks for native library loading, process APIs, and
   runtime or reflection activity.
   
   .. code-block:: bash
   
      dexray-intercept --hooks-process com.example.app

.. option:: --hooks-dex

   Enable DEX loading and unpacking hooks.

   .. code-block:: bash

      dexray-intercept --hooks-dex com.example.app

.. option:: --hooks-services

   Enable system service hooks (bluetooth, camera, clipboard, location, telephony).
   
   .. code-block:: bash
   
      dexray-intercept --hooks-services com.example.app

.. option:: --hooks-bypass

   Enable anti-analysis bypass hooks (root, frida, debugger, emulator detection).
   
   .. code-block:: bash
   
      dexray-intercept --hooks-bypass com.example.app

.. option:: --hooks-jni

   Enable JNI API tracing. JNI tracing is configured further with the
   ``--jni-*`` options.

   .. code-block:: bash

      dexray-intercept --hooks-jni com.example.app

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

.. option:: --deactivate-unlink

   Prevent native ``unlink()`` calls from deleting files while reporting success
   to the target application. This changes target behavior and automatically
   enables file hooks.

   .. code-block:: bash

      dexray-intercept --deactivate-unlink com.example.app

.. option:: --enable-sql

   Enable database operation monitoring.

**Process Hooks**

.. option:: --enable-process

   Enable Android process API and native process activity monitoring.

.. option:: --enable-runtime

   Enable runtime execution, shutdown, and reflection monitoring.

.. option:: --enable-library-loading

   Enable Java ``System`` and ``Runtime`` library-loading monitoring.

.. option:: --enable-native-libs

   Enable native linker-level library-loading monitoring.

**DEX Hooks**

.. option:: --enable-dex-unpacking

   Enable ART DEX detection and Java DEX class-loader monitoring.

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

JNI Tracing Options
^^^^^^^^^^^^^^^^^^^

JNI tracing is enabled with ``--hooks-jni``. The following options configure JNI
tracing and require ``--hooks-jni``:

- ``--jni-lib <pattern>`` - Limit tracing to libraries whose path contains the
  pattern. May be specified multiple times.
- ``--jni-backtrace <none|fuzzy|accurate>`` - Select native backtrace mode.
  The default is ``none``.
- ``--jni-include <regex>`` and ``--jni-exclude <regex>`` - Include or exclude
  JNI method names using regular expressions.
- ``--jni-include-export <substring>`` and ``--jni-exclude-export <substring>``
  - Include or exclude native exports by name.
- ``--jni-hide-data`` - Do not decode strings and buffers in JNI events.
- ``--jni-ignore-env`` - Do not trace ``JNIEnv`` calls.
- ``--jni-ignore-vm`` - Do not trace ``JavaVM`` calls.

.. code-block:: bash

   # Trace JNI activity only in matching libraries
   dexray-intercept -s --hooks-jni \
     --jni-lib "libtarget.so" \
     com.example.app

   # Trace selected JNI method families with fuzzy backtraces
   dexray-intercept -s --hooks-jni \
     --jni-backtrace fuzzy \
     --jni-include "Call.*Method" \
     com.example.app

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
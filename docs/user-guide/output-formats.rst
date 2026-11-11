Output Formats
==============

Dexray Intercept provides multiple output formats to support different analysis workflows and integration requirements.

Overview
--------

The tool generates output in two primary modes:

1. **Real-time Terminal Output** - Live event stream for monitoring
2. **JSON Profile Files** - Structured data for analysis and integration

Additionally, when friTap is enabled:

3. **TLS Key Logs** - For decrypting captured network traffic  
4. **Network Capture Files** - PCAP files of all network traffic

Real-Time Terminal Output
-------------------------

Events appear in the terminal as they occur, color-coded by category:

.. code-block:: text

   [*] [File] Read Operation:
   [*] Operation: FileInputStream.read
   [*] File Path: /data/user/0/com.test.filee2e/files/fis_read0.log
   [*] Buffer Size: 1 bytes
   [*] Offset: 0, Length: 1
   [*] Bytes Read: 1
   [*] Byte Value: 88
   [*] Data:
                 00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f
       00000000  58                                                |X               |

**Color Coding:**
   - **[CRYPTO]** - Blue - Cryptographic operations
   - **[WEB]** - Green - Network communications
   - **[FILE]** - Yellow - File system operations  
   - **[IPC]** - Cyan - Inter-process communication
   - **[BYPASS]** - Red - Anti-analysis bypass events
   - **[CUSTOM]** - Magenta - Custom script messages

**Verbosity Levels:**
   - **Normal**: Essential events only
   - **Verbose (``-v``)**: Additional event details and debug information
   - **Stack traces (``--enable-full-stacktrace``)**: Include call origin information

JSON Profile Format
-------------------

When analysis stops with Ctrl+C, a JSON profile is generated containing the
collected events.

Basic Structure
^^^^^^^^^^^^^^^

.. code-block:: json

   {
     "CATEGORY_NAME": [
       {
         "event_type": "specific.event.type",
         "timestamp": "2024-08-20T10:30:00.000Z",
         "event_specific_field": "value",
         "additional_field": 42,
         "metadata": {
           "additional_context": "value"
         }
       }
     ],
     "_metadata": {
       "created_at": "2024-08-20T10:30:00.000Z",
       "version": "2.0",
       "total_events": 1
     }
   }

Each profile category contains a list of events. Every event has an
``event_type`` and ``timestamp``; additional top-level fields depend on the
event type. Supplementary or category-specific information may be stored in
``metadata``.

Stack Traces
^^^^^^^^^^^^

Use ``--enable-full-stacktrace`` to request stack traces from supported hooks.
When available, traces are stored in the event's ``metadata``:

- ``java_stack_trace`` contains Java stack frames as strings.
- ``native_backtrace`` contains native frames with address, module, and symbol
  information. Module or symbol details may be unavailable.

For example, a Java trace can look like this (selected frames):

.. code-block:: json

   {
     "event_type": "file.create",
     "metadata": {
       "java_stack_trace": [
         "dalvik.system.VMStack.getThreadStackTrace(Native Method)",
         "java.lang.Thread.getStackTrace(Thread.java:1841)",
         "java.io.File.<init>(Native Method)"
       ]
     }
   }

A native trace can look like this (one selected frame):

.. code-block:: json

   {
     "event_type": "file.delete.native",
     "metadata": {
       "native_backtrace": [
         {
           "address": "0x7dc41accc159",
           "module": {
             "name": "libc.so",
             "base": "0x7dc41ac05000",
             "path": "/apex/com.android.runtime/lib64/bionic/libc.so"
           },
           "symbol": {
             "address": "0x7dc41accc159",
             "name": "remove+0x9",
             "moduleName": "libc.so"
           }
         }
       ]
     }
   }

The examples are excerpts; actual traces and event fields vary by hook and runtime.

Event Categories
^^^^^^^^^^^^^^^^

**CRYPTO_AES**
   AES encryption/decryption operations

.. code-block:: json

   {
     "event_type": "crypto.cipher.operation",
     "timestamp": "2026-11-11T20:54:03.281Z",
     "algorithm": "AES/CBC/PKCS5Padding",
     "operation_mode": 2,
     "operation_mode_desc": "DECRYPT_MODE (2)",
     "input_hex": "f6302125b8cfcfb245adc9344d712b2d",
     "output_hex": "48656c6c6f204145532045324521",
     "input_length": 16,
     "output_length": 14,
     "key_hex": "fc064967581dff0c55147a039b53b00b",
     "key_length": 0,
     "iv_hex": "23423551bc3a5ec38db1bdf040b15316",
     "iv_length": 0,
     "plaintext": "Hello AES E2E!"
   }

**CRYPTO_ENCODING**
   Encoding and decoding operations

.. code-block:: json

   {
     "event_type": "crypto.base64.encode_to_string",
     "timestamp": "2026-11-11T20:54:03.289Z",
     "input_hex": "48656c6c6f204261736536342045324521",
     "input_length": 17,
     "output_length": 24,
     "key_length": 0,
     "iv_length": 0,
     "plaintext": "Hello Base64 E2E!",
     "metadata": {
       "output_string": "SGVsbG8gQmFzZTY0IEUyRSE=",
       "flags": 2,
       "method": "encodeToString(byte[], int)",
       "input_content": "Hello Base64 E2E!"
     }
   }

**CRYPTO_KEYSTORE**
   Keystore operations

.. code-block:: json

   {
     "event_type": "crypto.keystore.get_instance",
     "timestamp": "2026-11-11T20:54:03.305Z",
     "input_length": 0,
     "output_length": 0,
     "key_length": 0,
     "iv_length": 0,
     "metadata": {
       "type": "BKS",
       "method": "getInstance(String)"
     }
   }

**WEB**
   Network communications

.. code-block:: json

   {
     "event_type": "http.request",
     "url": "https://api.example.com/login",
     "method": "POST",
     "headers": {
       "Content-Type": "application/json",
       "Authorization": "Bearer eyJ0eXAi..."
     },
     "body_preview": "{\"username\": \"user@example.com\"}",
     "response_code": 200,
     "response_headers": {
       "Set-Cookie": "session=abc123; HttpOnly"
     },
     "library": "OkHttp",
     "timestamp": "2024-08-20T10:30:15.000Z"
   }

**NETWORK_SOCKETS**
   Java and native socket activity

.. code-block:: json

   {
     "event_type": "socket.native.sendmsg",
     "timestamp": "2026-11-11T21:00:54.699Z",
     "method": "sendmsg",
     "socket_type": "unix:stream",
     "socket_descriptor": 110,
     "remote_address": "filesystem:/dev/socket/traced_producer",
     "data_length": 25,
     "has_buffer": true,
     "operation": "Socket Sendmsg",
     "socket_description": "Socket (unix:stream)",
     "address_family": 1,
     "protocol": 0,
     "result_code": 25,
     "operation_id": "socket-110-1",
     "captured_length": 25,
     "payload_truncated": false,
     "metadata": {
       "socket_noise_reason": "known_noisy_endpoint"
     }
   }

Native socket payloads can be stored in separate companion events. The
``operation_id`` links the payload event to its corresponding operation.

The corresponding payload event from the same run is:

.. code-block:: json

   {
     "event_type": "socket.native.sendmsg_data",
     "timestamp": "2026-11-11T21:00:54.699Z",
     "socket_descriptor": 110,
     "data_length": 25,
     "has_buffer": true,
     "operation_id": "socket-110-1",
     "captured_length": 25,
     "data_hex": "1500000010011a8e8080000a0c50726f6475636572506f7274",
     "payload_truncated": false,
     "metadata": {
       "socket_noise_reason": "inherited"
     }
   }

Some low-signal Unix socket events are classified in ``metadata`` using
``socket_noise_reason``. They are hidden from the console by default but remain
in the JSON profile. Use ``-v`` to show them in the console.

**FILE_SYSTEM**
   File operations

.. code-block:: json

   {
     "event_type": "file.write",
     "timestamp": "2026-11-11T09:45:36.106Z",
     "file_path": "/data/user/0/com.test.filee2e/files/fis_file.log",
     "operation": "FileOutputStream.write",
     "method": "java.io.FileOutputStream.write(byte[])",
     "variant": 0,
     "buffer_size": 13,
     "offset": 0,
     "length": 13,
     "data_hex": "4649532d46696c652d54657374",
     "plaintext": "FIS-File-Test",
     "file_type": "other",
     "is_large_data": false,
     "bytes_written": 13
   }

The console may show only a preview of large file data. The JSON event can
contain more data than the console preview.

**DATABASE**
   Java and native database operations

.. code-block:: json

   {
     "event_type": "database.native.prepare",
     "timestamp": "2026-11-11T09:49:58.871Z",
     "database_path": "/data/user/0/com.test.databasee2e/databases/sqlite_e2e.db",
     "database_type": "Native SQLite",
     "method": "sqlite3_prepare16_v2",
     "sql": "PRAGMA page_size",
     "result_code": 0,
     "status": "success",
     "native_function": "sqlite3_prepare16_v2",
     "module_name": "libsqlite.so",
     "architecture": "x64",
     "sql_encoding": "utf16",
     "statement_handle": "0x7786d7c2c800",
     "database_handle": "0x778857c30110",
     "metadata": {
       "operation_description": "Native SQLite operation"
     }
   }

**RUNTIME_HOOKS**
   Runtime and reflection activity

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

**PROCESS_CREATION**
   Android and native process activity

.. code-block:: json

   {
     "event_type": "process.signal",
     "timestamp": "2026-11-11T11:25:18.859Z",
     "target_pid": 5216,
     "signal": 0,
     "event_description": "Process signal sent",
     "metadata": {
       "library": "android.os.Process",
       "method": "sendSignal"
     }
   }

**IPC_BROADCAST**
   Broadcast and component activity

.. code-block:: json

   {
     "event_type": "broadcast.sent",
     "timestamp": 1794434103815,
     "method": "sendBroadcast",
     "intent_name": "com.test.ipce2e.ACTION_SIMPLE",
     "intent": {
       "intent_string": "Intent { act=com.test.ipce2e.ACTION_SIMPLE (has extras) }",
       "action": "com.test.ipce2e.ACTION_SIMPLE",
       "extras": "Bundle[{key=value}]",
       "flags": 0
     },
     "source_class": "android.content.ContextWrapper"
   }

**PROCESS_NATIVE_LIB**
   Native library-loading activity

.. code-block:: json

   {
     "event_type": "native.library.loaded",
     "timestamp": "2026-11-11T11:25:18.908Z",
     "success": true,
     "library_name": "liblog.so",
     "event_description": "Native library loaded successfully",
     "load_method": "android_dlopen_ext",
     "handle": "0x314eb83eb19b24b9"
   }

**BYPASS_DETECTION**
   Anti-analysis bypass events

.. code-block:: json

   {
     "event_type": "bypass.emulator.build_property",
     "timestamp": "2026-11-11T21:12:16.622Z",
     "bypass_category": "emulator_detection",
     "detection_method": "Build.BRAND",
     "original_value": "google",
     "bypassed_value": "samsung",
     "property_name": "BRAND",
     "device_profile": "samsung_galaxy_s10",
     "profile_source": "built_in",
     "metadata": {
       "matched_indicators": [
         "DEVICE=emu64xa",
         "MODEL=sdk_gphone64_x86_64",
         "PRODUCT=sdk_gphone64_x86_64",
         "HARDWARE=ranchu"
       ],
       "description": "Emulator detection via Build properties",
       "category": "emulator_detection",
       "severity": "medium",
       "mitre_technique": "T1497",
       "technique_name": "Virtualization/Sandbox Evasion"
     }
   }

**CUSTOM_SCRIPT**
   Custom script messages

.. code-block:: json

   {
     "event_type": "custom_script.message",
     "script_name": "banking_analysis.js",
     "message": {
       "hook_type": "pin_validation",
       "pin_length": 6,
       "validation_result": "success"
     },
     "timestamp": "2024-08-20T10:31:00.000Z"
   }

**JNI_TRACE**
   JNI environment and Java VM calls, and tracked native libraries

.. code-block:: json

   {
     "event_type": "jni.env.call",
     "timestamp": "2026-11-11T21:30:04.971Z",
     "metadata": {
       "jni_struct": "JNIEnv",
       "method": "NewStringUTF",
       "arguments": [
         "0x7dc270f4b9b0",
         "0x7dc0eac5698e"
       ],
       "return_value": "0x7dc427ae202d",
       "java_method_sig": null,
       "thread_id": 5647,
       "c_arg_types": ["JNIEnv*", "char*"],
       "c_ret_type": "jstring",
       "string_argument": "HelloUTF"
     }
   }

File Naming Convention
^^^^^^^^^^^^^^^^^^^^^^

JSON profiles are automatically named with timestamps:

.. code-block:: text

   profile_<target>_<timestamp>.json

Examples:
   - ``profile_com.banking.app_2024-08-20_10-30-45.json``
   - ``profile_1234_2024-08-20_15-45-30.json``
   - ``profile_unknown_app_2024-08-20_09-15-22.json``

DEX Artifacts
-------------

The native DEX hook sends captured payloads to Python through Frida. When
persistence succeeds, the ``DEX_LOADING`` event includes the local
``dumped_path``, SHA-256 hash, file type, and capture status.

Native payloads larger than 64 MiB are not captured. Capture or persistence
failures are reported in the event.

**Example native capture event** (selected fields):

.. code-block:: json

   {
     "event_type": "dex.unpacking.detected",
     "timestamp": "2026-11-11T21:18:49.706Z",
     "hooked_function": "libdexfile.so::<mangled OpenCommon symbol>",
     "magic": "dex038",
     "size": 2300,
     "original_location": "/data/app/<install-id>/com.test.dexe2e/base.apk",
     "dumped_path": "/path/to/dexray-intercept/unpacked/malicious/c19ce64f8e58cc0129f0d442fb4a9cebbff3df9cf5033866c981ffba9aee1768.dex",
     "dump_success": true,
     "sha256": "c19ce64f8e58cc0129f0d442fb4a9cebbff3df9cf5033866c981ffba9aee1768",
     "file_type": "dex",
     "operation_id": "dex-1",
     "captured_length": 2300,
     "has_buffer": true,
     "payload_truncated": false
   }

The paths and hooked symbol contain placeholders; their actual values depend
on the device and local environment.

The artifact directory reflects an origin-based classification; it is not by
itself a determination that the captured file is malicious.

**In-memory class-loader events** describe buffer metadata. They do not by
themselves guarantee that an artifact was captured:

.. code-block:: json

   {
     "event_type": "dex.in_memory_loader",
     "timestamp": "2026-11-11T21:18:49.765Z",
     "unpacking": false,
     "magic": "dex038",
     "class_loader_type": "InMemoryDexClassLoader",
     "method": "$init(ByteBuffer, ClassLoader)",
     "buffer_size": 732,
     "buffer_count": 1,
     "buffer_sizes": [732],
     "total_buffer_size": 732,
     "buffer_magics": ["dex038"]
   }

Network Capture Files (friTap)
------------------------------

When ``--enable-fritap`` is used, additional network analysis files are generated:

TLS Key Log Files
^^^^^^^^^^^^^^^^^

Contains extracted TLS keys for decrypting captured traffic:

.. code-block:: text

   # TLS Key Log Format
   CLIENT_RANDOM 52362c1a7cf70c40... 10203040506070...
   CLIENT_RANDOM 52362c1a7cf70c41... 20304050607080...

**Filename format:**
   ``dexray_tlskeys_<app>_<timestamp>.log``

**Usage:**
   Import into Wireshark or other network analysis tools to decrypt TLS traffic.

Network Capture Files
^^^^^^^^^^^^^^^^^^^^^

PCAP files containing all network traffic:

**Filename format:**
   ``dexray_unfiltered_traffic_<app>_<timestamp>.pcap``

**Contents:**
   - Raw network packets
   - All protocols (TCP, UDP, ICMP, etc.)
   - Decryptable when combined with TLS key logs

**Analysis workflow:**

.. code-block:: bash

   # Open in Wireshark with TLS keys
   wireshark dexray_unfiltered_traffic_com.banking.app_20240820_103000.pcap
   
   # In Wireshark, load TLS keys:
   # Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename
   # Select: dexray_tlskeys_com.banking.app_20240820_103000.log

Working with Output Data
------------------------

Programmatic Analysis
^^^^^^^^^^^^^^^^^^^^

**Python JSON Processing:**

.. code-block:: python

   import json
   from datetime import datetime

   # Load profile data
   with open('profile_com.example.app_2024-08-20_10-30-45.json', 'r') as f:
       profile = json.load(f)

   # Analyze crypto events
   crypto_events = profile.get('CRYPTO_AES', [])
   print(f"Found {len(crypto_events)} crypto operations")

   for event in crypto_events:
       if event['event_type'] == 'crypto.key.creation':
           print(f"AES key: {event['algorithm']} ({event['key_length']} bytes)")

   # Analyze network traffic
   web_events = profile.get('WEB', [])
   unique_domains = set()
   
   for event in web_events:
       if 'url' in event:
           from urllib.parse import urlparse
           domain = urlparse(event['url']).netloc
           unique_domains.add(domain)
   
   print(f"Contacted domains: {list(unique_domains)}")

**Filtering and Searching:**

.. code-block:: python

   # Find all bypass events
   bypass_events = profile.get('BYPASS_DETECTION', [])
   root_detections = [e for e in bypass_events if e.get('bypass_category') == 'root_detection']
   
   # Find crypto operations with specific algorithms
   aes_256_ops = [e for e in crypto_events if e.get('key_length') == 32]
   
   # Time-based filtering
   from datetime import datetime
   start_time = datetime.fromisoformat('2024-08-20T10:30:00.000Z'.replace('Z', '+00:00'))
   
   recent_events = []
   for category in profile:
       if category != '_metadata':
           for event in profile[category]:
               event_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
               if event_time > start_time:
                   recent_events.append(event)

Integration with Analysis Tools
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Threat Intelligence Platforms:**

.. code-block:: python

   # Extract IOCs from network events
   def extract_iocs(profile):
       iocs = {'domains': [], 'urls': [], 'ips': []}
       
       for event in profile.get('WEB', []):
           if 'url' in event:
               iocs['urls'].append(event['url'])
               domain = urlparse(event['url']).netloc
               iocs['domains'].append(domain)
       
       return iocs

**SIEM Integration:**

.. code-block:: python

   # Convert to common log format
   def to_siem_format(event):
       return {
           'timestamp': event['timestamp'],
           'source': 'dexray-intercept',
           'category': event.get('event_type', 'unknown'),
           'severity': get_severity(event),
           'details': json.dumps(event)
       }

**Malware Analysis Workflows:**

.. code-block:: python

   # Detect suspicious patterns
   def analyze_malware_indicators(profile):
       indicators = []
       
       # Check for root detection bypass
       bypass_events = profile.get('BYPASS_DETECTION', [])
       if any(e.get('bypass_category') == 'root_detection' for e in bypass_events):
           indicators.append('root_detection_evasion')
       
       # Check for network exfiltration
       web_events = profile.get('WEB', [])
       suspicious_domains = ['suspicious.com', 'evil.net']
       
       for event in web_events:
           url = event.get('url', '')
           if any(domain in url for domain in suspicious_domains):
               indicators.append('c2_communication')
       
       return indicators

Advanced Output Processing
-------------------------

Custom Event Filtering
^^^^^^^^^^^^^^^^^^^^^^

Filter events during analysis using the Python API:

.. code-block:: python

   from dexray_intercept import AppProfiler

   class CustomProfileCollector:
       def __init__(self, original_collector):
           self.original = original_collector
           self.filtered_events = []
       
       def process_frida_message(self, message, data=None):
           # Custom filtering logic
           payload = message.get('payload', {})
           event_type = payload.get('profileType', '')
           
           # Only collect crypto and network events
           if event_type in ['CRYPTO_AES', 'WEB']:
               return self.original.process_frida_message(message, data)
           
           return False

Real-time Event Streaming
^^^^^^^^^^^^^^^^^^^^^^^^^

Process events as they occur:

.. code-block:: python

   import json
   from queue import Queue
   from threading import Thread

   class EventStreamer:
       def __init__(self):
           self.event_queue = Queue()
           self.running = True
       
       def process_event(self, event_data):
           # Real-time processing
           if event_data.get('event_type') == 'crypto.key.creation':
               self.alert_crypto_key(event_data)
           elif 'suspicious.com' in str(event_data):
               self.alert_suspicious_network(event_data)
       
       def alert_crypto_key(self, event):
           print(f"🔐 CRYPTO ALERT: {event['algorithm']} key created")
       
       def alert_suspicious_network(self, event):
           print(f"🚨 NETWORK ALERT: Suspicious domain contacted")

Output Customization
-------------------

Environment Variables
^^^^^^^^^^^^^^^^^^^^^

Control output behavior:

.. code-block:: bash

   # Disable colored output
   export DEXRAY_NO_COLOR=1
   
   # Custom output directory
   export DEXRAY_OUTPUT_DIR=/path/to/analysis/output
   
   # Maximum content preview length
   export DEXRAY_PREVIEW_MAX_LENGTH=100

Profile Data Validation
^^^^^^^^^^^^^^^^^^^^^^^

Validate JSON profile integrity:

.. code-block:: python

   def validate_profile(profile_path):
       with open(profile_path, 'r') as f:
           profile = json.load(f)
       
       # Check required metadata
       if '_metadata' not in profile:
           return False, "Missing metadata"
       
       metadata = profile['_metadata']
       required_fields = ['created_at', 'version', 'total_events']
       
       for field in required_fields:
           if field not in metadata:
               return False, f"Missing metadata field: {field}"
       
       # Validate event structure
       total_events = 0
       for category, events in profile.items():
           if category == '_metadata':
               continue
           
           if not isinstance(events, list):
               return False, f"Category {category} is not a list"
           
           total_events += len(events)
           
           for event in events:
               if 'timestamp' not in event:
                   return False, f"Event missing timestamp in {category}"
       
       # Verify event count
       if total_events != metadata['total_events']:
           return False, "Event count mismatch"
       
       return True, "Profile is valid"

Best Practices
--------------

**Data Management:**
   - Regularly archive old profile files
   - Use descriptive filenames and directories
   - Implement log rotation for high-volume analysis

**Performance:**
   - Filter events in real-time when possible
   - Use streaming processing for large profiles
   - Consider data compression for storage

**Security:**
   - Sanitize profile data before sharing
   - Remove sensitive information from logs
   - Encrypt stored analysis results

**Integration:**
   - Standardize on JSON processing libraries
   - Implement error handling for malformed data
   - Use schema validation for automated processing

Troubleshooting Output Issues
----------------------------

**Common Problems:**

1. **Empty JSON profiles** - Verify hooks are enabled
2. **Large file sizes** - Use selective hook configuration
3. **Missing network captures** - Check friTap configuration
4. **Incomplete events** - Ensure app ran long enough for analysis

**Debug Steps:**

.. code-block:: bash

   # Enable verbose output
   dexray-intercept -v --hooks-crypto com.example.app
   
   # Check file permissions
   ls -la profile_*.json
   
   # Validate JSON syntax
   python3 -m json.tool profile_example.json

Next Steps
----------

- Learn about the Python API: :doc:`../api/python-api`
- Explore development workflows: :doc:`../development/index`
- Review command-line options: :doc:`cli-usage`
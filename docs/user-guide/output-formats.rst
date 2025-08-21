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

   [*] attaching to app: com.example.app
   [*] enabled hooks: aes_hooks, web_hooks, bypass_hooks
   [*] starting app profiling
   [*] press Ctrl+C to stop the profiling ...

   [CRYPTO] AES key creation: algorithm=AES, key_length=32, key=a1b2c3d4...
   [WEB] HTTP request: GET https://api.example.com/users/profile
   [BYPASS] Root detection bypassed: File.exists() -> /system/bin/su (false)
   [CUSTOM] my_script.js: Custom hook triggered with data: {...}

**Color Coding:**
   - **[CRYPTO]** - Blue - Cryptographic operations
   - **[WEB]** - Green - Network communications
   - **[FILE]** - Yellow - File system operations  
   - **[IPC]** - Cyan - Inter-process communication
   - **[BYPASS]** - Red - Anti-analysis bypass events
   - **[CUSTOM]** - Magenta - Custom script messages

**Verbosity Levels:**
   - **Normal**: Essential events only
   - **Verbose (``-v``)**: All events including debug information
   - **Stack traces (``--enable-full-stacktrace``)**: Include call origin information

JSON Profile Format
-------------------

When analysis stops (Ctrl+C), a comprehensive JSON profile is generated containing all captured events.

Basic Structure
^^^^^^^^^^^^^^^

.. code-block:: json

   {
     "CATEGORY_NAME": [
       {
         "event_type": "specific.event.type",
         "timestamp": "2024-08-20T10:30:00.000Z",
         "field1": "value1",
         "field2": "value2"
       }
     ],
     "_metadata": {
       "created_at": "2024-08-20T10:30:00.000Z",
       "version": "2.0",
       "total_events": 42,
       "category_breakdown": {
         "CRYPTO_AES": 15,
         "WEB": 20,
         "BYPASS_DETECTION": 7
       }
     }
   }

Event Categories
^^^^^^^^^^^^^^^^

**CRYPTO_AES**
   AES encryption/decryption operations

.. code-block:: json

   {
     "event_type": "crypto.cipher.operation",
     "algorithm": "AES/CBC/PKCS5Padding",
     "operation_mode": 1,
     "operation_mode_desc": "ENCRYPT_MODE (1)",
     "key_hex": "a1b2c3d4e5f67890...",
     "iv_hex": "1234567890abcdef...",
     "input_hex": "48656c6c6f20576f726c64",
     "output_hex": "8b7df143d91c7169...",
     "plaintext": "Hello World",
     "stack_trace": ["com.example.CryptoManager.encrypt()", "..."],
     "timestamp": "2024-08-20T10:30:00.000Z"
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

**FILE_SYSTEM**
   File operations

.. code-block:: json

   {
     "event_type": "file.write",
     "operation": "write",
     "file_path": "/data/data/com.example.app/shared_prefs/config.xml",
     "size": 256,
     "content_preview": "<?xml version=\"1.0\" encoding=\"utf-8\"?>...",
     "permissions": "rw-rw----",
     "timestamp": "2024-08-20T10:30:30.000Z"
   }

**BYPASS_DETECTION**
   Anti-analysis bypass events

.. code-block:: json

   {
     "event_type": "bypass.root.file_check",
     "bypass_category": "root_detection",
     "detection_method": "File.exists()",
     "file_path": "/system/bin/su",
     "original_result": true,
     "bypassed_result": false,
     "action": "file_check_bypassed",
     "metadata": {
       "description": "Root detection via file existence check",
       "severity": "high",
       "mitre_technique": "T1622"
     },
     "timestamp": "2024-08-20T10:30:45.000Z"
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

File Naming Convention
^^^^^^^^^^^^^^^^^^^^^^

JSON profiles are automatically named with timestamps:

.. code-block:: text

   profile_<target>_<timestamp>.json

Examples:
   - ``profile_com.banking.app_2024-08-20_10-30-45.json``
   - ``profile_1234_2024-08-20_15-45-30.json``
   - ``profile_unknown_app_2024-08-20_09-15-22.json``

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
   ammm -v --hooks-crypto com.example.app
   
   # Check file permissions
   ls -la profile_*.json
   
   # Validate JSON syntax
   python3 -m json.tool profile_example.json

Next Steps
----------

- Learn about the Python API: :doc:`../api/python-api`
- Explore development workflows: :doc:`../development/index`
- Check troubleshooting guide: :doc:`../troubleshooting`
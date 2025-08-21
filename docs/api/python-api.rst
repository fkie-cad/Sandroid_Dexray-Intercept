Python API Reference
====================

This section documents the Python API for Dexray Intercept, enabling programmatic control and analysis capabilities.

Core Classes
------------

AppProfiler
^^^^^^^^^^^

.. autoclass:: dexray_intercept.AppProfiler
   :members:
   :undoc-members:

The main orchestrator class that coordinates Frida instrumentation, event collection, and profile generation.

**Constructor Parameters:**

.. code-block:: python

   AppProfiler(
       process,                    # Frida process session
       verbose_mode=False,         # Enable verbose output
       output_format="CMD",        # Output format ("CMD" or "JSON")  
       base_path=None,            # Base path for file dumps
       deactivate_unlink=False,   # Disable file unlinking
       path_filters=None,         # Path filters for filesystem events
       hook_config=None,          # Hook configuration dict
       enable_stacktrace=False,   # Enable stack traces
       enable_fritap=False,       # Enable friTap integration
       fritap_output_dir="./fritap_output",  # friTap output directory
       target_name=None,          # Target app name
       spawn_mode=False,          # Whether target was spawned
       custom_scripts=None        # List of custom script paths
   )

**Basic Usage:**

.. code-block:: python

   from dexray_intercept import AppProfiler
   import frida

   # Connect to device and attach to app
   device = frida.get_usb_device()
   session = device.attach("com.example.app")

   # Create profiler with crypto and network monitoring
   profiler = AppProfiler(
       session,
       hook_config={
           'aes_hooks': True,
           'web_hooks': True,
           'bypass_hooks': True
       },
       verbose_mode=True
   )

   # Start profiling
   script = profiler.start_profiling("com.example.app")

   # Let app run and collect events...
   input("Press Enter to stop...")

   # Stop and get results
   profiler.stop_profiling()
   profile_data = profiler.get_profile_data()

**Key Methods:**

.. py:method:: start_profiling(app_name=None)

   Start the profiling process and load Frida scripts.
   
   :param app_name: Name of target application
   :returns: Loaded Frida script instance
   :rtype: frida.core.Script
   
   .. code-block:: python
   
      script = profiler.start_profiling("com.banking.app")

.. py:method:: stop_profiling()

   Stop profiling and cleanup resources including friTap processes.
   
   .. code-block:: python
   
      profiler.stop_profiling()

.. py:method:: get_profile_data()

   Get the collected profile data object.
   
   :returns: Profile data containing all events
   :rtype: ProfileData
   
   .. code-block:: python
   
      data = profiler.get_profile_data()
      crypto_events = data.get_events('CRYPTO_AES')

.. py:method:: write_profiling_log(filename="profile.json")

   Write profile data to JSON file with timestamp.
   
   :param filename: Base filename for output
   :returns: Generated filename with timestamp
   :rtype: str
   
   .. code-block:: python
   
      output_file = profiler.write_profiling_log("banking_analysis")
      print(f"Profile saved to: {output_file}")

**Hook Management:**

.. py:method:: enable_hook(hook_name, enabled=True)

   Enable or disable a specific hook at runtime.
   
   :param hook_name: Name of hook to control
   :param enabled: Whether to enable (True) or disable (False)
   
   .. code-block:: python
   
      # Enable AES hooks during runtime
      profiler.enable_hook('aes_hooks', True)
      
      # Disable web hooks
      profiler.enable_hook('web_hooks', False)

.. py:method:: get_enabled_hooks()

   Get list of currently enabled hooks.
   
   :returns: List of enabled hook names
   :rtype: List[str]
   
   .. code-block:: python
   
      enabled = profiler.get_enabled_hooks()
      print(f"Active hooks: {enabled}")

.. py:method:: enable_all_hooks()

   Enable all available hook categories.
   
   .. code-block:: python
   
      profiler.enable_all_hooks()

ProfileData
^^^^^^^^^^^

.. autoclass:: dexray_intercept.models.profile.ProfileData
   :members:
   :undoc-members:

Container class for organizing collected events by category with metadata.

**Basic Usage:**

.. code-block:: python

   # Get profile data from profiler
   profile_data = profiler.get_profile_data()

   # Access events by category  
   crypto_events = profile_data.get_events('CRYPTO_AES')
   network_events = profile_data.get_events('WEB')

   # Get metadata
   total_events = profile_data.get_event_count()
   categories = profile_data.get_categories()

   # Convert to JSON
   json_string = profile_data.to_json()
   
   # Save to file
   filename = profile_data.write_to_file("analysis_results.json")

**Key Methods:**

.. py:method:: get_events(category)

   Get all events for a specific category.
   
   :param category: Event category name (e.g., 'CRYPTO_AES', 'WEB')
   :returns: List of events in category
   :rtype: List[Event]

.. py:method:: get_categories()

   Get all available event categories.
   
   :returns: List of category names
   :rtype: List[str]

.. py:method:: get_event_count(category=None)

   Get event count for category or total.
   
   :param category: Specific category or None for total
   :returns: Number of events
   :rtype: int

.. py:method:: to_json(indent=4)

   Convert profile data to JSON string.
   
   :param indent: JSON indentation level
   :returns: JSON representation
   :rtype: str

.. py:method:: write_to_file(filename)

   Write profile data to timestamped JSON file.
   
   :param filename: Base filename
   :returns: Generated filename with timestamp
   :rtype: str

Event Classes
-------------

Base Event
^^^^^^^^^^

.. autoclass:: dexray_intercept.models.events.Event
   :members:
   :undoc-members:

Base class for all event types providing common functionality.

**Common Properties:**
   - ``event_type`` - Specific event type identifier
   - ``timestamp`` - ISO 8601 timestamp
   - ``metadata`` - Additional metadata dictionary

**Usage:**

.. code-block:: python

   for event in crypto_events:
       print(f"Event: {event.event_type}")
       print(f"Time: {event.timestamp}")
       print(f"Data: {event.get_event_data()}")

CryptoEvent
^^^^^^^^^^^

.. autoclass:: dexray_intercept.models.events.CryptoEvent
   :members:
   :undoc-members:

Specialized event for cryptographic operations.

**Properties:**
   - ``algorithm`` - Cryptographic algorithm used
   - ``operation_mode`` - Encryption/decryption mode
   - ``key_hex`` - Hexadecimal key representation  
   - ``iv_hex`` - Initialization vector
   - ``plaintext`` - Extracted plaintext (when available)

**Usage:**

.. code-block:: python

   crypto_events = profile_data.get_events('CRYPTO_AES')
   for event in crypto_events:
       if event.algorithm == 'AES':
           print(f"AES operation: {event.operation_mode_desc}")
           print(f"Key length: {event.key_length} bytes")
           if event.plaintext:
               print(f"Plaintext: {event.plaintext}")

NetworkEvent
^^^^^^^^^^^^

.. autoclass:: dexray_intercept.models.events.NetworkEvent
   :members:
   :undoc-members:

Event for network communications.

**Properties:**
   - ``url`` - Request URL
   - ``method`` - HTTP method
   - ``headers`` - Request/response headers
   - ``body_preview`` - Preview of request/response body
   - ``library`` - Network library used (OkHttp, Retrofit, etc.)

**Usage:**

.. code-block:: python

   network_events = profile_data.get_events('WEB')
   for event in network_events:
       if event.url:
           print(f"{event.method} {event.url}")
           if event.headers:
               print(f"Headers: {event.headers}")

Parsing and Processing
----------------------

Event Parsers
^^^^^^^^^^^^^

Parsers convert raw Frida messages into structured Event objects.

**Parser Factory:**

.. code-block:: python

   from dexray_intercept.parsers.factory import parser_factory

   # Get parser for category
   crypto_parser = parser_factory.get_parser('CRYPTO_AES')
   
   # Parse raw event data
   event = crypto_parser.parse(raw_json_string, timestamp)

**Custom Parsers:**

.. code-block:: python

   from dexray_intercept.parsers.base import BaseParser
   from dexray_intercept.models.events import Event

   class CustomParser(BaseParser):
       def parse_json_data(self, data, timestamp):
           # Create custom event from data
           event = CustomEvent(data['event_type'], timestamp)
           event.custom_field = data.get('custom_field')
           return event

   # Register custom parser
   parser_factory.register_parser('CUSTOM_CATEGORY', CustomParser())

Profile Collection
^^^^^^^^^^^^^^^^^^

.. autoclass:: dexray_intercept.services.profile_collector.ProfileCollector
   :members:
   :undoc-members:

Handles event collection and processing from Frida messages.

**Usage:**

.. code-block:: python

   from dexray_intercept.services.profile_collector import ProfileCollector

   collector = ProfileCollector(
       output_format="JSON",
       verbose_mode=True,
       enable_stacktrace=True
   )

   # Process Frida message
   success = collector.process_frida_message(message, data)

   # Get collected data
   profile_data = collector.get_profile_data()

Hook Management
---------------

HookManager
^^^^^^^^^^^

.. autoclass:: dexray_intercept.services.hook_manager.HookManager
   :members:
   :undoc-members:

Manages hook configuration and state.

**Usage:**

.. code-block:: python

   from dexray_intercept.services.hook_manager import HookManager

   # Create with initial config
   hook_config = {
       'aes_hooks': True,
       'web_hooks': True,
       'bypass_hooks': False
   }
   
   manager = HookManager(hook_config)

   # Runtime management
   manager.enable_hook('bypass_hooks', True)
   enabled_hooks = manager.get_enabled_hooks()
   
   # Get full configuration
   config = manager.get_hook_config()

Frida Integration
-----------------

InstrumentationService
^^^^^^^^^^^^^^^^^^^^^^

.. autoclass:: dexray_intercept.services.instrumentation.InstrumentationService
   :members:
   :undoc-members:

Manages Frida script loading and communication.

**Usage:**

.. code-block:: python

   from dexray_intercept.services.instrumentation import InstrumentationService

   service = InstrumentationService(
       process_session,
       custom_scripts=['./my_hooks.js']
   )

   # Set message handler
   service.set_message_handler(message_callback)

   # Load and start script
   script = service.load_script()

   # Send message to script
   service.send_message({'type': 'config', 'data': config})

Utility Functions
-----------------

Device Management
^^^^^^^^^^^^^^^^^

.. code-block:: python

   from dexray_intercept.services.instrumentation import setup_frida_device

   # Connect to USB device
   device = setup_frida_device()

   # Connect to remote device  
   device = setup_frida_device("192.168.1.100:27042")

   # Enable spawn gating
   device = setup_frida_device(enable_spawn_gating=True)

Command Line Integration
^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from dexray_intercept.ammm import parse_hook_config
   from argparse import Namespace

   # Parse CLI arguments to hook config
   args = Namespace()
   args.hooks_crypto = True
   args.enable_bypass = True
   
   hook_config = parse_hook_config(args)
   # Result: {'aes_hooks': True, 'encodings_hooks': True, 'keystore_hooks': True, 'bypass_hooks': True}

Advanced Usage Patterns
------------------------

Real-time Event Processing
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   class RealTimeAnalyzer:
       def __init__(self):
           self.alerts = []
           
       def message_handler(self, message, data):
           payload = message.get('payload', {})
           
           # Real-time analysis
           if payload.get('profileType') == 'CRYPTO_AES':
               self.analyze_crypto_event(payload)
           elif payload.get('profileType') == 'BYPASS_DETECTION':
               self.analyze_bypass_event(payload)
               
       def analyze_crypto_event(self, payload):
           # Check for weak encryption
           content = payload.get('profileContent', {})
           if content.get('key_length', 0) < 16:
               self.alerts.append("Weak encryption detected")
               
       def analyze_bypass_event(self, payload):
           # Alert on evasion attempts
           content = payload.get('profileContent', {})
           if content.get('bypass_category') == 'root_detection':
               self.alerts.append("Root detection evasion detected")

   # Usage
   analyzer = RealTimeAnalyzer()
   profiler = AppProfiler(session)
   profiler.instrumentation.set_message_handler(analyzer.message_handler)

Custom Event Types
^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from dexray_intercept.models.events import Event

   class CustomEvent(Event):
       def __init__(self, event_type, timestamp):
           super().__init__(event_type, timestamp)
           self.custom_data = {}
           
       def get_event_data(self):
           data = super().get_event_data()
           data.update(self.custom_data)
           return data

   # Custom processor
   class CustomProfileCollector(ProfileCollector):
       def _handle_custom_events(self, content, timestamp):
           event = CustomEvent("custom.event", timestamp)
           event.custom_data = content
           self.profile_data.add_event("CUSTOM", event)
           return True

Batch Processing
^^^^^^^^^^^^^^^^

.. code-block:: python

   import glob
   import json

   def analyze_profile_batch(profile_pattern):
       results = {}
       
       for profile_path in glob.glob(profile_pattern):
           with open(profile_path, 'r') as f:
               profile = json.load(f)
               
           # Analyze profile
           results[profile_path] = {
               'total_events': profile.get('_metadata', {}).get('total_events', 0),
               'crypto_events': len(profile.get('CRYPTO_AES', [])),
               'network_events': len(profile.get('WEB', [])),
               'bypass_events': len(profile.get('BYPASS_DETECTION', []))
           }
           
       return results

   # Usage
   batch_results = analyze_profile_batch("./analysis_*/profile_*.json")

Error Handling
--------------

Exception Classes
^^^^^^^^^^^^^^^^^

.. autoclass:: dexray_intercept.services.instrumentation.FridaBasedException
   :members:
   :undoc-members:

Custom exception for Frida-related errors.

**Common Error Scenarios:**

.. code-block:: python

   from dexray_intercept import AppProfiler, FridaBasedException
   import frida

   try:
       device = frida.get_usb_device()
       session = device.attach("com.example.app")
       profiler = AppProfiler(session)
       profiler.start_profiling()
       
   except frida.ProcessNotFoundError:
       print("Target app not found or not running")
   except frida.TransportError:
       print("Connection to device lost")
   except FridaBasedException as e:
       print(f"Frida instrumentation error: {e}")
   except Exception as e:
       print(f"Unexpected error: {e}")

Best Practices
--------------

**Resource Management:**

.. code-block:: python

   # Always cleanup resources
   try:
       profiler = AppProfiler(session)
       profiler.start_profiling()
       # ... analysis code ...
   finally:
       profiler.stop_profiling()

**Performance Optimization:**

.. code-block:: python

   # Use selective hooks for better performance
   hook_config = {
       'aes_hooks': True,        # Only what you need
       'web_hooks': True,
       # 'hooks_all': False     # Avoid unless necessary
   }

   # Process events efficiently
   def efficient_message_handler(message, data):
       payload = message.get('payload', {})
       
       # Quick filtering
       if payload.get('profileType') not in ['CRYPTO_AES', 'WEB']:
           return
           
       # Process only relevant events
       process_relevant_event(payload)

**Threading Considerations:**

.. code-block:: python

   import threading
   from queue import Queue

   class ThreadSafeAnalyzer:
       def __init__(self):
           self.event_queue = Queue()
           self.processing_thread = threading.Thread(target=self.process_events)
           self.processing_thread.daemon = True
           self.processing_thread.start()
           
       def message_handler(self, message, data):
           # Add to queue for background processing
           self.event_queue.put((message, data))
           
       def process_events(self):
           while True:
               message, data = self.event_queue.get()
               # Process in background thread
               self.analyze_event(message, data)
               self.event_queue.task_done()

Integration Examples
--------------------

**Threat Intelligence Integration:**

.. code-block:: python

   class ThreatIntelIntegrator:
       def __init__(self, ti_api_key):
           self.ti_api = ThreatIntelAPI(ti_api_key)
           
       def analyze_profile(self, profile_data):
           # Extract IOCs
           iocs = self.extract_iocs(profile_data)
           
           # Check against threat intelligence
           for ioc in iocs['domains']:
               threat_info = self.ti_api.check_domain(ioc)
               if threat_info.is_malicious:
                   print(f"Malicious domain detected: {ioc}")
                   
       def extract_iocs(self, profile_data):
           iocs = {'domains': [], 'ips': [], 'urls': []}
           
           for event in profile_data.get_events('WEB'):
               if hasattr(event, 'url') and event.url:
                   iocs['urls'].append(event.url)
                   # Extract domain from URL
                   from urllib.parse import urlparse
                   domain = urlparse(event.url).netloc
                   iocs['domains'].append(domain)
                   
           return iocs

**SIEM Integration:**

.. code-block:: python

   import syslog

   class SIEMIntegrator:
       def __init__(self):
           syslog.openlog("dexray-intercept")
           
       def send_alert(self, event):
           severity = self.get_severity(event)
           message = self.format_siem_message(event)
           syslog.syslog(severity, message)
           
       def get_severity(self, event):
           if hasattr(event, 'bypass_category'):
               return syslog.LOG_CRIT  # Critical for bypass attempts
           elif event.event_type.startswith('crypto'):
               return syslog.LOG_WARNING
           else:
               return syslog.LOG_INFO
               
       def format_siem_message(self, event):
           return f"dexray_event={event.event_type} timestamp={event.timestamp} data={event.get_event_data()}"

Next Steps
----------

- Explore TypeScript API for custom hooks: :doc:`typescript-api`
- Learn about development workflows: :doc:`../development/index`
- See practical examples in the user guide: :doc:`../user-guide/index`
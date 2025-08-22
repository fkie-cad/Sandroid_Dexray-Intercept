Development Guide
=================

This section provides comprehensive guidance for developers who want to extend, modify, or contribute to Dexray Intercept.

.. toctree::
   :maxdepth: 2

   creating-hooks

Overview
--------

Dexray Intercept is designed to be extensible at multiple levels:

**Hook Development**
   Create new TypeScript hooks to monitor specific Android behaviors not covered by built-in hooks.

**Parser Development**  
   Extend Python parsers to process new event types and extract meaningful insights.

**Core Development**
   Modify the core instrumentation engine, CLI interface, or analysis capabilities.

**Integration Development**
   Build tools and integrations that consume Dexray Intercept profiles for specialized analysis workflows.

Architecture for Developers
---------------------------

Understanding the System Flow
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: text

   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
   │   CLI Frontend  │    │  Core Services  │    │ Frida Backend   │
   │                 │    │                 │    │                 │
   │ • ammm.py       │    │ • AppProfiler   │    │ • TypeScript    │
   │ • Argument      │◄──►│ • HookManager   │◄──►│   Hooks         │
   │   Parsing       │    │ • ProfileData   │    │ • am_send()     │  
   │ • Hook Config   │    │ • EventParsers  │    │ • Java.perform  │
   └─────────────────┘    └─────────────────┘    └─────────────────┘
           │                       │                       │
           ▼                       ▼                       ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │                    Target Android Process                       │
   │                                                                 │
   │  JavaScript hooks execute in target process context             │
   └─────────────────────────────────────────────────────────────────┘

**Key Integration Points:**

1. **TypeScript → JavaScript**: ``frida-compile`` converts TypeScript hooks to JavaScript (via ``frida-compile agent/hooking_profile_loader.ts -o src/dexray_intercept/profiling.js``)
2. **JavaScript → Python**: ``am_send()`` passes structured event data to Python
3. **Python Processing**: Events are parsed, formatted, and stored in profiles
4. **CLI Integration**: New hooks require CLI parameter additions

Development Environment Setup
-----------------------------

Prerequisites
^^^^^^^^^^^^^

.. code-block:: bash

   # Install development dependencies
   npm install
   python3 -m pip install -e ".[dev]"

   # Install development tools
   npm install -g typescript
   npm install -g @types/node

**Recommended Development Tools:**
   - **VS Code** with TypeScript and Python extensions
   - **Android Studio** for APK analysis
   - **Frida DevTools** for live debugging
   - **Wireshark** for network analysis validation

Project Structure
^^^^^^^^^^^^^^^^^

.. code-block:: text

   Sandroid_Dexray-Intercept/
   ├── agent/                          # TypeScript hooks
   │   ├── hooking_profile_loader.ts   # Main hook orchestrator
   │   ├── crypto/                     # Cryptography hooks
   │   ├── network/                    # Network hooks
   │   ├── security/                   # Anti-analysis bypass hooks
   │   └── utils/                      # Shared utilities
   ├── src/dexray_intercept/          # Python package
   │   ├── ammm.py                     # CLI entry point
   │   ├── appProfiling.py             # Main profiler class
   │   ├── parsers/                    # Event parsers
   │   ├── models/                     # Data models
   │   └── services/                   # Core services
   ├── docs/                           # Documentation
   ├── tests/                          # Test suite
   └── package.json                    # Node.js dependencies

Development Workflow
--------------------

Standard Development Cycle
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # 1. Make changes to TypeScript hooks
   vim agent/my_category/my_hooks.ts

   # 2. Compile to JavaScript  
   npm run build

   # 3. Test with target application
   dexray-intercept --enable-my-hooks com.test.app

   # 4. Validate JSON output
   cat profile_com.test.app_*.json | jq .

   # 5. Run tests
   python3 -m pytest tests/

   # 6. Commit changes
   git add .
   git commit -m "Add new hook category: my_hooks"

Hook Development Cycle
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Development mode with auto-compilation
   npm run watch &                     # Auto-compile on changes
   
   # Test iteration
   while true; do
       dexray-intercept -v --enable-my-hooks com.test.app
       # Review output, make changes, repeat
   done

Core Development Areas
----------------------

Hook Categories
^^^^^^^^^^^^^^^

**Existing Categories:**
   - ``agent/crypto/`` - Cryptographic operations
   - ``agent/network/`` - Network communications  
   - ``agent/file/`` - File system operations
   - ``agent/ipc/`` - Inter-process communication
   - ``agent/process/`` - Process and runtime monitoring
   - ``agent/services/`` - Android system services
   - ``agent/security/`` - Anti-analysis bypass

**Creating New Categories:**
   1. Create directory under ``agent/``
   2. Implement hook functions following established patterns
   3. Add to ``hooking_profile_loader.ts`` for integration
   4. Create corresponding Python parsers
   5. Add CLI support in ``dexray-intercept.py``

Parser Development
^^^^^^^^^^^^^^^^^^

**Parser Structure:**

.. code-block:: python

   # src/dexray_intercept/parsers/my_category.py
   from .base import BaseParser
   from ..models.events import Event

   class MyCategoryEvent(Event):
       def __init__(self, event_type: str, timestamp: str):
           super().__init__(event_type, timestamp)
           self.custom_field = None
       
       def get_event_data(self):
           return {
               "event_type": self.event_type,
               "custom_field": self.custom_field,
               "timestamp": self.timestamp
           }

   class MyCategoryParser(BaseParser):
       def parse_json_data(self, data: dict, timestamp: str):
           event = MyCategoryEvent(data.get('event_type'), timestamp)
           event.custom_field = data.get('custom_field')
           
           # Add metadata for enhanced analysis
           event.add_metadata('category', 'my_category')
           event.add_metadata('severity', 'medium')
           
           return event

**Parser Registration:**

.. code-block:: python

   # src/dexray_intercept/parsers/factory.py
   from .my_category import MyCategoryParser

   def _register_default_parsers(self):
       self._parsers["MY_CATEGORY"] = MyCategoryParser()

Testing and Validation
-----------------------

Unit Testing
^^^^^^^^^^^^

.. code-block:: python

   # tests/test_my_parser.py
   import unittest
   from dexray_intercept.parsers.my_category import MyCategoryParser

   class TestMyCategoryParser(unittest.TestCase):
       def setUp(self):
           self.parser = MyCategoryParser()
       
       def test_parse_json_data(self):
           test_data = {
               'event_type': 'my_category.test',
               'custom_field': 'test_value'
           }
           
           event = self.parser.parse_json_data(test_data, '2024-08-20T10:30:00Z')
           
           self.assertEqual(event.event_type, 'my_category.test')
           self.assertEqual(event.custom_field, 'test_value')

Integration Testing
^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Test hook integration
   python3 tests/integration/test_hook_integration.py

   # Test with real app (requires device)
   python3 tests/integration/test_real_app.py com.example.testapp

Manual Testing
^^^^^^^^^^^^^^

.. code-block:: bash

   # Test specific hook categories
   dexray-intercept -v --enable-my-hooks com.test.app

   # Test with malware samples (use caution)
   dexray-intercept --hooks-bypass --enable-my-hooks malware.apk

   # Validate output format
   python3 -c "
   import json
   with open('profile.json') as f: 
       data = json.load(f)
       print(f'Events: {data.get(\"_metadata\", {}).get(\"total_events\", 0)}')
   "

Performance Testing
^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   # tests/performance/test_hook_performance.py
   import time
   from dexray_intercept import AppProfiler

   def test_hook_performance():
       start_time = time.time()
       
       # Run profiler with hooks
       profiler = AppProfiler(session, hook_config={'my_hooks': True})
       profiler.start_profiling()
       
       # Let app run for measured time
       time.sleep(30)
       
       profiler.stop_profiling()
       duration = time.time() - start_time
       
       # Validate performance impact
       assert duration < 35  # Should not add more than 5s overhead

Documentation Standards
-----------------------

Code Documentation
^^^^^^^^^^^^^^^^^^

**TypeScript Hooks:**

.. code-block:: typescript

   /**
    * Install hooks for monitoring custom Android behavior
    * 
    * This function hooks into com.example.CustomClass methods to track
    * sensitive operations and data access patterns.
    * 
    * Events generated:
    * - custom.method.called: When sensitiveMethod is invoked
    * - custom.data.access: When data access occurs
    * 
    * @example
    * // Enable in hook config
    * hook_config = { 'custom_hooks': true }
    */
   export function install_custom_hooks(): void {

**Python Classes:**

.. code-block:: python

   class CustomEvent(Event):
       """Event representing custom Android behavior.
       
       This event captures information about custom operations
       including method calls, data access, and timing information.
       
       Args:
           event_type: Specific event identifier (e.g., 'custom.method.called')
           timestamp: ISO 8601 timestamp when event occurred
           
       Example:
           >>> event = CustomEvent('custom.method.called', '2024-08-20T10:30:00Z')
           >>> event.method_name = 'sensitiveMethod'
           >>> event.get_event_data()
           {'event_type': 'custom.method.called', 'method_name': 'sensitiveMethod'}
       """

API Documentation
^^^^^^^^^^^^^^^^^

All public APIs should include:
   1. **Purpose and behavior description**
   2. **Parameter documentation with types**
   3. **Return value documentation**  
   4. **Usage examples**
   5. **Exception handling notes**

User Documentation
^^^^^^^^^^^^^^^^^^

New features require:
   1. **CLI usage examples** in user guide
   2. **Hook configuration documentation**
   3. **Event format specifications**
   4. **Integration examples**

Contributing Workflow
---------------------

Development Process
^^^^^^^^^^^^^^^^^^^

1. **Fork and Clone**

.. code-block:: bash

   git clone https://github.com/your-username/Sandroid_Dexray-Intercept.git
   cd Sandroid_Dexray-Intercept

2. **Create Feature Branch**

.. code-block:: bash

   git checkout -b feature/my-new-hook-category
   git checkout -b fix/parser-bug
   git checkout -b docs/improve-api-reference

3. **Development and Testing**

.. code-block:: bash

   # Make changes
   vim agent/my_category/my_hooks.ts
   vim src/dexray_intercept/parsers/my_category.py

   # Test changes
   npm run build
   python3 -m pytest tests/
   dexray-intercept --enable-my-category com.test.app

4. **Documentation**

.. code-block:: bash

   # Update documentation
   vim docs/user-guide/hook-configuration.rst
   vim docs/api/typescript-api.rst

   # Build and verify docs
   cd docs/
   make html

5. **Commit and Push**

.. code-block:: bash

   git add .
   git commit -m "Add new hook category for monitoring XYZ behavior"
   git push origin feature/my-new-hook-category

6. **Create Pull Request**
   - Describe changes and motivation
   - Include testing instructions
   - Reference related issues

Code Standards
^^^^^^^^^^^^^^

**TypeScript Style:**
   - Use TypeScript strict mode
   - Follow established naming conventions
   - Include comprehensive error handling
   - Document complex logic with comments

**Python Style:**  
   - Follow PEP 8 conventions
   - Use type hints for function signatures
   - Include docstrings for public methods
   - Handle exceptions appropriately

**Testing Requirements:**
   - Unit tests for new parsers
   - Integration tests for new hook categories
   - Performance testing for potentially heavy hooks
   - Documentation examples should be tested

Quality Assurance
-----------------

Pre-commit Checks
^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Run before committing
   npm run build                    # Ensure TypeScript compiles
   python3 -m pytest tests/        # Run test suite
   ruff check .                     # Python linting
   python3 -m mypy src/            # Type checking

Continuous Integration
^^^^^^^^^^^^^^^^^^^^^^

The project uses automated testing for:
   - **TypeScript compilation validation**
   - **Python unit and integration tests**
   - **Code quality and style checks** 
   - **Documentation build verification**

Release Process
^^^^^^^^^^^^^^^

.. code-block:: bash

   # Version bump
   npm version patch|minor|major

   # Update changelog
   vim CHANGELOG.md

   # Tag release
   git tag -a v0.3.1 -m "Release version 0.3.1"
   git push origin v0.3.1

Common Development Tasks
------------------------

Adding a New Hook Category
^^^^^^^^^^^^^^^^^^^^^^^^^^

See detailed guide: :doc:`creating-hooks`

Adding CLI Parameters
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   # In src/dexray_intercept/ammm.py

   # Add argument
   hooks.add_argument("--enable-my-feature", action="store_true", 
                      help="Enable my feature monitoring")

   # Add to individual hooks mapping
   individual_hooks = {
       'enable_my_feature': 'my_feature_hooks'
   }

Debugging Hook Issues
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Enable verbose mode
   dexray-intercept -v --enable-problematic-hook com.test.app

   # Check JavaScript compilation
   cat src/dexray_intercept/profiling.js | grep "my_hook_function"

   # Test with minimal app
   dexray-intercept --enable-problematic-hook com.android.calculator

   # Validate JSON output
   python3 -m json.tool profile_*.json

Extending Event Types
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   # Create new event class in src/dexray_intercept/models/events.py
   class MyCustomEvent(Event):
       def __init__(self, event_type: str, timestamp: str):
           super().__init__(event_type, timestamp)
           self.custom_property = None

   # Update parser to use new event type
   # Update factory registration
   # Add to __all__ exports

Next Steps
----------

Choose your development focus:

- **Creating new hooks**: :doc:`creating-hooks`
- **Understanding build process**: :doc:`building`
- **Contributing guidelines**: :doc:`contributing`

For questions or discussions:

- **GitHub Issues**: Technical questions and bug reports
- **GitHub Discussions**: Development discussions and feature requests
- **Pull Requests**: Code contributions and improvements
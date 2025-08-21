API Reference
=============

This section provides comprehensive API documentation for both Python and TypeScript components of Dexray Intercept.

.. toctree::
   :maxdepth: 2

   python-api
   typescript-api

Overview
--------

Dexray Intercept provides APIs at two levels:

**Python API**
   High-level interface for creating analysis tools, managing profiles, and processing events. Used for:
   
   - Building custom analysis applications
   - Processing profile data programmatically  
   - Extending the CLI functionality
   - Integrating with other security tools

**TypeScript API**
   Low-level Frida instrumentation interface for creating custom hooks. Used for:
   
   - Developing new hook categories
   - Creating application-specific instrumentation
   - Extending built-in monitoring capabilities
   - Implementing custom bypass techniques

Architecture Integration
------------------------

.. code-block:: text

   ┌─────────────────┐    ┌──────────────────┐
   │   Python API    │    │   TypeScript API │
   │                 │    │                  │
   │ • AppProfiler   │    │ • Hook Functions │
   │ • ProfileData   │◄───┤ • Event Creation │
   │ • EventParsers  │    │ • am_send()      │
   │ • HookManager   │    │ • Java.perform() │
   └─────────────────┘    └──────────────────┘
           │                       │
           ▼                       ▼
   ┌─────────────────────────────────────────┐
   │            Frida Runtime                │
   │                                         │
   │ JavaScript executed in target process   │
   └─────────────────────────────────────────┘

Development Workflow
--------------------

**Creating Analysis Tools (Python)**

1. Import the API components
2. Configure hook settings
3. Create AppProfiler instance
4. Process events and generate reports

**Creating Custom Hooks (TypeScript)**

1. Write hook functions following API patterns
2. Compile with frida-compile
3. Integrate with hook loader
4. Test with target applications

Quick Examples
--------------

**Python API Usage:**

.. code-block:: python

   from dexray_intercept import AppProfiler
   
   # Create profiler with specific hooks
   profiler = AppProfiler(
       process_session,
       hook_config={
           'aes_hooks': True,
           'web_hooks': True,
           'bypass_hooks': True
       }
   )
   
   # Start analysis
   profiler.start_profiling("com.example.app")
   
   # Process results
   profile_data = profiler.get_profile_data()
   crypto_events = profile_data.get_events('CRYPTO_AES')

**TypeScript API Usage:**

.. code-block:: typescript

   import { am_send, createCryptoEvent } from "../utils/logging.js"
   
   export function install_custom_hooks() {
       Java.perform(() => {
           const MyClass = Java.use("com.example.MyClass");
           
           MyClass.sensitiveMethod.implementation = function(data) {
               // Create structured event
               createCryptoEvent("custom.operation", {
                   operation_type: "sensitive_method",
                   data_length: data.length,
                   timestamp: Date.now()
               });
               
               return this.sensitiveMethod(data);
           };
       });
   }

TypeScript Compilation
---------------------

All TypeScript hooks must be compiled to JavaScript before use:

.. code-block:: bash

   # Compile all hooks
   npm run build
   
   # Watch mode for development
   npm run watch
   
   # Manual compilation
   npx frida-compile agent/hooking_profile_loader.ts -o src/dexray_intercept/profiling.js

.. important::
   **Always run** ``npm run build`` **after modifying TypeScript hooks** to ensure changes are included in the Python package.

API Compatibility
-----------------

**Version Compatibility:**
   - Python API: Stable, backwards compatible
   - TypeScript API: Evolving, breaking changes possible between versions
   - Event formats: Versioned, parsers handle legacy formats

**Threading Considerations:**
   - Python API is thread-safe for most operations
   - Event processing occurs on background threads
   - UI updates should use main thread

**Error Handling:**
   - Python exceptions follow standard Python patterns
   - TypeScript errors are caught and logged
   - Network timeouts and device disconnections are handled gracefully

Getting Started
---------------

Choose your development path:

- **Building analysis tools**: Start with :doc:`python-api`
- **Creating custom hooks**: Begin with :doc:`typescript-api`
- **Both**: Review both APIs for complete understanding

Each API section includes:

- Complete class and function reference
- Usage examples and patterns
- Best practices and common pitfalls
- Integration guidelines
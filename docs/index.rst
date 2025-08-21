SanDroid - Dexray Intercept Documentation
==========================================

.. image:: https://img.shields.io/badge/version-0.3.0.1-blue.svg
   :target: https://github.com/fkie-cad/Sandroid_Dexray-Intercept
   :alt: Version

.. image:: https://img.shields.io/badge/python-3.6+-brightgreen.svg
   :target: https://python.org
   :alt: Python Version

.. image:: https://img.shields.io/badge/platform-Android-green.svg
   :target: https://developer.android.com
   :alt: Platform

Welcome to the documentation for **SanDroid - Dexray Intercept**, a comprehensive Frida-based Android malware analysis tool designed to create runtime profiles that track application behavior in real-time.

.. warning::
   This tool is designed for **defensive security analysis** only. The samples directory contains actual malware. 
   Use with extreme caution in isolated environments.

What is Dexray Intercept?
-------------------------

Dexray Intercept is part of the dynamic analysis sandbox SanDroid. It uses Frida dynamic instrumentation to:

* **Monitor Android app behavior** in real-time during execution
* **Intercept and log** cryptographic operations, network traffic, file system access, and IPC communications
* **Bypass common anti-analysis techniques** including root, Frida, debugger, and emulator detection
* **Generate comprehensive JSON profiles** for further analysis and threat intelligence
* **Support custom hooks** for specialized analysis requirements

Key Features
------------

🔍 **Comprehensive Monitoring**
   - Cryptographic operations (AES, encodings, keystore)
   - Network communications (HTTP/HTTPS, WebSockets, sockets)
   - File system and database operations
   - Inter-process communication (intents, broadcasts, binder)
   - System services (location, camera, telephony, clipboard)
   - DEX unpacking and native library loading

🛡️ **Anti-Analysis Bypass**
   - Root detection bypass
   - Frida detection bypass  
   - Debugger detection bypass
   - Emulator detection bypass
   - Hook framework detection bypass

🔧 **Advanced Capabilities**
   - TLS key extraction via integrated friTap
   - Custom Frida script loading
   - Selective hook configuration for performance
   - Real-time terminal output with structured JSON logging
   - Stack trace analysis for call origin tracking

📊 **Output Formats**
   - Structured JSON profiles with metadata
   - Real-time terminal logging
   - Integration with threat intelligence platforms

Quick Start
-----------

.. code-block:: bash

   # Install the package
   pip install -e .

   # Basic usage - attach to running app
   ammm com.example.app

   # Spawn app with crypto and network hooks
   ammm -s --hooks-crypto --hooks-network com.example.app

   # Comprehensive analysis with bypass hooks
   ammm -s --hooks-all --hooks-bypass com.example.app

   # Custom analysis with TLS extraction
   ammm -s --enable-fritap --custom-script ./my_hooks.js com.example.app

Architecture Overview
--------------------

Dexray Intercept uses a **dual-language architecture**:

**Python Frontend**
   - CLI interface and argument parsing
   - Frida session management and device connection
   - Event processing and JSON profile generation
   - Result analysis and output formatting

**TypeScript/JavaScript Backend** 
   - Frida hooks written in TypeScript
   - Compiled to JavaScript using ``frida-compile``
   - Real-time instrumentation of Android applications
   - Structured message passing to Python frontend

.. toctree::
   :maxdepth: 2
   :caption: User Guide

   installation
   quickstart
   user-guide/index

.. toctree::
   :maxdepth: 2
   :caption: API Reference

   api/index

.. toctree::
   :maxdepth: 2
   :caption: Development

   development/index

.. toctree::
   :maxdepth: 1
   :caption: Help & Support

   troubleshooting

Requirements
-----------

**Runtime Requirements:**
   - Python 3.6 or higher
   - Node.js (for TypeScript compilation)
   - Rooted Android device or emulator
   - frida-tools installed

**Development Requirements:**
   - TypeScript compiler
   - frida-compile for hook compilation
   - @types/frida-gum for TypeScript definitions

Contributing
-----------

Contributions are welcome! Please read our development guide for information on:

- Creating new hooks
- Adding parsers for new event types  
- Extending the CLI interface
- Writing tests and documentation

License
-------

This project is licensed under the MIT License. See the LICENSE file for details.

Support
-------

For issues, questions, or contributions:

- **GitHub Issues**: Report bugs and request features
- **Documentation**: This comprehensive guide
- **Code Examples**: See the user guide and API reference

Indices and Tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
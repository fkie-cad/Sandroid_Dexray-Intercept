Installation
============

This guide covers the installation and setup of Sandroid - Dexray Intercept.

System Requirements
------------------

**Operating System**
   - Linux (recommended)
   - macOS 
   - Windows (with WSL recommended)

**Runtime Requirements**
   - Python 3.6 or higher
   - Node.js 14+ (for TypeScript compilation)
   - Android device or emulator with root access
   - USB debugging enabled

**Hardware Requirements**
   - Minimum 4GB RAM (8GB recommended for complex apps)
   - At least 2GB free disk space
   - USB port for device connection (or network for remote devices)

Installation Steps
-----------------

1. Install Python Dependencies
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Clone the repository
   git clone https://github.com/fkie-cad/Sandroid_Dexray-Intercept.git
   cd Sandroid_Dexray-Intercept

   # Install Python package in development mode
   python3 -m pip install -e .

This will install the following dependencies:

- ``frida>=15.0.0`` - Core Frida framework
- ``frida-tools>=11.0.0`` - Frida command-line tools
- ``AndroidFridaManager>=1.8.3`` - Android device management
- ``fritap`` - TLS key extraction (optional but recommended)
- ``cxxfilt`` - C++ symbol demangling
- Additional utility libraries (colorama, etc.)

2. Install Node.js Dependencies
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Install TypeScript compilation tools
   npm install

This installs:

- ``frida-compile`` - Compiles TypeScript hooks to JavaScript
- ``@types/frida-gum`` - TypeScript definitions for Frida
- ``typescript`` - TypeScript compiler

3. Build the Project
^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Compile TypeScript hooks to JavaScript
   npm run build

   # Or use watch mode during development
   npm run watch

The build process compiles ``agent/hooking_profile_loader.ts`` and all hook modules into ``src/dexray_intercept/profiling.js``.

4. Prepare Android Device
^^^^^^^^^^^^^^^^^^^^^^^^^

**For Physical Device:**

.. code-block:: bash

   # Enable USB debugging and connect device
   adb devices

   # Root the device (method varies by device)
   # Ensure frida-server can run with root privileges

**For Emulator:**

.. code-block:: bash

   # Start Android emulator with root
   emulator -avd <your_avd> -writable-system

   # Or use pre-rooted emulator images

5. Verify Installation
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Check if dexray-intercept command is available
   dexray-intercept --version

   # Test Frida server installation (will auto-install if needed)
   dexray-intercept -f

   # Verify device connection
   dexray-intercept --help

Expected output should show the help menu with all available options.

Development Installation
-----------------------

For contributors and developers who want to modify hooks or extend functionality:

.. code-block:: bash

   # Install with development dependencies
   python3 -m pip install -e ".[dev]"

   # Install pre-commit hooks (if available)
   pre-commit install

   # Run tests
   python3 -m pytest tests/

   # Build documentation
   cd docs/
   make html

Docker Installation (Alternative)
---------------------------------

A Docker-based installation is available for isolated environments:

.. code-block:: bash

   # Build Docker image
   docker build -t dexray-intercept .

   # Run with device passthrough
   docker run --privileged -v /dev/bus/usb:/dev/bus/usb dexray-intercept

.. note::
   Docker installation requires additional setup for USB device passthrough and may have performance implications.

Troubleshooting Installation
---------------------------

**Common Issues:**

1. **Frida installation fails**
   
   .. code-block:: bash
   
      # Try installing specific Frida version
      pip install frida==17.2.16 frida-tools==14.4.5

2. **TypeScript compilation errors**
   
   .. code-block:: bash
   
      # Clear node_modules and reinstall
      rm -rf node_modules package-lock.json
      npm install

3. **Device not detected**
   
   .. code-block:: bash
   
      # Check ADB connection
      adb kill-server
      adb start-server
      adb devices

4. **Permission issues**
   
   .. code-block:: bash
   
      # Fix permissions on Linux
      sudo usermod -a -G plugdev $USER
      # Log out and log back in

5. **Frida server compatibility**
   
   .. code-block:: bash
   
      # Let dexray-intercept auto-install compatible version
      dexray-intercept -f

**Architecture-specific Issues:**

- **Apple M1/M2 Macs**: May require Rosetta 2 for some Node.js packages
- **Windows**: Use WSL or ensure Python and Node.js are in PATH
- **Linux ARM**: May need to compile Frida from source

Verification Steps
-----------------

After installation, verify everything works:

.. code-block:: bash

   # 1. Check Python package installation
   python3 -c "import dexray_intercept; print('✓ Python package installed')"

   # 2. Check CLI availability  
   dexray-intercept --version

   # 3. Verify TypeScript compilation
   ls -la src/dexray_intercept/profiling.js

   # 4. Test device connection
   dexray-intercept -f  # This installs frida-server

   # 5. Run a simple test
   dexray-intercept --help

If all steps complete without errors, your installation is ready for use.

Next Steps
----------

- Continue to :doc:`quickstart` for your first analysis
- Read the :doc:`user-guide/index` for detailed usage
- Check :doc:`troubleshooting` if you encounter issues
User Guide
==========

This comprehensive user guide covers all aspects of using SanDroid - Dexray Intercept for Android malware analysis and application behavior profiling.

.. toctree::
   :maxdepth: 2

   cli-usage
   hook-configuration
   output-formats

Overview
--------

Dexray Intercept is designed to provide deep insights into Android application behavior through dynamic instrumentation. Whether you're analyzing malware, auditing applications for security vulnerabilities, or conducting general behavioral analysis, this guide will help you make the most of the tool's capabilities.

Key Concepts
------------

**Hooks**
   Frida-based instrumentation points that intercept and log specific Android API calls and operations. Hooks are organized into logical categories and can be selectively enabled.

**Profiles** 
   JSON-formatted reports containing all intercepted events, organized by category with rich metadata and timestamps.

**Bypass Techniques**
   Specialized hooks that circumvent common anti-analysis methods used by malware and security-conscious applications.

**Custom Scripts**
   User-provided Frida scripts that extend the built-in functionality with application-specific monitoring logic.

Workflow
--------

A typical analysis workflow involves:

1. **Target Selection** - Choose the Android application to analyze
2. **Hook Configuration** - Select appropriate monitoring categories  
3. **Execution** - Run the analysis with chosen parameters
4. **Data Collection** - Monitor real-time events and collect data
5. **Analysis** - Process the generated JSON profile for insights

The sections below provide detailed guidance for each aspect of this workflow.

Getting Help
------------

If you need assistance:

- Check the :doc:`../troubleshooting` section for common issues
- Review the :doc:`../api/index` for programmatic usage
- Consult the :doc:`../development/index` for extending functionality

.. note::
   This tool is designed for **defensive security analysis**. Always ensure you have proper authorization before analyzing applications and handle malware samples with appropriate security precautions.
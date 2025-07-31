#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Primary API - New Architecture (default)
from .appProfiling import AppProfiler, FridaBasedException
from .services.hook_manager import HookManager
from .services.instrumentation import InstrumentationService, setup_frida_device
from .services.profile_collector import ProfileCollector
from .models.profile import ProfileData
from .parsers.factory import parser_factory
from .formatters.factory import formatter_factory

# Backward compatibility layer
from .compatibility import AppProfilerAdapter, create_app_profiler
from .appProfiling_legacy import AppProfiler as AppProfilerLegacy

# Legacy factory function (still available for migration period)
create_app_profiler_legacy = create_app_profiler

__all__ = [
    # Primary new API
    'AppProfiler', 'FridaBasedException',
    'HookManager', 'InstrumentationService', 'ProfileCollector', 'ProfileData',
    'parser_factory', 'formatter_factory', 'setup_frida_device',
    
    # Backward compatibility 
    'AppProfilerAdapter', 'AppProfilerLegacy', 'create_app_profiler_legacy'
]

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Compatibility layer for transitioning between old and new architectures.
This module allows gradual migration by providing feature flags and adapters.
"""

import os

# Feature flag to force old architecture (new architecture is now default)
FORCE_OLD_ARCHITECTURE = os.getenv('DEXRAY_FORCE_OLD_ARCH', 'false').lower() == 'true'

def get_app_profiler_class():
    """Get the appropriate AppProfiler class based on feature flag"""
    if FORCE_OLD_ARCHITECTURE:
        from .appProfiling_legacy import AppProfiler
        return AppProfiler
    else:
        from .appProfiling import AppProfiler
        return AppProfiler

def get_parser_module():
    """Get the appropriate parser module based on feature flag"""
    if FORCE_OLD_ARCHITECTURE:
        from . import parser_legacy as parser
        return parser
    else:
        from . import parser
        return parser

class AppProfilerAdapter:
    """
    Adapter class that provides a unified interface for both old and new AppProfiler implementations.
    This allows code to work with either implementation seamlessly.
    """
    
    def __init__(self, *args, **kwargs):
        AppProfilerClass = get_app_profiler_class()
        self._profiler = AppProfilerClass(*args, **kwargs)
        self._is_new_arch = not FORCE_OLD_ARCHITECTURE
    
    def __getattr__(self, name):
        """Delegate all attribute access to the underlying profiler"""
        return getattr(self._profiler, name)
    
    def start_profiling(self):
        """Unified method for starting profiling"""
        if self._is_new_arch:
            return self._profiler.start_profiling()
        else:
            return self._profiler.instrument()
    
    def stop_profiling(self):
        """Unified method for stopping profiling"""
        if self._is_new_arch:
            self._profiler.stop_profiling()
        else:
            self._profiler.finish_app_profiling()
    
    def get_profile_json(self):
        """Unified method for getting profile as JSON"""
        if self._is_new_arch:
            return self._profiler.get_profiling_log_as_json()
        else:
            return self._profiler.get_profiling_log_as_JSON()
    
    def write_profile(self, filename="profile.json"):
        """Unified method for writing profile to file"""
        return self._profiler.write_profiling_log(filename)


def create_app_profiler(*args, **kwargs) -> AppProfilerAdapter:
    """
    Factory function to create the appropriate AppProfiler instance.
    
    This function abstracts away the choice between old and new architecture,
    making it easy to switch implementations via environment variable.
    """
    if FORCE_OLD_ARCHITECTURE:
        # Use old implementation when explicitly requested
        from .appProfiling_legacy import AppProfiler
        return AppProfiler(*args, **kwargs)
    else:
        # Default to new architecture
        from .appProfiling import AppProfiler
        return AppProfiler(*args, **kwargs)
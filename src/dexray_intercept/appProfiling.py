#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import frida
from typing import Optional, List, Dict, Any

from .services.instrumentation import InstrumentationService, FridaBasedException, setup_frida_device
from .services.profile_collector import ProfileCollector
from .services.hook_manager import HookManager
from .models.profile import ProfileData


class AppProfiler:
    """
    Main application profiler class.
    
    This class orchestrates the profiling process by coordinating between:
    - InstrumentationService: Manages Frida script loading and communication
    - ProfileCollector: Handles event collection and processing
    - HookManager: Manages hook configuration
    """
    
    def __init__(self, process, verbose_mode: bool = False, output_format: str = "CMD", 
                 base_path: Optional[str] = None, deactivate_unlink: bool = False, 
                 path_filters: Optional[List[str]] = None, hook_config: Optional[Dict[str, bool]] = None, 
                 enable_stacktrace: bool = False):
        """
        Initialize the AppProfiler.
        
        Args:
            process: Frida process object
            verbose_mode: Enable verbose output
            output_format: Output format ("CMD" or "JSON")
            base_path: Base path for file dumps
            deactivate_unlink: Disable file unlinking
            path_filters: Path filters for file system events
            hook_config: Hook configuration dictionary
            enable_stacktrace: Enable stack traces
        """
        self.process = process
        self.verbose_mode = verbose_mode
        self.output_format = output_format
        self.deactivate_unlink = deactivate_unlink
        self.enable_stacktrace = enable_stacktrace
        
        # Initialize services
        self.instrumentation = InstrumentationService(process)
        self.profile_collector = ProfileCollector(
            output_format=output_format,
            verbose_mode=verbose_mode,
            enable_stacktrace=enable_stacktrace,
            path_filters=path_filters,
            base_path=base_path
        )
        self.hook_manager = HookManager(hook_config)
        
        # Set up message handling
        self.instrumentation.set_message_handler(self._message_handler)
        
        # State tracking
        self.startup = True
        self.startup_unlink = True
        self.path_filters_sent = False
    
    def start_profiling(self) -> frida.core.Script:
        """Start the profiling process"""
        try:
            script = self.instrumentation.load_script()
            return script
        except Exception as e:
            raise FridaBasedException(f"Failed to start profiling: {str(e)}")
    
    def stop_profiling(self):
        """Stop the profiling process"""
        self.instrumentation.unload_script()
    
    def _message_handler(self, message: Dict[str, Any], data: Any = None):
        """Handle messages from Frida script"""
        try:
            # Handle initial startup messages
            if self._handle_startup_messages(message):
                return
            
            # Process regular profile messages
            self.profile_collector.process_frida_message(message, data)
            
        except Exception as e:
            if self.verbose_mode:
                print(f"[-] Error in message handler: {e}")
    
    def _handle_startup_messages(self, message: Dict[str, Any]) -> bool:
        """Handle startup configuration messages"""
        payload = message.get('payload')
        
        # Send verbose mode configuration
        if self.startup and payload == 'verbose_mode':
            self.instrumentation.send_message({
                'type': 'verbose_mode', 
                'payload': self.verbose_mode
            })
            self.startup = False
            return True
        
        # Send unlink configuration
        if self.startup_unlink and payload == 'deactivate_unlink':
            self.instrumentation.send_message({
                'type': 'deactivate_unlink', 
                'payload': self.deactivate_unlink
            })
            self.startup_unlink = False
            return True
        
        # Send hook configuration
        if payload == 'hook_config':
            self.instrumentation.send_message({
                'type': 'hook_config', 
                'payload': self.hook_manager.get_hook_config()
            })
            return True
        
        # Send stacktrace configuration
        if payload == 'enable_stacktrace':
            self.instrumentation.send_message({
                'type': 'enable_stacktrace', 
                'payload': self.enable_stacktrace
            })
            return True
        
        # Send path filters (once)
        if not self.path_filters_sent and self.profile_collector.path_filters:
            filters = self.profile_collector.path_filters
            if not isinstance(filters, list):
                filters = [filters]
            self.instrumentation.send_message({
                'type': 'path_filters', 
                'payload': filters
            })
            self.path_filters_sent = True
            return True
        
        return False
    
    # Hook management methods (delegated to HookManager)
    def enable_hook(self, hook_name: str, enabled: bool = True):
        """Enable or disable a specific hook at runtime"""
        self.hook_manager.enable_hook(hook_name, enabled)
        if self.instrumentation.is_script_loaded():
            self.instrumentation.send_message({
                'type': 'hook_config', 
                'payload': {hook_name: enabled}
            })
    
    def get_enabled_hooks(self) -> List[str]:
        """Return list of currently enabled hooks"""
        return self.hook_manager.get_enabled_hooks()
    
    def enable_all_hooks(self):
        """Enable all available hooks"""
        self.hook_manager.enable_all_hooks()
        if self.instrumentation.is_script_loaded():
            self.instrumentation.send_message({
                'type': 'hook_config', 
                'payload': self.hook_manager.get_hook_config()
            })
    
    def enable_hook_group(self, group_name: str):
        """Enable a group of related hooks"""
        self.hook_manager.enable_hook_group(group_name)
        if self.instrumentation.is_script_loaded():
            self.instrumentation.send_message({
                'type': 'hook_config', 
                'payload': self.hook_manager.get_hook_config()
            })
    
    # Profile data methods (delegated to ProfileCollector)
    def get_profile_data(self) -> ProfileData:
        """Get the collected profile data"""
        return self.profile_collector.get_profile_data()
    
    def get_profiling_log_as_json(self) -> str:
        """Get profile data as JSON string"""
        return self.profile_collector.get_profile_json()
    
    def write_profiling_log(self, filename: str = "profile.json") -> str:
        """Write profile data to file"""
        return self.profile_collector.write_profile_to_file(filename)
    
    def get_event_count(self, category: Optional[str] = None) -> int:
        """Get event count for category or total"""
        return self.profile_collector.get_event_count(category)
    
    def get_categories(self) -> List[str]:
        """Get all categories with events"""
        return self.profile_collector.get_categories()
    
    # Legacy compatibility methods
    def instrument(self) -> frida.core.Script:
        """Legacy method - use start_profiling() instead"""
        return self.start_profiling()
    
    def finish_app_profiling(self):
        """Legacy method - use stop_profiling() instead"""
        self.stop_profiling()
    
    def get_frida_script(self) -> str:
        """Get the path to the Frida script"""
        return self.instrumentation.get_script_path()
    
    def update_script(self, script):
        """Update script reference (for compatibility)"""
        # This is handled internally now
        pass
    
    # Utility methods
    def get_stats(self) -> Dict[str, Any]:
        """Get profiling statistics"""
        hook_stats = self.hook_manager.get_hook_stats()
        profile_summary = self.profile_collector.get_profile_data().get_summary()
        
        return {
            'hook_stats': hook_stats,
            'profile_summary': profile_summary,
            'script_loaded': self.instrumentation.is_script_loaded(),
            'output_format': self.output_format,
            'verbose_mode': self.verbose_mode
        }


# Legacy exception class for compatibility
class FridaBasedException(FridaBasedException):
    """Legacy exception class - redirects to new FridaBasedException"""
    pass


# Legacy function for compatibility
def setup_frida_handler(host: str = "", enable_spawn_gating: bool = False):
    """Legacy function - use setup_frida_device() instead"""
    return setup_frida_device(host, enable_spawn_gating)
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, List, Optional


class HookManager:
    """Manages hook configuration and runtime control"""
    
    def __init__(self, initial_config: Optional[Dict[str, bool]] = None):
        self.hook_config = self._init_hook_config(initial_config)
    
    def _init_hook_config(self, hook_config: Optional[Dict[str, bool]]) -> Dict[str, bool]:
        """Initialize hook configuration with all hooks disabled by default"""
        default_config = {
            # File system hooks
            'file_system_hooks': False,
            'database_hooks': False,
            
            # DEX and native library hooks
            'dex_unpacking_hooks': False,
            'java_dex_unpacking_hooks': False,
            'native_library_hooks': False,
            
            # IPC hooks
            'shared_prefs_hooks': False,
            'binder_hooks': False,
            'intent_hooks': False,
            'broadcast_hooks': False,
            
            # Crypto hooks
            'aes_hooks': False,
            'encodings_hooks': False,
            'keystore_hooks': False,
            
            # Network hooks
            'web_hooks': False,
            'socket_hooks': False,
            
            # Process hooks
            'process_hooks': False,
            'runtime_hooks': False,
            
            # Service hooks
            'bluetooth_hooks': False,
            'camera_hooks': False,
            'clipboard_hooks': False,
            'location_hooks': False,
            'telephony_hooks': False,
        }
        
        if hook_config:
            default_config.update(hook_config)
        
        return default_config
    
    def enable_hook(self, hook_name: str, enabled: bool = True) -> bool:
        """Enable or disable a specific hook"""
        if hook_name in self.hook_config:
            self.hook_config[hook_name] = enabled
            return True
        else:
            raise ValueError(f"Unknown hook: {hook_name}")
    
    def is_hook_enabled(self, hook_name: str) -> bool:
        """Check if a hook is enabled"""
        return self.hook_config.get(hook_name, False)
    
    def get_enabled_hooks(self) -> List[str]:
        """Return list of currently enabled hooks"""
        return [hook for hook, enabled in self.hook_config.items() if enabled]
    
    def get_disabled_hooks(self) -> List[str]:
        """Return list of currently disabled hooks"""
        return [hook for hook, enabled in self.hook_config.items() if not enabled]
    
    def enable_all_hooks(self):
        """Enable all available hooks"""
        for hook in self.hook_config:
            self.hook_config[hook] = True
    
    def disable_all_hooks(self):
        """Disable all hooks"""
        for hook in self.hook_config:
            self.hook_config[hook] = False
    
    def enable_hook_group(self, group_name: str):
        """Enable a group of related hooks"""
        hook_groups = {
            'crypto': ['aes_hooks', 'encodings_hooks', 'keystore_hooks'],
            'network': ['web_hooks', 'socket_hooks'],
            'filesystem': ['file_system_hooks', 'database_hooks'],
            'ipc': ['shared_prefs_hooks', 'binder_hooks', 'intent_hooks', 'broadcast_hooks'],
            'process': ['dex_unpacking_hooks', 'java_dex_unpacking_hooks', 'native_library_hooks', 'process_hooks', 'runtime_hooks'],
            'services': ['bluetooth_hooks', 'camera_hooks', 'clipboard_hooks', 'location_hooks', 'telephony_hooks']
        }
        
        if group_name in hook_groups:
            for hook in hook_groups[group_name]:
                if hook in self.hook_config:
                    self.hook_config[hook] = True
        else:
            raise ValueError(f"Unknown hook group: {group_name}")
    
    def get_hook_config(self) -> Dict[str, bool]:
        """Get current hook configuration"""
        return self.hook_config.copy()
    
    def update_config(self, new_config: Dict[str, bool]):
        """Update hook configuration with new values"""
        for hook, enabled in new_config.items():
            if hook in self.hook_config:
                self.hook_config[hook] = enabled
            else:
                raise ValueError(f"Unknown hook: {hook}")
    
    def get_available_hooks(self) -> List[str]:
        """Get list of all available hooks"""
        return list(self.hook_config.keys())
    
    def get_hook_stats(self) -> Dict[str, int]:
        """Get statistics about hook configuration"""
        enabled = len(self.get_enabled_hooks())
        disabled = len(self.get_disabled_hooks())
        total = len(self.hook_config)
        
        return {
            'total_hooks': total,
            'enabled_hooks': enabled,
            'disabled_hooks': disabled,
            'enabled_percentage': round((enabled / total) * 100, 1) if total > 0 else 0
        }
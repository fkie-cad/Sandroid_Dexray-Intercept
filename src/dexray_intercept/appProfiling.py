#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import frida
import subprocess
import os
import signal
import shutil
import threading
from pathlib import Path
from datetime import datetime
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
                 enable_stacktrace: bool = False, enable_fritap: bool = False, 
                 fritap_output_dir: str = "./fritap_output", target_name: Optional[str] = None, 
                 spawn_mode: bool = False, custom_scripts: Optional[List[str]] = None):
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
            enable_fritap: Enable fritap for TLS key extraction
            fritap_output_dir: Directory for fritap output files
            target_name: Target application name or package identifier
            spawn_mode: Whether the target was spawned (True) or attached to (False)
            custom_scripts: List of paths to custom Frida scripts to load
        """
        self.process = process
        
        # Handle fritap spawn mode where process might be None initially
        if process is None and enable_fritap and spawn_mode:
            if verbose_mode:
                print("[*] fritap spawn mode - process session will be set after fritap spawns target")
        self.verbose_mode = verbose_mode
        self.output_format = output_format
        self.deactivate_unlink = deactivate_unlink
        self.enable_stacktrace = enable_stacktrace
        
        # Target and mode information
        self.target_name = target_name
        self.spawn_mode = spawn_mode
        
        # Custom scripts configuration
        self.custom_scripts = custom_scripts or []
        self.custom_script_instances = []
        
        # Fritap configuration
        self.enable_fritap = enable_fritap
        self.fritap_output_dir = fritap_output_dir
        self.fritap_process = None
        self.fritap_keylog_file = None
        self.fritap_pcap_file = None
        self.fritap_pcap_filename = None
        self.fritap_finished = threading.Event()
        self.fritap_monitor_thread = None
        self._shutdown_requested = False
        
        # Check fritap availability early if enabled
        if self.enable_fritap:
            if not self._check_fritap_availability():
                print("[-] fritap not available, disabling fritap functionality")
                self.enable_fritap = False
        
        # Initialize services
        self.instrumentation = InstrumentationService(process, custom_scripts=self.custom_scripts) if process else None
        self.profile_collector = ProfileCollector(
            output_format=output_format,
            verbose_mode=verbose_mode,
            enable_stacktrace=enable_stacktrace,
            path_filters=path_filters,
            base_path=base_path
        )
        self.hook_manager = HookManager(hook_config)
        
        # Set up message handling (only if instrumentation service exists)
        if self.instrumentation:
            self.instrumentation.set_message_handler(self._message_handler)
        
        # State tracking
        self.startup = True
        self.startup_unlink = True
        self.path_filters_sent = False
    
    def _check_fritap_availability(self) -> bool:
        """Check if fritap is installed and available"""
        return shutil.which('fritap') is not None
    
    def set_process_session(self, process_session):
        """Update the process session after fritap spawns the target"""
        self.process = process_session
        if self.instrumentation is None:
            self.instrumentation = InstrumentationService(process_session, custom_scripts=self.custom_scripts)
            self.instrumentation.set_message_handler(self._message_handler)
        else:
            self.instrumentation.process = process_session
        
        if self.verbose_mode:
            print("[*] process session updated successfully")
    
    def _generate_fritap_filenames(self, app_name: str) -> tuple:
        """Generate fritap output filenames with correct signatures"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        keylog_file = f"dexray_tlskeys_{app_name}_{timestamp}.log"
        pcap_file = f"dexray_unfiltered_traffic_{app_name}_{timestamp}.pcap"
        return keylog_file, pcap_file
    
    def _start_fritap(self, app_name: str) -> Optional[int]:
        """Start fritap subprocess for TLS key extraction
        
        Returns:
            PID of spawned process if fritap spawned the target, None otherwise
        """
        if not self.enable_fritap:
            return None
        
        try:
            # Create output directory if it doesn't exist
            os.makedirs(self.fritap_output_dir, exist_ok=True)
            
            # Generate filenames
            keylog_filename, self.fritap_pcap_filename = self._generate_fritap_filenames(app_name)
            self.fritap_keylog_file = os.path.join(self.fritap_output_dir, keylog_filename)
            self.fritap_pcap_file = os.path.join(self.fritap_output_dir, self.fritap_pcap_filename)
            
            # Build fritap command
            fritap_cmd = [
                'fritap',
                '-m',  # Mobile app flag for Android
                '-k', self.fritap_keylog_file,
                '-p', self.fritap_pcap_file,
                '-f' # enable full packet capture
            ]
            
            # Add verbose flag if enabled
            if self.verbose_mode:
                fritap_cmd.append('-v')
            
            # Add spawn flag if in spawn mode
            if self.spawn_mode:
                fritap_cmd.append('--spawn')
            
            # Add target
            target = self.target_name or app_name
            fritap_cmd.append(target)
            
            if self.verbose_mode:
                print(f"[*] starting fritap: {' '.join(fritap_cmd)}")
                print(f"[*] mode: {'spawn' if self.spawn_mode else 'attach'}")
                print(f"[*] target: {target}")
                print(f"[*] keylog file: {self.fritap_keylog_file}")
                print(f"[*] pcap file: {self.fritap_pcap_file}")
            
            self.fritap_process = subprocess.Popen(
                fritap_cmd,
                stdout=subprocess.PIPE if self.spawn_mode else (subprocess.DEVNULL if not self.verbose_mode else None),
                stderr=subprocess.PIPE if self.spawn_mode else (subprocess.DEVNULL if not self.verbose_mode else None),
                preexec_fn=os.setsid,  # Create new process group for clean termination
                text=True if self.spawn_mode else False
            )
            
            if self.verbose_mode:
                print(f"[*] fritap started with PID: {self.fritap_process.pid}")
                
            # If fritap is spawning, we need to wait for it to be ready
            if self.spawn_mode:
                import time
                time.sleep(3)  # Give fritap time to spawn and attach
                if self.verbose_mode:
                    print("[*] fritap spawn mode - waiting for target to be ready")
            
            # Start monitoring fritap process in a separate thread
            if self.fritap_process:
                self.fritap_monitor_thread = threading.Thread(
                    target=self._monitor_fritap_process, 
                    daemon=True
                )
                self.fritap_monitor_thread.start()
            
            return None
                
        except FileNotFoundError:
            print("[-] fritap not found. Please install fritap first.")
            print("[-] fritap can be installed from: https://github.com/fkie-cad/friTap")
            self.enable_fritap = False
            return None
        except Exception as e:
            print(f"[-] failed to start fritap: {e}")
            self.enable_fritap = False
            return None
    
    def _monitor_fritap_process(self):
        """Monitor fritap process in a separate thread"""
        if not self.fritap_process:
            return
        
        try:
            # Wait for fritap to finish
            self.fritap_process.wait()
            
            if self.verbose_mode:
                print("[*] fritap process finished")
            
            # Signal that fritap has finished
            self.fritap_finished.set()
            
        except Exception as e:
            if self.verbose_mode:
                print(f"[-] error monitoring fritap process: {e}")
            self.fritap_finished.set()
    
    def _send_signal_to_fritap(self, sig: int):
        """Send signal to fritap process"""
        if self.fritap_process and self.fritap_process.poll() is None:
            try:
                # Send signal to the process group
                os.killpg(os.getpgid(self.fritap_process.pid), sig)
                return True
            except Exception as e:
                if self.verbose_mode:
                    print(f"[-] error sending signal {sig} to fritap: {e}")
                return False
        return False
    
    def send_interrupt_to_fritap(self):
        """Send SIGINT (Ctrl+C) to fritap process"""
        if self.verbose_mode:
            print("[*] sending interrupt signal to fritap")
        return self._send_signal_to_fritap(signal.SIGINT)
    
    def wait_for_fritap(self, timeout: Optional[float] = None):
        """Wait for fritap to finish
        
        Args:
            timeout: Maximum time to wait in seconds (None for indefinite)
            
        Returns:
            True if fritap finished, False if timeout occurred
        """
        if not self.fritap_process:
            return True
        
        return self.fritap_finished.wait(timeout)
    
    def _stop_fritap(self):
        """Stop fritap subprocess"""
        self._shutdown_requested = True
        
        if self.fritap_process and self.fritap_process.poll() is None:
            try:
                if self.verbose_mode:
                    print("[*] stopping fritap gracefully")
                
                # First try SIGINT (Ctrl+C equivalent)
                self._send_signal_to_fritap(signal.SIGINT)
                
                # Wait a bit for graceful shutdown
                try:
                    self.fritap_process.wait(timeout=3)
                    if self.verbose_mode:
                        print("[*] fritap stopped gracefully")
                    self.fritap_finished.set()
                    return
                except subprocess.TimeoutExpired:
                    pass
                
                # If still running, try SIGTERM
                if self.verbose_mode:
                    print("[*] sending SIGTERM to fritap")
                self._send_signal_to_fritap(signal.SIGTERM)
                
                try:
                    self.fritap_process.wait(timeout=5)
                    if self.verbose_mode:
                        print("[*] fritap stopped")
                    self.fritap_finished.set()
                except subprocess.TimeoutExpired:
                    # Force kill if graceful termination fails
                    if self.verbose_mode:
                        print("[*] force killing fritap")
                    self._send_signal_to_fritap(signal.SIGKILL)
                    self.fritap_process.wait(timeout=2)
                    if self.verbose_mode:
                        print("[*] fritap force stopped")
                    self.fritap_finished.set()
                    
            except Exception as e:
                if self.verbose_mode:
                    print(f"[-] error stopping fritap: {e}")
                self.fritap_finished.set()
    
    def start_profiling(self, app_name: str = None) -> frida.core.Script:
        """Start the profiling process"""
        try:
            # Get app name from process if not provided
            if app_name is None:
                try:
                    app_name = getattr(self.process, 'name', 'unknown_app')
                except Exception:
                    app_name = 'unknown_app'
            
            # Start fritap FIRST if enabled (fritap-first initialization)
            # Skip if fritap is already running (e.g., started manually in spawn mode)
            if self.enable_fritap and (not self.fritap_process or self.fritap_process.poll() is not None):
                if self.verbose_mode:
                    print("[*] starting fritap before dexray-intercept hooks")
                self._start_fritap(app_name)
                
                # In spawn mode, give fritap extra time to fully initialize the spawned process
                if self.spawn_mode:
                    import time
                    if self.verbose_mode:
                        print("[*] waiting for fritap to fully initialize spawned process")
                    time.sleep(2)  # Additional wait for spawn mode
            elif self.enable_fritap and self.fritap_process and self.fritap_process.poll() is None:
                if self.verbose_mode:
                    print("[*] fritap already running, proceeding with dexray-intercept hooks")
            
            # Now start dexray-intercept's Frida script
            if self.verbose_mode and self.enable_fritap:
                print("[*] starting dexray-intercept hooks")
            
            if self.instrumentation is None:
                raise FridaBasedException("No process session available - cannot load Frida script")
            
            script = self.instrumentation.load_script()
            return script
        except Exception as e:
            # Clean up fritap if script loading fails
            if self.enable_fritap:
                self._stop_fritap()
            raise FridaBasedException(f"Failed to start profiling: {str(e)}")
    
    def stop_profiling(self):
        """Stop the profiling process"""
        if self.verbose_mode:
            print("[*] stopping profiling")
        
        # Stop Frida instrumentation first
        if self.instrumentation:
            self.instrumentation.unload_script()
        
        # Stop fritap and wait for it to finish
        if self.enable_fritap:
            self._stop_fritap()
            
            # Wait for fritap to finish writing its files
            if self.verbose_mode:
                print("[*] waiting for fritap to finish...")
            
            # Wait up to 10 seconds for fritap to finish gracefully
            if not self.wait_for_fritap(timeout=10):
                if self.verbose_mode:
                    print("[-] fritap did not finish within timeout")
            else:
                print("[*] fritap finished successfully")
                if self.fritap_keylog_file and os.path.exists(self.fritap_keylog_file):
                    print(f"[*] TLS keys saved to: {self.fritap_keylog_file}")
                if self.fritap_pcap_file and os.path.exists(self.fritap_pcap_file):
                    print(f"[*] Traffic capture saved to: {self.fritap_pcap_file}")
                else:
                    saved__pcap_name = "_"+self.fritap_pcap_filename
                    dst = Path(self.fritap_pcap_file)
                    src = Path(saved__pcap_name)

                    src.replace(dst)
                    print(f"[*] Traffic capture saved to: {self.fritap_pcap_file}")

    
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
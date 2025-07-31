#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import frida
import os
from typing import Optional, Callable


class FridaBasedException(Exception):
    """Custom exception for Frida-related errors"""
    pass


class InstrumentationService:
    """Service for managing Frida instrumentation"""
    
    def __init__(self, process, frida_agent_script: str = "profiling.js"):
        self.process = process
        self.frida_agent_script = frida_agent_script
        self.script: Optional[frida.core.Script] = None
        self.message_handler: Optional[Callable] = None
    
    def load_script(self) -> frida.core.Script:
        """Load and create the Frida script"""
        try:
            runtime = "qjs"
            script_path = self._get_script_path()
            
            with open(script_path, encoding='utf8', newline='\n') as f:
                script_string = f.read()
                self.script = self.process.create_script(script_string, runtime=runtime)
            
            if self.message_handler:
                self.script.on("message", self.message_handler)
            
            self.script.load()
            return self.script
            
        except frida.ProcessNotFoundError:
            raise FridaBasedException("Unable to find target process")
        except frida.InvalidOperationError:
            raise FridaBasedException("Invalid operation! Please run Dexray Intercept in debug mode in order to understand the source of this error and report it.")
        except frida.TransportError:
            raise FridaBasedException("Timeout error due to some internal frida error's. Try to restart frida-server again.")
        except frida.ProtocolError:
            raise FridaBasedException("Connection is closed. Probably the target app crashed")
        except FileNotFoundError:
            raise FridaBasedException(f"Frida script not found: {script_path}")
        except Exception as e:
            raise FridaBasedException(f"Failed to load Frida script: {str(e)}")
    
    def set_message_handler(self, handler: Callable):
        """Set the message handler for script communication"""
        self.message_handler = handler
        if self.script:
            self.script.on("message", handler)
    
    def send_message(self, message: dict):
        """Send a message to the Frida script"""
        if self.script:
            self.script.post(message)
        else:
            raise FridaBasedException("Script not loaded. Call load_script() first.")
    
    def unload_script(self):
        """Unload the Frida script"""
        if self.script:
            try:
                self.script.unload()
            except Exception:
                # Ignore errors during unload
                pass
            finally:
                self.script = None
    
    def is_script_loaded(self) -> bool:
        """Check if script is loaded"""
        return self.script is not None
    
    def _get_script_path(self) -> str:
        """Get the full path to the Frida script"""
        # Assuming the script is in the same directory as this module
        current_dir = os.path.dirname(os.path.dirname(__file__))
        return os.path.join(current_dir, self.frida_agent_script)
    
    def get_script_path(self) -> str:
        """Get the script path (public method for compatibility)"""
        return self._get_script_path()
    
    def restart_script(self):
        """Restart the Frida script"""
        self.unload_script()
        return self.load_script()


def setup_frida_device(host: str = "", enable_spawn_gating: bool = False):
    """Setup and return a Frida device connection"""
    try:
        if len(host) > 4:
            # Use IP address of the target machine instead of USB
            device = frida.get_device_manager().add_remote_device(host)
        else:
            device = frida.get_usb_device()

        # Handle child processes
        def on_child_added(child):
            print(f"[*] Attached to child process with pid {child.pid}")
            device.resume(child.pid)

        # Handle spawned processes
        def on_spawn_added(spawn):
            print(f"[*] Process spawned with pid {spawn.pid}. Name: {spawn.identifier}")
            device.resume(spawn.pid)

        device.on("child_added", on_child_added)
        if enable_spawn_gating:
            device.enable_spawn_gating()
            device.on("spawn_added", on_spawn_added)
        
        return device
    
    except frida.InvalidArgumentError:
        raise FridaBasedException("Unable to find device")
    except frida.ServerNotRunningError:
        raise FridaBasedException("Frida server not running. Start frida-server and try it again.")
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import frida
import os
import threading
from typing import Optional, Callable, List, Dict, Any
from datetime import datetime


class FridaBasedException(Exception):
    """Custom exception for Frida-related errors"""
    pass


def list_devices() -> List[Dict[str, Any]]:
    """Enumerate all connected Frida devices.

    Returns:
        List of device dictionaries with 'id', 'name', and 'type' keys.
    """
    try:
        devices = frida.enumerate_devices()
        return [
            {
                'id': device.id,
                'name': device.name,
                'type': device.type
            }
            for device in devices
        ]
    except Exception as e:
        raise FridaBasedException(f"Failed to enumerate devices: {str(e)}")


class InstrumentationService:
    """Service for managing Frida instrumentation"""
    
    def __init__(self, process, frida_agent_script: str = "profiling.js", custom_scripts: Optional[List[str]] = None):
        self.process = process
        self.frida_agent_script = frida_agent_script
        self.script: Optional[frida.core.Script] = None
        self.message_handler: Optional[Callable] = None
        self.custom_scripts = custom_scripts or []
        self.custom_script_instances: List[frida.core.Script] = []
    
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
            
            # Load custom scripts
            self._load_custom_scripts()
            
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
    
    def _load_custom_scripts(self):
        """Load custom Frida scripts"""
        for script_path in self.custom_scripts:
            try:
                if not os.path.exists(script_path):
                    print(f"[-] Custom script not found: {script_path}")
                    continue
                
                with open(script_path, 'r', encoding='utf-8') as f:
                    script_content = f.read()
                
                # Create custom message handler that adds script identification
                script_name = os.path.basename(script_path)
                custom_handler = self._create_custom_script_handler(script_name)
                
                # Create and load the custom script
                custom_script = self.process.create_script(script_content, runtime="qjs")
                custom_script.on("message", custom_handler)
                custom_script.load()
                
                self.custom_script_instances.append(custom_script)
                print(f"[*] Loaded custom script: {script_name}")
                
            except Exception as e:
                print(f"[-] Failed to load custom script {script_path}: {e}")
    
    def _create_custom_script_handler(self, script_name: str):
        """Create a message handler for custom scripts that adds identification"""
        def custom_handler(message, data):
            # Modify the message to identify it as coming from a custom script
            if message.get('type') == 'send' and 'payload' in message:
                payload = message['payload']
                
                # Check if it's already structured as a profile message
                if isinstance(payload, dict) and 'profileType' in payload:
                    # It's already structured - mark as custom
                    payload['profileType'] = 'CUSTOM_SCRIPT'
                    if 'profileContent' not in payload:
                        payload['profileContent'] = {}
                    if isinstance(payload['profileContent'], dict):
                        payload['profileContent']['script_name'] = script_name
                else:
                    # Wrap unstructured messages
                    message['payload'] = {
                        'profileType': 'CUSTOM_SCRIPT',
                        'profileContent': {
                            'script_name': script_name,
                            'message': payload
                        },
                        'timestamp': datetime.now().isoformat()
                    }
            
            # Forward to main message handler
            if self.message_handler:
                self.message_handler(message, data)
        
        return custom_handler
    
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
        """Unload the Frida script and all custom scripts"""
        # Unload custom scripts
        for custom_script in self.custom_script_instances:
            try:
                custom_script.unload()
            except Exception:
                # Ignore errors during unload
                pass
        self.custom_script_instances.clear()
        
        # Unload main script
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


class TargetSpawnGating:
    """Coordinates early instrumentation of one spawn-gated target process.

    The coordinator keeps only the first spawn whose identifier exactly matches
    the requested package paused. Unrelated and later matching spawns resume
    immediately so device-wide spawn gating does not block other processes.
    """

    def __init__(self, device, target_identifier: str):
        self.device = device
        self.target_identifier = target_identifier
        self._target_pid: Optional[int] = None
        self._target_resumed = False
        self._gating_enabled = False
        self._target_spawned = threading.Event()
        self._lock = threading.Lock()

    def _resume_spawn(self, pid: int, description: str) -> None:
        """Resume a gated spawn while reporting non-fatal resume failures."""
        try:
            self.device.resume(pid)
        except Exception as error:
            print(
                f"[-] Failed to resume {description} "
                f"with pid {pid}: {error}"
            )

    def _on_spawn_added(self, spawn) -> None:
        """Retain the first matching target spawn and resume all others."""
        if spawn.identifier != self.target_identifier:
            print(
                f"[*] Resuming unrelated gated spawn: "
                f"{spawn.identifier} ({spawn.pid})"
            )
            self._resume_spawn(spawn.pid, "unrelated gated spawn")
            return

        with self._lock:
            if self._target_pid is not None:
                print(
                    f"[*] Resuming additional target spawn: "
                    f"{spawn.identifier} ({spawn.pid})"
                )
                self._resume_spawn(spawn.pid, "additional target spawn")
                return

            self._target_pid = spawn.pid
            self._target_spawned.set()

        print(
            f"[*] Target spawn gated: "
            f"{spawn.identifier} ({spawn.pid})"
        )

    def enable(self) -> None:
        """Enable device-wide spawn gating after registering the callback."""
        if self._gating_enabled:
            return

        self.device.on("spawn-added", self._on_spawn_added)
        self.device.enable_spawn_gating()
        self._gating_enabled = True

    def wait_for_target(self, timeout: float) -> int:
        """Wait for the first matching paused target process."""
        if not self._target_spawned.wait(timeout):
            raise FridaBasedException(
                "Timed out waiting for the explicit component to spawn "
                f"the target package '{self.target_identifier}'"
            )

        with self._lock:
            if self._target_pid is None:
                raise FridaBasedException(
                    "Target spawn notification completed without a PID"
                )

            return self._target_pid

    def resume_target(self) -> None:
        """Resume the retained target after profiling startup completes."""
        with self._lock:
            if self._target_pid is None or self._target_resumed:
                return

            target_pid = self._target_pid

        self.device.resume(target_pid)

        with self._lock:
            self._target_resumed = True

        print(
            f"[*] Resumed target process with Dexray hooks installed: "
            f"{target_pid}"
        )

    def disable(self) -> None:
        """Disable device-wide spawn gating after target startup."""
        if not self._gating_enabled:
            return

        try:
            self.device.disable_spawn_gating()
        except Exception as error:
            print(f"[-] Failed to disable spawn gating: {error}")
        finally:
            self._gating_enabled = False

    def abort(self) -> None:
        """Release a retained target and disable gating after startup failure."""
        try:
            self.resume_target()
        finally:
            self.disable()

def setup_frida_device(host: str = "", device_id: str = "", enable_spawn_gating: bool = False):
    """Setup and return a Frida device connection.

    Args:
        host: Remote device address in format 'ip:port'. Takes precedence over device_id.
        device_id: Specific device ID to connect to (e.g., 'emulator-5554', 'HVA12345').
                   Use list_devices() to see available device IDs.
        enable_spawn_gating: Enable spawn gating to catch newly spawned processes.

    Returns:
        Frida device object.
    """
    try:
        if len(host) > 4:
            # Use IP address of the target machine instead of USB
            device = frida.get_device_manager().add_remote_device(host)
        elif device_id:
            # Use specific device by ID
            device = frida.get_device(device_id)
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
            device.on("spawn-added", on_spawn_added)
            device.enable_spawn_gating()

        return device

    except frida.InvalidArgumentError:
        if device_id:
            raise FridaBasedException(f"Device not found: '{device_id}'. Use --list-devices to see available devices.")
        raise FridaBasedException("Unable to find device")
    except frida.ServerNotRunningError:
        raise FridaBasedException("Frida server not running. Start frida-server and try it again.")
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import json
import logging
import os
from datetime import datetime
from typing import Optional, List, Dict, Any

from ..models.profile import ProfileData
from ..models.events import Event, DEXEvent
from ..parsers.factory import parser_factory
from ..formatters.factory import formatter_factory
from ..utils.android_utils import is_benign_dump
from ..utils.string_utils import strip_ansi_codes
from ..utils.event_logger import EventLogger

# Set up logger for dexray-intercept (for file logging and debugging)
logger = logging.getLogger('dexray_intercept')


class ProfileCollector:
    """Service for collecting and processing profile events"""

    def __init__(self, output_format: str = "CMD", verbose_mode: bool = False,
                 enable_stacktrace: bool = False, path_filters: Optional[List[str]] = None,
                 base_path: Optional[str] = None):
        # Validate and normalize output format
        # Supported modes: "CMD" (terminal only), "JSON" (silent), "DUAL" (terminal + JSON)
        valid_formats = ["CMD", "JSON", "DUAL"]
        if output_format not in valid_formats:
            logger.warning(f"Invalid output_format '{output_format}', defaulting to 'CMD'")
            output_format = "CMD"

        self.output_format = output_format
        self.verbose_mode = verbose_mode
        self.enable_stacktrace = enable_stacktrace
        self.path_filters = path_filters or []

        # Profile data storage
        self.profile_data = ProfileData()

        # DEX unpacking tracking
        # DEX payloads are persisted directly from Frida binary attachments.

        # Output control
        self.skip_output = False
        self.startup = True
        self.startup_unlink = True

        # Setup paths for DEX dumps
        from ..utils.android_utils import create_unpacking_folder
        self.benign_path, self.malicious_path = create_unpacking_folder(base_path)

        # Get formatter (use CMD formatter for DUAL mode to get terminal output)
        formatter_mode = output_format if output_format != "DUAL" else "CMD"
        self.formatter = formatter_factory.get_formatter(
            formatter_mode,
            verbose_mode=verbose_mode
        )

        # Initialize event logger for unified logging (replaces print() calls)
        self.event_logger = EventLogger()

        # Configure terminal output based on mode
        # Only set up event_logger's terminal handler in standalone mode
        # In integrated mode (Sandroid with base_path), use logger which goes through Sandroid's RichHandler
        self.integrated_mode = base_path is not None
        if self._should_print_to_terminal() and not self.integrated_mode:
            self.event_logger.setup_terminal_output(True)

    def _should_print_to_terminal(self) -> bool:
        """Check if events should be printed to terminal (CMD or DUAL mode)"""
        return self.output_format in ["CMD", "DUAL"]

    def process_frida_message(self, message: Dict[str, Any], data: Any = None) -> bool:
        """Process a message from Frida script"""
        try:
            if message.get("type") == 'error':
                if self.verbose_mode:
                    error_msg = message.get('stack', str(message))
                    self.event_logger.error(f"[-] Error in frida script: {error_msg}")
                return False
            
            payload = message.get("payload")
            if not payload or "profileType" not in payload:
                return False
            
            profile_type = payload["profileType"]
            timestamp = payload.get("timestamp", datetime.now().isoformat())

            # Handle special console messages
            if profile_type in ["console", "console_dev"]:
                if profile_type == "console_dev":
                    content = payload.get("console_dev", "")
                else:
                    content = payload.get("console", "")
                self._handle_console_message(content, profile_type)
                return True

            # For all non-console messages, use profileContent as before
            profile_content = payload.get("profileContent", "")

            # Handle custom script messages
            if profile_type == "CUSTOM_SCRIPT":
                return self._handle_custom_script_message(profile_content, timestamp)
            
            # Handle DEX loading specially
            if profile_type == "DEX_LOADING":
                return self._handle_dex_loading(profile_content, timestamp, data)
            
            # Process regular events
            profile_content = self._attach_native_socket_payload(
                profile_type,
                profile_content,
                data
            )

            return self._process_event(profile_type, profile_content, timestamp)
            
        except Exception as e:
            if self.verbose_mode:
                self.event_logger.error(f"[-] Error processing message: {e}")
            return False
    
    def _handle_console_message(self, content: str, message_type: str):
        """Handle console messages"""
        if "creating local copy of unpacked file" in content:
            self.skip_output = True
            return

        if "Unpacking detected!" in content:
            self.skip_output = False
            return

        if self.skip_output:
            return

        if message_type == "console_dev":
            # Show devlog messages when verbose mode is enabled
            if self.verbose_mode and len(content) > 3:
                # In integrated mode (Sandroid), use logger.info to go through RichHandler
                # In standalone, use event_logger for clean output
                if self.integrated_mode:
                    logger.info(f"[DEBUG] {content}")
                else:
                    logger.debug(f"[console_dev] {content}")
                    if self._should_print_to_terminal():
                        self.event_logger.event(f"[DEBUG] {content}")
        elif message_type == "console":
            if content != "Unknown":
                # In integrated mode, only use logger (goes through Sandroid's RichHandler)
                # In standalone, use both logger (file) and event_logger (terminal)
                logger.info(f"[console] {content}")
                if self._should_print_to_terminal() and not self.integrated_mode:
                    self.event_logger.event(content)
    
    def _handle_custom_script_message(self, content, timestamp: str) -> bool:
        """Handle custom script messages"""
        try:
            # Extract script name and message content
            script_name = content.get('script_name', 'unknown_script') if isinstance(content, dict) else 'unknown_script'
            message_content = content.get('message', content) if isinstance(content, dict) else content
            
            # Create custom script event
            event = self._create_custom_script_event(script_name, message_content, timestamp)
            
            # Add to profile data
            self.profile_data.add_event("CUSTOM_SCRIPT", event)

            # Display for CMD/DUAL output with special formatting
            if self._should_print_to_terminal():
                self.event_logger.event(f"[CUSTOM] {script_name}: {message_content}")

            return True

        except Exception as e:
            if self.verbose_mode:
                self.event_logger.error(f"[-] Error handling custom script message: {e}")
            return False
    
    def _create_custom_script_event(self, script_name: str, message_content, timestamp: str):
        """Create a custom script event"""
        from ..models.events import Event
        
        class CustomScriptEvent(Event):
            def __init__(self, script_name: str, message_content, timestamp: str):
                super().__init__("custom_script.message", timestamp)
                self.script_name = script_name
                self.message_content = message_content
            
            def get_event_data(self):
                return {
                    "script_name": self.script_name,
                    "message": self.message_content,
                    "event_type": self.event_type
                }
        
        return CustomScriptEvent(script_name, message_content, timestamp)
    
    def _handle_dex_loading(
        self,
        content: str,
        timestamp: str,
        data: Any = None
    ) -> bool:
        """Parse, persist, and render DEX loading events."""
        parser = parser_factory.get_parser("DEX_LOADING")

        if parser is None:
            return False

        event = parser.parse(content, timestamp)

        if event is None:
            return False

        if event.event_type == "dex.unpacking.detected":
            self._persist_dex_attachment(event, data)

        self.profile_data.add_event("DEX_LOADING", event)

        if self._should_print_to_terminal() and self.formatter:
            formatted = self.formatter.format_event(event)

            if formatted:
                self.event_logger.event(formatted)
                logger.info(
                    "[DEX_LOADING] %s",
                    strip_ansi_codes(formatted)
                )

        return True

    def _persist_dex_attachment(
        self,
        event: DEXEvent,
        data: Any
    ) -> None:
        """Persist a complete native DEX attachment as a local artifact."""
        event.dump_success = False

        if not event.has_buffer:
            event.dump_error = (
                event.capture_error or "DEX payload was not captured"
            )
            return

        if not isinstance(data, (bytes, bytearray, memoryview)):
            event.dump_error = "DEX event did not include binary payload data"
            return

        payload = bytes(data)
        expected_length = event.captured_length

        if (
            expected_length is not None
            and len(payload) != expected_length
        ):
            event.dump_error = (
                f"Captured length mismatch: expected {expected_length}, "
                f"received {len(payload)}"
            )
            return

        if event.size is not None and len(payload) != event.size:
            event.dump_error = (
                f"DEX size mismatch: expected {event.size}, "
                f"received {len(payload)}"
            )
            return

        digest = hashlib.sha256(payload).hexdigest()
        extension = event.file_type or "dex"

        if extension not in {"dex", "cdex", "odex"}:
            extension = "dex"

        origin = event.original_location or ""
        output_directory = (
            self.benign_path
            if is_benign_dump(origin)
            else self.malicious_path
        )
        dumped_path = os.path.join(
            output_directory,
            f"{digest}.{extension}"
        )

        try:
            if not os.path.exists(dumped_path):
                temporary_path = f"{dumped_path}.tmp"

                with open(temporary_path, "wb") as output_file:
                    output_file.write(payload)

                os.replace(temporary_path, dumped_path)

            event.dumped_path = dumped_path
            event.sha256 = digest
            event.dump_success = True
        except OSError as error:
            event.dump_error = str(error)
    
    
    def _attach_native_socket_payload(self, category: str, content: str, data: Any) -> str:
        """Attach Frida binary data to native socket companion events."""
        if category != "NETWORK_SOCKETS" or data is None:
            return content

        try:
            event_data = json.loads(content)
        except (TypeError, ValueError, json.JSONDecodeError):
            return content

        event_type = event_data.get("event_type", "")

        if (
            not event_type.startswith("socket.native.")
            or not event_type.endswith("_data")
        ):
            return content

        if not isinstance(data, (bytes, bytearray, memoryview)):
            return content

        raw_data = bytes(data)

        event_data["captured_length"] = len(raw_data)
        event_data["data_hex"] = raw_data.hex()
        event_data["has_buffer"] = True

        return json.dumps(event_data)
    
    def _process_event(self, category: str, content: str, timestamp: str) -> bool:
        """Process a regular event"""
        # Skip certain events based on filters
        if self._should_skip_event(category, content):
            return False
        
        # Parse the event
        parser = parser_factory.get_parser(category)
        if parser:
            event = parser.parse(content, timestamp)
        else:
            event = self._create_generic_event(category, content, timestamp)
        
        if not event:
            return False
        
        # Add to profile data
        self.profile_data.add_event(category, event)

        # Format and display for CMD/DUAL output
        if self._should_print_to_terminal() and self.formatter:
            formatted = self.formatter.format_event(event)
            if formatted:
                # In integrated mode (Sandroid): only use logger (goes through RichHandler)
                # In standalone: use event_logger for terminal, logger for file
                clean_formatted = strip_ansi_codes(formatted)
                if self.integrated_mode:
                    logger.info(clean_formatted)
                else:
                    # Standalone: only print to terminal
                    self.event_logger.event(formatted)

        return True
    
    def _should_skip_event(self, category: str, content: str) -> bool:
        """Determine if event should be skipped"""
        if self.skip_output:
            return True
        
        # Skip certain file system events unless verbose
        if category == "FILE_SYSTEM" and not self.verbose_mode:
            if "stat" in content or "/system/fonts/" in content:
                return True
        
        # Apply path filters if configured
        if self.path_filters and category == "FILE_SYSTEM":
            # Simple path filtering logic
            for path_filter in self.path_filters:
                if path_filter in content:
                    return False
            return True  # Skip if no filters match
        
        return False
    
    def _create_generic_event(self, category: str, content: str, timestamp: str) -> Event:
        """Create a generic event for unknown categories"""
        from ..models.events import Event
        
        class GenericEvent(Event):
            def __init__(self, category: str, content: str, timestamp: str):
                super().__init__(f"{category}::unknown", timestamp)
                self.category = category
                self.content = content
            
            def get_event_data(self):
                return {
                    "payload": self.content,
                    "category": self.category
                }
        
        return GenericEvent(category, content, timestamp)


    def get_profile_data(self) -> ProfileData:
        """Get the collected profile data"""
        return self.profile_data
    
    def get_profile_json(self) -> str:
        """Get profile data as JSON string"""
        return self.profile_data.to_json()
    
    def write_profile_to_file(self, filename: str = "profile.json") -> str:
        """Write profile data to file"""
        return self.profile_data.write_to_file(filename)
    
    def get_event_count(self, category: Optional[str] = None) -> int:
        """Get event count for category or total"""
        return self.profile_data.get_event_count(category)
    
    def get_categories(self) -> List[str]:
        """Get all categories with events"""
        return self.profile_data.get_categories()
    
    def clear_profile_data(self):
        """Clear collected profile data"""
        self.profile_data = ProfileData()
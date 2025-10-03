#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from typing import Optional, List, Dict, Any
from datetime import datetime
from colorama import Fore

from ..models.profile import ProfileData
from ..models.events import Event, DEXEvent
from ..parsers.factory import parser_factory
from ..formatters.factory import formatter_factory
from ..utils.android_utils import (
    getFilePath, get_orig_path, get_filename_from_path,
    is_benign_dump, pull_file_from_device
)
from ..utils.string_utils import strip_ansi_codes

# Set up logger for dexray-intercept
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
        self.dex_list = []
        self.downloaded_origins = {}
        self.orig_file_location = ""

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

    def _should_print_to_terminal(self) -> bool:
        """Check if events should be printed to terminal (CMD or DUAL mode)"""
        return self.output_format in ["CMD", "DUAL"]

    def process_frida_message(self, message: Dict[str, Any], data: Any = None) -> bool:
        """Process a message from Frida script"""
        try:
            if message.get("type") == 'error':
                if self.verbose_mode:
                    error_msg = message.get('stack', str(message))
                    print(f"[-] Error in frida script: {error_msg}")
                return False
            
            payload = message.get("payload")
            if not payload or "profileType" not in payload:
                return False
            
            profile_type = payload["profileType"]
            profile_content = payload.get("profileContent", "")
            timestamp = payload.get("timestamp", datetime.now().isoformat())
            
            # Handle special console messages
            if profile_type in ["console", "console_dev"]:
                self._handle_console_message(profile_content, profile_type)
                return True
            
            # Handle custom script messages
            if profile_type == "CUSTOM_SCRIPT":
                return self._handle_custom_script_message(profile_content, timestamp)
            
            # Handle DEX loading specially
            if profile_type == "DEX_LOADING":
                return self._handle_dex_loading(profile_content, timestamp)
            
            # Process regular events
            return self._process_event(profile_type, profile_content, timestamp)
            
        except Exception as e:
            if self.verbose_mode:
                print(f"[-] Error processing message: {e}")
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
            if self.verbose_mode and len(content) > 3:
                logger.debug(f"[console_dev] {content}")
                if self._should_print_to_terminal():
                    print(f"[***] {content}")
        elif message_type == "console":
            if content != "Unknown":
                logger.info(f"[console] {content}")
                if self._should_print_to_terminal():
                    print(f"[***] {content}")
    
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
                print(f"[CUSTOM] {script_name}: {message_content}")

            return True
            
        except Exception as e:
            if self.verbose_mode:
                print(f"[-] Error handling custom script message: {e}")
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
    
    def _handle_dex_loading(self, content: str, timestamp: str) -> bool:
        """Handle DEX loading events"""
        import json

        if content not in self.dex_list:
            self.dex_list.append(content)

        # Try to parse as JSON (new format)
        try:
            data = json.loads(content)
            event_type = data.get('event_type', '')

            # Handle new JSON format events
            if event_type == 'dex.unpacking.detected':
                # Store original location if present
                if 'original_location' in data:
                    self.orig_file_location = data['original_location']

                # Extract file path and trigger dump
                file_path = data.get('dumped_path', '')
                if file_path:
                    self._dump_dex_file(file_path, timestamp)

                # Parse and display event
                if self._should_print_to_terminal():
                    parser = parser_factory.get_parser("DEX_LOADING")
                    if parser:
                        event = parser.parse(content, timestamp)
                        if event and self.formatter:
                            formatted = self.formatter.format_event(event)
                            if formatted:
                                print(formatted)
                                clean_formatted = strip_ansi_codes(formatted)
                                logger.info(f"[DEX_LOADING] {clean_formatted}")
                        # Add to profile data
                        self.profile_data.add_event("DEX_LOADING", event)
                return True

            elif event_type.startswith('dex.'):
                # Other DEX events (classloader, memory dumps, etc.)
                if 'original_location' in data:
                    self.orig_file_location = data['original_location']
                elif 'file_path' in data:
                    # For classloader events, store file path as orig location
                    self.orig_file_location = data['file_path']

                # Parse and display
                if self._should_print_to_terminal():
                    parser = parser_factory.get_parser("DEX_LOADING")
                    if parser:
                        event = parser.parse(content, timestamp)
                        if event and self.formatter:
                            formatted = self.formatter.format_event(event)
                            if formatted:
                                print(formatted)
                                clean_formatted = strip_ansi_codes(formatted)
                                logger.info(f"[DEX_LOADING] {clean_formatted}")
                        # Add to profile data
                        self.profile_data.add_event("DEX_LOADING", event)
                return True

        except (json.JSONDecodeError, ValueError):
            # Legacy string format handling
            if "dumped" in content:
                # Handle file dumping (old format)
                file_path = getFilePath(content)
                self._dump_dex_file(file_path, timestamp)
                return True
            else:
                # Regular DEX loading event (old format)
                if self._should_print_to_terminal():
                    # Parse and display
                    parser = parser_factory.get_parser("DEX_LOADING")
                    if parser:
                        event = parser.parse(content, timestamp)
                        if event and self.formatter:
                            formatted = self.formatter.format_event(event)
                            if formatted:
                                print(formatted)
                                clean_formatted = strip_ansi_codes(formatted)
                                logger.info(f"[DEX_LOADING] {clean_formatted}")

                    # Add to profile data
                    self.profile_data.add_event("DEX_LOADING", event or self._create_generic_event("DEX_LOADING", content, timestamp))

                if "orig location" in content:
                    self.orig_file_location = get_orig_path(content)

                return True
    
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
                print(formatted)
                # Strip ANSI codes for clean log file output and preserve newlines
                clean_formatted = strip_ansi_codes(formatted)
                logger.info(clean_formatted)

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
    
    def _dump_dex_file(self, file_path: str, timestamp: str):
        """Handle DEX file dumping"""
        if not file_path:
            return
        
        file_name = get_filename_from_path(file_path)
        
        # Check if already downloaded
        if self.orig_file_location in self.downloaded_origins:
            previously_downloaded = self.downloaded_origins[self.orig_file_location]
            msg = f"[*] File '{file_name}' has already been dumped as {previously_downloaded}"
            logger.info(msg)
            if self._should_print_to_terminal():
                print(msg)
            return

        # Determine if benign or malicious
        if is_benign_dump(self.orig_file_location):
            dump_path = f"{self.benign_path}/{file_name}"
            pull_file_from_device(file_path, dump_path)
            msg = f"[*] Dumped benign DEX to: {dump_path}"
            logger.info(msg)
            if self._should_print_to_terminal():
                print(f"{Fore.GREEN}{msg}")
        else:
            msg = "[*] Unpacking detected!"
            logger.warning(msg)
            if self._should_print_to_terminal():
                print(msg)
            dump_path = f"{self.malicious_path}/{file_name}"
            pull_file_from_device(file_path, dump_path)
            msg = f"[*] Dumped DEX payload to: {dump_path}"
            logger.warning(msg)
            if self._should_print_to_terminal():
                print(f"{Fore.RED}{msg}")
        
        # Record the download
        self.downloaded_origins[self.orig_file_location] = file_name
        
        # Create DEX event for profile
        from ..parsers.dex import DEXParser
        parser = DEXParser()
        event = parser.parse_dex_loading_list(self.dex_list)
        
        dex_event = DEXEvent("dex.unpacking", timestamp)
        dex_event.unpacking = True
        dex_event.dumped = dump_path
        dex_event.orig_location = self.orig_file_location
        
        # Copy parsed data
        for key, value in event.items():
            if hasattr(dex_event, key):
                setattr(dex_event, key, value)
            else:
                dex_event.add_metadata(key, value)
        
        self.profile_data.add_event("DEX_LOADING", dex_event)
        self.dex_list.clear()
    
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
        self.dex_list.clear()
        self.downloaded_origins.clear()
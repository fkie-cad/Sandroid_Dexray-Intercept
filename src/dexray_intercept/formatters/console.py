#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from .base import BaseFormatter
from ..models.events import (
    Event, FileSystemEvent, CryptoEvent, NetworkEvent, 
    ProcessEvent, IPCEvent, ServiceEvent, DEXEvent,
    JNIEvent
)
from ..utils.hexdump import hexdump
from ..utils.string_utils import truncate_string


class ConsoleFormatter(BaseFormatter):
    """Console formatter for human-readable output"""
    
    def __init__(self, verbose_mode: bool = False):
        self.verbose_mode = verbose_mode
    
    def format_event(self, event: Event) -> Optional[str]:
        """Format event for console output"""
        if self.should_skip_event(event):
            return None
        
        # Route to specific formatter based on event type
        if isinstance(event, FileSystemEvent):
            return self._format_filesystem_event(event)
        elif isinstance(event, CryptoEvent):
            return self._format_crypto_event(event)
        elif isinstance(event, NetworkEvent):
            return self._format_network_event(event)
        elif isinstance(event, ProcessEvent):
            return self._format_process_event(event)
        elif isinstance(event, IPCEvent):
            return self._format_ipc_event(event)
        elif isinstance(event, ServiceEvent):
            return self._format_service_event(event)
        elif isinstance(event, DEXEvent):
            return self._format_dex_event(event)
        elif isinstance(event,JNIEvent):
            return self._format_jni_event(event)
        else:
            return self._format_generic_event(event)
    
    def _format_filesystem_event(self, event: FileSystemEvent) -> str:
        """Format file system events"""
        lines = []
        
        if event.event_type == 'file.create':
            lines.append("\n[*] [File] File Creation:")
            lines.append(f"[*] Operation: {event.operation or 'Unknown'}")
            lines.append(f"[*] File Path: {event.file_path or 'Unknown'}")
            if event.parent_path:
                lines.append(f"[*] Parent: {event.parent_path}")
                lines.append(f"[*] Child: {event.child_path}")
        
        elif event.event_type == 'file.stream.create':
            lines.append("\n[*] [File] Stream Creation:")
            lines.append(f"[*] Operation: {event.operation or 'Unknown'}")
            lines.append(f"[*] Stream Type: {event.stream_type or 'Unknown'}")
            lines.append(f"[*] File Path: {event.file_path or 'Unknown'}")
        
        elif event.event_type == 'file.read':
            lines.append("\n[*] [File] Read Operation:")
            lines.append(f"[*] Operation: {event.operation or 'Unknown'}")
            lines.append(f"[*] File Path: {event.file_path or 'Unknown'}")
            lines.append(f"[*] Buffer Size: {event.buffer_size or 0} bytes")
            if event.offset is not None:
                lines.append(f"[*] Offset: {event.offset}, Length: {event.length or 0}")
            if event.bytes_read:
                lines.append(f"[*] Bytes Read: {event.bytes_read}")
            
            # Display data if available (truncated for terminal)
            if event.data_hex:
                lines.append("[*] Data:")
                data_dump = hexdump(event.data_hex, header=True, ansi=True, truncate=True, max_bytes=0x50)
                for line in data_dump.split('\n'):
                    lines.append(f"    {line}")
            elif event.hexdump_display:
                lines.append("[*] Data:")
                for line in event.hexdump_display.split('\n'):
                    lines.append(f"    {line}")
            elif event.plaintext:
                plaintext = truncate_string(event.plaintext, 100)
                lines.append(f"[*] Content: {plaintext}")
        
        elif event.event_type == 'file.write':
            lines.append("\n[*] [File] Write Operation:")
            lines.append(f"[*] Operation: {event.operation or 'Unknown'}")
            lines.append(f"[*] File Path: {event.file_path or 'Unknown'}")
            lines.append(f"[*] Buffer Size: {event.buffer_size or 0} bytes")
            if event.offset is not None:
                lines.append(f"[*] Offset: {event.offset}, Length: {event.length or 0}")
            if event.is_large_data:
                lines.append(f"[*] Data truncated (showing {getattr(event, 'displayed_length', 0)} of {getattr(event, 'original_length', 0)} bytes)")
            
            # Display data based on file type (truncated for terminal)
            if event.file_type == 'xml' and event.plaintext:
                plaintext = truncate_string(event.plaintext, 200)
                lines.append(f"[*] XML Content: {plaintext}")
            elif event.data_hex:
                lines.append("[*] Binary Data:" if event.file_type == 'binary' else "[*] Data:")
                data_dump = hexdump(event.data_hex, header=True, ansi=True, truncate=True, max_bytes=0x50)
                for line in data_dump.split('\n'):
                    lines.append(f"    {line}")
            elif event.hexdump_display:
                lines.append("[*] Data:")
                for line in event.hexdump_display.split('\n'):
                    lines.append(f"    {line}")
            elif event.plaintext:
                plaintext = truncate_string(event.plaintext, 100)
                lines.append(f"[*] Content: {plaintext}")
        
        elif event.event_type.startswith('file.delete'):
            lines.append(f"\n[*] [File] File Deletion ({event.event_type}):")
            lines.append(f"[*] File Path: {event.file_path or 'Unknown'}")
        
        else:
            # Fallback for unknown filesystem events
            lines.append(f"[*] [File] {event.event_type}: {event.file_path or 'Unknown'}")
        
        lines.append("")  # Empty line
        return '\n'.join(lines)
    
    def _format_crypto_event(self, event: CryptoEvent) -> str:
        """Format crypto events"""
        lines = []
        
        if event.event_type == 'crypto.cipher.operation':
            lines.append(f"\n[*] AES {event.operation_mode_desc or 'UNKNOWN'} Operation:")
            lines.append(f"    Algorithm: {event.algorithm or 'N/A'}")

            # Display input data with hexdump (truncated for terminal, full in JSON)
            if event.input_hex:
                lines.append(f"    Input ({event.input_length or 0} bytes):")
                input_dump = hexdump(event.input_hex, header=True, ansi=True, truncate=True, max_bytes=0x50)
                if input_dump:
                    for line in input_dump.split('\n'):
                        lines.append(f"      {line}")

            # Display output data with hexdump (truncated for terminal, full in JSON)
            if event.output_hex:
                lines.append(f"    Output ({event.output_length or 0} bytes):")
                output_dump = hexdump(event.output_hex, header=True, ansi=True, truncate=True, max_bytes=0x50)
                if output_dump:
                    for line in output_dump.split('\n'):
                        lines.append(f"      {line}")

            # Display plaintext if available (truncated for terminal)
            if event.plaintext:
                plaintext = truncate_string(event.plaintext, 100)
                lines.append(f"    Plaintext: {plaintext}")
        
        elif event.event_type == 'crypto.key.creation':
            lines.append("[*] AES Key Created:")
            lines.append(f"    Algorithm: {event.algorithm or 'N/A'}")
            lines.append(f"    Key Length: {event.key_length or 0} bytes")
            if event.key_hex:
                lines.append("    Key:")
                key_dump = hexdump(event.key_hex, header=True, ansi=True, truncate=True, max_bytes=0x50)
                if key_dump:
                    for line in key_dump.split('\n'):
                        lines.append(f"      {line}")

        elif event.event_type == 'crypto.iv.creation':
            lines.append("[*] AES IV Created:")
            lines.append(f"    IV Length: {event.iv_length or 0} bytes")
            if event.iv_hex:
                lines.append("    IV:")
                iv_dump = hexdump(event.iv_hex, header=True, ansi=True, truncate=True, max_bytes=0x50)
                if iv_dump:
                    for line in iv_dump.split('\n'):
                        lines.append(f"      {line}")
        
        else:
            lines.append(f"[*] Crypto: {event.event_type}")
        
        lines.append("")  # Empty line
        return '\n'.join(lines)
    
    def _format_network_event(self, event: NetworkEvent) -> str:
        """Format network events"""
        lines = []
        
        # Handle different web event types
        if event.event_type.startswith('url.'):
            lines.append(f"[*] [{event.event_type}] URL: {event.url or 'unknown'}")
            if event.req_method:
                lines.append(f"[*] [{event.event_type}] Method: {event.req_method}")
        
        elif event.event_type.startswith('uri.'):
            lines.append(f"[*] [{event.event_type}] URI: {event.uri or 'unknown'}")
        
        elif event.event_type.startswith(('http.', 'https.')):
            lines.append(f"[*] [{event.event_type}] URL: {event.url or 'unknown'}")
            if event.status_code:
                lines.append(f"[*] [{event.event_type}] Status: {event.status_code}")
            if event.method:
                lines.append(f"[*] [{event.event_type}] Method: {event.method}")
        
        elif event.event_type.startswith('okhttp.'):
            lines.append(f"[*] [{event.event_type}] URL: {event.url or 'unknown'}")
            if event.headers:
                lines.append(f"[*] [{event.event_type}] Headers: {event.headers}")
            if event.body:
                body = truncate_string(event.body, 100)
                lines.append(f"[*] [{event.event_type}] Body: {body}")
        
        elif event.event_type.startswith('webview.'):
            lines.append(f"[*] [{event.event_type}] URL: {event.url or 'N/A'}")
            if event.data:
                lines.append(f"[*] [{event.event_type}] Data: {event.data}")
            if event.mime_type:
                lines.append(f"[*] [{event.event_type}] MIME Type: {event.mime_type}")
        
        elif event.event_type.startswith('socket.'):
            operation = event.operation or 'Socket Operation'
            socket_desc = event.socket_description or 'Unknown Socket'
            lines.append(f"\n[*] [Socket] {operation} ({socket_desc}):")
            
            if event.socket_descriptor:
                lines.append(f"[*] Socket FD: {event.socket_descriptor}")
            
            if event.local_address:
                lines.append(f"[*] Local: {event.local_address}")
                
            if event.remote_address:
                lines.append(f"[*] Remote: {event.remote_address}")
                
            if event.connection_string:
                lines.append(f"[*] Connection: {event.connection_string}")
                
            if event.data_length:
                lines.append(f"[*] Data Length: {event.data_length} bytes")
                
            if event.has_buffer:
                lines.append("[*] Buffer Data: Available")
        
        else:
            lines.append(f"[*] [Network] {event.event_type}: {getattr(event, 'url', '') or getattr(event, 'uri', '') or 'Unknown'}")
        
        lines.append("")  # Empty line
        return '\n'.join(lines)
    
    def _format_process_event(self, event: ProcessEvent) -> str:
        """Format process events"""
        lines = []
        
        if event.event_type == 'process.creation':
            lines.append("\n[*] [Process] New Process Creation:")
            if event.nice_name:
                lines.append(f"[*] Process Name: {event.nice_name}")
            if event.uid is not None:
                lines.append(f"[*] UID: {event.uid}")
            if event.gid is not None:
                lines.append(f"[*] GID: {event.gid}")
            if event.target_sdk_version:
                lines.append(f"[*] Target SDK: {event.target_sdk_version}")
            if event.abi:
                lines.append(f"[*] ABI: {event.abi}")
        
        elif event.event_type in ['process.kill', 'process.signal']:
            action = 'Kill Process' if event.event_type == 'process.kill' else 'Send Signal'
            lines.append(f"\n[*] [Process] {action}:")
            if event.target_pid:
                lines.append(f"[*] Target PID: {event.target_pid}")
            if event.signal:
                lines.append(f"[*] Signal: {event.signal}")
        
        elif event.event_type.startswith('process.fork'):
            lines.append(f"\n[*] [Process] Fork Operation ({event.event_type}):")
            if event.caller_pid:
                lines.append(f"[*] Caller PID: {event.caller_pid}")
            if event.child_pid:
                lines.append(f"[*] Child PID: {event.child_pid}")
            if event.success is not None:
                lines.append(f"[*] Success: {event.success}")
        
        elif event.event_type.startswith('process.system'):
            lines.append(f"\n[*] [Process] System Command ({event.event_type}):")
            if event.command:
                lines.append(f"[*] Command: {event.command}")
            if event.return_value is not None:
                lines.append(f"[*] Return Value: {event.return_value}")
        
        elif event.event_type == 'runtime.exec':
            lines.append("\n[*] [Runtime] Command Execution:")
            if event.command:
                lines.append(f"[*] Command: {event.command}")
            if event.working_directory:
                lines.append(f"[*] Working Directory: {event.working_directory}")
            if event.environment:
                lines.append(f"[*] Environment: {event.environment}")
        
        elif event.event_type in ['runtime.load_library', 'runtime.load']:
            action = 'Load Library' if event.event_type == 'runtime.load_library' else 'Load'
            lines.append(f"\n[*] [Runtime] {action}:")
            if event.library_name:
                lines.append(f"[*] Library: {event.library_name}")
            if event.filename:
                lines.append(f"[*] Filename: {event.filename}")
        
        elif event.event_type.startswith('reflection.'):
            lines.extend(self._format_reflection_event(event))
        
        else:
            lines.append(f"[*] [Process] {event.event_type}: {event.command or event.library_name or 'Unknown'}")
        
        lines.append("")  # Empty line
        return '\n'.join(lines)
    
    def _format_reflection_event(self, event: ProcessEvent) -> list:
        """Format reflection-specific events"""
        lines = []
        
        if event.event_type in ['reflection.class_for_name', 'reflection.load_class']:
            action = 'Class.forName' if event.event_type == 'reflection.class_for_name' else 'ClassLoader.loadClass'
            lines.append(f"\n[*] [Reflection] {action}:")
            if 'class_name' in event.metadata:
                lines.append(f"[*] Class: {event.metadata['class_name']}")
            if 'initialize' in event.metadata:
                lines.append(f"[*] Initialize: {event.metadata['initialize']}")
            if 'resolve' in event.metadata:
                lines.append(f"[*] Resolve: {event.metadata['resolve']}")
        
        elif event.event_type in ['reflection.get_method', 'reflection.get_declared_method']:
            access = 'Public' if event.event_type == 'reflection.get_method' else 'Declared'
            lines.append(f"\n[*] [Reflection] Get {access} Method:")
            if 'class_name' in event.metadata:
                lines.append(f"[*] Class: {event.metadata['class_name']}")
            if 'method_name' in event.metadata:
                lines.append(f"[*] Method: {event.metadata['method_name']}")
            if 'method_signature' in event.metadata:
                lines.append(f"[*] Signature: {event.metadata['method_signature']}")
        
        elif event.event_type == 'reflection.method_invoke':
            lines.append("\n[*] [Reflection] Method Invoke:")
            if 'method_name' in event.metadata:
                lines.append(f"[*] Method: {event.metadata['method_name']}")
            if 'target_instance' in event.metadata:
                lines.append(f"[*] Target: {event.metadata['target_instance']}")
            if 'arguments' in event.metadata and event.metadata['arguments']:
                lines.append(f"[*] Arguments: {event.metadata['arguments']}")
            if 'result' in event.metadata and event.metadata['result']:
                result = truncate_string(str(event.metadata['result']), 100)
                lines.append(f"[*] Result: {result}")
        
        else:
            lines.append(f"[*] [Reflection] {event.event_type}")
        
        return lines
    
    def _format_ipc_event(self, event: IPCEvent) -> str:
        """Format IPC events"""
        lines = []
        
        if event.event_type.startswith('shared_prefs.'):
            if event.key and event.value:
                lines.append(f"[*] [{event.event_type}] {event.key} = {event.value}")
            elif event.file:
                lines.append(f"[*] [{event.event_type}] File: {event.file}")
            else:
                lines.append(f"[*] [{event.event_type}] {event.method or 'unknown'}")
        
        elif event.event_type.startswith('datastore'):
            if event.key and event.value:
                lines.append(f"[*] [{event.event_type}] {event.key} = {event.value}")
            elif event.data:
                lines.append(f"[*] [{event.event_type}] Data: {event.data}")
            else:
                lines.append(f"[*] [{event.event_type}] {event.method or 'unknown'}")
        
        elif event.event_type == 'binder.transaction':
            transaction_desc = event.transaction_desc or 'Unknown'
            sender_pid = event.sender_pid or 'unknown'
            code = event.code or 'unknown'
            data_size = event.data_size or 0
            lines.append(f"\n[*] [Binder] {transaction_desc}:")
            lines.append(f"[*] Sender PID: {sender_pid}, Code: {code}, Data Size: {data_size} bytes")
            if event.payload_hex:
                payload_preview = truncate_string(event.payload_hex, 200)
                lines.append(f"[*] Payload Preview: {payload_preview}")
        
        elif event.event_type.startswith('intent.'):
            lines.append(f"\n[*] [Intent] {event.event_type}:")
            if event.intent_name:
                lines.append(f"[*] Intent: {event.intent_name}")
            if event.intent:
                intent_info = event.intent
                if intent_info.get('action'):
                    lines.append(f"[*] Action: {intent_info['action']}")
                if intent_info.get('component'):
                    lines.append(f"[*] Component: {intent_info['component']}")
                if intent_info.get('data_uri'):
                    lines.append(f"[*] Data URI: {intent_info['data_uri']}")
                if intent_info.get('mime_type'):
                    lines.append(f"[*] MIME Type: {intent_info['mime_type']}")
            if event.extras_formatted:
                lines.append("[*] Extras:")
                for extra in event.extras_formatted:
                    lines.append(f"    {extra}")
        
        elif event.event_type.startswith('broadcast.'):
            lines.append(f"\n[*] [Broadcast] {event.event_type}:")
            if event.intent_name:
                lines.append(f"[*] Intent: {event.intent_name}")
            if event.intent_details:
                details = event.intent_details
                if details.get('action'):
                    lines.append(f"[*] Action: {details['action']}")
                if details.get('component'):
                    lines.append(f"[*] Component: {details['component']}")
                if details.get('data_uri'):
                    lines.append(f"[*] Data URI: {details['data_uri']}")
        
        else:
            lines.append(f"[*] [IPC] {event.event_type}")
        
        lines.append("")  # Empty line
        return '\n'.join(lines)
    
    def _format_service_event(self, event: ServiceEvent) -> str:
        """Format service events"""
        lines = []
        
        # Bluetooth events
        if event.event_type.startswith('bluetooth.'):
            lines.append(f"\n[*] [Bluetooth] {event.event_description or event.event_type}:")
            if event.characteristic_uuid:
                lines.append(f"[*] Characteristic UUID: {event.characteristic_uuid}")
            if event.device_address:
                lines.append(f"[*] Device Address: {event.device_address}")
            if event.device_name:
                lines.append(f"[*] Device Name: {event.device_name}")
            if event.value_hex:
                lines.append(f"[*] Value (hex): {event.value_hex}")
        
        # Telephony events
        elif event.event_type.startswith('telephony.'):
            lines.append(f"\n[*] [Telephony] {event.event_description or event.event_type}:")
            if event.destination_address:
                lines.append(f"[*] Destination: {event.destination_address}")
            if event.message_text:
                text = truncate_string(event.message_text, 100)
                lines.append(f"[*] Message: {text}")
            if event.phone_number:
                lines.append(f"[*] Phone Number: {event.phone_number}")
            if event.imei:
                lines.append(f"[*] IMEI: {event.imei}")
            if event.property_key:
                lines.append(f"[*] Property: {event.property_key} = {event.property_value or 'N/A'}")
        
        # Location events
        elif event.event_type.startswith('location.'):
            lines.append(f"\n[*] [Location] {event.event_description or event.event_type}:")
            if event.provider:
                lines.append(f"[*] Provider: {event.provider}")
            if event.latitude is not None and event.longitude is not None:
                lines.append(f"[*] Coordinates: {event.latitude}, {event.longitude}")
            if event.accuracy is not None:
                lines.append(f"[*] Accuracy: {event.accuracy}m")
            if event.has_location is not None:
                lines.append(f"[*] Has Location: {event.has_location}")
        
        # Clipboard events
        elif event.event_type.startswith('clipboard.'):
            lines.append(f"\n[*] [Clipboard] {event.event_description or event.event_type}:")
            if event.content_type:
                lines.append(f"[*] Content Type: {event.content_type}")
            if event.content:
                content = truncate_string(event.content, 100)
                lines.append(f"[*] Content: {content}")
            if event.item_count is not None:
                lines.append(f"[*] Items: {event.item_count}")
        
        # Camera events
        elif event.event_type.startswith('camera.'):
            lines.append(f"\n[*] [Camera] {event.event_description or event.event_type}:")
            if event.camera_id:
                lines.append(f"[*] Camera ID: {event.camera_id}")
            if event.camera_count is not None:
                lines.append(f"[*] Available Cameras: {event.camera_count}")
            if event.success is not None:
                lines.append(f"[*] Success: {event.success}")
        
        else:
            lines.append(f"[*] [Service] {event.event_type}")
        
        lines.append("")  # Empty line
        return '\n'.join(lines)
    
    def _format_dex_event(self, event: DEXEvent) -> str:
        """Format DEX events"""
        lines = []

        # Handle legacy format
        if event.event_type == "dex.loading" and event.even_type:
            lines.append(f"[*] Method used for unpacking: {event.even_type}")

        # Handle new structured events
        elif event.event_type == "dex.unpacking.detected":
            if hasattr(event, 'hooked_function') and event.hooked_function:
                # Extract just the function name from demangled format
                func_parts = str(event.hooked_function).split("::")
                func_name = func_parts[-1] if len(func_parts) > 1 else event.hooked_function
                lines.append(f"[*] Method used for unpacking: {func_name}")
            if hasattr(event, 'magic') and event.magic:
                lines.append(f"[*] Magic: {event.magic}")
            if hasattr(event, 'size') and event.size:
                lines.append(f"[*] Size: {event.size}")
            if hasattr(event, 'original_location') and event.original_location:
                lines.append(f"[*] Original location: {event.original_location}")

        elif event.event_type.startswith("dex.classloader."):
            loader_type = getattr(event, 'class_loader_type', 'Unknown')
            file_path = getattr(event, 'file_path', 'Unknown')
            lines.append(f"[*] {loader_type} loading: {file_path}")

        elif event.event_type == "dex.in_memory_loader":
            buffer_size = getattr(event, 'buffer_size', 'Unknown')
            lines.append(f"[*] InMemoryDexClassLoader: {buffer_size} bytes")

        elif event.event_type == "dex.dump_success":
            file_name = getattr(event, 'file_name', 'Unknown')
            bytes_written = getattr(event, 'bytes_written', 'Unknown')
            lines.append(f"[*] Dumped successfully: {file_name} ({bytes_written} bytes)")

        else:
            lines.append(f"[*] DEX: {event.event_type}")

        return '\n'.join(lines) if lines else ""
    
    def _format_jni_event(self, event: JNIEvent) -> str:
        """Format JNI events"""
        lines = []
        md = event.metadata or {}
        event_type = event.event_type

        # Prefer parser-generated description when present
        desc = md.get("description")

        if event_type == "jni.library.tracked":
            lines.append("\n[*] [JNI] Library Tracked:")
            lines.append(f"[*] Library Path: {md.get('library_path', 'Unknown')}")
            if desc:
                lines.append(f"[*] Description: {desc}")

        elif event_type == "jni.env.call":
            method = md.get("method", "Unknown")
            args = md.get("arguments", [])
            ret = md.get("return_value", "Unknown")
            sig = md.get("java_method_sig")
            thread_id = md.get("thread_id")

            lines.append("\n[*] [JNI] JNIEnv Call:")
            lines.append(f"[*] Method: {method}")
            if sig:
                lines.append(f"[*] Java Signature: {sig}")
            # Arguments
            if args:
                arg_str = ", ".join(map(str, args))
                lines.append(f"[*] Arguments: {arg_str}")
            else:
                lines.append("[*] Arguments: (none)")
            lines.append(f"[*] Return: {ret}")
            if thread_id is not None:
                lines.append(f"[*] Thread ID: {thread_id}")

            # Enriched details if available
            if md.get("class_name"):
                lines.append(f"[*] Class Name: {md['class_name']}")
            if md.get("string_argument"):
                lines.append(f"[*] String Argument: {md['string_argument']}")
            if md.get("string_return"):
                lines.append(f"[*] Decoded Return: {md['string_return']}")
            if method == "GetStringCritical" and md.get("string_return"):
                lines.append(f"[*] Critical String: {md['string_return']}")
                
            # Decoded method/field IDs
            if method in ("GetMethodID", "GetStaticMethodID"):
                if md.get("method_name"):
                    lines.append(f"[*] Target Method Name: {md['method_name']}")
                if md.get("method_signature"):
                    lines.append(f"[*] Target Method Signature: {md['method_signature']}")
                if md.get("method_descriptor"):
                    lines.append(f"[*] Method Descriptor: {md['method_descriptor']}")

            if method in ("GetFieldID", "GetStaticFieldID"):
                if md.get("field_name"):
                    lines.append(f"[*] Target Field Name: {md['field_name']}")
                if md.get("field_signature"):
                    lines.append(f"[*] Target Field Signature: {md['field_signature']}")
                if md.get("field_descriptor"):
                    lines.append(f"[*] Field Descriptor: {md['field_descriptor']}")

            # Decoded RegisterNatives array
            if method == "RegisterNatives" and md.get("registered_natives"):
                lines.append("[*] Registered natives:")
                for native in md["registered_natives"]:
                    name = native.get("name") or "<unknown>"
                    sig = native.get("signature") or ""
                    addr = native.get("address") or "<addr?>"
                    lines.append(f"    {addr} - {name}{sig}")

            # ThrowNew / FatalError messages
            if method == "ThrowNew" and md.get("throw_message"):
                lines.append(f"[*] Exception Message: {md['throw_message']}")
            if method == "FatalError" and md.get("fatal_message"):
                lines.append(f"[*] Fatal Error Message: {md['fatal_message']}")

            # GetJavaVM decoded JavaVM pointer
            if method == "GetJavaVM" and md.get("java_vm_ptr"):
                lines.append(f"[*] JavaVM*: {md['java_vm_ptr']}")

            # DefineClass decoded info
            if method == "DefineClass":
                if md.get("define_class_name"):
                    lines.append(f"[*] Class Name: {md['define_class_name']}")
                if md.get("class_data_length") is not None:
                    lines.append(f"[*] Class Data Length: {md['class_data_length']} bytes")
                if md.get("class_data_hex"):
                    lines.append(f"[*] Class Data (hex, truncated): {md['class_data_hex']}")
            
            # Direct buffer details (if present)
            if method in ("NewDirectByteBuffer", "GetDirectBufferAddress", "GetDirectBufferCapacity"):
                if md.get("direct_buffer_address"):
                    lines.append(f"[*] Direct Buffer Address: {md['direct_buffer_address']}")
                if md.get("direct_buffer_capacity") is not None:
                    lines.append(f"[*] Direct Buffer Capacity: {md['direct_buffer_capacity']} bytes")
                if md.get("buffer_hex"):
                    lines.append("[*] Direct Buffer Data (console view, truncated):")
                    dump = hexdump(md["buffer_hex"], header=True, ansi=True,
                                   truncate=True, max_bytes=0x50)
                    if dump:
                        for line in dump.split('\n'):
                            lines.append(f"    {line}")
                if md.get("buffer_truncated"):
                    lines.append("[*] Direct buffer data truncated in console view")
            
            if md.get("array_length") is not None:
                lines.append(f"[*] Array Length: {md['array_length']} elements")

            if md.get("array_hex"):
                # JSON contains the full hex; console shows a truncated hexdump
                lines.append("[*] Array Data (console view, truncated):")
                dump = hexdump(md["array_hex"], header=True, ansi=True,
                            truncate=True, max_bytes=0x50)
                if dump:
                    for line in dump.split('\n'):
                        lines.append(f"    {line}")
            
            if md.get("array_values") is not None:
                lines.append(f"[*] Array Values: {md['array_values']}")

            # Java-level params/args (for Call*/NewObject* when available)
            if md.get("java_params"):
                lines.append(f"[*] Java Params: {md['java_params']}")
            if md.get("java_args"):
                lines.append(f"[*] Java Args: {md['java_args']}")
            if md.get("java_ret_type"):
                lines.append(f"[*] Java Return Type: {md['java_ret_type']}")
            if md.get("java_ret_value") is not None:
                lines.append(f"[*] Java Return Value: {md['java_ret_value']}")

            # Backtrace (if available)
            self._append_jni_backtrace(md, lines)
            
            if desc:
                lines.append(f"[*] Summary: {desc}")

        elif event_type == "jni.vm.call":
            method = md.get("method", "Unknown")
            args = md.get("arguments", [])
            ret = md.get("return_value", "Unknown")
            thread_id = md.get("thread_id")

            lines.append("\n[*] [JNI] JavaVM Call:")
            lines.append(f"[*] Method: {method}")
            if args:
                arg_str = ", ".join(map(str, args))
                lines.append(f"[*] Arguments: {arg_str}")
            else:
                lines.append("[*] Arguments: (none)")
            lines.append(f"[*] Return: {ret}")
            if thread_id is not None:
                lines.append(f"[*] Thread ID: {thread_id}")

            # Backtrace (if available)
            self._append_jni_backtrace(md, lines)

            if desc:
                lines.append(f"[*] Summary: {desc}")

        else:
            # Fallback for any unexpected JNI event
            lines.append(f"\n[*] [JNI] {event_type}: {md or 'Unknown'}")

        lines.append("")  # Empty line at end
        return "\n".join(lines)
    
    def _append_jni_backtrace(self, md, lines):
        bt = md.get("backtrace")
        if not bt:
            return

        lines.append("[*] Backtrace:")
        max_frames = 16
        count = 0
        for frame in bt:
            if count >= max_frames:
                break

            if isinstance(frame, str):
                lines.append(f"    {frame}")
                count += 1
                continue

            if isinstance(frame, dict):
                mod = frame.get("module")
                # Stop when frame without module info is reached
                if not mod:
                    break

                addr = frame.get("address") or "0x?"
                sym = frame.get("symbol") or {}

                mod_name = mod.get("name") or ""
                sym_name = sym.get("name") or ""

                if sym_name:
                    if mod_name:
                        lines.append(f"    {addr}: {mod_name}!{sym_name}")
                    else:
                        lines.append(f"    {addr}: {sym_name}")
                elif mod_name:
                    lines.append(f"    {addr}: {mod_name}")
                else:
                    lines.append(f"    {addr}")

                count += 1
    
    def _format_generic_event(self, event: Event) -> str:
        """Format generic events"""
        return f"[*] {event.event_type}: {getattr(event, 'payload', 'Unknown')}"
    
    def should_skip_event(self, event: Event) -> bool:
        """Determine if event should be skipped from console output"""
        # Skip certain verbose events unless in verbose mode
        if not self.verbose_mode:
            skip_types = ['parse_error', 'console_dev']
            if any(skip_type in event.event_type for skip_type in skip_types):
                return True
        
        # Skip file write events for certain paths unless verbose
        if isinstance(event, FileSystemEvent) and not self.verbose_mode:
            if event.file_path and "/system/fonts/" in event.file_path:
                return True
            if "stat" in getattr(event, 'operation', ''):
                return True
        
        return False
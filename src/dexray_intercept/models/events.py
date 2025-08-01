#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
from typing import Dict, Any
from datetime import datetime


class Event(ABC):
    """Base class for all security events"""
    
    def __init__(self, event_type: str, timestamp: str = None):
        self.event_type = event_type
        self.timestamp = timestamp or datetime.now().isoformat()
        self.metadata = {}
    
    def add_metadata(self, key: str, value: Any):
        """Add metadata to the event"""
        self.metadata[key] = value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization"""
        result = {
            'event_type': self.event_type,
            'timestamp': self.timestamp
        }
        result.update(self.get_event_data())
        if self.metadata:
            result['metadata'] = self.metadata
        return result
    
    @abstractmethod
    def get_event_data(self) -> Dict[str, Any]:
        """Get event-specific data"""
        pass


class FileSystemEvent(Event):
    """File system operation event"""
    
    def __init__(self, event_type: str, file_path: str, timestamp: str = None):
        super().__init__(event_type, timestamp)
        self.file_path = file_path
        self.operation = None
        self.buffer_size = 0
        self.offset = None
        self.length = None
        self.data_hex = None
        self.plaintext = None
        self.file_type = None
        self.is_large_data = False
        self.fd = None
        self.parent_path = None
        self.child_path = None
        self.stream_type = None
        self.bytes_read = None
        self.bytes_written = None
        self.hexdump_display = None
    
    def get_event_data(self) -> Dict[str, Any]:
        data = {'file_path': self.file_path}
        
        # Only include non-None values
        optional_fields = [
            'operation', 'buffer_size', 'offset', 'length', 'data_hex',
            'plaintext', 'file_type', 'is_large_data', 'fd', 'parent_path',
            'child_path', 'stream_type', 'bytes_read', 'bytes_written',
            'hexdump_display'
        ]
        
        for field in optional_fields:
            value = getattr(self, field)
            if value is not None:
                data[field] = value
                
        return data


class CryptoEvent(Event):
    """Cryptographic operation event"""
    
    def __init__(self, event_type: str, algorithm: str = None, timestamp: str = None):
        super().__init__(event_type, timestamp)
        self.algorithm = algorithm
        self.operation_mode = None
        self.operation_mode_desc = None
        self.input_hex = None
        self.output_hex = None
        self.input_length = 0
        self.output_length = 0
        self.key_hex = None
        self.key_length = 0
        self.iv_hex = None
        self.iv_length = 0
        self.plaintext = None
    
    def get_event_data(self) -> Dict[str, Any]:
        data = {}
        
        # Include all non-None values
        fields = [
            'algorithm', 'operation_mode', 'operation_mode_desc',
            'input_hex', 'output_hex', 'input_length', 'output_length',
            'key_hex', 'key_length', 'iv_hex', 'iv_length', 'plaintext'
        ]
        
        for field in fields:
            value = getattr(self, field)
            if value is not None:
                data[field] = value
                
        return data


class NetworkEvent(Event):
    """Network operation event"""
    
    def __init__(self, event_type: str, timestamp: str = None):
        super().__init__(event_type, timestamp)
        self.url = None
        self.uri = None
        self.method = None
        self.req_method = None
        self.status_code = None
        self.headers = None
        self.body = None
        self.data = None
        self.mime_type = None
        self.socket_type = None
        self.socket_descriptor = None
        self.local_ip = None
        self.local_port = None
        self.remote_ip = None
        self.remote_port = None
        self.local_address = None
        self.remote_address = None
        self.connection_string = None
        self.data_length = 0
        self.has_buffer = False
        self.operation = None
        self.socket_description = None
    
    def get_event_data(self) -> Dict[str, Any]:
        data = {}
        
        fields = [
            'url', 'uri', 'method', 'req_method', 'status_code', 'headers',
            'body', 'data', 'mime_type', 'socket_type', 'socket_descriptor',
            'local_ip', 'local_port', 'remote_ip', 'remote_port',
            'local_address', 'remote_address', 'connection_string',
            'data_length', 'has_buffer', 'operation', 'socket_description'
        ]
        
        for field in fields:
            value = getattr(self, field)
            if value is not None:
                data[field] = value
                
        return data


class ProcessEvent(Event):
    """Process operation event"""
    
    def __init__(self, event_type: str, timestamp: str = None):
        super().__init__(event_type, timestamp)
        self.nice_name = None
        self.uid = None
        self.gid = None
        self.target_sdk_version = None
        self.abi = None
        self.target_pid = None
        self.signal = None
        self.caller_pid = None
        self.child_pid = None
        self.success = None
        self.command = None
        self.return_value = None
        self.library_name = None
        self.filename = None
        self.working_directory = None
        self.environment = None
        self.event_description = None
    
    def get_event_data(self) -> Dict[str, Any]:
        data = {}
        
        fields = [
            'nice_name', 'uid', 'gid', 'target_sdk_version', 'abi',
            'target_pid', 'signal', 'caller_pid', 'child_pid', 'success',
            'command', 'return_value', 'library_name', 'filename',
            'working_directory', 'environment', 'event_description'
        ]
        
        for field in fields:
            value = getattr(self, field)
            if value is not None:
                data[field] = value
                
        return data


class IPCEvent(Event):
    """Inter-Process Communication event"""
    
    def __init__(self, event_type: str, timestamp: str = None):
        super().__init__(event_type, timestamp)
        self.key = None
        self.value = None
        self.file = None
        self.method = None
        self.data = None
        self.intent_name = None
        self.intent = None
        self.intent_details = None
        self.intent_flag = None
        self.extras_formatted = None
        self.transaction_type = None
        self.transaction_desc = None
        self.sender_pid = None
        self.code = None
        self.data_size = 0
        self.payload_hex = None
    
    def get_event_data(self) -> Dict[str, Any]:
        data = {}
        
        fields = [
            'key', 'value', 'file', 'method', 'data', 'intent_name',
            'intent', 'intent_details', 'intent_flag', 'extras_formatted',
            'transaction_type', 'transaction_desc', 'sender_pid', 'code',
            'data_size', 'payload_hex'
        ]
        
        for field in fields:
            value = getattr(self, field)
            if value is not None:
                data[field] = value
                
        return data


class ServiceEvent(Event):
    """Android system service event"""
    
    def __init__(self, event_type: str, timestamp: str = None):
        super().__init__(event_type, timestamp)
        self.event_description = None
        self.characteristic_uuid = None
        self.device_address = None
        self.device_name = None
        self.value_hex = None
        self.destination_address = None
        self.message_text = None
        self.phone_number = None
        self.imei = None
        self.property_key = None
        self.property_value = None
        self.provider = None
        self.latitude = None
        self.longitude = None
        self.accuracy = None
        self.has_location = None
        self.content_type = None
        self.content = None
        self.item_count = None
        self.camera_id = None
        self.camera_count = None
        self.success = None
    
    def get_event_data(self) -> Dict[str, Any]:
        data = {}
        
        fields = [
            'event_description', 'characteristic_uuid', 'device_address',
            'device_name', 'value_hex', 'destination_address', 'message_text',
            'phone_number', 'imei', 'property_key', 'property_value',
            'provider', 'latitude', 'longitude', 'accuracy', 'has_location',
            'content_type', 'content', 'item_count', 'camera_id',
            'camera_count', 'success'
        ]
        
        for field in fields:
            value = getattr(self, field)
            if value is not None:
                data[field] = value
                
        return data


class DEXEvent(Event):
    """DEX loading/unpacking event"""
    
    def __init__(self, event_type: str, timestamp: str = None):
        super().__init__(event_type, timestamp)
        self.unpacking = False
        self.dumped = None
        self.orig_location = None
        self.even_type = None  # Keep original field name for compatibility
    
    def get_event_data(self) -> Dict[str, Any]:
        data = {}
        
        fields = ['unpacking', 'dumped', 'orig_location', 'even_type']
        
        for field in fields:
            value = getattr(self, field)
            if value is not None:
                data[field] = value
                
        return data


class DatabaseEvent(Event):
    """Database operation event"""
    
    def __init__(self, event_type: str, timestamp: str = None):
        super().__init__(event_type, timestamp)
        self.database_path = None
        self.database_type = None  # SQLite, SQLCipher, WCDB, Room, etc.
        self.method = None
        self.table = None
        self.sql = None
        self.bind_args = None
        self.content_values = None
        self.where_clause = None
        self.where_args = None
        self.columns = None
        self.group_by = None
        self.having = None
        self.order_by = None
        self.limit = None
        self.flags = None
        self.flags_description = None
        self.password = None
        self.access_type = None  # readable, writable
        self.create_if_necessary = None
        self.has_factory = None
        self.transaction_action = None  # begin, end, successful
        self.dao_operation = None  # insert, update, delete
        self.entity = None
        self.callback_type = None  # onCreate, onOpen
        self.database_object = None
        self.database_name = None
        self.database_class = None
        self.result_code = None
        self.status = None
        self.rows_affected = None
        self.throw_on_error = None
        self.null_column_hack = None
        self.cancellation_signal = None
        self.pragma_type = None
    
    def get_event_data(self) -> Dict[str, Any]:
        data = {}
        
        fields = [
            'database_path', 'database_type', 'method', 'table', 'sql',
            'bind_args', 'content_values', 'where_clause', 'where_args',
            'columns', 'group_by', 'having', 'order_by', 'limit', 'flags',
            'flags_description', 'password', 'access_type', 'create_if_necessary',
            'has_factory', 'transaction_action', 'dao_operation', 'entity',
            'callback_type', 'database_object', 'database_name', 'database_class',
            'result_code', 'status', 'rows_affected', 'throw_on_error',
            'null_column_hack', 'cancellation_signal', 'pragma_type'
        ]
        
        for field in fields:
            value = getattr(self, field)
            if value is not None:
                data[field] = value
                
        return data
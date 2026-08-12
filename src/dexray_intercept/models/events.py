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
        # hexdump_display is excluded - it's only for console display and contains ANSI codes
        optional_fields = [
            'operation', 'buffer_size', 'offset', 'length', 'data_hex',
            'plaintext', 'file_type', 'is_large_data', 'fd', 'parent_path',
            'child_path', 'stream_type', 'bytes_read', 'bytes_written'
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
        self.update_call = None
        self.doFinal_variant = None

    def get_event_data(self) -> Dict[str, Any]:
        data = {}

        # Include all non-None values
        fields = [
            'algorithm', 'operation_mode', 'operation_mode_desc',
            'input_hex', 'output_hex', 'input_length', 'output_length',
            'key_hex', 'key_length', 'iv_hex', 'iv_length', 'plaintext',
            'update_call', 'doFinal_variant'
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

        # new/raw IPC fields
        self.stream = None
        self.hook_family = None
        self.declaring_class = None
        self.method_signature = None
        self.receiver_identity = None
        self.thread_id = None
        self.thread_name = None
        self.stack_trace = None

        self.intent_name = None
        self.intent = None
        self.intent_flag = None
        self.transaction_type = None
        self.transaction_desc = None
        self.sender_pid = None
        self.code = None
        self.data_size = None
        self.payload_hex = None
        self.receiver_permission = None
        self.receiver_class = None
        self.actions = None
        self.bundle = None
        self.source_class = None
        self.flags = None
        self.is_control = None # bool: True = control/liveness, False = data tx
        self.notification_id = None
        self.foreground_service_type = None
        self.request_code = None
        self.initial_data = None
        self.initial_code = None
        self.options = None

    def get_event_data(self) -> Dict[str, Any]:
        data = {}

        fields = [
            'key', 'value', 'file', 'method', 'data',
            'stream', 'hook_family', 'declaring_class', 'method_signature',
            'receiver_identity', 'thread_id', 'thread_name',
            'intent_name', 'intent', 'intent_flag',
            'transaction_type', 'transaction_desc',
            'sender_pid', 'code', 'data_size', 'payload_hex',
            'receiver_permission', 'receiver_class', 'actions', 'bundle',
            'source_class', 'flags', 'is_control', 'notification_id',
            'foreground_service_type', 'request_code', 'initial_data',
            'initial_code', 'options',
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

        # generic hook metadata
        self.library = None
        self.method = None

        # bluetooth GATT
        self.characteristic_uuid = None
        self.value_hex = None
        self.value_length = None

        # bluetooth adapter / device
        self.adapter_available = None
        self.kill_apps = None
        self.mac_address = None
        self.device_address = None
        self.device_name = None

        # SMS
        self.destination_address = None
        self.service_center_address = None
        self.message_text = None
        self.text_length = None
        self.message_parts = None
        self.parts_count = None
        self.has_sent_intent = None
        self.has_delivery_intent = None
        self.has_sent_intents = None
        self.has_delivery_intents = None

        # telephony manager
        self.phone_number = None
        self.imsi = None
        self.device_id = None
        self.imei = None
        self.sim_operator = None
        self.denied = None
        self.error = None

        # system / build
        self.property_key = None
        self.property_value = None
        self.build_properties = None

        # wifi
        self.ssid = None
        self.bssid = None

        # content resolver
        self.uri = None
        self.has_result = None
        self.action = None

        # secure settings
        self.settings_key = None
        self.settings_value = None

        # location
        self.provider = None
        self.latitude = None
        self.longitude = None
        self.accuracy = None
        self.has_location = None
        self.min_time_ms = None
        self.min_distance_m = None
        self.has_listener = None
        self.has_looper = None
        self.overload = None

        # clipboard
        self.content_type = None
        self.content = None
        self.item_count = None
        self.has_clip = None
        self.item_index = None
        self.total_items = None
        self.content_length = None
        self.error_message = None

        # camera
        self.camera_id = None
        self.camera_count = None
        self.camera_ids = None
        self.has_callback = None
        self.has_handler = None
        self.has_executor = None

        # generic result
        self.success = None

    def get_event_data(self) -> Dict[str, Any]:
        data = {}

        fields = [
            'event_description',

            # generic hook metadata
            'library', 'method',

            # bluetooth GATT
            'characteristic_uuid', 'value_hex', 'value_length',

            # bluetooth adapter / device
            'adapter_available', 'kill_apps', 'mac_address',
            'device_address', 'device_name',

            # SMS
            'destination_address', 'service_center_address', 'message_text',
            'text_length', 'message_parts', 'parts_count',
            'has_sent_intent', 'has_delivery_intent',
            'has_sent_intents', 'has_delivery_intents',

            # telephony manager
            'phone_number', 'imsi', 'device_id', 'imei', 'sim_operator',
            'denied', 'error',

            # system / build
            'property_key', 'property_value', 'build_properties',

            # wifi
            'ssid', 'bssid',

            # content resolver
            'uri', 'has_result', 'action',

            # secure settings
            'settings_key', 'settings_value',

            # location
            'provider', 'latitude', 'longitude', 'accuracy', 'has_location',
            'min_time_ms', 'min_distance_m', 'has_listener', 'has_looper',
            'overload',

            # clipboard
            'content_type', 'content', 'item_count', 'has_clip',
            'item_index', 'total_items', 'content_length', 'error_message',

            # camera
            'camera_id', 'camera_count', 'camera_ids',
            'has_callback', 'has_handler', 'has_executor',

            # generic result
            'success',
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
        self.connection_pool_size = None
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

        # query / conflict / open details
        self.distinct = None
        self.edit_table = None
        self.conflict_algorithm = None
        self.has_error_handler = None

        self.password_type = None
        self.overload_signature = None
        self.has_database_hook = None

        # Room fields
        self.query_type = None
        self.table_names = None
        self.in_transaction = None
        self.owner_class = None
        self.observer_class = None
        self.old_version = None
        self.new_version = None

        # native SQLite
        self.native_function = None
        self.module_name = None
        self.architecture = None
        self.sql_encoding = None
        self.statement_handle = None
        self.bind_index = None
        self.bind_type = None
        self.bind_value = None
        self.bind_value_hex = None
        self.bind_value_length = None
        self.bind_value_preview_length = None
        self.bind_value_truncated = None
        self.value_available = None

    def get_event_data(self) -> Dict[str, Any]:
        data = {}

        fields = [
            'database_path', 'database_type', 'method', 'table', 'sql',
            'bind_args', 'content_values', 'where_clause', 'where_args',
            'columns', 'group_by', 'having', 'order_by', 'limit', 'flags',
            'flags_description', 'connection_pool_size', 'password', 'access_type', 'create_if_necessary',
            'has_factory', 'transaction_action', 'dao_operation', 'entity',
            'callback_type', 'database_object', 'database_name', 'database_class',
            'result_code', 'status', 'rows_affected', 'throw_on_error',
            'null_column_hack', 'cancellation_signal', 'pragma_type',
            'distinct', 'edit_table', 'conflict_algorithm', 'has_error_handler',
            'password_type', 'overload_signature', 'has_database_hook',
            'query_type', 'table_names', 'in_transaction',
            'owner_class', 'observer_class', 'old_version', 'new_version',
            'native_function', 'module_name', 'architecture', 'sql_encoding',
            'statement_handle', 'bind_index', 'bind_type', 'bind_value',
            'bind_value_hex', 'bind_value_length',
            'bind_value_preview_length', 'bind_value_truncated',
            'value_available',
        ]

        for field in fields:
            value = getattr(self, field)
            if value is not None:
                data[field] = value

        return data

class JNIEvent(Event):
    """JNI operation event"""
    def __init__(self, event_type: str, timestamp: str):
        super().__init__(event_type, timestamp)

    def get_event_data(self) -> Dict[str, Any]:
        data = {}
        fields = []
        for field in fields:
            value = getattr(self, field)
            if value is not None:
                data[field] = value
        return data
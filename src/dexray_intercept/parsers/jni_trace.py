#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from .base import BaseParser
from ..models.events import JNIEvent

class JniTraceParser(BaseParser):
    """Parser for JNI tracing events"""

    def parse_json_data(self, data: dict, timestamp: str) -> Optional[JNIEvent]:
        event_type = data.get('event_type', 'jni.unknown')
        event = JNIEvent(event_type, timestamp)

        # For "jni.env.call" events
        if event_type == "jni.env.call":
            # New stable names (with fallback to legacy)
            jni_struct = data.get('jni_struct', 'JNIEnv')
            method = data.get('method')
            args = data.get('arguments', [])
            ret = data.get('return_value')
            sig = data.get('java_method_sig')
            thread_id = data.get('thread_id')
            c_arg_types = data.get('c_arg_types')
            c_ret_type = data.get('c_ret_type')

            # Stable metadata
            event.add_metadata('jni_struct', jni_struct)
            event.add_metadata('method', method)
            event.add_metadata('arguments', args)
            event.add_metadata('return_value', ret)
            event.add_metadata('java_method_sig', sig)
            event.add_metadata('thread_id', thread_id)
            event.add_metadata('c_arg_types', c_arg_types)
            event.add_metadata('c_ret_type', c_ret_type)

            # Enriched fields (if present)
            class_name = data.get('class_name')
            if class_name is not None:
                event.add_metadata('class_name', class_name)

            string_argument = data.get('string_argument')
            if string_argument is not None:
                event.add_metadata('string_argument', string_argument)

            string_return = data.get('string_return')
            if string_return is not None:
                event.add_metadata('string_return', string_return)

            # Backtrace (array of addresses)
            bt = data.get('backtrace')
            if bt is not None:
                event.add_metadata('backtrace', bt)
            
            # Method/field decoding for GetMethodID / GetFieldID and variants
            if 'method_name' in data:
                event.add_metadata('method_name', data.get('method_name'))
            if 'method_signature' in data:
                event.add_metadata('method_signature', data.get('method_signature'))
            if 'method_descriptor' in data:
                event.add_metadata('method_descriptor', data.get('method_descriptor'))

            if 'field_name' in data:
                event.add_metadata('field_name', data.get('field_name'))
            if 'field_signature' in data:
                event.add_metadata('field_signature', data.get('field_signature'))
            if 'field_descriptor' in data:
                event.add_metadata('field_descriptor', data.get('field_descriptor'))

            # RegisterNatives
            if 'registered_natives' in data:
                event.add_metadata('registered_natives', data.get('registered_natives'))
            
            # Exception / error messages
            if 'throw_message' in data:
                event.add_metadata('throw_message', data.get('throw_message'))
            if 'fatal_message' in data:
                event.add_metadata('fatal_message', data.get('fatal_message'))

            # GetJavaVM decoded pointer
            if 'java_vm_ptr' in data:
                event.add_metadata('java_vm_ptr', data.get('java_vm_ptr'))

            # DefineClass decoded info
            if 'define_class_name' in data:
                event.add_metadata('define_class_name', data.get('define_class_name'))
            if 'class_data_length' in data:
                event.add_metadata('class_data_length', data.get('class_data_length'))
            if 'class_data_hex' in data:
                event.add_metadata('class_data_hex', data.get('class_data_hex'))
            if 'class_data_truncated' in data:
                event.add_metadata('class_data_truncated', data.get('class_data_truncated'))
                
            # Array / buffer metadata for jbyteArray
            if 'array_length' in data:
                event.add_metadata('array_length', data.get('array_length'))
            if 'array_hex' in data:
                event.add_metadata('array_hex', data.get('array_hex'))
            if 'array_truncated' in data:
                event.add_metadata('array_truncated', data.get('array_truncated'))
            if 'array_values' in data:
                event.add_metadata('array_values', data.get('array_values'))

            # Java-level parameter metadata (if provided)
            if 'java_params' in data:
                event.add_metadata('java_params', data.get('java_params'))
            if 'java_args' in data:
                event.add_metadata('java_args', data.get('java_args'))
            if 'java_ret_type' in data:
                event.add_metadata('java_ret_type', data.get('java_ret_type'))
            if 'java_method_descriptor' in data:
                event.add_metadata('java_method_descriptor', data.get('java_method_descriptor'))
            if 'java_ret_value' in data:
                event.add_metadata('java_ret_value', data.get('java_ret_value'))
            
            if 'direct_buffer_address' in data:
                event.add_metadata('direct_buffer_address', data.get('direct_buffer_address'))
            if 'direct_buffer_capacity' in data:
                event.add_metadata('direct_buffer_capacity', data.get('direct_buffer_capacity'))
            if 'buffer_hex' in data:
                event.add_metadata('buffer_hex', data.get('buffer_hex'))
            if 'buffer_truncated' in data:
                event.add_metadata('buffer_truncated', data.get('buffer_truncated'))
            
        # For "jni.vm.call" events
        elif event_type == "jni.vm.call":
            jni_struct = data.get('jni_struct', 'JavaVM')
            method = data.get('method')
            args = data.get('arguments', [])
            ret = data.get('return_value')
            thread_id = data.get('thread_id')

            event.add_metadata('jni_struct', jni_struct)
            event.add_metadata('method', method)
            event.add_metadata('arguments', args)
            event.add_metadata('return_value', ret)
            event.add_metadata('thread_id', thread_id)
            
            bt = data.get('backtrace')
            if bt is not None:
                event.add_metadata('backtrace', bt)

        # For library tracking meta-events
        elif event_type == "jni.library.tracked":
            path = data.get('library_path')
            event.add_metadata('library_path', path)
            event.add_metadata('description', data.get('description'))

        return event
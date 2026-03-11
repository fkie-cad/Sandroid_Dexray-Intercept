#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from typing import Optional
from .base import BaseParser
from ..models.events import JNIEvent

class JniTraceParser(BaseParser):
    """Parser for JNI tracing events"""

    def parse_json_data(self, data: dict, timestamp: str) -> Optional[JNIEvent]:
        """Parse JSON data into JNIEvent"""
        event_type = data.get('event_type', 'jni.unknown')
        event = JNIEvent(event_type, timestamp)

        # For "jni.env.call" events
        if event_type == "jni.env.call":
            event.add_metadata('jni_method', data.get('jni_method'))
            event.add_metadata('jni_args', data.get('jni_args', []))
            event.add_metadata('jni_ret', data.get('jni_ret'))
            event.add_metadata('java_method_sig', data.get('java_method_sig'))
            event.add_metadata('thread_id', data.get('thread_id'))

        # For "jni.vm.call" events
        elif event_type == "jni.vm.call":
            event.add_metadata('jvm_method', data.get('jvm_method'))
            event.add_metadata('jvm_args', data.get('jvm_args', []))
            event.add_metadata('jvm_ret', data.get('jvm_ret'))
            event.add_metadata('thread_id', data.get('thread_id'))

        # For library tracking meta-events
        elif event_type == "jni.library.tracked":
            event.add_metadata('library_path', data.get('library_path'))

        return event
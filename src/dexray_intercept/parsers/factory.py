#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from .base import BaseParser
from .filesystem import FileSystemParser
from .crypto import CryptoParser
from .network import WebParser, SocketParser
from .process import ProcessParser, RuntimeParser, NativeLibParser
from .ipc import SharedPrefsParser, BinderParser, IntentParser, BroadcastParser
from .services import ServiceParser, TelephonyParser
from .dex import DEXParser
from .database import DatabaseParser
from .bypass import BypassParser


class ParserFactory:
    """Factory for creating appropriate parsers based on event category"""
    
    def __init__(self):
        self._parsers = {}
        self._register_default_parsers()
    
    def _register_default_parsers(self):
        """Register default parsers for each category"""
        # File System
        self._parsers["FILE_SYSTEM"] = FileSystemParser()
        
        # Crypto
        self._parsers["CRYPTO_AES"] = CryptoParser()
        self._parsers["CRYPTO_KEYSTORE"] = CryptoParser()
        self._parsers["CRYPTO_ENCODING"] = CryptoParser()
        
        # Network
        self._parsers["WEB"] = WebParser()
        self._parsers["NETWORK_SOCKETS"] = SocketParser()
        
        # Process
        self._parsers["PROCESS_CREATION"] = ProcessParser()
        self._parsers["PROCESS_NATIVE_LIB"] = NativeLibParser()
        self._parsers["RUNTIME_HOOKS"] = RuntimeParser()
        
        # IPC
        self._parsers["IPC_SHARED-PREF"] = SharedPrefsParser()
        self._parsers["IPC_BINDER"] = BinderParser()
        self._parsers["IPC_INTENT"] = IntentParser()
        self._parsers["IPC_BROADCAST"] = BroadcastParser()
        
        # Services
        self._parsers["BLUETOOTH"] = ServiceParser()
        self._parsers["TELEPHONY"] = TelephonyParser()
        self._parsers["LOCATION_ACCESS"] = ServiceParser()
        self._parsers["CLIPBOARD"] = ServiceParser()
        self._parsers["CAMERA"] = ServiceParser()
        
        # DEX
        self._parsers["DEX_LOADING"] = DEXParser()
        
        # Database
        self._parsers["DATABASE"] = DatabaseParser()
        
        # Dynamic library loading
        self._parsers["DYNAMIC_LIB_LOADING"] = NativeLibParser()
        
        # Bypass hooks
        self._parsers["BYPASS_DETECTION"] = BypassParser()
    
    def get_parser(self, category: str) -> Optional[BaseParser]:
        """Get appropriate parser for the given category"""
        return self._parsers.get(category)
    
    def register_parser(self, category: str, parser: BaseParser):
        """Register a custom parser for a category"""
        self._parsers[category] = parser
    
    def get_supported_categories(self):
        """Get list of supported categories"""
        return list(self._parsers.keys())
    
    def parse_event(self, category: str, raw_data: str, timestamp: str):
        """Parse event using appropriate parser"""
        parser = self.get_parser(category)
        if parser:
            return parser.parse(raw_data, timestamp)
        else:
            # Return a generic event for unknown categories
            from ..models.events import Event
            
            class GenericEvent(Event):
                def __init__(self, category: str, raw_data: str, timestamp: str):
                    super().__init__(f"{category}::unknown", timestamp)
                    self.category = category
                    self.raw_data = raw_data
                
                def get_event_data(self):
                    return {
                        "payload": self.raw_data,
                        "category": self.category
                    }
            
            return GenericEvent(category, raw_data, timestamp)


# Global factory instance
parser_factory = ParserFactory()
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from typing import Optional
from .base import BaseParser
from ..models.events import DatabaseEvent


class DatabaseParser(BaseParser):
    """Parser for database events (SQLite, SQLCipher, WCDB, Room, Native SQLite)"""
    
    def parse_json_data(self, data: dict, timestamp: str) -> Optional[DatabaseEvent]:
        """Parse JSON data into DatabaseEvent"""
        event_type = data.get('event_type', 'database.unknown')
        
        event = DatabaseEvent(event_type, timestamp)
        
        # Map JSON fields to event attributes
        field_mapping = {
            'database_path': 'database_path',
            'database_type': 'database_type',
            'method': 'method',
            'table': 'table',
            'sql': 'sql',
            'bind_args': 'bind_args',
            'content_values': 'content_values',
            'where_clause': 'where_clause',
            'where_args': 'where_args',
            'columns': 'columns',
            'group_by': 'group_by',
            'having': 'having',
            'order_by': 'order_by',
            'limit': 'limit',
            'flags': 'flags',
            'flags_description': 'flags_description',
            'password': 'password',
            'access_type': 'access_type',
            'create_if_necessary': 'create_if_necessary',
            'has_factory': 'has_factory',
            'transaction_action': 'transaction_action',
            'dao_operation': 'dao_operation',
            'entity': 'entity',
            'callback_type': 'callback_type',
            'database_object': 'database_object',
            'database_name': 'database_name', 
            'database_class': 'database_class',
            'result_code': 'result_code',
            'status': 'status',
            'rows_affected': 'rows_affected',
            'throw_on_error': 'throw_on_error',
            'null_column_hack': 'null_column_hack',
            'cancellation_signal': 'cancellation_signal',
            'pragma_type': 'pragma_type'
        }
        
        for json_field, event_field in field_mapping.items():
            if json_field in data:
                setattr(event, event_field, data[json_field])
        
        # Add event descriptions based on type
        if event_type.startswith('database.sqlite.'):
            if 'exec' in event_type:
                event.add_metadata('operation_description', 'SQLite SQL execution')
            elif 'query' in event_type:
                event.add_metadata('operation_description', 'SQLite query operation')
            elif 'insert' in event_type:
                event.add_metadata('operation_description', 'SQLite insert operation')
            elif 'update' in event_type:
                event.add_metadata('operation_description', 'SQLite update operation')
            elif 'delete' in event_type:
                event.add_metadata('operation_description', 'SQLite delete operation')
            elif 'open' in event_type:
                event.add_metadata('operation_description', 'SQLite database open/create')
        elif event_type.startswith('database.sqlcipher.'):
            if 'exec' in event_type:
                event.add_metadata('operation_description', 'SQLCipher SQL execution')
            elif 'open' in event_type:
                event.add_metadata('operation_description', 'SQLCipher database access')
            elif 'transaction' in event_type:
                event.add_metadata('operation_description', 'SQLCipher transaction operation')
            elif 'pragma' in event_type:
                event.add_metadata('operation_description', 'SQLCipher PRAGMA statement')
        elif event_type.startswith('database.room.'):
            if 'builder' in event_type:
                event.add_metadata('operation_description', 'Room database initialization')
            elif 'dao' in event_type:
                event.add_metadata('operation_description', 'Room DAO operation')
            elif 'callback' in event_type:
                event.add_metadata('operation_description', 'Room database lifecycle callback')
        elif event_type.startswith('database.native.'):
            event.add_metadata('operation_description', 'Native SQLite operation')
        
        # Add any remaining metadata
        for key, value in data.items():
            if key not in ['event_type', 'timestamp'] and not hasattr(event, key):
                event.add_metadata(key, value)
        
        return event
    
    def parse_legacy_data(self, raw_data: str, timestamp: str) -> Optional[DatabaseEvent]:
        """Parse legacy database data"""
        try:
            # Try to parse as JSON first (structured events)
            try:
                data = json.loads(raw_data)
                return self.parse_json_data(data, timestamp)
            except json.JSONDecodeError:
                # Handle legacy string format
                event = DatabaseEvent("database.legacy", timestamp)
                
                # Try to extract basic info from legacy format
                if "SQLiteExecSQL" in raw_data:
                    event.event_type = "database.sqlite.exec_legacy"
                    event.add_metadata('operation_description', 'Legacy SQLite execution')
                elif "SQLiteRawQuery" in raw_data:
                    event.event_type = "database.sqlite.query_legacy"
                    event.add_metadata('operation_description', 'Legacy SQLite query')
                elif "SQLiteInsert" in raw_data:
                    event.event_type = "database.sqlite.insert_legacy"
                    event.add_metadata('operation_description', 'Legacy SQLite insert')
                elif "SQLiteUpdate" in raw_data:
                    event.event_type = "database.sqlite.update_legacy"
                    event.add_metadata('operation_description', 'Legacy SQLite update')
                elif "SQLiteDelete" in raw_data:
                    event.event_type = "database.sqlite.delete_legacy"
                    event.add_metadata('operation_description', 'Legacy SQLite delete')
                elif "SQLiteOpenDatabase" in raw_data:
                    event.event_type = "database.sqlite.open_legacy"
                    event.add_metadata('operation_description', 'Legacy SQLite database open')
                elif "SQLCipher" in raw_data:
                    event.event_type = "database.sqlcipher.legacy"
                    event.add_metadata('operation_description', 'Legacy SQLCipher operation')
                elif "Room" in raw_data:
                    event.event_type = "database.room.legacy"
                    event.add_metadata('operation_description', 'Legacy Room operation')
                elif "WCDB" in raw_data:
                    event.event_type = "database.wcdb.legacy"
                    event.add_metadata('operation_description', 'Legacy WCDB operation')
                elif "NativeSQLite" in raw_data:
                    event.event_type = "database.native.legacy"
                    event.add_metadata('operation_description', 'Legacy Native SQLite operation')
                
                event.add_metadata('raw_data', raw_data)
                return event
                
        except Exception as e:
            return self.handle_parse_error(raw_data, timestamp, str(e))
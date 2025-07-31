#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from xml.dom.minidom import parseString


def escape_special_characters(data: str) -> str:
    """Escape special characters in string data"""
    return data.replace('\"','\\\"').replace('\n', '\\n').replace('\t', '\\t').replace('\u001b','\\u001b')


def unescape_special_characters(data: str) -> str:
    """Unescape special characters in string data"""
    return data.replace('\\\"','\"').replace('\\n', '\n').replace('\\t', '\t').replace('\\u001b','\u001b')


def format_xml_content(xml_content: str) -> str:
    """Parse and pretty-print XML content"""
    try:
        xml = parseString(xml_content)
        return xml.toprettyxml(indent="    ")
    except Exception as e:
        print(f"Error formatting XML content: {e}")
        return xml_content


def truncate_string(text: str, max_length: int = 100) -> str:
    """Truncate string to max length with ellipsis"""
    if len(text) > max_length:
        return text[:max_length] + "..."
    return text
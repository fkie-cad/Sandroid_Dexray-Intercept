#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from xml.dom.minidom import parseString


def escape_special_characters(data: str) -> str:
    """Escape special characters in string data"""
    return data.replace('\"','\\\"').replace('\n', '\\n').replace('\t', '\\t').replace('\u001b','\\u001b')


def unescape_special_characters(data: str) -> str:
    """Unescape special characters in string data"""
    return data.replace('\\\"','\"').replace('\\n', '\n').replace('\\t', '\t').replace('\\u001b','\u001b')


def strip_ansi_codes(text: str) -> str:
    """
    Remove ANSI escape sequences from text.
    This is essential for log files to prevent corrupted output.

    Args:
        text: String potentially containing ANSI codes

    Returns:
        Clean string without ANSI codes
    """
    if not text:
        return text
    # Pattern matches ANSI escape sequences like \033[0m, \033[1;32m, \x1b[36m, etc.
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m|\033\[[0-9;]*m')
    return ansi_escape.sub('', text)


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
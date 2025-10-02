#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def is_zero_row(bytes_data: bytes, offset: int, length: int = 16) -> bool:
    """Check if a row contains only zeros"""
    end = min(offset + length, len(bytes_data))
    return all(b == 0 for b in bytes_data[offset:end])


def hexdump(hex_string: str, header: bool = True, ansi: bool = True, truncate: bool = False, max_bytes: int = 0x70) -> str:
    """
    Convert hex string to hexdump format with colors like the old frida hexdump

    Args:
        hex_string: Hex string (e.g., "48656c6c6f")
        header: Whether to show the header row
        ansi: Whether to use ANSI color codes
        truncate: Whether to truncate output to max_bytes and skip zero rows (for terminal display)
        max_bytes: Maximum bytes to display when truncate=True (default: 0x70 = 80 bytes)

    Returns:
        Formatted hexdump string
    """
    if not hex_string:
        return ""

    # Remove any spaces or non-hex characters
    hex_clean = ''.join(c for c in hex_string if c in '0123456789abcdefABCDEF')

    if len(hex_clean) == 0:
        return ""

    # Convert hex string to bytes
    try:
        if len(hex_clean) % 2 != 0:
            hex_clean = '0' + hex_clean  # pad with leading zero
        bytes_data = bytes.fromhex(hex_clean)
    except ValueError:
        return f"Invalid hex data: {hex_string}"

    original_length = len(bytes_data)

    # Truncate if requested
    if truncate and len(bytes_data) > max_bytes:
        bytes_data = bytes_data[:max_bytes]
        was_truncated = True
    else:
        was_truncated = False

    # ANSI color codes - using valid ANSI escape sequences
    if ansi:
        colors = {
            'reset': '\033[0m',
            'gray': '\033[90m',       # bright black/gray for header and separators
            'cyan': '\033[36m',       # cyan for hex values
            'green': '\033[32m',      # green for printable ASCII
            'yellow': '\033[33m',     # yellow for non-printable (dots)
            'bold': '\033[1m'         # bold for emphasis
        }
    else:
        colors = {k: '' for k in ['reset', 'gray', 'cyan', 'green', 'yellow', 'bold']}

    result = []

    # Header row
    if header:
        header_line = f"{colors['gray']}           00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f{colors['reset']}"
        result.append(header_line)

    # Process 16 bytes per line
    zero_count = 0
    prev_was_zero = False

    for i in range(0, len(bytes_data), 16):
        # Check if this row is all zeros (only when truncating)
        if truncate and is_zero_row(bytes_data, i, 16):
            zero_count += min(16, len(bytes_data) - i)
            prev_was_zero = True
            continue

        # If we skipped zero rows, add a summary line
        if prev_was_zero:
            result.append(f"{colors['gray']}         [{zero_count} bytes of zeros]{colors['reset']}")
            zero_count = 0
            prev_was_zero = False

        # Address offset
        address = f"{i:08x}"
        line = f"{colors['gray']}{address}{colors['reset']}  "

        # Hex values
        hex_part = ""
        ascii_part = ""

        for j in range(16):
            if i + j < len(bytes_data):
                byte_val = bytes_data[i + j]
                hex_part += f"{colors['cyan']}{byte_val:02x}{colors['reset']} "

                # ASCII representation
                if 32 <= byte_val <= 126:  # printable ASCII
                    ascii_part += f"{colors['green']}{chr(byte_val)}{colors['reset']}"
                else:
                    ascii_part += f"{colors['yellow']}.{colors['reset']}"
            else:
                hex_part += "   "
                ascii_part += " "

            # Add extra space after 8 bytes
            if j == 7:
                hex_part += " "

        # Combine hex and ASCII parts
        line += hex_part + f" {colors['gray']}|{colors['reset']}{ascii_part}{colors['gray']}|{colors['reset']}"
        result.append(line)

    # Handle trailing zeros
    if prev_was_zero:
        result.append(f"{colors['gray']}         [{zero_count} bytes of zeros]{colors['reset']}")

    # Add truncation notice if data was truncated
    if was_truncated:
        result.append(f"{colors['gray']}         ... (showing {len(bytes_data)} of {original_length} bytes){colors['reset']}")

    return '\n'.join(result)


def hex_to_string_safe(hex_str):
    """Safe hex to string conversion with better error handling"""
    if not hex_str or not isinstance(hex_str, str):
        return None
    try:
        # Remove any whitespace and ensure even length
        hex_str = hex_str.replace(" ", "").replace("\n", "")
        if len(hex_str) % 2 != 0:
            hex_str = "0" + hex_str
        
        bytes_object = bytes.fromhex(hex_str)
        # Try UTF-8 first, then fall back to latin-1 for binary data
        try:
            return bytes_object.decode("utf-8")
        except UnicodeDecodeError:
            # For binary data, show printable chars and dots for non-printable
            return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in bytes_object)
    except ValueError:
        return f"<invalid_hex: {hex_str[:50]}{'...' if len(hex_str) > 50 else ''}>"


def hex_to_string(hex_str):
    """Simple hex to string conversion"""
    bytes_object = bytes.fromhex(hex_str)
    return bytes_object.decode("utf-8", errors='replace')
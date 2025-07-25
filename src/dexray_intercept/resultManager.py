#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

# Global list to store output data
output_data = {}
skip_output = False

def handle_output(data, category, output_format):
    global skip_output
    """
    Handles output based on the specified format.

    :param data: The content to be outputted or saved.
    :param category: The category or class type of the data.
    :param output_format: "CMD" for command line output, "JSON" for JSON file output.
    """
    if "creating local copy of unpacked file" in data:
        skip_output = True
    
    if " Unpacking detected!" in data:
        skip_output = False


    if skip_output:
        return

    if output_format == "CMD":
        if category == "console_dev":
            print("[***] " + data)
        elif category == "error":
            print("[-] " + data)
        elif category == "newline":
            print()
        else:
            print("[*] " + data)
    elif output_format == "JSON":
        if category not in output_data:
            output_data[category] = []
        output_data[category].append(data)

def finalize_json_output(output_data, filename="profile.json"):
    """
    Writes all collected data to a JSON file.
    """
    with open(filename, "w") as file:
        json.dump(output_data, file, indent=4)

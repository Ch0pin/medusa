#!/usr/bin/env python3
"""
frida_to_med.py

Usage:
    python frida_to_med.py /path/to/frida_script.js

What it does:
- Reads a Frida JS file
- Removes any Java.perform(...) wrappers
- Prompts user for Name (module-category/module-name), Description, Help
- Produces a JSON file named <module-name>.med in the current directory
"""

from pathlib import Path
import sys
import json
import re

def strip_java_perform_wrappers(source: str) -> str:
    """
    Remove any occurrences of Java.perform(...) wrappers and return the inner code.
    Handles:
      - Java.perform(function () { ... });
      - Java.perform(() => { ... });
      - java.perform(...)
    If multiple wrappers exist, remove them all (unwrapping).
    If no wrapper is found, return the original source.
    """
    lowered = source.lower()
    candidates = []
    # find all occurrences of "java.perform"
    for m in re.finditer(r'\bjava\.perform\b', lowered):
        candidates.append(m.start())

    if not candidates:
        return source  # nothing to do

    out = []
    idx = 0
    length = len(source)
    while idx < length:
        # find next java.perform in the original source (case-insensitive)
        m = re.search(r'\bjava\.perform\b', source[idx:], flags=re.IGNORECASE)
        if not m:
            out.append(source[idx:])
            break

        start = idx + m.start()
        out.append(source[idx:start])  # keep everything before wrapper

        # find the '(' after java.perform
        paren_idx = source.find('(', start)
        if paren_idx == -1:
            # malformed; just keep remainder and break
            out.append(source[start:])
            break

        # find the first '{' after that '('
        brace_open = source.find('{', paren_idx)
        if brace_open == -1:
            # malformed; keep remainder and break
            out.append(source[start:])
            break

        # Now find the matching closing brace by scanning and counting braces
        i = brace_open
        depth = 0
        matched = False
        while i < length:
            ch = source[i]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    # found matching brace for the wrapper
                    brace_close = i
                    matched = True
                    break
            i += 1

        if not matched:
            # malformed/unbalanced braces — keep remainder and break
            out.append(source[start:])
            break

        # Extract the inner content (between the first '{' and its matching '}')
        inner = source[brace_open+1:brace_close]

        # Trim leading/trailing whitespace/newlines of inner
        inner = inner.strip('\r\n')

        # Append inner (effectively removing the wrapper)
        out.append(inner)

        # Advance idx to just after the ')' or semicolon that closes the Java.perform call.
        # We'll try to find the next ')' after brace_close.
        after = brace_close + 1
        # Skip whitespace
        while after < length and source[after].isspace():
            after += 1
        # If there's a closing parenthesis and optional semicolon, skip them
        if after < length and source[after] == ')':
            after += 1
            # skip any whitespaces then a semicolon
            while after < length and source[after].isspace():
                after += 1
            if after < length and source[after] == ';':
                after += 1
        # else just continue from after brace
        idx = after

    # join everything and return
    result = ''.join(out)
    # Normalize leading/trailing whitespace/newlines
    return result.strip('\r\n')

def build_module_json(name: str, description: str, help_text: str, code: str) -> dict:
    """
    Build the JSON structure exactly as required, embedding the code
    inside the "Code" string and including the surrounding braces and markers.
    """
    # Prepare the code block with comment markers
    # Indent the user code for nicer readability inside the JSON string.
    indented_code = '\n'.join('    ' + line for line in code.splitlines())
    code_block = (
        "{\n\n"
        "//---------------write your code below this line----------------\n"
        f"{indented_code}\n\n"
        "//---------------write your code above this line----------------\n\n"
        "   }"
    )
    return {
        "Name": name,
        "Description": description,
        "Help": help_text,
        "Code": code_block
    }

def prompt_required(prompt_msg: str, validator=None, err_msg="Invalid input"):
    while True:
        val = input(prompt_msg).strip()
        if not val:
            print("Cannot be empty.")
            continue
        if validator and not validator(val):
            print(err_msg)
            continue
        return val

def validate_module_name(n: str) -> bool:
    # must be in form category/name, simple allowed chars (letters, digits, underscore, dash)
    return bool(re.match(r'^[A-Za-z0-9_\-]+\/[A-Za-z0-9_\-]+$', n))

def main():
    if len(sys.argv) < 2:
        print("Usage: python frida_to_med.py path/to/frida_script.js")
        sys.exit(2)

    script_path = Path(sys.argv[1])
    if not script_path.exists() or not script_path.is_file():
        print(f"Error: file not found: {script_path}")
        sys.exit(1)

    raw = script_path.read_text(encoding='utf-8')

    # Strip wrappers
    stripped = strip_java_perform_wrappers(raw).strip()
    # If after stripping it's empty, fall back to original content trimmed
    if not stripped:
        stripped = raw.strip()

    print("Parsed script preview (first 400 chars):")
    print("-" * 40)
    print(stripped[:400])
    print("-" * 40)

    # Prompt user for metadata
    name = prompt_required(
        "Enter module name in format <module-category>/<module-name>: ",
        validator=validate_module_name,
        err_msg="Name must be like 'category/name' and may contain letters, digits, '_' or '-'."
    )

    description = input("Enter description (optional): ").strip()
    help_text = input("Enter help text (optional): ").strip()

    module_json = build_module_json(name, description, help_text, stripped)

    # output filename is <module-name>.med
    module_name = name.split('/', 1)[1]
    out_filename = f"{module_name}.med"
    out_path = Path.cwd() / out_filename

    # write pretty JSON
    out_path.write_text(json.dumps(module_json, indent=4, ensure_ascii=False), encoding='utf-8')

    print(f"Wrote module to: {out_path.resolve()}")

if __name__ == '__main__':
    main()

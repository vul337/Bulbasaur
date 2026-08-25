#!/usr/bin/env python3
"""
File utility functions for the Bulbasaur agent bridge.

This module contains functions for:
- Loading branch mappings from CSV
- Parsing source locations
- Reading source code context
- Saving and reading Rust functions
- Reading error information
"""

import csv
import os
import re
import struct
from pathlib import Path
from typing import Dict, Tuple, Optional
from elftools.elf.elffile import ELFFile


def _lookup_hash(hash_value: int, values: Dict[str, str], default: str = "") -> str:
    """Look up a metadata hash in decimal and common hexadecimal spellings."""
    if hash_value == 0:
        return default
    for key in (str(hash_value), hex(hash_value), hex(hash_value)[2:].upper(), hex(hash_value)[2:].lower()):
        if key in values:
            return values[key]
    return default


def _metadata_objects(debug_target: str) -> list[Path]:
    """Find instrumented objects in the order used for process-wide IDs."""
    target = Path(debug_target).resolve()
    search_dirs = [target.parent / "src" / "shared", target.parent.parent / "src" / "shared"]
    by_name: Dict[str, Path] = {}
    for directory in search_dirs:
        if directory.is_dir():
            for path in directory.glob("*.so*"):
                if path.is_file():
                    by_name.setdefault(path.name, path.resolve())

    # Follow DT_NEEDED from the executable rather than scanning every nearby
    # DSO. A directory can contain unrelated instrumented libraries whose
    # guards are not initialized by this target and must not consume IDs.
    dependencies: list[Path] = []
    pending: list[Path] = [target]
    seen: set[Path] = {target}
    while pending:
        current = pending.pop(0)
        try:
            with current.open("rb") as f:
                elf_file = ELFFile(f)
                dynamic = elf_file.get_section_by_name(".dynamic")
                needed = [
                    tag.needed
                    for tag in dynamic.iter_tags()
                    if tag.entry.d_tag == "DT_NEEDED"
                ] if dynamic is not None else []
        except (FileNotFoundError, OSError, ValueError):
            needed = []
        for name in needed:
            dependency = by_name.get(name)
            if dependency is None or dependency in seen:
                continue
            seen.add(dependency)
            dependencies.append(dependency)
            pending.append(dependency)
    # DSOs are initialized before the main executable. Keep the executable last.
    return dependencies + [target]


def _parse_metadata_object(
    path: Path,
    hash_to_location: Dict[str, str],
    hash_to_function_name: Dict[str, str],
    branch_offset: int,
    edge_offset: int,
) -> Tuple[Dict[int, Dict[str, str]], Dict[int, Dict[str, str]], int, int, bool]:
    """Parse one ELF object's source metadata and guard counts."""
    branch_map: Dict[int, Dict[str, str]] = {}
    edge_map: Dict[int, Dict[str, str]] = {}
    try:
        with path.open("rb") as f:
            elf_file = ELFFile(f)
            sections = {section.name: section for section in elf_file.iter_sections()}
            branch_guards = sections.get("__branch_guards")
            sancov_guards = sections.get("__sancov_guards")
            if branch_guards is None and sancov_guards is None:
                return branch_map, edge_map, 0, 0, False

            branch_count = branch_guards["sh_size"] // 4 if branch_guards else 0
            edge_count = sancov_guards["sh_size"] // 4 if sancov_guards else 0
            branch_base = branch_guards["sh_addr"] if branch_guards else 0
            edge_base = sancov_guards["sh_addr"] if sancov_guards else 0

            debug_info = sections.get("__debug_info")
            if debug_info is not None and branch_guards is not None:
                data = debug_info.data()
                for offset in range(0, len(data) - 15, 16):
                    address, hash_value = struct.unpack("<QQ", data[offset:offset + 16])
                    if address < branch_base or (address - branch_base) % 4:
                        continue
                    branch_id = branch_offset + (address - branch_base) // 4 + 1
                    branch_map[branch_id] = {
                        "location": _lookup_hash(hash_value, hash_to_location),
                        "function_name": _lookup_hash(hash_value, hash_to_function_name, "<anonymous>"),
                    }

            edge_debug_info = sections.get("__edge_debug_info")
            if edge_debug_info is not None and sancov_guards is not None:
                data = edge_debug_info.data()
                for offset in range(0, len(data) - 15, 16):
                    address, hash_value = struct.unpack("<QQ", data[offset:offset + 16])
                    if address < edge_base or (address - edge_base) % 4:
                        continue
                    edge_id = edge_offset + (address - edge_base) // 4 + 4
                    edge_map[edge_id] = {
                        "location": _lookup_hash(hash_value, hash_to_location),
                        "function_name": _lookup_hash(hash_value, hash_to_function_name, "<anonymous>"),
                    }
            return branch_map, edge_map, branch_count, edge_count, True
    except (FileNotFoundError, OSError):
        return {}, {}, 0, 0, False



def _load_metadata_mapping(
    debug_target: str,
    hash_to_location: Dict[str, str],
    hash_to_function_name: Dict[str, str],
) -> Tuple[Dict[int, Dict[str, str]], Dict[int, Dict[str, str]]]:
    """Load source mappings while accounting for instrumented DSOs."""
    branch_map: Dict[int, Dict[str, str]] = {}
    edge_map: Dict[int, Dict[str, str]] = {}
    branch_offset = 0
    edge_offset = 0
    parsed_any = False
    objects = _metadata_objects(debug_target)
    for object_path in objects:
        object_branches, object_edges, branch_count, edge_count, parsed = _parse_metadata_object(
            object_path,
            hash_to_location,
            hash_to_function_name,
            branch_offset,
            edge_offset,
        )
        if not parsed:
            continue
        parsed_any = True
        branch_map.update(object_branches)
        edge_map.update(object_edges)
        print(
            f"Loaded metadata object {object_path}: {branch_count} branch guards, "
            f"{edge_count} edge guards, {len(object_branches)} branch locations, "
            f"{len(object_edges)} edge locations"
        )
        branch_offset += branch_count
        edge_offset += edge_count
    if not parsed_any:
        raise RuntimeError(
            f"No Bulbasaur guard sections found in {debug_target} or nearby runtime libraries"
        )
    print(
        f"Loaded {len(branch_map)} branch mappings and {len(edge_map)} edge mappings "
        f"across {len(objects)} metadata objects"
    )
    return branch_map, edge_map


def load_branch_mapping(csv_path: str, debug_target: str) -> Tuple[Dict[int, Dict[str, str]], Dict[int, Dict[str, str]]]:
    """
    Load branch ID and edge ID to source location and function name mappings by:
    1. Reading hash values from __debug_info and __edge_debug_info sections in binary
    2. Mapping hash values to source locations and function names from CSV file
    
    CSV format: hash_val,location_str,function_name
    Returns two dictionaries: (branch_map, edge_map)
    
    Args:
        csv_path: Path to CSV file containing hash -> location and function_name mappings
        debug_target: Path to the binary file containing debug sections
    
    Returns:
        Tuple of (branch_map, edge_map) where:
        - branch_map: Dictionary mapping branch_id (int) -> {"location": str, "function_name": str}
        - edge_map: Dictionary mapping edge_id (int) -> {"location": str, "function_name": str}
    """
    # Step 1: Load hash -> location and hash -> function_name mappings from CSV
    hash_to_location = {}
    hash_to_function_name = {}
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            row_num = 0
            for row in reader:
                row_num += 1
                if len(row) < 2:
                    continue
                
                hash_val = row[0].strip()
                location_str = row[1].strip()
                function_name = row[2].strip() if len(row) > 2 else ""
                
                # Skip header row
                if row_num == 1 and hash_val.lower() in ['hash_val', 'hash', 'hash_value']:
                    continue
                
                # Store mapping (support multiple hash formats)
                if hash_val:  # Only store non-empty hash values
                    hash_to_location[hash_val] = location_str
                    # Store function_name, use empty string if not provided
                    hash_to_function_name[hash_val] = function_name if function_name else "<anonymous>"
                    
                    # Also store normalized versions for easier lookup
                    # Try to normalize hex format
                    if hash_val.startswith('0x') or hash_val.startswith('0X'):
                        hash_to_location[hash_val[2:].upper()] = location_str
                        hash_to_location[hash_val[2:].lower()] = location_str
                        hash_to_function_name[hash_val[2:].upper()] = function_name if function_name else "<anonymous>"
                        hash_to_function_name[hash_val[2:].lower()] = function_name if function_name else "<anonymous>"
                    
        print(f"Loaded {len(hash_to_location)} hash->location mappings from {csv_path}")
    except FileNotFoundError:
        raise FileNotFoundError(f"Branch mapping CSV file not found: {csv_path}")
    except Exception as e:
        raise RuntimeError(f"Error loading branch mapping CSV: {e}")

    if not hash_to_location:
        raise RuntimeError(
            f"Branch mapping CSV {csv_path} contains no source locations; "
            "DEBUG instrumentation is required for Agent mode"
        )

    # IDs are process-wide, so parse instrumented DSOs before the executable.
    # The legacy parser below cannot account for a shared library's guard
    # offset and is intentionally unreachable.
    return _load_metadata_mapping(
        debug_target, hash_to_location, hash_to_function_name
    )
    
    # Helper function to lookup location from hash
    def lookup_location(hash_value):
        """Look up location string from hash value."""
        if hash_value == 0:
            return ""
        
        # Try multiple formats for hash lookup
        hash_str = str(hash_value)
        hash_hex = hex(hash_value)
        hash_hex_upper = hex(hash_value)[2:].upper()
        hash_hex_lower = hex(hash_value)[2:].lower()
        
        for hash_key in [hash_str, hash_hex, hash_hex_upper, hash_hex_lower]:
            if hash_key in hash_to_location:
                return hash_to_location[hash_key]
        
        return ""
    
    # Helper function to lookup function_name from hash
    def lookup_function_name(hash_value):
        """Look up function name from hash value."""
        if hash_value == 0:
            return "<anonymous>"
        
        # Try multiple formats for hash lookup
        hash_str = str(hash_value)
        hash_hex = hex(hash_value)
        hash_hex_upper = hex(hash_value)[2:].upper()
        hash_hex_lower = hex(hash_value)[2:].lower()
        
        for hash_key in [hash_str, hash_hex, hash_hex_upper, hash_hex_lower]:
            if hash_key in hash_to_function_name:
                return hash_to_function_name[hash_key]
        
        return "<anonymous>"
    
    # Step 2: Parse ELF file and extract sections
    branch_map = {}  # branch_id -> {"location": str, "function_name": str}
    edge_map = {}    # edge_id -> {"location": str, "function_name": str}
    
    try:
        with open(debug_target, 'rb') as f:
            elf_file = ELFFile(f)
            
            # Find required sections
            debug_info_section = None
            edge_debug_info_section = None
            branch_guards_section = None
            sancov_guards_section = None
            
            for section in elf_file.iter_sections():
                if section.name == '__debug_info':
                    debug_info_section = section
                elif section.name == '__edge_debug_info':
                    edge_debug_info_section = section
                elif section.name == '__branch_guards':
                    branch_guards_section = section
                elif section.name == '__sancov_guards':
                    sancov_guards_section = section
            
            # Get section addresses
            if branch_guards_section is None:
                raise ValueError(f"__branch_guards section not found in {debug_target}")
            if sancov_guards_section is None:
                raise ValueError(f"__sancov_guards section not found in {debug_target}")
            
            branch_guards_start = branch_guards_section['sh_addr']
            sancov_guards_start = sancov_guards_section['sh_addr']
            
            print(f"__branch_guards section starts at address: 0x{branch_guards_start:x}")
            print(f"__sancov_guards section starts at address: 0x{sancov_guards_start:x}")
            
            # Step 3: Parse __debug_info section
            if debug_info_section is None:
                print("Warning: __debug_info section not found, skipping branch mapping")
            else:
                debug_data = debug_info_section.data()
                data_size = len(debug_data)
                
                # Each entry is (64-bit address, 64-bit hash) = 16 bytes
                num_entries = data_size // 16
                print(f"Found {num_entries} entries in __debug_info section")
                
                for i in range(num_entries):
                    offset = i * 16
                    if offset + 16 > data_size:
                        assert False, f"Offset {offset} + 16 > data_size {data_size}"
                    
                    # Read (address, hash) pair
                    branch_addr = struct.unpack('<Q', debug_data[offset:offset+8])[0]
                    hash_value = struct.unpack('<Q', debug_data[offset+8:offset+16])[0]
                    
                    # Calculate branch_id: (address - branch_guards_start) / 4
                    if branch_addr < branch_guards_start:
                        if i < 10:  # Only warn for first few
                            print(f"Warning: Branch address 0x{branch_addr:x} < branch_guards_start 0x{branch_guards_start:x}")
                        continue
                    
                    branch_id = (branch_addr - branch_guards_start) // 4 + 1
                    
                    # Look up location and function_name from hash
                    location = lookup_location(hash_value)
                    function_name = lookup_function_name(hash_value)
                    branch_map[branch_id] = {
                        "location": location,
                        "function_name": function_name
                    }
                    
                    if not location and i < 10:  # Only warn for first few
                        print(f"Warning: Hash {hash_value} (0x{hash_value:x}) for branch_id={branch_id} not found in CSV")
                
                print(f"Loaded {len(branch_map)} branch mappings from __debug_info section")
            
            # Step 4: Parse __edge_debug_info section
            if edge_debug_info_section is None:
                print("Warning: __edge_debug_info section not found, skipping edge mapping")
            else:
                edge_debug_data = edge_debug_info_section.data()
                edge_data_size = len(edge_debug_data)
                
                # Each entry is (64-bit address, 64-bit hash) = 16 bytes
                num_edge_entries = edge_data_size // 16
                print(f"Found {num_edge_entries} entries in __edge_debug_info section")
                
                for i in range(num_edge_entries):
                    offset = i * 16
                    if offset + 8 > edge_data_size:
                        assert False, f"Offset {offset} + 16 > data_size {edge_data_size}"
                    
                    # Read (address, hash) pair
                    edge_addr = struct.unpack('<Q', edge_debug_data[offset:offset+8])[0]
                    hash_value = struct.unpack('<Q', edge_debug_data[offset+8:offset+16])[0]
                    
                    # Calculate edge_id: (address - sancov_guards_start) / 4
                    if edge_addr < sancov_guards_start:
                        if i < 10:  # Only warn for first few
                            print(f"Warning: Edge address 0x{edge_addr:x} < sancov_guards_start 0x{sancov_guards_start:x}")
                        continue
                    
                    edge_id = (edge_addr - sancov_guards_start) // 4 + 4
                    
                    # Look up location and function_name from hash
                    location = lookup_location(hash_value)
                    function_name = lookup_function_name(hash_value)
                    edge_map[edge_id] = {
                        "location": location,
                        "function_name": function_name
                    }
                    
                    if not location and i < 10:  # Only warn for first few
                        print(f"Warning: Hash {hash_value} (0x{hash_value:x}) for edge_id={edge_id} not found in CSV")
                
                print(f"Loaded {len(edge_map)} edge mappings from __edge_debug_info section")
            
            return branch_map, edge_map
            
    except FileNotFoundError:
        raise FileNotFoundError(f"Binary file not found: {debug_target}")
    except Exception as e:
        raise RuntimeError(f"Error reading debug sections from {debug_target}: {e}")


def is_library_function(location_str: str, base_source_path: Optional[str] = None) -> bool:
    """
    Check if a source location is in a library function (system library).
    
    Args:
        location_str: Source location string in format "file_path:line_number"
        base_source_path: Optional base path of the project source code
    
    Returns:
        True if the location is in a library function, False otherwise
    """
    if not location_str or not location_str.strip():
        return False
    
    try:
        file_path, _ = parse_source_location(location_str)
    except ValueError:
        # If we can't parse it, assume it's not a library function
        return False
    
    # Normalize path
    file_path = os.path.normpath(file_path)
    
    # Check for system library paths
    library_paths = [
        '/usr/lib/',
        '/lib/',
        '/usr/local/lib/',
        '/lib64/',
        '/usr/lib64/',
        '/usr/include/',
        '/usr/local/include/',
    ]
    
    # Check if path contains library directory
    for lib_path in library_paths:
        if lib_path in file_path:
            return True
    
    # Check if path ends with .so (shared library)
    if file_path.endswith('.so') or '.so.' in file_path:
        return True
    
    # If base_source_path is provided, check if the file is within the project
    if base_source_path:
        base_path = os.path.normpath(base_source_path)
        # Check if file_path is relative to base_source_path
        if not os.path.isabs(file_path):
            # Relative path - check if it would be within base_source_path
            full_path = os.path.normpath(os.path.join(base_path, file_path))
            if os.path.commonpath([base_path, full_path]) == base_path:
                return False  # It's within the project
        else:
            # Absolute path - check if it's within base_source_path
            try:
                if os.path.commonpath([base_path, file_path]) == base_path:
                    return False  # It's within the project
            except ValueError:
                # Paths don't share a common path, likely a library
                pass
    
    # If path is absolute and doesn't match project path, it might be a library
    # But we'll be conservative and only mark obvious library paths
    return False


def parse_source_location(location_str: str) -> Tuple[str, int]:
    """
    Parse source location string to extract file path and line number.
    
    Expected format: "file_path:line_number" or "file_path:line_number:column"
    Returns: (file_path: str, line_number: int)
    """
    # Try to match patterns like "file.c:123" or "file.c:123:45"
    match = re.match(r'^(.+?):(\d+)(?::\d+)?$', location_str)
    if match:
        # Debug metadata is emitted from the builder's absolute worktree
        # (for example /work/build/../../src/systemd/...). Normalize it before
        # the bridge opens the runner-mounted source tree.
        file_path = os.path.normpath(match.group(1))
        line_number = int(match.group(2))
        return file_path, line_number
    else:
        raise ValueError(f"Invalid source location format: {location_str}")


def read_source_context(file_path: str, line_number: int, context_lines: int = 10) -> Tuple[str, int, int]:
    """
    Read source code context around the specified line number.
    
    Args:
        file_path: Path to source file (can be relative or absolute) (str)
        line_number: Line number in the file (1-indexed) (int)
        context_lines: Number of lines before and after to include (int)
    
    Returns:
        Tuple of (context_code: str, start_line: int, end_line: int)
    """
    try:
        # Try to open the file
        if not os.path.isabs(file_path):
            # If relative path, try to find it
            # You might want to add a base path parameter for this
            pass
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        # Calculate context range
        start_line = max(0, line_number - context_lines - 1)  # 0-indexed
        end_line = min(len(lines), line_number + context_lines)  # 0-indexed
        
        # Extract context with line numbers
        context_lines_list = []
        for i in range(start_line, end_line):
            line_num = i + 1  # 1-indexed for display
            line_content = lines[i]
            # Add line number prefix, preserving original line ending
            context_lines_list.append(f"{line_num:5d}: {line_content}")
        
        context_code = ''.join(context_lines_list)
        
        # Return context with 1-indexed line numbers for display
        return context_code, start_line + 1, end_line
        
    except FileNotFoundError:
        raise FileNotFoundError(f"Source file not found: {file_path}")
    except Exception as e:
        raise RuntimeError(f"Error reading source file {file_path}: {e}")


def save_rust_function(branch_id: int, rust_code: str, output_dir: str) -> str:
    """
    Save Rust mutation function to file in mut_funcs/{branch_id}/{timestamp}/lib.rs
    
    Each generation creates a new timestamped subdirectory to avoid dlopen() caching issues.
    
    Args:
        branch_id: Branch ID (int)
        rust_code: Rust function code (str)
        output_dir: Base output directory (str)
    
    Returns:
        Path to the timestamped directory containing the Rust code (str)
    """
    from datetime import datetime
    
    mut_funcs_dir = os.path.join(output_dir, "mut_funcs")
    branch_base_dir = os.path.join(mut_funcs_dir, str(branch_id))
    
    # Create timestamped subdirectory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]  # Include milliseconds
    branch_dir = os.path.join(branch_base_dir, timestamp)
    
    # Create directories
    os.makedirs(branch_dir, exist_ok=True)
    
    # Save Rust code to lib.rs
    lib_rs_path = os.path.join(branch_dir, "lib.rs")
    with open(lib_rs_path, 'w', encoding='utf-8') as f:
        f.write(rust_code)
    
    print(f"Saved Rust function to {lib_rs_path} (timestamp: {timestamp})")
    return branch_dir


def read_previous_rust_function(branch_dir: str) -> Optional[str]:
    """
    Read previously generated Rust function from branch directory.
    Now supports timestamped subdirectories: mut_funcs/{branch_id}/{timestamp}/
    Will find the most recent timestamped subdirectory.
    
    Args:
        branch_dir: Base directory for the branch (mut_funcs/{branch_id}) (str)
    
    Returns:
        Rust function code as string, or None if not found
    """
    if not os.path.exists(branch_dir):
        return None
    
    # Look for timestamped subdirectories
    try:
        subdirs = [d for d in os.listdir(branch_dir) 
                   if os.path.isdir(os.path.join(branch_dir, d)) and 
                   len(d) > 10 and d.replace('_', '').replace('.', '').isdigit()]
        
        if not subdirs:
            # Fallback: check if lib.rs exists directly in branch_dir (legacy format)
            lib_rs_path = os.path.join(branch_dir, "lib.rs")
            if os.path.exists(lib_rs_path):
                try:
                    with open(lib_rs_path, 'r', encoding='utf-8') as f:
                        return f.read()
                except Exception as e:
                    print(f"Error reading previous Rust function: {e}")
                    return None
            return None
        
        # Sort by timestamp (newest first) - timestamp format: YYYYMMDD_HHMMSS_mmm
        subdirs.sort(reverse=True)
        
        # Try the most recent subdirectory
        latest_subdir = subdirs[0]
        lib_rs_path = os.path.join(branch_dir, latest_subdir, "lib.rs")
        
        if os.path.exists(lib_rs_path):
            try:
                with open(lib_rs_path, 'r', encoding='utf-8') as f:
                    print(f"Read previous Rust function from {lib_rs_path} (timestamp: {latest_subdir})")
                    return f.read()
            except Exception as e:
                print(f"Error reading previous Rust function: {e}")
                return None
        
        return None
    except Exception as e:
        print(f"Error reading previous Rust function: {e}")
        return None


def read_runtime_error_info(branch_dir: str) -> Optional[str]:
    """
    Read runtime error information from branch directory.
    Error info is stored as a text file in mut_funcs/{branch_id}/
    
    Args:
        branch_dir: Directory containing the error info (str)
    
    Returns:
        Error information as string, or None if not found
    """
    # Look for common error file names
    error_file_names = ["error.txt", "error.log", "runtime_error.txt", "failure.txt"]
    
    for error_file_name in error_file_names:
        error_file_path = os.path.join(branch_dir, error_file_name)
        if os.path.exists(error_file_path):
            try:
                with open(error_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    error_info = f.read()
                print(f"Read error info from {error_file_path}")
                return error_info
            except Exception as e:
                print(f"Error reading error file {error_file_path}: {e}")
                continue
    
    # If no standard error file found, list all files in directory
    if os.path.exists(branch_dir):
        files = os.listdir(branch_dir)
        # Look for any text file that might contain error info
        for file in files:
            if file.endswith(('.txt', '.log')) and file != 'lib.rs':
                error_file_path = os.path.join(branch_dir, file)
                try:
                    with open(error_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        error_info = f.read()
                    print(f"Read error info from {error_file_path}")
                    return error_info
                except:
                    continue
    
    print(f"Warning: No error info file found in {branch_dir}")
    return None

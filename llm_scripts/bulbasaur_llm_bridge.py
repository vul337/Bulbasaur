#!/usr/bin/env python3
"""
Bulbasaur Agent Bridge Script

This script bridges Bulbasaur with a local agent by:
1. Creating a socket to receive branch IDs from Bulbasaur
2. Looking up source code locations from CSV mapping file
3. Reading source code context around the branch location
4. Sending context to the configured Agent for analysis
"""

import argparse
import socket
import subprocess
import sys
import os
import time
from pathlib import Path
from typing import Dict, Optional

# Import modules
from file_utils import (
    load_branch_mapping,
    parse_source_location,
    read_source_context,
    save_rust_function,
    read_previous_rust_function,
    read_runtime_error_info,
    is_library_function,
)
from compilation import compile_rust_to_so
from agent_cli import LLMAgent
from seed_enricher import enrich_corpus


class BufferedConn:
    """
    Newline-framed wrapper around a TCP socket.

    The fuzzer sends one request per line ("1 <branch> <edge>\\n") and waits for a
    reply before sending the next. Reading raw with conn.recv() assumes one packet
    == one request, so if two requests are ever coalesced into a single TCP segment
    the second is silently dropped and request/response framing desyncs. This buffers
    received bytes and hands back exactly one complete line at a time, so coalesced
    or split segments are handled correctly. sendall/close delegate to the socket.
    """

    def __init__(self, conn: socket.socket):
        self._conn = conn
        self._buf = b""

    def readline(self, recv_size: int = 4096) -> str:
        """Return the next newline-delimited message (without the newline), or '' on EOF."""
        while b"\n" not in self._buf:
            chunk = self._conn.recv(recv_size)
            if not chunk:
                # EOF: return any trailing partial line, else empty string.
                line, self._buf = self._buf, b""
                return line.decode("utf-8", errors="ignore").strip()
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        return line.decode("utf-8", errors="ignore").strip()

    def sendall(self, data):
        return self._conn.sendall(data)

    def pushback(self, line: str) -> None:
        """Put one already-read line back in front of the receive buffer."""
        prefix = (line.rstrip("\n") + "\n").encode("utf-8")
        self._buf = prefix + self._buf

    def close(self):
        return self._conn.close()


def _resolve_snapshot_source(file_path: str, source_base_path: str) -> str:
    """Resolve builder-absolute debug paths against the runner source snapshot."""
    candidate = Path(os.path.normpath(file_path))
    if candidate.is_file() or not source_base_path:
        return str(candidate)
    base = Path(source_base_path)
    parts = candidate.parts
    # Debug metadata contains the builder worktree (for example
    # /work/build/../../src/systemd/src/foo.c). Preserve the stable source
    # suffix and resolve it below the copied debug snapshot.
    for marker in ("src", "include", "test"):
        indexes = [index for index, part in enumerate(parts) if part == marker]
        for index in reversed(indexes):
            relative = Path(*parts[index:])
            snapshot = base / relative
            if snapshot.is_file():
                return str(snapshot)
    return str(candidate)


def handle_branch_request(
    conn: socket.socket,
    branch_map: Dict[int, Dict[str, str]],
    edge_map: Dict[int, Dict[str, str]],
    output_dir: str,
    llm_agent: LLMAgent
) -> bool:
    """
    Handle a branch ID request from Bulbasaur.
    
    Message format:
    - "1 branch_id edge_id" - Generate new mutation function
    
    Args:
        conn: Socket connection
        branch_map: Dictionary mapping branch_id (int) -> {"location": str, "function_name": str}
        edge_map: Dictionary mapping edge_id (int) -> {"location": str, "function_name": str}
        output_dir: Output directory for storing mutation functions
        llm_agent: LLMAgent instance for generating and fixing code
    
    Returns:
        bool: True if request was handled, False if connection should be closed
    """
    try:
        # Receive command and branch ID from Bulbasaur (one newline-framed message)
        data = conn.readline()
        if not data:
            return False
        
        # Parse command format: "command branch_id edge_id"
        parts = data.split()
        if len(parts) < 2:
            print(f"Warning: Invalid message format: {data}, need at least command and branch_id")
            conn.sendall("1 1".encode('utf-8'))
            return True
        
        command = parts[0].strip()
        branch_id_str = parts[1].strip()
        edge_id_str = parts[2].strip() if len(parts) > 2 else None
        
        # Convert string IDs to integers (branch_map and edge_map use int keys)
        try:
            branch_id: int = int(branch_id_str)
        except ValueError:
            error_msg = f"ERROR: Invalid branch ID format: {branch_id_str} (must be an integer)"
            print(error_msg)
            conn.sendall("1 1".encode('utf-8'))
            return True
        
        edge_id: Optional[int] = None
        if edge_id_str is not None:
            try:
                edge_id = int(edge_id_str)
            except ValueError:
                error_msg = f"ERROR: Invalid edge ID format: {edge_id_str} (must be an integer)"
                print(error_msg)
                conn.sendall("1 1".encode('utf-8'))
                return True
        
        print(f"\nReceived command: {command}, branch ID: {branch_id}, edge ID: {edge_id}")
        
        # Look up branch source location and function name
        if branch_id not in branch_map:
            print(f"WARN: Branch ID {branch_id} has no source mapping; skipping")
            # A guard without source metadata is not an agent/runtime error.
            # Tell the fuzzer that this request is not actionable so it does
            # not retry the same unmappable guard indefinitely.
            conn.sendall("1 0".encode('utf-8'))
            return True
        
        branch_info = branch_map[branch_id]
        branch_location = branch_info.get("location", "")
        branch_function_name = branch_info.get("function_name", "<anonymous>")
        print(f"Branch location: {branch_location}")
        print(f"Branch function: {branch_function_name}")
        
        # Check if branch_location is empty
        if not branch_location or branch_location.strip() == "":
            print(f"WARN: Branch ID {branch_id} has an empty source location; skipping")
            conn.sendall("1 0".encode('utf-8'))
            return True
        
        # Check if branch_location is in a library function
        if is_library_function(branch_location, llm_agent.base_source_path):
            print(f"Branch ID {branch_id} is in a library function ({branch_location}), skipping")
            conn.sendall("1 0".encode('utf-8'))  # Use "1 0" to indicate unable to break through
            return True
        
        # Look up edge source location and function name
        if edge_id is None or edge_id not in edge_map:
            print(f"WARN: Edge ID {edge_id} has no source mapping; skipping")
            conn.sendall("1 0".encode('utf-8'))
            return True
        
        edge_info = edge_map[edge_id]
        edge_location = edge_info.get("location", "")
        edge_function_name = edge_info.get("function_name", "<anonymous>")
        print(f"Edge location: {edge_location}")
        print(f"Edge function: {edge_function_name}")
        
        # Check if edge_location is empty
        if not edge_location or edge_location.strip() == "":
            print(f"WARN: Edge ID {edge_id} has an empty source location; skipping")
            conn.sendall("1 0".encode('utf-8'))
            return True
        
        # Check if edge_location is in a library function
        if is_library_function(edge_location, llm_agent.base_source_path):
            print(f"Edge ID {edge_id} is in a library function ({edge_location}), skipping")
            conn.sendall("1 0".encode('utf-8'))  # Use "1 0" to indicate unable to break through
            return True
        
        # Get branch directory path (use branch_id for directory naming)
        mut_funcs_dir = os.path.join(output_dir, "mut_funcs")
        branch_dir = os.path.join(mut_funcs_dir, str(branch_id))
        
        # Parse source locations
        try:
            # Parse branch location
            branch_file_path, branch_line_number = parse_source_location(branch_location)
            if llm_agent.base_source_path and not os.path.isabs(branch_file_path):
                branch_file_path = os.path.join(llm_agent.base_source_path, branch_file_path)
            branch_file_path = _resolve_snapshot_source(branch_file_path, llm_agent.base_source_path)

            # Parse edge location
            edge_file_path, edge_line_number = parse_source_location(edge_location)
            if llm_agent.base_source_path and not os.path.isabs(edge_file_path):
                edge_file_path = os.path.join(llm_agent.base_source_path, edge_file_path)
            edge_file_path = _resolve_snapshot_source(edge_file_path, llm_agent.base_source_path)
            
            # Read source context for both locations
            branch_context, branch_start_line, branch_end_line = read_source_context(
                branch_file_path, branch_line_number, context_lines=10
            )
            
            edge_context, edge_start_line, edge_end_line = read_source_context(
                edge_file_path, edge_line_number, context_lines=10
            )
            
            print(f"Read branch context from {branch_file_path}:{branch_line_number}")
            print(f"Branch context lines: {branch_start_line}-{branch_end_line}")
            print(f"Read edge context from {edge_file_path}:{edge_line_number}")
            print(f"Edge context lines: {edge_start_line}-{edge_end_line}")
            
            rust_code = None
            task_type = "unknown"  # Track task type for logging
            
            # Handle different commands
            try:
                if command == "1":
                    # Command 1: Generate new mutation function
                    print("Command 1: Generating new mutation function...")
                    # Read previous Rust function
                    previous_rust_code = read_previous_rust_function(branch_dir)
                    # Prepare log_dir for saving conversation history
                    log_dir = os.path.join(output_dir, "conversation_logs")
                    
                    if previous_rust_code is None:
                        print(f"Warning: Previous Rust function not found for branch {branch_id}, generating new one")
                        task_type = "generate"
                        rust_code = llm_agent.generate_mutation_function(
                            branch_id, edge_id,
                            branch_location, branch_context, branch_start_line, branch_end_line,
                            edge_location, edge_context, edge_start_line, edge_end_line,
                            branch_function_name=branch_function_name,
                            log_dir=log_dir
                        )
                    else:
                        task_type = "regenerate"
                        rust_code = llm_agent.regenerate_mutation_function(
                            branch_id, edge_id,
                            branch_location, branch_context, branch_start_line, branch_end_line,
                            edge_location, edge_context, edge_start_line, edge_end_line,
                            previous_rust_code,
                            branch_function_name=branch_function_name,
                            log_dir=log_dir
                        )
                else:
                    error_msg = f"ERROR: Unknown command: {command}"
                    print(error_msg)
                    conn.sendall("1 1".encode('utf-8'))
                    return True
            except Exception as e:
                error_msg = f"ERROR: Failed to generate Rust code for branch {branch_id} -> edge {edge_id}: {str(e)}"
                print(error_msg)
                import traceback
                traceback.print_exc()
                conn.sendall("1 1".encode('utf-8'))
                return True
            
            if rust_code is None:
                # Agent determined it's impossible to break through
                error_msg = f"Agent determined it's impossible to break through from branch {branch_id} to edge {edge_id}"
                print(error_msg)
                conn.sendall("1 0".encode('utf-8'))
                return True
            
            # Save Rust function to file
            branch_dir = save_rust_function(branch_id, rust_code, output_dir)
            
            # Compile with error feedback loop (applies to all commands)
            max_fix_attempts = 3
            so_path = None
            
            for attempt in range(max_fix_attempts):
                # Compile Rust code to .so library
                so_path, error_message = compile_rust_to_so(branch_dir, branch_id)
                
                if so_path:
                    # Compilation successful
                    print(f"Compilation successful on attempt {attempt + 1}")
                    break
                
                # Compilation failed - check if it's a code error (not system error)
                if error_message and ("error[" in error_message.lower() or "error:" in error_message.lower()):
                    print(f"Compilation failed on attempt {attempt + 1}, asking Agent to fix...")
                    print(f"Error message: {error_message[:500]}...")  # Print first 500 chars
                    
                    # Ask the Agent to fix the error
                    try:
                        # Update task type if this is a compilation fix
                        if task_type != "fix_compile":
                            task_type = "fix_compile"
                        rust_code = llm_agent.fix_compilation_error(
                            branch_id, rust_code, error_message,
                            log_dir=log_dir
                        )
                        
                        # Save the fixed code to a new timestamped directory
                        # Update branch_dir to the new directory
                        branch_dir = save_rust_function(branch_id, rust_code, output_dir)
                        
                        # Try again in next iteration
                        continue
                    except Exception as e:
                        print(f"Error asking Agent to fix code: {e}")
                        break
                else:
                    # System error (cargo not found, etc.) - don't try to fix
                    print("System error during compilation, not attempting Agent fix")
                    break
            
            if so_path:
                # Compilation successful, send success response: "0 branch_id so_path"
                print(f"Compilation successful. Sending success response for branch {branch_id}...")
                response = f"0 {branch_id} {so_path}"
                conn.sendall(response.encode('utf-8'))
                print(f"Sent success response: {response}")
            else:
                # Compilation failed after all attempts
                error_msg = f"ERROR: Failed to compile mutation function for branch {branch_id} after {max_fix_attempts} attempts"
                print(error_msg)
                conn.sendall("1 1".encode('utf-8'))
            
        except Exception as e:
            error_msg = f"ERROR: {str(e)}"
            print(f"Error processing branch {branch_id} -> edge {edge_id}: {e}")
            import traceback
            traceback.print_exc()
            conn.sendall("1 1".encode('utf-8'))
        
        return True
        
    except Exception as e:
        print(f"Error handling branch request: {e}")
        import traceback
        traceback.print_exc()
        return False


def create_socket():
    """
    Create a socket for communication with Bulbasaur.
    """
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind to localhost on an available port
        sock.bind(('localhost', 0))
        port = sock.getsockname()[1]
        
        print(f"Socket created and bound to localhost:{port}")
        
        # Listen for connections
        sock.listen(1)
        print(f"Socket listening on localhost:{port}")
        
        return sock, port
        
    except Exception as e:
        raise RuntimeError(f"Error creating socket: {e}")


def launch_bulbasaur(fuzzer_path, corpus, output_dir, full_target, 
                        trace_target, fast_target, exec_args, socket_port=None,
                        log_file=None, cpu_id=None, dict_files=None, jobs=1):
    """
    Launch Bulbasaur with the specified parameters.
    
    Command format:
    /Bulbasaur/fuzzer -i corpus -o output_dir -M 0 -f full_target -t trace_target -x dict_file -- fast_target exec_args
    
    Args:
        log_file: Optional path to log file. If provided, stdout and stderr will be redirected to this file.
        cpu_id: Optional CPU ID to bind the fuzzer process to using taskset. If None, no CPU binding is performed.
        dict_files: Optional list of dictionary file paths. Each dictionary will be added with -x parameter.
    """
    cmd = [
        fuzzer_path,
        "-i", corpus,
        "-o", output_dir,
        "-M", "0",
        "-f", full_target,
        "-t", trace_target,
        "-p", str(socket_port),
        "-j", str(jobs),
    ]
    
    # Add CPU binding if requested (fuzzer has -b parameter for CPU binding)
    if cpu_id is not None:
        cmd.extend(["-b", str(cpu_id)])
        print(f"CPU binding enabled: binding to CPU {cpu_id}")
    
    # Add dictionary files if provided (fuzzer uses -x parameter for dictionaries)
    if dict_files:
        for dict_file in dict_files:
            if not os.path.exists(dict_file):
                print(f"Warning: Dictionary file not found: {dict_file}, skipping...")
                continue
            cmd.extend(["-x", dict_file])
            print(f"Added dictionary: {dict_file}")
    
    cmd.extend([
        "--",
        fast_target
    ])
    
    # Add execution arguments (if provided)
    if exec_args:
        cmd.extend(exec_args)
    
    print(f"Launching Bulbasaur with command:")
    print(f"  {' '.join(cmd)}")
    
    try:
        # Start the process
        env = os.environ.copy()
        
        # Set Rust environment variables for debugging
        env["RUST_BACKTRACE"] = "full"
        env["RUST_LOG"] = "info"
        
        # Set up output redirection
        if log_file:
            # Ensure the directory exists
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            
            # Open file in append mode for stdout
            # Redirect stderr to stdout so both go to the same file
            log_handle = open(log_file, 'a', encoding='utf-8')
            print(f"Redirecting stdout and stderr to: {log_file}")
            stdout_dest = log_handle
            stderr_dest = subprocess.STDOUT  # Redirect stderr to stdout
        else:
            stdout_dest = subprocess.PIPE
            stderr_dest = subprocess.PIPE
        
        process = subprocess.Popen(
            cmd,
            stdout=stdout_dest,
            stderr=stderr_dest,
            text=True,
            env=env
        )
        
        print(f"Bulbasaur process started with PID: {process.pid}")
        if log_file:
            print(f"Output will be saved to: {log_file}")
        
        # Check if we should wait for debugger attach
        wait_for_debugger = os.environ.get('WAIT_FOR_DEBUGGER', '').lower() in ('1', 'true', 'yes')
        if wait_for_debugger:
            print(f"\n{'='*60}")
            print("WAITING FOR DEBUGGER ATTACH")
            print(f"{'='*60}")
            print(f"Process PID: {process.pid}")
            print(f"\nTo attach VS Code debugger:")
            print(f"  1. Press F5 or go to Run and Debug")
            print(f"  2. Select 'Attach to Bulbasaur (Rust)'")
            print(f"  3. Choose process PID: {process.pid}")
            print(f"\nOr attach with gdb manually:")
            print(f"  gdb -p {process.pid}")
            print(f"\nWaiting 30 seconds for debugger to attach...")
            print(f"{'='*60}\n")
            import time
            time.sleep(30)
            print("Continuing execution...\n")
        
        return process
        
    except FileNotFoundError:
        raise FileNotFoundError(f"Fuzzer executable not found: {fuzzer_path}")
    except Exception as e:
        raise RuntimeError(f"Error launching Bulbasaur: {e}")


def socket_server_loop(
    sock: socket.socket,
    branch_map: Dict[int, Dict[str, str]],
    edge_map: Dict[int, Dict[str, str]],
    output_dir: str,
    base_source_path: Optional[str],
    agent: str,
    agent_model: Optional[str],
    agent_timeout: int,
    skill_path: Optional[str] = None,
    agent_start_delay: int = 60,
) -> None:
    """
    Main loop for handling socket connections from Bulbasaur.
    
    Args:
        sock: Socket to listen on
        branch_map: Dictionary mapping branch_id (int) -> {"location": str, "function_name": str}
        edge_map: Dictionary mapping edge_id (int) -> {"location": str, "function_name": str}
        output_dir: Output directory for storing mutation functions
        base_source_path: Base path for resolving relative source file paths (or None)
        agent: Agent CLI to use (``claude``, ``codex``, or ``mini``).
        agent_model: Optional model name passed to the selected CLI.
        agent_timeout: Per-agent invocation timeout in seconds.
        skill_path: Optional shared skill file.
        agent_start_delay: Seconds after the fuzzer starts before agent requests
            are allowed. Requests received earlier get an explicit skip reply.
    """
    print("Waiting for Bulbasaur connections...")
    agent_start_at = time.monotonic() + max(0, int(agent_start_delay))
    if agent_start_delay > 0:
        print(
            f"Agent mutator generation is delayed for {int(agent_start_delay)}s "
            "while the fuzzer warms up."
        )
    
    while True:
        try:
            conn, addr = sock.accept()
            conn = BufferedConn(conn)
            print(f"\nAccepted connection from {addr}")
            print("Connection established. Will handle multiple requests on this connection.")
            
            # Keep the connection open and handle multiple requests
            # Rust fuzzer sends multiple requests (branch 1, branch 2, ...) on the same connection
            while True:
                try:
                    # Read and acknowledge early requests without constructing
                    # an agent.  The fuzzer's request/response protocol is
                    # synchronous, so replying "unable" keeps fuzzing moving
                    # instead of blocking the target for the whole warm-up.
                    if time.monotonic() < agent_start_at:
                        early_data = conn.readline()
                        if not early_data:
                            print("Connection closed during agent warm-up")
                            break
                        # The request may have been sent after the warm-up
                        # deadline while readline() was blocked. Re-check after
                        # receiving it so that such a request is not discarded.
                        if time.monotonic() < agent_start_at:
                            print(
                                "Skipping mutator request during agent warm-up: "
                                f"{early_data}"
                            )
                            conn.sendall("1 0".encode("utf-8"))
                            continue
                        conn.pushback(early_data)

                    # Create a new Agent instance for each request
                    # Each request gets its own agent with fresh conversation history
                    llm_agent = LLMAgent(
                        base_source_path=base_source_path,
                        agent=agent,
                        model=agent_model,
                        timeout=agent_timeout,
                        skill_path=skill_path,
                    )
                    
                    # Handle the branch request
                    # Returns False if connection should be closed (e.g., empty data received)
                    should_continue = handle_branch_request(conn, branch_map, edge_map, output_dir, llm_agent)
                    
                    if not should_continue:
                        print("Connection closed by client or empty data received")
                        break
                        
                except socket.error as e:
                    # Connection error (closed by client, network error, etc.)
                    print(f"Connection error: {e}")
                    break
                except Exception as e:
                    print(f"Error handling branch request: {e}")
                    import traceback
                    traceback.print_exc()
                    # Continue to next request instead of closing connection
                    # Send error response to client
                    try:
                        conn.sendall("1 1".encode('utf-8'))
                    except:
                        # If we can't send, connection is probably broken
                        break
            
            conn.close()
            print(f"Connection from {addr} closed")
            
        except KeyboardInterrupt:
            print("\nReceived interrupt signal")
            break
        except Exception as e:
            print(f"Error in socket server loop: {e}")
            import traceback
            traceback.print_exc()
            break


def main():
    parser = argparse.ArgumentParser(
        description='Bulbasaur Agent Bridge - connect the fuzzer to Claude Code, Codex, or the built-in mini harness'
    )
    
    parser.add_argument(
        '--fuzzer',
        required=True,
        help='Path to Bulbasaur fuzzer executable'
    )
    
    parser.add_argument(
        '--fast-target',
        required=True,
        help='Path to fast target executable'
    )
    
    parser.add_argument(
        '--trace-target',
        required=True,
        help='Path to trace target executable'
    )
    
    parser.add_argument(
        '--full-target',
        required=True,
        help='Path to full target executable'
    )

    parser.add_argument(
        '--debug-target',
        required=True,
        help='Path to debug target executable'
    )
    
    parser.add_argument(
        '--corpus',
        required=True,
        help='Path to corpus directory'
    )
    
    parser.add_argument(
        '--output-dir',
        required=True,
        help='Path to output directory'
    )
    
    parser.add_argument(
        '--branch-mapping',
        required=True,
        help='Path to CSV file mapping debug information to source locations (format: hash_val,location_str)'
    )
    
    parser.add_argument(
        '--source-base-path',
        required=True,
        help='Base path for resolving relative source file paths'
    )
    
    parser.add_argument(
        '--agent',
        choices=('claude', 'codex', 'mini'),
        default=os.getenv('BULBASAUR_AGENT', 'mini'),
        help='Agent backend for mutators and seed enrichment (default: mini).'
    )

    parser.add_argument(
        '--agent-model',
        default=os.getenv('BULBASAUR_AGENT_MODEL', 'gpt-5.6-luna'),
        help='Model name passed to the selected agent CLI.'
    )

    parser.add_argument(
        '--agent-timeout',
        type=int,
        default=int(os.getenv('BULBASAUR_AGENT_TIMEOUT', '900')),
        help='Timeout in seconds for one agent request (default: 900).'
    )

    parser.add_argument(
        '--agent-start-delay',
        type=int,
        default=int(os.getenv('BULBASAUR_AGENT_START_DELAY', '60')),
        help='Seconds after the fuzzer starts before mutator generation is enabled (default: 60).'
    )

    parser.add_argument(
        '--agent-skill',
        default=str(os.path.join(os.path.dirname(__file__), 'skills', 'bulbasaur-mutator', 'SKILL.md')),
        help='Shared skill/prompt file passed to the agent.'
    )
    
    parser.add_argument(
        '--fuzzer-log',
        default=None,
        help='Path to log file for Bulbasaur stdout and stderr. If not specified, output will be discarded. Default: {output_dir}/fuzzer.log'
    )
    
    parser.add_argument(
        '--cpu-id',
        type=int,
        default=None,
        help='CPU ID to bind the fuzzer process to using taskset. If not specified, no CPU binding is performed.'
    )
    
    parser.add_argument(
        '--jobs',
        type=int,
        default=1,
        help='Number of parallel jobs/threads for Bulbasaur (default: 1)'
    )
    
    parser.add_argument(
        '--dict',
        action='append',
        default=[],
        dest='dict_files',
        help='Dictionary file for fuzzing. Can be specified multiple times to add multiple dictionaries. Example: --dict dict1.txt --dict dict2.txt'
    )

    parser.add_argument(
        '--seed-enrich',
        action='store_true',
        default=os.getenv('BULBASAUR_SEED_ENRICH', '0') == '1',
        help='Run the selected agent before fuzzing to generate additional corpus seeds.'
    )

    parser.add_argument(
        '--seed-enrich-dir',
        default=os.getenv('BULBASAUR_SEED_ENRICH_DIR'),
        help='Output corpus for seed enrichment; defaults to <corpus>.enriched.'
    )

    # Use REMAINDER to capture all execution arguments, including those starting
    # with '-'. This must be the final parser argument.
    parser.add_argument(
        '--exec-args',
        nargs=argparse.REMAINDER,
        default=[],
        help='Execution arguments for the target program. All arguments after --exec-args are passed through verbatim.'
    )

    args = parser.parse_args()

    # Seed enrichment and mutator logs live inside the fuzz output bundle.
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Validate paths
    if not os.path.exists(args.fuzzer):
        print(f"Error: Fuzzer not found: {args.fuzzer}", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(args.fast_target):
        print(f"Error: Fast target not found: {args.fast_target}", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(args.full_target):
        print(f"Error: Full target not found: {args.full_target}", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.exists(args.trace_target):
        print(f"Error: Trace target not found: {args.trace_target}", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.exists(args.debug_target):
        print(f"Error: Debug target not found: {args.debug_target}", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.exists(args.corpus):
        print(f"Error: Corpus directory not found: {args.corpus}", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.exists(args.branch_mapping):
        print(f"Error: Branch mapping CSV not found: {args.branch_mapping}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(args.source_base_path):
        print(f"Error: Source base path not found or not a directory: {args.source_base_path}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(args.agent_skill):
        print(f"Error: Agent skill not found: {args.agent_skill}", file=sys.stderr)
        sys.exit(1)

    if args.agent_timeout < 1:
        print("Error: Agent timeout must be >= 1 second", file=sys.stderr)
        sys.exit(1)

    if args.agent_start_delay < 0:
        print("Error: Agent start delay must be >= 0 seconds", file=sys.stderr)
        sys.exit(1)
        
    if args.jobs < 1:
        print("Error: The number of jobs must be >= 1", file=sys.stderr)
        sys.exit(1)


    # Mutator generation is an Agent-mode feature. Fail before launching the
    # fuzzer when neither Claude Code nor Codex is available, instead of letting
    # the fuzzer run indefinitely without ever receiving a mutator.
    try:
        agent_probe = LLMAgent(
            base_source_path=args.source_base_path,
            agent=args.agent,
            model=args.agent_model,
            timeout=args.agent_timeout,
            skill_path=args.agent_skill,
        )
        print(f"Agent CLI ready: {agent_probe.agent}")
    except (FileNotFoundError, ValueError) as e:
        print(
            "Error: Agent mode requires Claude Code, Codex, or the vendored mini harness "
            f"and valid --agent settings: {e}",
            file=sys.stderr,
        )
        sys.exit(1)

    
    try:
        # Step 1: Load branch and edge mappings
        print("=" * 60)
        print("Step 1: Loading branch and edge mappings")
        print("=" * 60)
        branch_map, edge_map = load_branch_mapping(args.branch_mapping, args.debug_target)
        print(f"Loaded {len(branch_map)} branch mappings and {len(edge_map)} edge mappings")
        print()

        # Optional initial corpus stage. It runs before the socket/fuzzer are
        # started, so the fuzzer sees one stable corpus for its whole run.
        corpus_for_fuzzer = args.corpus
        if args.seed_enrich:
            enriched = args.seed_enrich_dir or (args.corpus.rstrip(os.sep) + ".enriched")
            seed_workspace = os.path.join(args.output_dir, "seed_enrichment")
            print("=" * 60)
            print(f"Step 2: Enriching the initial corpus with the {args.agent} agent")
            print("=" * 60)
            report = enrich_corpus(
                input_corpus=args.corpus,
                output_corpus=enriched,
                source_root=args.source_base_path,
                agent=args.agent,
                model=args.agent_model,
                api_key=agent_probe.api_key,
                base_url=agent_probe.base_url,
                agent_timeout=args.agent_timeout,
                conversation_dir=os.path.join(args.output_dir, "conversation_logs"),
                workspace_dir=seed_workspace,
            )
            corpus_for_fuzzer = enriched
            print(f"Seed enrichment added {report['generated_count']} seeds; corpus: {corpus_for_fuzzer}")
            print(f"Seed workspace/report retained at: {report['workdir']}")
            print()
        
        # Step 3: Create socket
        print("=" * 60)
        print("Step 3: Creating socket")
        print("=" * 60)
        sock, port = create_socket()
        print(f"Socket ready on port {port}\n")
        
        # Step 4: Launch Bulbasaur
        print("=" * 60)
        print("Step 4: Launching Bulbasaur")
        print("=" * 60)
        
        # Determine log file path
        if args.fuzzer_log:
            log_file = args.fuzzer_log
        else:
            # Default to output_dir/fuzzer.log
            log_file = os.path.join(args.output_dir, "fuzzer.log")
        
        process = launch_bulbasaur(
            args.fuzzer,
            corpus_for_fuzzer,
            args.output_dir,
            args.full_target,
            args.trace_target,
            args.fast_target,
            args.exec_args,
            socket_port=port,
            log_file=log_file,
            cpu_id=args.cpu_id,
            dict_files=args.dict_files if args.dict_files else None,
            jobs=args.jobs,
        )
        print(f"Bulbasaur launched successfully\n")
        
        # Step 5: Start socket server loop
        print("=" * 60)
        print("Step 4: Starting socket server loop")
        print("=" * 60)

        print("Waiting for branch ID requests from Bulbasaur...")
        print("Press Ctrl+C to exit.\n")

        try:
                socket_server_loop(
                    sock, branch_map, edge_map,
                    args.output_dir, args.source_base_path,
                    args.agent, args.agent_model, args.agent_timeout, args.agent_skill,
                    args.agent_start_delay,
                )
        except KeyboardInterrupt:
            print("\nReceived interrupt signal, terminating...")
            process.terminate()
            process.wait()
        finally:
            sock.close()
            print("Socket closed.")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


class MockSocketConnection:
    """
    Mock socket connection for testing handle_branch_request.
    Simulates a socket connection by reading from stdin and writing to stdout.
    """
    def __init__(self):
        self.received_data = None
        self.sent_data = []

    def readline(self, recv_size: int = 4096):
        """Simulate receiving one framed message - read from stdin"""
        data = input("Enter command (format: 'command branch_id edge_id' or 'quit' to exit): ").strip()
        if data.lower() == 'quit':
            return ''
        return data

    def sendall(self, data):
        """Simulate sending data - print to stdout"""
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        self.sent_data.append(data)
        print(f"[Response sent]: {data}")
    
    def close(self):
        """Simulate closing connection"""
        print("[Connection closed]")


def test_handle_branch_request(branch_mapping, debug_target, output_dir, source_base_path):
    """
    Test function for handle_branch_request.
    
    This function:
    1. Loads branch and edge mappings
    2. Enters an interactive loop reading commands from stdin
    4. Simulates socket connections and calls handle_branch_request
    
    Args:
        branch_mapping: Path to CSV file mapping debug information to source locations
        debug_target: Path to debug target executable
        output_dir: Output directory for storing mutation functions
        source_base_path: Base path for resolving relative source file paths
    
    Usage:
        test_handle_branch_request(
            branch_mapping="./branch_mapping.csv",
            debug_target="./target_debug",
            output_dir="./test_output",
            source_base_path="/path/to/source"
        )
        
    Then enter commands like:
        - "1 123 456"  (command 1, branch_id 123, edge_id 456)
        - "quit"       (exit the test)
    """
    print("=" * 80)
    print("Testing handle_branch_request")
    print("=" * 80)
    print()
    
    # Step 1: Load branch and edge mappings
    print("=" * 60)
    print("Step 1: Loading branch and edge mappings")
    print("=" * 60)
    try:
        branch_map, edge_map = load_branch_mapping(branch_mapping, debug_target)
        print(f"Loaded {len(branch_map)} branch mappings and {len(edge_map)} edge mappings")
        print()
    except Exception as e:
        print(f"ERROR: Failed to load branch mappings: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Step 2: Enter interactive loop. The selected agent inspects source directly;
    # there is no one-time documentation summary or callgraph preprocessing.
    print("=" * 60)
    print("Step 3: Entering interactive test loop")
    print("=" * 60)
    print("Enter commands in the format: 'command branch_id edge_id'")
    print("Example: '1 123 456' (command 1, branch_id 123, edge_id 456)")
    print("Type 'quit' to exit")
    print()
    
    try:
        while True:
            # Create a new Agent instance for each request
            llm_agent = LLMAgent(
                base_source_path=source_base_path,
                agent=os.getenv("BULBASAUR_AGENT", "mini"),
                model=os.getenv("BULBASAUR_AGENT_MODEL", "gpt-5.6-luna"),
                timeout=int(os.getenv("BULBASAUR_AGENT_TIMEOUT", "900")),
            )
            
            # Create mock connection
            mock_conn = MockSocketConnection()
            
            # Handle the branch request
            print("\n" + "-" * 80)
            print("New request:")
            print("-" * 80)
            try:
                handle_branch_request(mock_conn, branch_map, edge_map, output_dir, llm_agent)
            except KeyboardInterrupt:
                print("\nReceived interrupt signal")
                break
            except Exception as e:
                print(f"Error handling branch request: {e}")
                import traceback
                traceback.print_exc()
                # Continue to next iteration
                continue
            
            print("-" * 80)
            print()
            
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except EOFError:
        print("\n\nEnd of input reached")
    except Exception as e:
        print(f"\n\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\nTest completed.")


if __name__ == '__main__':
    import sys
    
    # Check if running in test mode
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        # Test mode: run test_handle_branch_request
        if len(sys.argv) < 6:
            print("Usage: python bulbasaur_llm_bridge.py --test <branch_mapping> <debug_target> <output_dir> <source_base_path>")
            print("\nExample:")
            print("  python bulbasaur_llm_bridge.py --test ./mapping.csv ./target_debug ./output ./source")
            sys.exit(1)
        
        branch_mapping = sys.argv[2]
        debug_target = sys.argv[3]
        output_dir = sys.argv[4]
        source_base_path = sys.argv[5]
        test_handle_branch_request(
            branch_mapping=branch_mapping,
            debug_target=debug_target,
            output_dir=output_dir,
            source_base_path=source_base_path
        )
    else:
        # Normal mode: run main
        main()

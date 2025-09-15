#!/usr/bin/env python3

"""
Direct MemFD Content Extractor
Uses ptrace to directly intercept and extract memfd writes in real-time
"""

import os
import sys
import subprocess
import time
import signal
import threading
from pathlib import Path

class DirectMemFDExtractor:
    def __init__(self, binary_path, output_dir="/tmp/memfd_extraction"):
        self.binary_path = Path(binary_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.extracted_data = {}
        
    def extract_with_detailed_strace(self):
        """Use strace with maximum detail to capture all data"""
        print("[+] Running detailed strace extraction...")
        
        # Use very large string size and raw output
        strace_cmd = [
            'strace', '-f', '-s', '1000000',  # Very large string capture
            '-e', 'trace=memfd_create,write', 
            '-x',  # Print all chars in hex
            '-v',  # Verbose mode
            str(self.binary_path)
        ]
        
        strace_output_file = self.output_dir / "full_strace.log"
        
        try:
            # Set ulimit in the environment
            env = os.environ.copy()
            
            with open(strace_output_file, 'w') as f:
                process = subprocess.Popen(
                    strace_cmd,
                    stderr=f,
                    stdout=subprocess.PIPE,
                    preexec_fn=lambda: os.system('ulimit -c 0'),
                    env=env
                )
                
                stdout, _ = process.communicate(timeout=30)
                
            print(f"[+] Strace output saved to {strace_output_file}")
            
            # Parse the detailed output
            return self._parse_detailed_strace(strace_output_file)
            
        except subprocess.TimeoutExpired:
            process.kill()
            print("[-] Strace timed out")
            return False
    
    def _parse_detailed_strace(self, strace_file):
        """Parse detailed strace output to extract complete memfd data"""
        print("[+] Parsing detailed strace output...")
        
        memfd_map = {}
        current_writes = {}  # Track ongoing writes
        
        with open(strace_file, 'r') as f:
            content = f.read()
        
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines):
            # Track memfd creation
            if 'memfd_create(' in line and '=' in line:
                parts = line.split('"')
                if len(parts) >= 2:
                    name = parts[1]
                    fd_part = line.split('= ')[-1].strip()
                    try:
                        fd = int(fd_part)
                        memfd_map[fd] = name
                        current_writes[fd] = bytearray()
                        print(f"[+] Tracking memfd: fd={fd}, name='{name}'")
                    except ValueError:
                        pass
            
            # Track writes to memfds
            elif 'write(' in line and '=' in line:
                # Extract fd from write call
                if line.strip().startswith('write('):
                    try:
                        fd_str = line.split('write(')[1].split(',')[0].strip()
                        fd = int(fd_str)
                        
                        if fd in memfd_map:
                            print(f"[+] Processing write to memfd {fd} ({memfd_map[fd]})")
                            # Extract the data portion
                            data = self._extract_write_data(line)
                            if data:
                                current_writes[fd].extend(data)
                                print(f"[+] Extracted {len(data)} bytes, total: {len(current_writes[fd])}")
                    except (ValueError, IndexError):
                        pass
        
        # Save extracted data
        extracted_files = []
        for fd, data in current_writes.items():
            if len(data) > 0:
                name = memfd_map.get(fd, f"unknown_{fd}")
                output_file = self.output_dir / f"memfd_{fd}_{name}_complete.bin"
                
                with open(output_file, 'wb') as f:
                    f.write(data)
                
                print(f"[+] Saved {len(data)} bytes to {output_file}")
                extracted_files.append(output_file)
        
        return extracted_files
    
    def _extract_write_data(self, line):
        """Extract binary data from a strace write line"""
        try:
            # Find the data portion between quotes
            start_quote = line.find('"')
            if start_quote == -1:
                return None
            
            # Find the matching end quote, handling escaped quotes
            pos = start_quote + 1
            data_str = ""
            
            while pos < len(line):
                if line[pos] == '"' and (pos == 0 or line[pos-1] != '\\'):
                    break
                data_str += line[pos]
                pos += 1
            
            # Convert the string with escape sequences to bytes
            return self._unescape_string(data_str)
            
        except Exception as e:
            print(f"[-] Error extracting write data: {e}")
            return None
    
    def _unescape_string(self, s):
        """Convert escaped string from strace to bytes"""
        result = bytearray()
        i = 0
        
        while i < len(s):
            if s[i] == '\\' and i + 1 < len(s):
                next_char = s[i + 1]
                
                if next_char == 'x' and i + 3 < len(s):
                    # Hex escape \xNN
                    try:
                        hex_value = int(s[i+2:i+4], 16)
                        result.append(hex_value)
                        i += 4
                        continue
                    except ValueError:
                        pass
                elif next_char == '\\':
                    result.append(ord('\\'))
                    i += 2
                    continue
                elif next_char == '"':
                    result.append(ord('"'))
                    i += 2
                    continue
                elif next_char == 'n':
                    result.append(ord('\n'))
                    i += 2
                    continue
                elif next_char == 'r':
                    result.append(ord('\r'))
                    i += 2
                    continue
                elif next_char == 't':
                    result.append(ord('\t'))
                    i += 2
                    continue
                elif next_char.isdigit():
                    # Octal escape \nnn
                    octal = ""
                    j = i + 1
                    while j < len(s) and j < i + 4 and s[j].isdigit():
                        octal += s[j]
                        j += 1
                    if octal:
                        try:
                            result.append(int(octal, 8))
                            i = j
                            continue
                        except ValueError:
                            pass
            
            # Regular character
            result.append(ord(s[i]))
            i += 1
        
        return bytes(result)
    
    def extract_with_proc_inspection(self):
        """Extract by quickly inspecting /proc/PID files during execution"""
        print("[+] Attempting /proc inspection method...")
        
        # Run the binary in background and try to catch it
        env = os.environ.copy()
        
        try:
            process = subprocess.Popen(
                [str(self.binary_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=lambda: os.system('ulimit -c 0'),
                env=env
            )
            
            pid = process.pid
            print(f"[+] Target PID: {pid}")
            
            # Give it a moment to start and create memfds
            time.sleep(0.1)
            
            # Check /proc/PID/fd for file descriptors
            fd_dir = Path(f"/proc/{pid}/fd")
            
            if fd_dir.exists():
                for fd_link in fd_dir.iterdir():
                    try:
                        target = fd_link.readlink()
                        if 'memfd:' in str(target):
                            print(f"[+] Found memfd: {fd_link.name} -> {target}")
                            
                            # Try to read the memfd content via /proc/PID/mem
                            self._read_memfd_via_proc(pid, int(fd_link.name), str(target))
                            
                    except (OSError, ValueError):
                        pass
            
            # Wait for process to complete
            process.wait(timeout=5)
            
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
            print(f"[-] /proc inspection failed: {e}")
            if 'process' in locals():
                process.kill()
    
    def _read_memfd_via_proc(self, pid, fd, target_name):
        """Attempt to read memfd content via /proc/PID/mem"""
        try:
            # This is tricky because we need the memory address
            # For now, just note that we found the memfd
            print(f"[+] Detected memfd {fd}: {target_name}")
            
            # Could implement memory mapping reading here if needed
            
        except Exception as e:
            print(f"[-] Failed to read memfd {fd}: {e}")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary_path>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    extractor = DirectMemFDExtractor(binary_path)
    
    print("=== Direct MemFD Content Extractor ===")
    print(f"Target binary: {binary_path}")
    print(f"Output directory: {extractor.output_dir}")
    print()
    
    # Method 1: Detailed strace
    files = extractor.extract_with_detailed_strace()
    
    # Method 2: /proc inspection
    extractor.extract_with_proc_inspection()
    
    # Analyze results
    if files:
        print("\n=== Extracted Files Analysis ===")
        for file_path in files:
            if file_path.exists():
                size = file_path.stat().st_size
                print(f"\nFile: {file_path.name} ({size} bytes)")
                
                # Show file type
                try:
                    result = subprocess.run(['file', str(file_path)], 
                                          capture_output=True, text=True)
                    print(f"Type: {result.stdout.strip()}")
                except:
                    pass
                
                # Show first bytes in hex and ASCII
                with open(file_path, 'rb') as f:
                    data = f.read(min(256, size))
                    print("First bytes:")
                    for i in range(0, len(data), 16):
                        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
                        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[i:i+16])
                        print(f"  {i:04x}: {hex_part:<48} |{ascii_part}|")
                
                # Look for strings
                try:
                    result = subprocess.run(['strings', str(file_path)], 
                                          capture_output=True, text=True)
                    strings = result.stdout.strip()
                    if strings:
                        print("Strings found:")
                        for line in strings.split('\n')[:10]:
                            print(f"  {line}")
                except:
                    pass
    
    print(f"\n[+] Extraction complete. Results in {extractor.output_dir}")

if __name__ == "__main__":
    main()
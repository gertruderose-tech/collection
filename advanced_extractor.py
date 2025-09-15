#!/usr/bin/env python3

"""
Advanced MemFD Content Extractor
Extracts real contents from self-extracting binaries using multiple techniques
"""

import os
import sys
import subprocess
import tempfile
import time
import struct
import re
from pathlib import Path

class MemFDExtractor:
    def __init__(self, binary_path, output_dir="/tmp/memfd_extraction"):
        self.binary_path = Path(binary_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
    def extract_with_strace_dump(self):
        """Extract memfd contents by intercepting strace output"""
        print("[+] Method 1: Strace-based extraction")
        
        # Run strace with detailed write tracing
        strace_cmd = [
            'strace', '-f', '-s', '65536',  # Large string capture
            '-e', 'trace=memfd_create,write,close,mmap',
            '-x',  # Print all non-ASCII chars in hex
            str(self.binary_path)
        ]
        
        # Set ulimit to bypass anti-analysis
        env = os.environ.copy()
        
        try:
            # Run strace and capture output
            result = subprocess.run(
                strace_cmd, 
                stderr=subprocess.PIPE, 
                stdout=subprocess.PIPE,
                text=True,
                timeout=30,
                preexec_fn=lambda: os.system('ulimit -c 0')
            )
            
            strace_output = result.stderr
            
            # Save full strace output
            strace_file = self.output_dir / "detailed_strace.log"
            with open(strace_file, 'w') as f:
                f.write(strace_output)
            
            # Parse strace output to extract memfd writes
            return self._parse_strace_writes(strace_output)
            
        except subprocess.TimeoutExpired:
            print("[-] Strace timed out")
            return False
    
    def _parse_strace_writes(self, strace_output):
        """Parse strace output and extract memfd write data"""
        print("[+] Parsing strace output for memfd writes...")
        
        memfd_map = {}  # fd -> name mapping
        extracted_files = []
        
        lines = strace_output.split('\n')
        
        for line in lines:
            # Track memfd_create calls
            memfd_match = re.search(r'memfd_create\("([^"]+)".*= (\d+)', line)
            if memfd_match:
                name, fd = memfd_match.groups()
                memfd_map[fd] = name
                print(f"[+] Found memfd_create: fd={fd}, name='{name}'")
                continue
            
            # Track write calls to memfds
            write_match = re.search(r'write\((\d+), "([^"]*)"(?:\\x[0-9a-fA-F]{2})*.*?, (\d+)\) = (\d+)', line)
            if write_match:
                fd, data_preview, expected_bytes, actual_bytes = write_match.groups()
                
                if fd in memfd_map:
                    name = memfd_map[fd]
                    print(f"[+] Found write to memfd {fd} ('{name}'): {actual_bytes} bytes")
                    
                    # Try to extract the actual data from the strace line
                    extracted_data = self._extract_hex_data_from_strace_line(line)
                    if extracted_data:
                        output_file = self.output_dir / f"memfd_{fd}_{name}.extracted"
                        with open(output_file, 'wb') as f:
                            f.write(extracted_data)
                        print(f"[+] Saved {len(extracted_data)} bytes to {output_file}")
                        extracted_files.append(output_file)
        
        return extracted_files
    
    def _extract_hex_data_from_strace_line(self, line):
        """Extract binary data from strace write line"""
        try:
            # Look for the data part in quotes with hex escapes
            data_start = line.find('"') + 1
            data_end = line.rfind('"')
            if data_start <= 0 or data_end <= data_start:
                return None
            
            data_str = line[data_start:data_end]
            
            # Convert escape sequences to bytes
            result = bytearray()
            i = 0
            while i < len(data_str):
                if data_str[i] == '\\' and i + 1 < len(data_str):
                    if data_str[i+1] == 'x' and i + 3 < len(data_str):
                        # Hex escape \xNN
                        hex_str = data_str[i+2:i+4]
                        try:
                            result.append(int(hex_str, 16))
                            i += 4
                            continue
                        except ValueError:
                            pass
                    elif data_str[i+1] in '\\\"':
                        # Escaped backslash or quote
                        result.append(ord(data_str[i+1]))
                        i += 2
                        continue
                    elif data_str[i+1].isdigit():
                        # Octal escape
                        octal = data_str[i+1:i+4]
                        try:
                            result.append(int(octal, 8))
                            i += 4
                            continue
                        except ValueError:
                            pass
                
                # Regular character
                result.append(ord(data_str[i]))
                i += 1
            
            return bytes(result)
        except Exception as e:
            print(f"[-] Error extracting hex data: {e}")
            return None
    
    def extract_with_gdb_memory_dump(self):
        """Extract memfd contents using GDB memory dumping"""
        print("[+] Method 2: GDB-based memory extraction")
        
        # Create GDB script
        gdb_script = self.output_dir / "extract.gdb"
        with open(gdb_script, 'w') as f:
            f.write("""
set environment SHELL=/bin/bash
set confirm off
set pagination off

# Set ulimit to bypass anti-analysis
shell ulimit -c 0

# Run the program
run

# Wait for memfd creation
continue

# Try to find and dump memory regions
info proc mappings

# Dump different memory regions that might contain the extracted data
dump binary memory memfd_region1.bin 0x7f0000000000 0x7f0000100000
dump binary memory memfd_region2.bin 0x7faf62000000 0x7faf63000000

quit
""")
        
        try:
            # Run GDB
            gdb_cmd = ['gdb', '-batch', '-x', str(gdb_script), str(self.binary_path)]
            result = subprocess.run(
                gdb_cmd,
                cwd=str(self.output_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60
            )
            
            print(f"[+] GDB output saved")
            
            # Check for generated dump files
            dump_files = list(self.output_dir.glob("memfd_region*.bin"))
            return dump_files
            
        except subprocess.TimeoutExpired:
            print("[-] GDB timed out")
            return []
    
    def extract_with_proc_mem(self):
        """Extract memfd contents by reading /proc/PID/mem during execution"""
        print("[+] Method 3: /proc/mem-based extraction")
        
        # This method would require running the binary in background
        # and quickly reading its memory before it exits
        # Implementation would be more complex and timing-dependent
        
        return []
    
    def analyze_extracted_files(self, files):
        """Analyze extracted files to identify their contents"""
        print("[+] Analyzing extracted files...")
        
        for file_path in files:
            if not file_path.exists():
                continue
                
            size = file_path.stat().st_size
            print(f"\n=== Analysis of {file_path.name} ({size} bytes) ===")
            
            # File type detection
            try:
                file_result = subprocess.run(['file', str(file_path)], 
                                           capture_output=True, text=True)
                print(f"File type: {file_result.stdout.strip()}")
            except:
                pass
            
            # Hex dump first 256 bytes
            with open(file_path, 'rb') as f:
                data = f.read(256)
                print("First 256 bytes (hex):")
                for i in range(0, len(data), 16):
                    hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
                    ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[i:i+16])
                    print(f"{i:08x}: {hex_part:<48} {ascii_part}")
            
            # Strings extraction
            try:
                strings_result = subprocess.run(['strings', str(file_path)], 
                                              capture_output=True, text=True)
                strings_output = strings_result.stdout.strip()
                if strings_output:
                    print("Strings found:")
                    for line in strings_output.split('\n')[:20]:
                        print(f"  {line}")
            except:
                pass
            
            # Check for script patterns
            with open(file_path, 'rb') as f:
                data = f.read()
                if b'#!/' in data or b'bash' in data or b'sh' in data:
                    print("*** POTENTIAL SCRIPT CONTENT DETECTED ***")
                    
                    # Try to extract readable script parts
                    try:
                        text_data = data.decode('utf-8', errors='ignore')
                        script_lines = [line for line in text_data.split('\n') 
                                      if any(keyword in line.lower() for keyword in 
                                           ['echo', 'bash', 'sh', 'ulimit', 'wget', 'curl'])]
                        if script_lines:
                            print("Script-like content:")
                            for line in script_lines[:10]:
                                print(f"  {line}")
                    except:
                        pass

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary_path>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    extractor = MemFDExtractor(binary_path)
    
    print("=== Advanced MemFD Content Extractor ===")
    print(f"Target binary: {binary_path}")
    print(f"Output directory: {extractor.output_dir}")
    print()
    
    all_extracted_files = []
    
    # Method 1: Strace-based extraction
    strace_files = extractor.extract_with_strace_dump()
    if strace_files:
        all_extracted_files.extend(strace_files)
    
    # Method 2: GDB-based extraction  
    gdb_files = extractor.extract_with_gdb_memory_dump()
    if gdb_files:
        all_extracted_files.extend(gdb_files)
    
    # Analyze all extracted files
    if all_extracted_files:
        extractor.analyze_extracted_files(all_extracted_files)
    else:
        print("[-] No files were extracted")
    
    print(f"\n[+] Extraction complete. Check {extractor.output_dir} for results.")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3

"""
Memory Dumper for UPX-packed binaries
Extracts the real unpacked content from memory using GDB
"""

import os
import sys
import subprocess
import time
import tempfile
from pathlib import Path

class MemoryDumper:
    def __init__(self, binary_path, output_dir="/tmp/memfd_extraction"):
        self.binary_path = Path(binary_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def dump_with_gdb_breakpoint(self):
        """Use GDB to break after unpacking and dump memory"""
        print("[+] Using GDB to dump unpacked memory...")
        
        # Create a comprehensive GDB script
        gdb_script = self.output_dir / "memory_dump.gdb"
        with open(gdb_script, 'w') as f:
            f.write("""
set confirm off
set pagination off
set environment SHELL=/bin/bash

# Set ulimit to bypass the anti-analysis check
shell ulimit -c 0

# Start the program
start

# Set breakpoint after the unpacking is likely done
# Based on strace, the unpacking happens early in execution
# Let's break after some initial instructions
break *0x401000
continue

# If we hit the breakpoint, dump the memory regions
if $_exitcode == void
    echo Dumping memory regions...\\n
    
    # Dump the main unpacked region (from strace: mmap(0x401000, 2019101, ...))
    dump binary memory unpacked_main.bin 0x401000 0x401000+2019101
    
    # Also dump some surrounding areas that might contain data
    dump binary memory unpacked_region1.bin 0x400000 0x500000
    dump binary memory unpacked_region2.bin 0x5ee000 0x700000
    
    # Get memory layout
    info proc mappings
    
    # Continue execution briefly to see what happens
    continue
end

# If the breakpoint wasn't hit, just run and dump whatever we can
if $_exitcode != void
    echo Program exited, attempting memory dump of core areas...\\n
    
    # Try to dump common memory regions
    set $ignore_errors = 1
    dump binary memory final_dump.bin 0x401000 0x600000
end

quit
""")
        
        # Run GDB with the script
        try:
            result = subprocess.run([
                'gdb', '-batch', '-x', str(gdb_script), str(self.binary_path)
            ], cwd=str(self.output_dir), capture_output=True, text=True, timeout=60)
            
            print(f"[+] GDB execution completed")
            print("GDB output:", result.stdout)
            if result.stderr:
                print("GDB errors:", result.stderr)
            
            # Check what files were created
            dump_files = list(self.output_dir.glob("*.bin"))
            return dump_files
            
        except subprocess.TimeoutExpired:
            print("[-] GDB timed out")
            return []
    
    def dump_with_core_file(self):
        """Create a core dump and extract from it"""
        print("[+] Attempting core dump extraction...")
        
        # Enable core dumps temporarily
        os.system('ulimit -c unlimited')
        
        try:
            # Run the binary and try to catch it
            env = os.environ.copy()
            env['ULIMIT_CORE'] = '0'  # But keep the binary's check happy
            
            process = subprocess.Popen([str(self.binary_path)], 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE,
                                     preexec_fn=lambda: os.system('ulimit -c 0'))
            
            pid = process.pid
            print(f"[+] Target PID: {pid}")
            
            # Let it run briefly then send SIGQUIT to create core
            time.sleep(0.2)
            try:
                os.kill(pid, 3)  # SIGQUIT
            except ProcessLookupError:
                pass
            
            process.wait()
            
            # Look for core file
            core_files = list(Path('.').glob(f'core*{pid}*')) + list(Path('.').glob('core'))
            if core_files:
                core_file = core_files[0]
                print(f"[+] Found core file: {core_file}")
                return self._extract_from_core(core_file)
            else:
                print("[-] No core file generated")
                return []
                
        except Exception as e:
            print(f"[-] Core dump failed: {e}")
            return []
        finally:
            os.system('ulimit -c 0')  # Restore
    
    def _extract_from_core(self, core_file):
        """Extract data from core file using GDB"""
        gdb_script = self.output_dir / "core_extract.gdb"
        with open(gdb_script, 'w') as f:
            f.write(f"""
set confirm off
set pagination off

# Load the core file
core-file {core_file}

# Show memory layout
info proc mappings

# Try to dump the mapped regions we know about
dump binary memory core_region1.bin 0x401000 0x401000+2000000
dump binary memory core_region2.bin 0x5ee000 0x700000

quit
""")
        
        try:
            result = subprocess.run([
                'gdb', str(self.binary_path), '-batch', '-x', str(gdb_script)
            ], cwd=str(self.output_dir), capture_output=True, text=True)
            
            print("Core extraction output:", result.stdout)
            dump_files = list(self.output_dir.glob("core_region*.bin"))
            return dump_files
            
        except Exception as e:
            print(f"[-] Core extraction failed: {e}")
            return []
    
    def extract_strings_and_analyze(self):
        """Extract strings directly from the binary to find embedded content"""
        print("[+] Analyzing binary for embedded content...")
        
        try:
            # Extract all strings
            result = subprocess.run(['strings', '-a', str(self.binary_path)], 
                                  capture_output=True, text=True)
            
            strings_file = self.output_dir / "all_strings.txt"
            with open(strings_file, 'w') as f:
                f.write(result.stdout)
            
            # Look for script-like content
            script_patterns = []
            for line in result.stdout.split('\n'):
                if any(keyword in line.lower() for keyword in [
                    'echo', 'bash', '#!/', 'ulimit', 'wget', 'curl', 
                    'connection', 'watching', 'problem'
                ]):
                    script_patterns.append(line)
            
            if script_patterns:
                print(f"[+] Found {len(script_patterns)} potential script lines:")
                for line in script_patterns[:20]:
                    print(f"  {line}")
                
                # Save script patterns
                script_file = self.output_dir / "extracted_script_patterns.txt"
                with open(script_file, 'w') as f:
                    f.write('\n'.join(script_patterns))
                
                return [script_file]
            
            return []
            
        except Exception as e:
            print(f"[-] String extraction failed: {e}")
            return []
    
    def run_with_memory_monitoring(self):
        """Run the binary while monitoring its memory usage"""
        print("[+] Running with memory monitoring...")
        
        # Create a script to monitor /proc/PID/maps during execution
        monitor_script = self.output_dir / "monitor.sh"
        with open(monitor_script, 'w') as f:
            f.write("""#!/bin/bash
ulimit -c 0
{} &
PID=$!
echo "Monitoring PID: $PID"

# Give it time to start
sleep 0.1

# Monitor memory maps
if [ -d "/proc/$PID" ]; then
    echo "=== Memory Maps ==="
    cat /proc/$PID/maps > memory_maps.txt
    
    echo "=== File Descriptors ==="
    ls -la /proc/$PID/fd/ > file_descriptors.txt 2>/dev/null || true
    
    echo "=== Status ==="
    cat /proc/$PID/status > process_status.txt 2>/dev/null || true
fi

wait $PID
""".format(self.binary_path))
        
        os.chmod(monitor_script, 0o755)
        
        try:
            result = subprocess.run([str(monitor_script)], 
                                  cwd=str(self.output_dir),
                                  capture_output=True, text=True)
            
            print("Monitor output:", result.stdout)
            
            # Check what monitoring files were created
            monitor_files = [
                self.output_dir / "memory_maps.txt",
                self.output_dir / "file_descriptors.txt", 
                self.output_dir / "process_status.txt"
            ]
            
            return [f for f in monitor_files if f.exists()]
            
        except Exception as e:
            print(f"[-] Memory monitoring failed: {e}")
            return []

def analyze_extracted_files(files):
    """Analyze extracted files"""
    if not files:
        print("[-] No files to analyze")
        return
        
    print("\n=== File Analysis ===")
    for file_path in files:
        if not file_path.exists():
            continue
            
        size = file_path.stat().st_size
        print(f"\n--- {file_path.name} ({size} bytes) ---")
        
        # File type
        try:
            result = subprocess.run(['file', str(file_path)], 
                                  capture_output=True, text=True)
            print(f"Type: {result.stdout.strip()}")
        except:
            pass
        
        # First few bytes
        if size > 0:
            with open(file_path, 'rb') as f:
                data = f.read(min(128, size))
                print("First bytes (hex):")
                for i in range(0, len(data), 16):
                    hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
                    ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[i:i+16])
                    print(f"  {i:04x}: {hex_part:<48} |{ascii_part}|")
        
        # Look for text content if it's not too large
        if size < 1000000:  # Less than 1MB
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    text = f.read()
                    
                # Look for script-like content
                script_lines = []
                for line in text.split('\n'):
                    if any(keyword in line.lower() for keyword in [
                        'echo', 'bash', 'ulimit', 'wget', 'curl', 'connection', 'watching'
                    ]):
                        script_lines.append(line.strip())
                
                if script_lines:
                    print("Script-like content found:")
                    for line in script_lines[:10]:
                        print(f"  {line}")
                        
            except:
                pass

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary_path>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    dumper = MemoryDumper(binary_path)
    
    print("=== Advanced Memory Dumper ===")
    print(f"Target: {binary_path}")
    print(f"Output: {dumper.output_dir}")
    print()
    
    all_files = []
    
    # Method 1: GDB breakpoint dumping
    gdb_files = dumper.dump_with_gdb_breakpoint()
    all_files.extend(gdb_files)
    
    # Method 2: String analysis
    string_files = dumper.extract_strings_and_analyze() 
    all_files.extend(string_files)
    
    # Method 3: Memory monitoring
    monitor_files = dumper.run_with_memory_monitoring()
    all_files.extend(monitor_files)
    
    # Method 4: Core dump (if other methods don't work)
    if not gdb_files:
        core_files = dumper.dump_with_core_file()
        all_files.extend(core_files)
    
    # Analyze results
    analyze_extracted_files(all_files)
    
    print(f"\n[+] Memory dumping complete. Check {dumper.output_dir} for results.")

if __name__ == "__main__":
    main()
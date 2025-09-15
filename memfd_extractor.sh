#!/bin/bash

# Advanced MemFD Extractor
# Extracts real script contents from self-extracting binaries using LD_PRELOAD

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_PATH="${SCRIPT_DIR}/requirement"
OUTPUT_DIR="/tmp/memfd_extraction"
HOOK_LIB="${SCRIPT_DIR}/memfd_hook.so"

echo "=== Advanced MemFD Content Extractor ==="
echo "Binary: $BINARY_PATH"
echo "Output: $OUTPUT_DIR"
echo

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Compile the hook library if needed
if [[ ! -f "$HOOK_LIB" || "$SCRIPT_DIR/memfd_hook.c" -nt "$HOOK_LIB" ]]; then
    echo "[+] Compiling MemFD hook library..."
    gcc -shared -fPIC -ldl -o "$HOOK_LIB" "$SCRIPT_DIR/memfd_hook.c"
    if [[ $? -ne 0 ]]; then
        echo "[-] Failed to compile hook library"
        exit 1
    fi
    echo "[+] Hook library compiled successfully"
fi

# Clean previous extraction attempts
rm -f "$OUTPUT_DIR"/*

echo "[+] Running binary with MemFD hook..."
echo "    Command: LD_PRELOAD=$HOOK_LIB $BINARY_PATH"

# Set ulimit to 0 to bypass anti-analysis
ulimit -c 0

# Run with hook
export LD_PRELOAD="$HOOK_LIB"
timeout 30 "$BINARY_PATH" || true
unset LD_PRELOAD

echo
echo "[+] Extraction completed. Analyzing results..."

# Check what was extracted
if [[ -d "$OUTPUT_DIR" ]]; then
    echo
    echo "=== Extraction Results ==="
    ls -la "$OUTPUT_DIR/"
    
    echo
    echo "=== Hook Log ==="
    if [[ -f "$OUTPUT_DIR/memfd_hook.log" ]]; then
        cat "$OUTPUT_DIR/memfd_hook.log"
    else
        echo "No hook log found"
    fi
    
    echo
    echo "=== Extracted Files Analysis ==="
    for file in "$OUTPUT_DIR"/*.dump; do
        if [[ -f "$file" ]]; then
            echo "File: $(basename "$file")"
            echo "Size: $(stat -c%s "$file") bytes"
            echo "Type: $(file "$file")"
            echo "First 256 bytes (hex):"
            hexdump -C "$file" | head -16
            echo "Strings (printable content):"
            strings "$file" | head -20
            echo "---"
        fi
    done
else
    echo "[-] No extraction directory found"
fi

# Additional strace analysis
echo
echo "=== Running strace analysis ==="
echo "[+] Tracing system calls with focus on memfd operations..."

strace_output="$OUTPUT_DIR/strace.log"
ulimit -c 0
timeout 30 strace -f -e trace=memfd_create,write,close,mmap,munmap,execve \
    -o "$strace_output" "$BINARY_PATH" 2>/dev/null || true

if [[ -f "$strace_output" ]]; then
    echo "Strace output saved to: $strace_output"
    echo
    echo "MemFD operations:"
    grep -E "(memfd_create|write.*fd=[34])" "$strace_output" || echo "No memfd operations found"
fi

echo
echo "=== Summary ==="
echo "Check $OUTPUT_DIR for extracted memfd contents"
echo "Look for files matching the patterns mentioned in the problem:"
echo "- upX (fd=3) with 3299 bytes"  
echo "- upx (fd=4) with 2019101 bytes"
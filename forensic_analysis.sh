#!/bin/bash

# Forensic Analysis Script for the 'requirement' binary
# This script implements the safe analysis procedures described in the README.md

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE_DIR="${SCRIPT_DIR}/evidence"
BINARY_PATH="${SCRIPT_DIR}/requirement"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Create evidence directory
create_evidence_dir() {
    log "Creating evidence directory..."
    mkdir -p "${EVIDENCE_DIR}"
    success "Evidence directory created: ${EVIDENCE_DIR}"
}

# Preserve original binary with metadata
preserve_binary() {
    log "Preserving original binary..."
    if [[ -f "${BINARY_PATH}" ]]; then
        cp -a "${BINARY_PATH}" "${EVIDENCE_DIR}/requirement.bin"
        
        # Calculate and store hashes
        sha256sum "${EVIDENCE_DIR}/requirement.bin" > "${EVIDENCE_DIR}/requirement.bin.sha256"
        sha1sum "${EVIDENCE_DIR}/requirement.bin" > "${EVIDENCE_DIR}/requirement.bin.sha1"
        md5sum "${EVIDENCE_DIR}/requirement.bin" > "${EVIDENCE_DIR}/requirement.bin.md5"
        
        # Store file metadata
        ls -la "${BINARY_PATH}" > "${EVIDENCE_DIR}/requirement.metadata"
        file "${BINARY_PATH}" > "${EVIDENCE_DIR}/requirement.filetype"
        
        success "Binary preserved with hashes and metadata"
    else
        error "Original binary not found at ${BINARY_PATH}"
        return 1
    fi
}

# Basic static analysis
static_analysis() {
    log "Performing static analysis..."
    
    local binary="${EVIDENCE_DIR}/requirement.bin"
    local output_dir="${EVIDENCE_DIR}/static_analysis"
    mkdir -p "${output_dir}"
    
    # File type analysis
    file "${binary}" > "${output_dir}/file_type.txt"
    
    # ELF header analysis
    if command -v readelf &> /dev/null; then
        readelf -h "${binary}" > "${output_dir}/elf_header.txt" 2>&1 || true
        readelf -l "${binary}" > "${output_dir}/program_headers.txt" 2>&1 || true
        readelf -S "${binary}" > "${output_dir}/section_headers.txt" 2>&1 || true
    fi
    
    # Strings extraction with different minimum lengths
    strings -a -n 4 "${binary}" > "${output_dir}/strings_min4.txt"
    strings -a -n 8 "${binary}" > "${output_dir}/strings_min8.txt"
    strings -a -n 20 "${binary}" > "${output_dir}/strings_min20.txt"
    
    # Search for specific patterns
    log "Searching for suspicious patterns..."
    
    # Shell-related patterns
    grep -i "bash\|shell\|/bin/sh\|/usr/bin/env" "${output_dir}/strings_min4.txt" > "${output_dir}/shell_patterns.txt" || true
    
    # Network-related patterns
    grep -E "(http|https|ftp|ssh|telnet)://|curl|wget|nc |netcat" "${output_dir}/strings_min4.txt" > "${output_dir}/network_patterns.txt" || true
    
    # File system patterns
    grep -E "/tmp|/var|/etc|/home|/root|\.sh|\.bash|\.py|\.pl" "${output_dir}/strings_min4.txt" > "${output_dir}/filesystem_patterns.txt" || true
    
    # Crypto/encoding patterns
    grep -E "base64|openssl|gpg|encrypt|decrypt|hash|sha|md5" "${output_dir}/strings_min4.txt" > "${output_dir}/crypto_patterns.txt" || true
    
    # Packer signatures
    grep -i "upx\|pack\|compress\|stub" "${output_dir}/strings_min4.txt" > "${output_dir}/packer_patterns.txt" || true
    
    success "Static analysis completed"
}

# Attempt unpacking with various tools
attempt_unpacking() {
    log "Attempting to unpack binary..."
    
    local binary="${EVIDENCE_DIR}/requirement.bin"
    local unpack_dir="${EVIDENCE_DIR}/unpacking"
    mkdir -p "${unpack_dir}"
    
    # Try UPX unpacking
    if command -v upx &> /dev/null; then
        log "Trying UPX unpacking..."
        upx -t "${binary}" > "${unpack_dir}/upx_test.log" 2>&1 || true
        upx -d "${binary}" -o "${unpack_dir}/requirement.upx_unpacked" > "${unpack_dir}/upx_unpack.log" 2>&1 || true
        
        if [[ -f "${unpack_dir}/requirement.upx_unpacked" ]]; then
            success "UPX unpacking successful"
            file "${unpack_dir}/requirement.upx_unpacked" > "${unpack_dir}/unpacked.filetype"
        else
            warn "UPX unpacking failed - see ${unpack_dir}/upx_unpack.log"
        fi
    else
        warn "UPX not available for unpacking"
    fi
    
    # Hex dump analysis for manual inspection
    log "Creating hex dumps for manual analysis..."
    head -c 1024 "${binary}" | hexdump -C > "${unpack_dir}/header_hex.txt"
    tail -c 1024 "${binary}" | hexdump -C > "${unpack_dir}/tail_hex.txt"
}

# Generate analysis report
generate_report() {
    log "Generating analysis report..."
    
    local report="${EVIDENCE_DIR}/analysis_summary.txt"
    
    cat > "${report}" << EOF
FORENSIC ANALYSIS SUMMARY
========================
Generated: $(date)
Analyst: Automated Analysis Script
Binary: requirement

FILE INFORMATION:
$(cat "${EVIDENCE_DIR}/requirement.metadata" 2>/dev/null || echo "Metadata not available")

FILE TYPE:
$(cat "${EVIDENCE_DIR}/requirement.filetype" 2>/dev/null || echo "File type not available")

CRYPTOGRAPHIC HASHES:
SHA256: $(cat "${EVIDENCE_DIR}/requirement.bin.sha256" 2>/dev/null || echo "Not available")
SHA1: $(cat "${EVIDENCE_DIR}/requirement.bin.sha1" 2>/dev/null || echo "Not available")
MD5: $(cat "${EVIDENCE_DIR}/requirement.bin.md5" 2>/dev/null || echo "Not available")

SUSPICIOUS PATTERNS FOUND:
EOF
    
    # Add pattern analysis results
    for pattern_file in "${EVIDENCE_DIR}/static_analysis"/*_patterns.txt; do
        if [[ -f "${pattern_file}" && -s "${pattern_file}" ]]; then
            echo "" >> "${report}"
            echo "$(basename "${pattern_file}" .txt | tr '_' ' ' | tr '[:lower:]' '[:upper:]'):" >> "${report}"
            head -10 "${pattern_file}" >> "${report}"
        fi
    done
    
    cat >> "${report}" << EOF

RECOMMENDATIONS:
1. DO NOT execute this binary on production systems
2. Further analysis should be conducted in isolated environments
3. Consider dynamic analysis with memory dumps if execution is necessary
4. Monitor for similar binaries using the provided IOCs

EVIDENCE COLLECTED:
$(find "${EVIDENCE_DIR}" -type f | sort)
EOF
    
    success "Analysis report generated: ${report}"
}

# Main execution
main() {
    log "Starting forensic analysis of 'requirement' binary"
    log "Analysis timestamp: ${TIMESTAMP}"
    
    create_evidence_dir
    preserve_binary
    static_analysis
    attempt_unpacking
    generate_report
    
    success "Forensic analysis completed successfully!"
    log "All evidence and analysis results stored in: ${EVIDENCE_DIR}"
    
    # Display summary
    echo ""
    echo "QUICK SUMMARY:"
    echo "=============="
    echo "Binary Type: $(file "${BINARY_PATH}" | cut -d: -f2)"
    echo "Size: $(stat -c%s "${BINARY_PATH}") bytes"
    echo "SHA256: $(sha256sum "${BINARY_PATH}" | cut -d' ' -f1)"
    echo ""
    echo "Evidence directory: ${EVIDENCE_DIR}"
    echo "Full report: ${EVIDENCE_DIR}/analysis_summary.txt"
}

# Run main function
main "$@"
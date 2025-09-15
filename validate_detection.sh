#!/bin/bash

# Validation script for detection rules
# Tests YARA rules against the requirement binary

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="${SCRIPT_DIR}/requirement"
YARA_RULES="${SCRIPT_DIR}/detection.yara"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

# Test YARA rules if yara is available
test_yara_rules() {
    log "Testing YARA rules..."
    
    if command -v yara &> /dev/null; then
        log "Running YARA analysis..."
        if yara "${YARA_RULES}" "${BINARY}"; then
            success "YARA rules detected the binary successfully"
        else
            fail "YARA rules did not detect the binary"
        fi
    else
        log "YARA not available, skipping rule validation"
        log "To install YARA: apt-get install yara or download from https://yara.readthedocs.io/"
    fi
}

# Test hash-based detection
test_hash_detection() {
    log "Testing hash-based detection..."
    
    local sha256_hash=$(sha256sum "${BINARY}" | cut -d' ' -f1)
    local expected_hash="e636d9f7a45be4031e7ebce1f501e50086ae10b1c65feb48ab0c64a6bf582768"
    
    if [[ "${sha256_hash}" == "${expected_hash}" ]]; then
        success "Hash-based detection: MATCH (SHA256: ${sha256_hash})"
    else
        fail "Hash mismatch! Expected: ${expected_hash}, Got: ${sha256_hash}"
    fi
}

# Test string-based detection
test_string_detection() {
    log "Testing string-based detection..."
    
    local upx_found=false
    local bash_found=false
    
    # Test for UPX signatures
    if strings "${BINARY}" | grep -q "UPX"; then
        upx_found=true
        success "UPX signature detected"
    else
        fail "UPX signature not found"
    fi
    
    # Test for bash signatures
    if strings "${BINARY}" | grep -q "GNU bash\|BASH_ENV"; then
        bash_found=true
        success "Bash signature detected"
    else
        fail "Bash signature not found"
    fi
    
    if [[ "${upx_found}" == true && "${bash_found}" == true ]]; then
        success "String-based detection: POSITIVE"
    else
        fail "String-based detection: NEGATIVE"
    fi
}

# Test file type detection
test_file_type_detection() {
    log "Testing file type detection..."
    
    local file_type=$(file "${BINARY}")
    
    if echo "${file_type}" | grep -q "ELF 64-bit"; then
        success "ELF 64-bit binary detected"
    else
        fail "Expected ELF 64-bit binary"
    fi
    
    if echo "${file_type}" | grep -q "statically linked"; then
        success "Statically linked binary detected"
    else
        fail "Expected statically linked binary"
    fi
    
    if echo "${file_type}" | grep -q "no section header"; then
        success "No section headers detected (suspicious)"
    else
        fail "Expected no section headers"
    fi
}

# Main execution
main() {
    echo "Detection Rule Validation"
    echo "========================="
    echo "Binary: ${BINARY}"
    echo "YARA Rules: ${YARA_RULES}"
    echo ""
    
    if [[ ! -f "${BINARY}" ]]; then
        fail "Binary file not found: ${BINARY}"
        exit 1
    fi
    
    if [[ ! -f "${YARA_RULES}" ]]; then
        fail "YARA rules file not found: ${YARA_RULES}"
        exit 1
    fi
    
    test_hash_detection
    test_string_detection
    test_file_type_detection
    test_yara_rules
    
    echo ""
    echo "Validation complete!"
    echo ""
    echo "Summary of detection methods:"
    echo "1. Hash-based detection (SHA256 IOC)"
    echo "2. String-based detection (UPX + Bash signatures)" 
    echo "3. File type detection (ELF properties)"
    echo "4. YARA rule detection (comprehensive patterns)"
    echo ""
    echo "For operational use:"
    echo "- Deploy IOCs to SIEM/EDR platforms"
    echo "- Implement YARA rules in malware scanners"
    echo "- Monitor for similar file characteristics"
}

# Run validation
main "$@"
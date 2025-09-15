/*
YARA Rule for detecting the suspicious 'requirement' binary
Author: Automated Forensic Analysis
Date: 2025-09-15
Description: Detects packed executable with embedded bash shell and self-deletion capabilities
*/

rule Suspicious_Requirement_Binary {
    meta:
        author = "Automated Forensic Analysis"
        date = "2025-09-15"
        description = "Detects suspicious packed binary with embedded bash shell"
        threat_level = "HIGH"
        sample_sha256 = "e636d9f7a45be4031e7ebce1f501e50086ae10b1c65feb48ab0c64a6bf582768"
        
    strings:
        // UPX packer signatures
        $upx1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
        $upx2 = "$Id: UPX 5.02 Copyright (C) 1996-2025 the UPX Team. All Rights Reserved. $"
        $upx3 = "UPX!" ascii
        $upx4 = "RPhupX" ascii
        
        // Bash shell indicators
        $bash1 = "GNU bash, version" ascii
        $bash2 = "BASH_ENV" ascii
        $bash3 = "/bin/sh;" ascii
        $bash4 = "Shell" ascii
        
        // File system references
        $fs1 = "/var/mai" ascii
        $fs2 = "/etc/locp" ascii
        
        // ELF header for 64-bit executable
        $elf_header = { 7F 45 4C 46 02 01 01 03 }
        
        // Specific build ID
        $build_id = "79c58a2a94970f0131dfea1270704e9a3697ca42" ascii
        
    condition:
        // Must be an ELF file
        $elf_header at 0 and
        
        // Must have UPX signatures (indicating packing)
        (2 of ($upx*)) and
        
        // Must have bash shell indicators
        (2 of ($bash*)) and
        
        // File size should match (approximately)
        filesize > 1000000 and filesize < 1200000 and
        
        // Additional confidence indicators
        (1 of ($fs*) or $build_id)
}

rule Generic_Self_Extracting_Shell_Binary {
    meta:
        author = "Automated Forensic Analysis"
        date = "2025-09-15"
        description = "Generic detection for self-extracting binaries with embedded shells"
        threat_level = "MEDIUM"
        
    strings:
        // Common shell indicators
        $shell1 = "bash" ascii nocase
        $shell2 = "/bin/sh" ascii
        $shell3 = "/usr/bin/env" ascii
        $shell4 = "#!/" ascii
        
        // Self-deletion indicators
        $delete1 = "unlink" ascii
        $delete2 = "rm -f" ascii
        $delete3 = "self" ascii nocase
        
        // Memory execution indicators
        $mem1 = "memfd_create" ascii
        $mem2 = "exec" ascii
        $mem3 = "mmap" ascii
        
        // Packer indicators
        $pack1 = "packed" ascii nocase
        $pack2 = "compress" ascii nocase
        $pack3 = "UPX" ascii nocase
        
    condition:
        // Must be an executable file
        (uint32(0) == 0x464c457f) and  // ELF magic
        
        // Must have shell indicators
        (2 of ($shell*)) and
        
        // Must have either self-deletion, memory execution, or packing indicators
        (1 of ($delete*) or 1 of ($mem*) or 1 of ($pack*)) and
        
        // Size constraint to avoid false positives on large legitimate binaries
        filesize > 100000 and filesize < 10000000
}

rule Embedded_Bash_Shell_Detection {
    meta:
        author = "Automated Forensic Analysis"
        date = "2025-09-15"
        description = "Detects executables with embedded bash shell functionality"
        threat_level = "MEDIUM"
        
    strings:
        $bash_version = "GNU bash, version" ascii
        $bash_env = "BASH_ENV" ascii
        $bash_command = "bash -c" ascii nocase
        $shell_builtin = "builtin" ascii
        $shell_export = "export" ascii
        $shell_source = "source" ascii
        
    condition:
        // ELF executable
        uint32(0) == 0x464c457f and
        
        // Must have bash version string (strong indicator of embedded bash)
        $bash_version and
        
        // Must have additional bash/shell indicators
        (2 of ($bash_env, $bash_command, $shell_builtin, $shell_export, $shell_source))
}
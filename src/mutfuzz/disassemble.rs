use anyhow::{Context, Result};
use iced_x86::{Decoder, DecoderOptions, FlowControl};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};
use rustc_demangle::demangle;
use std::collections::HashMap;

/// Information about a single conditional jump instruction in the binary.
#[allow(dead_code)]
pub struct JumpInfo {
    /// Human-readable opcode name (e.g., "je", "jne")
    pub opcode: String,
    /// Raw instruction bytes
    pub hex_data: Vec<u8>,
    /// Demangled function name containing this jump
    pub function_name: String,
    /// Byte offset within the binary file
    pub file_offset: usize,
}

/// Result of disassembling a binary for mutable conditional jumps.
#[allow(dead_code)]
pub struct DisassemblyResult {
    /// Map from file offset to jump info
    pub jumps: HashMap<usize, JumpInfo>,
    /// Map from function name to list of jump file offsets
    pub function_map: HashMap<String, Vec<usize>>,
    /// Map from function name to file offset of its first instruction
    pub function_reach: HashMap<String, usize>,
}

/// Patterns to filter out instrumentation/runtime functions.
const FILTER_PATTERNS: &[&str] = &[
    "__afl",
    "__asan",
    "__ubsan",
    "__sanitizer",
    "__lsan",
    "__sancov",
    "AFL_",
    "std::",
    "core::",
    "alloc::",
    "__rust_",
    "rust_begin_unwind",
    "libfuzzer_sys::",
    "arbitrary::",
    "Fuzz",
    "fuzz",
    "asan",
    "ubsan",
    "sanitizer",
    "interceptor",
    "Interceptor",
    "assert",
    "printf",
    "memcpy",
    "memset",
    "memcmp",
    "strcmp",
    "strcpy",
    "register_tm_clones",
    "_init",
    "_cxx_global",
];

fn should_filter(name: &str) -> bool {
    FILTER_PATTERNS.iter().any(|pat| name.contains(pat))
}

fn should_include(name: &str, only_mutate: &[String], avoid_mutating: &[String]) -> bool {
    if should_filter(name) {
        return false;
    }
    for pat in avoid_mutating {
        if name.contains(pat.as_str()) {
            return false;
        }
    }
    if !only_mutate.is_empty() {
        return only_mutate.iter().any(|pat| name.contains(pat.as_str()));
    }
    true
}

/// Opcode name from iced-x86 mnemonic for conditional jumps.
fn jump_opcode_name(instr: &iced_x86::Instruction) -> Option<&'static str> {
    use iced_x86::Mnemonic;
    match instr.mnemonic() {
        Mnemonic::Je => Some("je"),
        Mnemonic::Jne => Some("jne"),
        Mnemonic::Jl => Some("jl"),
        Mnemonic::Jle => Some("jle"),
        Mnemonic::Jg => Some("jg"),
        Mnemonic::Jge => Some("jge"),
        Mnemonic::Jb => Some("jb"),
        Mnemonic::Jbe => Some("jbe"),
        Mnemonic::Ja => Some("ja"),
        Mnemonic::Jae => Some("jae"),
        Mnemonic::Js => Some("js"),
        Mnemonic::Jns => Some("jns"),
        Mnemonic::Jo => Some("jo"),
        Mnemonic::Jno => Some("jno"),
        Mnemonic::Jp => Some("jp"),
        Mnemonic::Jnp => Some("jnp"),
        _ => None,
    }
}

/// Disassemble a binary and find all mutable conditional jumps.
///
/// Uses the `object` crate to parse the binary and `iced-x86` to decode instructions.
/// Only x86-64 binaries are supported.
pub fn get_jumps(
    binary_data: &[u8],
    only_mutate: &[String],
    avoid_mutating: &[String],
) -> Result<DisassemblyResult> {
    let obj = object::File::parse(binary_data).context("failed to parse binary")?;

    let mut jumps = HashMap::new();
    let mut function_map: HashMap<String, Vec<usize>> = HashMap::new();
    let mut function_reach: HashMap<String, usize> = HashMap::new();

    // Collect all .text-like executable sections with their address ranges
    let mut sections: Vec<(u64, u64, u64)> = Vec::new(); // (vaddr, file_offset, size)
    for section in obj.sections() {
        if let Ok(name) = section.name() {
            if name == ".text" || name.starts_with(".text.") {
                sections.push((
                    section.address(),
                    section.file_range().map(|(off, _)| off).unwrap_or(0),
                    section.size(),
                ));
            }
        }
    }

    // Helper: convert virtual address to file offset
    let vaddr_to_file_offset = |vaddr: u64| -> Option<u64> {
        for &(sec_vaddr, sec_file_off, sec_size) in &sections {
            if vaddr >= sec_vaddr && vaddr < sec_vaddr + sec_size {
                return Some(sec_file_off + (vaddr - sec_vaddr));
            }
        }
        None
    };

    // Iterate over function symbols
    for symbol in obj.symbols() {
        if symbol.kind() != SymbolKind::Text {
            continue;
        }
        let sym_size = symbol.size();
        if sym_size == 0 {
            continue;
        }
        let sym_addr = symbol.address();
        let raw_name = symbol.name().unwrap_or("<unknown>");
        let func_name = format!("{:#}", demangle(raw_name));

        let include = should_include(&func_name, only_mutate, avoid_mutating);

        // Always record function_reach for reachability purposes
        if let Some(func_file_offset) = vaddr_to_file_offset(sym_addr) {
            function_reach.insert(func_name.clone(), func_file_offset as usize);
        }

        if !include {
            continue;
        }

        // Get the raw bytes for this function from the binary
        let func_file_offset = match vaddr_to_file_offset(sym_addr) {
            Some(off) => off as usize,
            None => continue,
        };
        let end = func_file_offset + sym_size as usize;
        if end > binary_data.len() {
            continue;
        }
        let func_bytes = &binary_data[func_file_offset..end];

        // Decode instructions
        let mut decoder = Decoder::with_ip(64, func_bytes, sym_addr, DecoderOptions::NONE);
        while decoder.can_decode() {
            let instr = decoder.decode();
            if instr.flow_control() != FlowControl::ConditionalBranch {
                continue;
            }

            let opcode_name = match jump_opcode_name(&instr) {
                Some(name) => name,
                None => continue,
            };

            // Calculate file offset of this instruction
            let instr_vaddr = instr.ip();
            let instr_file_offset = match vaddr_to_file_offset(instr_vaddr) {
                Some(off) => off as usize,
                None => continue,
            };

            // Extract raw instruction bytes
            let instr_len = instr.len();
            if instr_file_offset + instr_len > binary_data.len() {
                continue;
            }
            let raw_bytes = binary_data[instr_file_offset..instr_file_offset + instr_len].to_vec();

            jumps.insert(
                instr_file_offset,
                JumpInfo {
                    opcode: opcode_name.to_string(),
                    hex_data: raw_bytes,
                    function_name: func_name.clone(),
                    file_offset: instr_file_offset,
                },
            );

            function_map
                .entry(func_name.clone())
                .or_default()
                .push(instr_file_offset);
        }
    }

    // Warn if --only-mutate patterns didn't match any functions with jumps
    if !only_mutate.is_empty() {
        let matched_funcs: std::collections::HashSet<&str> =
            function_map.keys().map(|s| s.as_str()).collect();
        for pat in only_mutate {
            if !matched_funcs.iter().any(|f| f.contains(pat.as_str())) {
                eprintln!(
                    "WARNING: --only-mutate pattern {:?} did not match any functions with mutable jumps",
                    pat
                );
            }
        }
    }

    // Warn if --avoid-mutating patterns didn't match anything (may be a typo)
    if !avoid_mutating.is_empty() {
        let all_funcs: Vec<&str> = function_reach.keys().map(|s| s.as_str()).collect();
        for pat in avoid_mutating {
            if !all_funcs.iter().any(|f| f.contains(pat.as_str())) {
                eprintln!(
                    "WARNING: --avoid-mutating pattern {:?} did not match any function names (typo?)",
                    pat
                );
            }
        }
    }

    Ok(DisassemblyResult {
        jumps,
        function_map,
        function_reach,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_filter() {
        assert!(should_filter("__asan_init"));
        assert!(should_filter("std::vec::Vec"));
        assert!(should_filter("core::ptr::drop_in_place"));
        assert!(!should_filter("my_function"));
    }

    #[test]
    fn test_should_include_with_patterns() {
        let only: Vec<String> = vec!["my_mod".to_string()];
        let avoid: Vec<String> = vec![];
        assert!(should_include("my_mod::func", &only, &avoid));
        assert!(!should_include("other_mod::func", &only, &avoid));

        let only2: Vec<String> = vec![];
        let avoid2: Vec<String> = vec!["skip_me".to_string()];
        assert!(!should_include("skip_me::func", &only2, &avoid2));
        assert!(should_include("keep_me::func", &only2, &avoid2));
    }
}

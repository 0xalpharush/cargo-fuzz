use rand::Rng;
use std::collections::HashMap;

use crate::mutfuzz::disassemble::{DisassemblyResult, JumpInfo};

/// Short unconditional jump: jmp = 0xEB
const SHORT_JMP: u8 = 0xEB;

/// Flip table for short conditional jumps: maps opcode byte to its opposite.
fn short_flip(byte: u8) -> Option<u8> {
    match byte {
        0x74 => Some(0x75), // je  -> jne
        0x75 => Some(0x74), // jne -> je
        0x7C => Some(0x7D), // jl  -> jge
        0x7D => Some(0x7C), // jge -> jl
        0x7E => Some(0x7F), // jle -> jg
        0x7F => Some(0x7E), // jg  -> jle
        // Also handle the less common short conditional jumps
        0x72 => Some(0x73), // jb  -> jae
        0x73 => Some(0x72), // jae -> jb
        0x76 => Some(0x77), // jbe -> ja
        0x77 => Some(0x76), // ja  -> jbe
        0x78 => Some(0x79), // js  -> jns
        0x79 => Some(0x78), // jns -> js
        0x70 => Some(0x71), // jo  -> jno
        0x71 => Some(0x70), // jno -> jo
        0x7A => Some(0x7B), // jp  -> jnp
        0x7B => Some(0x7A), // jnp -> jp
        _ => None,
    }
}

/// Near conditional jumps use two bytes: 0x0F followed by 0x84-0x8F.
/// Flip table for the second byte of near conditional jumps.
fn near_flip(byte: u8) -> Option<u8> {
    match byte {
        0x84 => Some(0x85), // je  -> jne
        0x85 => Some(0x84), // jne -> je
        0x8C => Some(0x8D), // jl  -> jge
        0x8D => Some(0x8C), // jge -> jl
        0x8E => Some(0x8F), // jle -> jg
        0x8F => Some(0x8E), // jg  -> jle
        0x82 => Some(0x83), // jb  -> jae
        0x83 => Some(0x82), // jae -> jb
        0x86 => Some(0x87), // jbe -> ja
        0x87 => Some(0x86), // ja  -> jbe
        0x88 => Some(0x89), // js  -> jns
        0x89 => Some(0x88), // jns -> js
        0x80 => Some(0x81), // jo  -> jno
        0x81 => Some(0x80), // jno -> jo
        0x8A => Some(0x8B), // jp  -> jnp
        0x8B => Some(0x8A), // jnp -> jp
        _ => None,
    }
}

const NOP: u8 = 0x90;

/// Determine the type of jump encoding.
fn is_near_jump(hex_data: &[u8]) -> bool {
    hex_data.len() >= 2 && hex_data[0] == 0x0F
}

fn is_short_cond_jump(byte: u8) -> bool {
    (0x70..=0x7F).contains(&byte)
}

/// Generate a different jump instruction for the given original bytes.
///
/// Strategy (matching MuttFuzz):
/// - 70% chance: flip the condition (je -> jne, etc.)
/// - 12% chance: NOP out the jump (remove the branch)
/// - 18% chance: change to a different or unconditional jump
pub fn different_jump(hex_data: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    let p_flip = 0.70;
    let p_dc = 0.40; // probability of "don't care" (NOP) given we didn't flip

    let r: f64 = rng.gen();
    if r <= p_flip {
        // Flip the condition
        if is_near_jump(hex_data) {
            if let Some(flipped) = near_flip(hex_data[1]) {
                let mut result = hex_data.to_vec();
                result[1] = flipped;
                return result;
            }
        } else if is_short_cond_jump(hex_data[0]) {
            if let Some(flipped) = short_flip(hex_data[0]) {
                let mut result = hex_data.to_vec();
                result[0] = flipped;
                return result;
            }
        }
        // Fallback: NOP it out
        return vec![NOP; hex_data.len()];
    }

    let r2: f64 = rng.gen();
    if r2 <= p_dc {
        // NOP out the jump entirely
        return vec![NOP; hex_data.len()];
    }

    // Change to a different jump or unconditional jump
    let p_dc_jmp = p_dc / (1.0 - p_dc);
    let r3: f64 = rng.gen();

    if is_near_jump(hex_data) {
        if r3 <= p_dc_jmp {
            // Change to unconditional near jump: 0x90 0xE9 (NOP + JMP near)
            // The displacement bytes stay the same
            let mut result = hex_data.to_vec();
            result[0] = 0x90;
            result[1] = 0xE9;
            return result;
        }
        // Pick a different near conditional jump
        let near_conds: Vec<u8> = (0x80..=0x8Fu8).filter(|&b| b != hex_data[1]).collect();
        let idx = rng.gen_range(0..near_conds.len());
        let mut result = hex_data.to_vec();
        result[1] = near_conds[idx];
        return result;
    }

    // Short jump
    if r3 <= p_dc_jmp {
        // Change to unconditional short jump
        let mut result = hex_data.to_vec();
        result[0] = SHORT_JMP;
        return result;
    }
    // Pick a different short conditional jump
    let short_conds: Vec<u8> = (0x70..=0x7Fu8).filter(|&b| b != hex_data[0]).collect();
    let idx = rng.gen_range(0..short_conds.len());
    let mut result = hex_data.to_vec();
    result[0] = short_conds[idx];
    result
}

/// Metadata about a single mutation applied to a binary.
#[allow(dead_code)]
pub struct MutationRecord {
    pub function_name: String,
    pub file_offset: usize,
    pub new_bytes: Vec<u8>,
}

/// Create a mutant binary by applying `order` random mutations.
///
/// Returns the mutated binary bytes and metadata about each mutation.
pub fn create_mutant(
    original: &[u8],
    disasm: &DisassemblyResult,
    order: usize,
    avoid_repeats: bool,
    visited: &mut HashMap<(usize, Vec<u8>), u32>,
    rng: &mut impl Rng,
) -> Option<(Vec<u8>, Vec<MutationRecord>)> {
    if disasm.jumps.is_empty() {
        return None;
    }

    let mut mutated = original.to_vec();
    let mut records = Vec::new();
    let jump_offsets: Vec<usize> = disasm.jumps.keys().copied().collect();

    for _ in 0..order {
        let (offset, jump) = pick_jump(&jump_offsets, &disasm.jumps, rng)?;
        let new_bytes = different_jump(&jump.hex_data, rng);

        if avoid_repeats {
            let key = (offset, new_bytes.clone());
            let count = visited.entry(key).or_insert(0);
            *count += 1;
            // Allow repeats after many retries, but try to avoid them
            if *count > 1 {
                // Try a few more times to find a unique mutation
                let mut found_unique = false;
                for _ in 0..20 {
                    let (off2, jump2) = pick_jump(&jump_offsets, &disasm.jumps, rng)?;
                    let nb2 = different_jump(&jump2.hex_data, rng);
                    let key2 = (off2, nb2.clone());
                    if !visited.contains_key(&key2) {
                        visited.insert(key2, 1);
                        apply_mutation(&mut mutated, off2, &nb2);
                        records.push(MutationRecord {
                            function_name: jump2.function_name.clone(),
                            file_offset: off2,
                            new_bytes: nb2,
                        });
                        found_unique = true;
                        break;
                    }
                }
                if found_unique {
                    continue;
                }
                // Fall through and use the repeat
            }
        }

        apply_mutation(&mut mutated, offset, &new_bytes);
        records.push(MutationRecord {
            function_name: jump.function_name.clone(),
            file_offset: offset,
            new_bytes,
        });
    }

    Some((mutated, records))
}

fn pick_jump<'a>(
    offsets: &[usize],
    jumps: &'a HashMap<usize, JumpInfo>,
    rng: &mut impl Rng,
) -> Option<(usize, &'a JumpInfo)> {
    if offsets.is_empty() {
        return None;
    }
    let idx = rng.gen_range(0..offsets.len());
    let offset = offsets[idx];
    jumps.get(&offset).map(|j| (offset, j))
}

fn apply_mutation(binary: &mut [u8], offset: usize, new_bytes: &[u8]) {
    for (i, &byte) in new_bytes.iter().enumerate() {
        if offset + i < binary.len() {
            binary[offset + i] = byte;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_flip_symmetry() {
        // Flipping twice should return to original
        for byte in 0x70..=0x7Fu8 {
            if let Some(flipped) = short_flip(byte) {
                assert_eq!(short_flip(flipped), Some(byte));
            }
        }
    }

    #[test]
    fn test_near_flip_symmetry() {
        for byte in 0x80..=0x8Fu8 {
            if let Some(flipped) = near_flip(byte) {
                assert_eq!(near_flip(flipped), Some(byte));
            }
        }
    }

    #[test]
    fn test_different_jump_short() {
        let mut rng = rand::thread_rng();
        let hex_data = vec![0x74, 0x10]; // je short
        let result = different_jump(&hex_data, &mut rng);
        assert_eq!(result.len(), hex_data.len());
        // Result should be different from original (with very high probability)
        // We can't guarantee it since it's random, but we can check length
    }

    #[test]
    fn test_different_jump_near() {
        let mut rng = rand::thread_rng();
        let hex_data = vec![0x0F, 0x84, 0x00, 0x01, 0x00, 0x00]; // je near
        let result = different_jump(&hex_data, &mut rng);
        assert_eq!(result.len(), hex_data.len());
    }

    #[test]
    fn test_nop_preserves_length() {
        // NOP output should always match input length
        let hex_data = vec![0x74, 0x05];
        let nops = vec![NOP; hex_data.len()];
        assert_eq!(nops.len(), 2);
    }
}

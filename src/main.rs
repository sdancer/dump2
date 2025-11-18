use anyhow::{bail, Context, Result};
use goblin::mach::Mach;
use goblin::Object;
use std::env;
use std::fs;
use std::path::Path;

/// Convert "deadbeef" or "de ad be ef" to bytes
fn parse_hex_pattern(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    if cleaned.len() % 2 != 0 {
        bail!("Hex pattern length must be even (after removing whitespace)");
    }

    let bytes = hex::decode(cleaned)
        .with_context(|| format!("Failed to parse hex pattern `{}`", s))?;
    Ok(bytes)
}

/// Naive search for pattern in haystack; yields all match indices
fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return Vec::new();
    }

    let mut matches = Vec::new();
    for i in 0..=haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            matches.push(i);
        }
    }
    matches
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        eprintln!(
            "Usage: {} <mach-o-dylib> <hex-pattern> <target-base-hex>",
            args[0]
        );
        eprintln!("Example: {} libfoo.dylib \"de ad be ef\" 0x100000000", args[0]);
        std::process::exit(1);
    }

    let path = &args[1];
    let pattern_str = &args[2];
    let target_base_str = &args[3];

    let target_base = if let Some(stripped) = target_base_str.strip_prefix("0x") {
        u64::from_str_radix(stripped, 16)
            .with_context(|| format!("Invalid target base hex: {}", target_base_str))?
    } else {
        u64::from_str_radix(target_base_str, 16)
            .with_context(|| format!("Invalid target base hex: {}", target_base_str))?
    };

    let pattern = parse_hex_pattern(pattern_str)?;

    let buf = fs::read(Path::new(path))
        .with_context(|| format!("Failed to read file `{}`", path))?;

    let obj = Object::parse(&buf).with_context(|| "Failed to parse object")?;

    // Handle Mach-O only
    let mach = match obj {
        Object::Mach(mach) => mach,
        _ => bail!("File is not a Mach-O object"),
    };

    // Handle thin Mach-O or first arch of fat Mach-O
    let macho = match mach {
        Mach::Binary(m) => m,
    Mach::Fat(fat) => {
        // fat.arches() -> Result<Vec<FatArch>, _>   in goblin 0.8
        let arches = fat
            .arches()
            .with_context(|| "Failed to list architectures in fat Mach-O")?;

        if arches.is_empty() {
            bail!("No architectures in fat Mach-O");
        }

        let first_arch = &arches[0];

        first_arch
            .parse(&buf)
            .with_context(|| "Failed to parse first arch in fat Mach-O")?
    }
    };


    // Determine original base as vmaddr of the first segment (usually __TEXT)
    let mut orig_base: Option<u64> = None;

    for seg in macho.segments.iter() {
        if let Ok(seghdr) = seg {
            orig_base = Some(seghdr.vmaddr);
            break;
        }
    }

    let orig_base = orig_base.ok_or_else(|| anyhow::anyhow!("Could not determine original base"))?;

    println!(
        "File: {}\nOriginal base: 0x{:x}\nTarget base: 0x{:x}\nSlide: {:+#x}\n",
        path,
        orig_base,
        target_base,
        (target_base as i64 - orig_base as i64)
    );

    if pattern.is_empty() {
        bail!("Pattern is empty after parsing");
    }

    let mut total_matches = 0usize;

    // Iterate segments and their sections
    for (seg_idx, seg) in macho.segments.iter().enumerate() {
        let seg = match seg {
            Ok(s) => s,
            Err(_) => continue,
        };

        let seg_name = seg.name().unwrap_or("").to_string();
        let seg_vmaddr = seg.vmaddr;
        let seg_file_off = seg.fileoff;
        let seg_file_size = seg.filesize;

        // Get the sections belonging to this segment
        let sections = match seg.sections() {
            Ok(secs) => secs,
            Err(_) => continue,
        };

        for (sect_idx, sect) in sections.iter().enumerate() {
            let sect = match sect {
                Ok(s) => s,
                Err(_) => continue,
            };

            let sect_name = sect.name().unwrap_or("").to_string();
            let sect_vmaddr = sect.addr;
            let sect_size = sect.size;
            let sect_file_off = sect.offset as u64;

            // Safety check: ensure this section maps inside file
            let start = sect_file_off as usize;
            let end = sect_file_off
                .checked_add(sect_size)
                .ok_or_else(|| anyhow::anyhow!("Section size overflow"))? as usize;

            if end > buf.len() {
                // Corrupt / stripped / weird section, skip
                continue;
            }

            let section_bytes = &buf[start..end];
            let matches = find_all(section_bytes, &pattern);

            if matches.is_empty() {
                continue;
            }

            println!(
                "=== Segment #{}, Section #{} ===",
                seg_idx, sect_idx
            );
            println!(
                "Segment: {:<16} vmaddr=0x{:016x} fileoff=0x{:x} filesize=0x{:x}",
                seg_name, seg_vmaddr, seg_file_off, seg_file_size
            );
            println!(
                "Section: {:<16} vmaddr=0x{:016x} fileoff=0x{:x} size=0x{:x}",
                sect_name, sect_vmaddr, sect_file_off, sect_size
            );

            for rel_off in matches {
                let file_off = start + rel_off;
                let offset_in_section = rel_off as u64;

                let orig_va = sect_vmaddr
                    .checked_add(offset_in_section)
                    .ok_or_else(|| anyhow::anyhow!("VA overflow"))?;

                // Rebase: remove original base, add target base
                let rebased_va = orig_va - orig_base + target_base;

                println!(
                    "  match @ file_off=0x{:x}, orig_va=0x{:016x}, rebased_va=0x{:016x}",
                    file_off, orig_va, rebased_va
                );

                total_matches += 1;
            }

            println!();
        }
    }

    if total_matches == 0 {
        println!("No matches found for pattern {}", pattern_str);
    } else {
        println!("Total matches: {}", total_matches);
    }

    Ok(())
}

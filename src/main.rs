mod codegen;
mod disasm;
mod memory;
mod scanner;
mod types;

use anyhow::Context;
use memmap2::Mmap;
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::Path;

use crate::codegen::{generate_elixir_chunk, generate_enums_elixir, generate_opcodes_elixir};
use crate::memory::Mem;
use crate::scanner::{scan_all_segments_for_packets_and_structs, scan_for_enums};
use crate::types::{EnumDef, FieldType, PacketInfo, SubType};

fn resolve_unresolved_types(
    packets: &mut [PacketInfo],
    structs: &mut [PacketInfo],
    enums: &[EnumDef],
) {
    let mut addr_to_name = HashMap::new();

    // 1. Build a map of VAddr -> Name from Enums
    for e in enums {
        addr_to_name.insert(e.vaddr, e.name.clone());
    }

    // 2. Build a map of VAddr -> Name from Structs
    for s in structs.iter() {
        addr_to_name.insert(s.vaddr, s.name.clone());
    }

    // 3. Helper closure to resolve a single SubType
    let resolver = |subtype: &mut SubType| {
        if let SubType::Unresolved(addr) = subtype {
            if let Some(name) = addr_to_name.get(addr) {
                *subtype = SubType::Resolved(*addr, name.clone());
            } else {
                println!("failed to resolve {}", addr);
            }
        }
    };

    let process_field = |f_type: &mut FieldType, ty_ptr: &mut SubType| {
        resolver(ty_ptr);
        match f_type {
            FieldType::Array(element_type) => {
                if let FieldType::Struct(ref mut subtype)
                | FieldType::Enum {
                    name: ref mut subtype,
                    ..
                } = **element_type
                {
                    resolver(subtype);
                }
            }
            FieldType::Map(key_type, val_type) => {
                for inner in [key_type, val_type] {
                    if let FieldType::Struct(ref mut subtype)
                    | FieldType::Enum {
                        name: ref mut subtype,
                        ..
                    } = **inner
                    {
                        resolver(subtype);
                    }
                }
            }
            FieldType::Struct(subtype) => {
                resolver(subtype);
            }
            FieldType::Enum { name: subtype, .. } => {
                resolver(subtype);
            }
            _ => {}
        }
    };

    for pkt in packets.iter_mut() {
        for field in pkt.fields.iter_mut() {
            process_field(&mut field.f_type, &mut field.ty_ptr);
        }
    }
    for pkt in structs.iter_mut() {
        for field in pkt.fields.iter_mut() {
            process_field(&mut field.f_type, &mut field.ty_ptr);
        }
    }
}

fn main() -> Result<(), anyhow::Error> {
    let path = std::env::args()
        .nth(1)
        .context("provide Mach-O path on the CLI")?;
    let file = File::open(Path::new(&path))?;
    let map = unsafe { Mmap::map(&file)? };
    let mem = Mem::new(&map)?;

    let common_source = 0x0000_0001_05d1_f850u64;
    let enums_with_addr = scan_for_enums(&mem, common_source);
    println!("Found {} enums", enums_with_addr.len());

    let mut new_symbols: Vec<(String, u64)> = Vec::new();
    let mut enums = Vec::new();
    for (addr, e) in enums_with_addr {
        new_symbols.push((e.name.clone(), addr));
        enums.push(e);
    }

    let mem = Mem::with_additional_symbols(mem.data, mem.segments, new_symbols, &vec![]);

    let (mut packets, mut structs) = scan_all_segments_for_packets_and_structs(&mem)?;
    println!(
        "Scan complete → {} packets, {} structs found",
        packets.len(),
        structs.len()
    );

    resolve_unresolved_types(&mut packets, &mut structs, &enums);

    let prefix = "DevPacketData_";
    packets.retain(|p| p.name.starts_with(prefix));
    structs.retain(|s| s.name.starts_with(prefix));
    println!(
        "Filtered -> {} packets, {} structs",
        packets.len(),
        structs.len()
    );

    let json = serde_json::to_string_pretty(&structs)?;
    fs::write("structs.json", &json)?;
    let json = serde_json::to_string_pretty(&packets)?;
    fs::write("packets.json", &json)?;
    let json = serde_json::to_string_pretty(&enums)?;
    fs::write("enums.json", &json)?;

    fs::create_dir_all("out").ok();
    // In original code, packets and structs were merged for generation
    let mut all_packets = packets;
    all_packets.extend(structs);

    let per_part = (all_packets.len() + 63) / 64;

    let opcodes_ex = generate_opcodes_elixir(&all_packets);
    fs::write("out/opcodes.ex", opcodes_ex)?;

    let enums_ex = generate_enums_elixir(&enums);
    fs::write("out/enums.ex", enums_ex)?;

    for (idx, chunk) in all_packets.chunks(per_part).enumerate() {
        if chunk.is_empty() {
            break;
        }
        let fname = format!("out/packets_{:02}.ex", idx);
        let body = generate_elixir_chunk(chunk);
        fs::write(&fname, body)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // (You can paste the integration test `loads_packets_from_testdata` here)
}

use crate::disasm::{arm64_store_imm, find_packet_opcode, resolve_lazy_object};
use crate::memory::{Mem, fixup_pointer};
use crate::types::{EnumDef, Field, PacketInfo, SubType, collapse_fields, to_field_type};
use byteorder::{ByteOrder, LittleEndian};
use std::collections::BTreeMap;

pub fn scan_for_enums(mem: &Mem, common_source: u64) -> Vec<(u64, EnumDef)> {
    let mut map = BTreeMap::<String, (u64, EnumDef)>::new();
    let target_source = fixup_pointer(common_source);

    for seg in &mem.segments {
        if seg.filesize == 0 {
            continue;
        }
        let start = seg.fileoff as usize;
        let end = start + seg.filesize as usize;
        if end > mem.data.len() {
            continue;
        }
        let seg_slice = &mem.data[start..end];
        let base = seg.vmaddr;
        let upper = seg_slice.len().saturating_sub(56);

        for off in (0..upper).step_by(8) {
            let q0_raw = LittleEndian::read_u64(&seg_slice[off..off + 8]);
            if fixup_pointer(q0_raw) != target_source {
                continue;
            }
            let q1 = LittleEndian::read_u64(&seg_slice[off + 8..off + 16]);
            if q1 != 0 {
                continue;
            }
            let name_ptr_raw = LittleEndian::read_u64(&seg_slice[off + 16..off + 24]);
            let name_dup_raw = LittleEndian::read_u64(&seg_slice[off + 24..off + 32]);
            if fixup_pointer(name_ptr_raw) != fixup_pointer(name_dup_raw) {
                continue;
            }
            let addr = base + off as u64;
            if let Some((addr, e)) = read_enum(mem, addr) {
                map.entry(e.name.clone()).or_insert((addr, e));
            }
        }
    }
    map.into_values().collect()
}

pub fn scan_all_segments_for_packets_and_structs(
    mem: &Mem,
) -> Result<(Vec<PacketInfo>, Vec<PacketInfo>), anyhow::Error> {
    let _packets: Vec<PacketInfo> = Vec::new(); // Not used in original directly, but part of logic
    let mut structs = Vec::new();
    let common_source = 0x0000_0001_05d1_f850u64;

    for seg in &mem.segments {
        if seg.filesize <= 16 {
            continue;
        }
        let start = seg.fileoff as usize;
        let end = start + seg.filesize as usize;
        if end > mem.data.len() {
            continue;
        }
        let slice = &mem.data[start..end];
        let base_addr = seg.vmaddr;
        let upper = slice.len().saturating_sub(16);

        for off in (0..upper).step_by(8) {
            let addr = base_addr + off as u64;
            let q0 = LittleEndian::read_u64(&slice[off..off + 8]);
            if (q0 & 0xffffffff) != (common_source & 0xffffffff) {
                continue;
            }
            // let _q1 = LittleEndian::read_u64(&slice[off + 8..off + 16]); // unused

            if let Ok((_, cls)) = read_packet(&mem, addr) {
                structs.push(cls);
            }
        }
    }

    structs.sort_by_key(|p| p.name.clone());
    structs.dedup_by_key(|p| p.name.clone());

    Ok((vec![], structs)) // Original code returned (packets, structs) but filled structs only
}

fn read_enum(mem: &Mem, entry: u64) -> Option<(u64, EnumDef)> {
    let hdr = mem.read_bytes(entry, 56).ok()?;
    if LittleEndian::read_u64(&hdr[8..16]) != 0 {
        return None;
    }
    let name_ptr_raw = LittleEndian::read_u64(&hdr[16..24]);
    let name_dup_raw = LittleEndian::read_u64(&hdr[24..32]);
    let name_ptr = fixup_pointer(name_ptr_raw);
    let name_dup = fixup_pointer(name_dup_raw);

    if name_ptr != name_dup {
        return None;
    }
    let fields_ptr_raw = LittleEndian::read_u64(&hdr[32..40]);
    let fields_ptr = fixup_pointer(fields_ptr_raw);
    let magic = LittleEndian::read_u32(&hdr[40..44]);
    let field_cnt = (LittleEndian::read_u32(&hdr[44..48]) & 0xffff) as usize;

    if magic != 0x45 {
        return None;
    }
    let name = mem.get_ascii_string(name_ptr).ok()?;
    let blob = mem.read_bytes(fields_ptr, field_cnt * 16).ok()?;
    let mut fields = Vec::with_capacity(field_cnt);

    for i in 0..field_cnt {
        let p = i * 16;
        let fname_ptr_raw = LittleEndian::read_u64(&blob[p..p + 8]);
        let fname_ptr = fixup_pointer(fname_ptr_raw);
        let value = LittleEndian::read_u64(&blob[p + 8..p + 16]);
        let mut fname = mem.get_ascii_string(fname_ptr).ok()?;
        if let Some(stripped) = fname.strip_prefix(&format!("{}::", name)) {
            fname = stripped.to_owned();
        }
        fields.push((fname, value));
    }

    let maxv = fields.iter().map(|(_, v)| *v).max().unwrap_or(0);
    let repr = if maxv <= u8::MAX as u64 {
        "u8"
    } else if maxv <= i32::MAX as u64 {
        "i32"
    } else {
        "i64"
    }
    .to_owned();

    Some((
        entry,
        EnumDef {
            name,
            repr,
            fields,
            vaddr: entry,
        },
    ))
}

pub fn read_packet(mem: &Mem, entry: u64) -> Result<(u64, PacketInfo), anyhow::Error> {
    let rec = mem.read_bytes(entry, 72)?;
    let s_name_raw = LittleEndian::read_u64(&rec[24..32]);
    let s_name = fixup_pointer(s_name_raw);
    let name = mem.get_ascii_string(s_name)?;

    let p_fields_raw = LittleEndian::read_u64(&rec[32..40]);
    let p_fields = fixup_pointer(p_fields_raw);
    let field_cnt = LittleEndian::read_u32(&rec[40..44]) as usize;

    let opcode = if name.starts_with("DevPacket") || name.ends_with("Data") {
        find_packet_opcode(mem, entry)
    } else {
        None
    };

    let fields = read_fields(mem, p_fields, field_cnt & 0xffff)?;
    if name == "DevPacketData_Common_BattlePassGroupInfo" {
        println!("{:?}", fields);
    }
    let mut fields = collapse_fields(fields);
    fields.sort_by_key(|f| f.offset);

    Ok((
        entry,
        PacketInfo {
            name,
            opcode,
            mem_size: 0,
            flags: 0,
            fields,
            vaddr: entry,
        },
    ))
}

fn read_fields(mem: &Mem, arr_ptr: u64, count: usize) -> anyhow::Result<Vec<Field>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let ptrs = mem.read_bytes(arr_ptr, count * 8)?;
    let mut out_rev = Vec::with_capacity(count);
    let mut i: isize = count as isize - 1;
    while i >= 0 {
        let field_addr_raw = LittleEndian::read_u64(&ptrs[(i as usize) * 8..][..8]);
        let field_addr = fixup_pointer(field_addr_raw);
        let field = read_field(mem, field_addr)?;
        out_rev.push(field);
        i -= 1;
    }
    Ok(out_rev)
}

fn read_field(mem: &Mem, field_addr: u64) -> anyhow::Result<Field> {
    let rec = mem.read_bytes(field_addr, 0x40)?;
    let s_name_raw = LittleEndian::read_u64(&rec[0..8]);
    let s_name = fixup_pointer(s_name_raw);
    let unk1 = LittleEndian::read_u64(&rec[8..16]);
    let unk2 = LittleEndian::read_u32(&rec[16..20]);
    let unk3 = LittleEndian::read_u32(&rec[20..24]);
    let f_type = LittleEndian::read_u32(&rec[24..28]);
    let unk4 = LittleEndian::read_u32(&rec[28..32]);
    let unk5 = LittleEndian::read_u32(&rec[32..36]);
    let raw_offset = LittleEndian::read_u32(&rec[50..54]);
    let lazy_func_ptr_raw = LittleEndian::read_u64(&rec[56..64]);
    let lazy_func_ptr = fixup_pointer(lazy_func_ptr_raw);

    let name = mem.get_ascii_string(s_name)?;

    let (offset, ty_name_opt) = match f_type {
        25 => {
            let ty_name = resolve_lazy_object(&mem, lazy_func_ptr);
            let n = match ty_name {
                Some(a) => SubType::Unresolved(a),
                None => SubType::None,
            };
            (raw_offset, n)
        }
        30 => {
            let ty_name = resolve_lazy_object(&mem, lazy_func_ptr);
            let n = match ty_name {
                Some(a) => SubType::Unresolved(a),
                None => SubType::None,
            };
            (raw_offset, n)
        }
        76 => {
            let off = arm64_store_imm(mem, lazy_func_ptr + 4).unwrap_or(0xffff);
            (off, SubType::None)
        }
        _ => (raw_offset, SubType::None),
    };

    let f_type = to_field_type(f_type, ty_name_opt.clone());

    Ok(Field {
        name,
        f_type,
        offset,
        ty_ptr: ty_name_opt.clone(),
        unk1,
        unk2,
        unk3,
        unk4,
        unk5,
    })
}

use anyhow::Context;
use byteorder::{ByteOrder, LittleEndian};
use capstone::arch;
use capstone::arch::arm64::Arm64Reg;
use capstone::arch::arm64::{Arm64Insn, Arm64OperandType};
use capstone::prelude::*;
use goblin::Object;
use goblin::mach::{Mach, MachO, SingleArch};
use memmap2::Mmap;
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::path::Path;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum FieldType {
    U8,
    I32,
    I64,
    F32,
    StringUtf16,
    Bool,
    Array(Box<FieldType>),
    Struct(String),
    Enum {
        name: String,
        repr: Option<Box<FieldType>>,
    },
    Unresolved,
    Unknown(u32),
}

fn to_field_type(code: u32, subtype: Option<String>) -> FieldType {
    use FieldType::*;
    match code {
        0 => U8,
        3 => I32,
        4 => I64,
        10 => F32,
        21 => StringUtf16,
        22 => Array(Box::new(Unresolved)),
        25 => Struct(subtype.unwrap_or_default()),
        30 => Enum {
            name: subtype.unwrap_or_default(),
            repr: None,
        },
        44 => Bool,
        other => Unknown(other),
    }
}

#[derive(Debug, Serialize)]
struct EnumDef {
    name: String,
    repr: String,
    fields: Vec<(String, u64)>,
}

#[derive(Debug, Serialize)]
struct PacketInfo {
    name: String,
    opcode: Option<u32>, // <--- Added this field
    mem_size: u64,
    flags: u64,
    fields: Vec<Field>,
}

#[derive(Debug, Clone, Serialize)]
struct Field {
    name: String,
    f_type: FieldType,
    offset: u32,
    ty_ptr: Option<String>,
    unk1: u64,
    unk2: u32,
    unk3: u32,
    unk4: u32,
    unk5: u32,
}

#[derive(Clone, Debug)]
struct SegmentInfo {
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    name: String,
}

struct Mem<'a> {
    data: &'a [u8],
    segments: Vec<SegmentInfo>,
    addr2name: HashMap<u64, String>,
    name2addr: HashMap<String, u64>,
    data_symbols: Vec<(String, u64)>,
}

impl<'a> Mem<'a> {
    fn new(data: &'a [u8]) -> Result<Self, anyhow::Error> {
        let macho = parse_macho(data)?;
        let mut segments = Vec::new();
        for seg in macho.segments.iter() {
            let seg_name = seg
                .name()
                .map(|s| s.to_string())
                .unwrap_or_else(|_| "<unknown>".to_string());
            segments.push(SegmentInfo {
                vmaddr: seg.vmaddr,
                vmsize: seg.vmsize,
                fileoff: seg.fileoff,
                filesize: seg.filesize,
                name: seg_name,
            });
        }
        let (addr2name, name2addr, data_symbols) = build_symbol_maps(&macho);
        Ok(Self {
            data,
            segments,
            addr2name,
            name2addr,
            data_symbols,
        })
    }

    fn vaddr_to_off(&self, vaddr: u64) -> Option<usize> {
        self.segments.iter().find_map(|seg| {
            if seg.filesize == 0 {
                return None;
            }
            let seg_start = seg.vmaddr;
            let seg_end = seg.vmaddr + seg.filesize.max(seg.vmsize);
            if vaddr >= seg_start && vaddr < seg_end {
                let rel = vaddr - seg_start;
                Some((seg.fileoff + rel) as usize)
            } else {
                None
            }
        })
    }

    fn read_bytes(&self, vaddr: u64, len: usize) -> Result<&'a [u8], anyhow::Error> {
        let off = self
            .vaddr_to_off(vaddr)
            .ok_or_else(|| anyhow::anyhow!("vaddr {:#x} outside mapped segments", vaddr))?;
        self.data
            .get(off..off + len)
            .with_context(|| format!("slice out of range (vaddr {:#x})", vaddr))
    }

    fn read_u64(&self, vaddr: u64) -> Result<u64, anyhow::Error> {
        Ok(LittleEndian::read_u64(self.read_bytes(vaddr, 8)?))
    }

    fn get_ascii_string(&self, vaddr: u64) -> anyhow::Result<String> {
        let off = self
            .vaddr_to_off(vaddr)
            .ok_or_else(|| anyhow::anyhow!("string addr {:#x} outside mapped segments", vaddr))?;
        let slice = &self.data[off..];
        let nul = slice
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| anyhow::anyhow!("unterminated ASCII @ {:#x}", vaddr))?;
        Ok(std::str::from_utf8(&slice[..nul])?.to_owned())
    }
}

// Critical fixup for UE Mach-O truncated 32-bit pointers
#[inline]
fn fixup_pointer(ptr: u64) -> u64 {
    (ptr & 0xffffffff) + 0x100000000
}

fn parse_macho<'a>(data: &'a [u8]) -> Result<MachO<'a>, anyhow::Error> {
    let obj = Object::parse(data)?;
    let mach = match obj {
        Object::Mach(m) => m,
        _ => anyhow::bail!("File is not a Mach-O image"),
    };
    Ok(match mach {
        Mach::Binary(macho) => macho,
        Mach::Fat(fat) => {
            let arch = fat
                .get(0)
                .with_context(|| "Failed to read first architecture in fat Mach-O")?;
            match arch {
                SingleArch::MachO(m) => m,
                SingleArch::Archive(_) => anyhow::bail!("Fat Mach-O contained archive"),
            }
        }
    })
}

fn build_symbol_maps(
    macho: &MachO<'_>,
) -> (
    HashMap<u64, String>,
    HashMap<String, u64>,
    Vec<(String, u64)>,
) {
    let mut addr2name = HashMap::<u64, String>::new();
    let mut name2addr = HashMap::<String, u64>::new();
    let mut data_symbols = Vec::<(String, u64)>::new();
    for sym in macho.symbols() {
        let Ok((name, nlist)) = sym else { continue };
        if name.is_empty() || nlist.n_value == 0 || nlist.is_undefined() || nlist.is_stab() {
            continue;
        }
        let owned = name.to_owned();
        let addr = nlist.n_value;
        addr2name.entry(addr).or_insert_with(|| owned.clone());
        name2addr.entry(owned.clone()).or_insert(addr);
        data_symbols.push((owned, addr));
    }
    (addr2name, name2addr, data_symbols)
}

fn read_packet(mem: &Mem, entry: u64) -> Result<(u64, PacketInfo), anyhow::Error> {
    let rec = mem.read_bytes(entry, 72)?;
    let s_name_raw = LittleEndian::read_u64(&rec[24..32]);
    let s_name = fixup_pointer(s_name_raw);
    let name = mem.get_ascii_string(s_name)?;

    let p_fields_raw = LittleEndian::read_u64(&rec[32..40]);
    let p_fields = fixup_pointer(p_fields_raw);
    let field_cnt = LittleEndian::read_u32(&rec[40..44]) as usize;

    // Try to find opcode if it looks like a packet
    let opcode = if name.starts_with("DevPacket") || name.ends_with("Data") {
        find_packet_opcode(mem, entry)
    } else {
        None
    };

    if let Some(op) = opcode {
        println!("{} found opcode: {:#x}", name, op);
    }

    let fields = read_fields(mem, p_fields, field_cnt & 0xffff)?;
    let mut fields = collapse_fields(fields);
    fields.sort_by_key(|f| f.offset);

    Ok((
        entry,
        PacketInfo {
            name,
            opcode, // <--- Store it
            mem_size: 0,
            flags: 0,
            fields,
        },
    ))
}

fn collapse_fields(fields: Vec<Field>) -> Vec<Field> {
    let mut out = Vec::with_capacity(fields.len());
    let mut i = 0;
    while i < fields.len() {
        let mut cur = fields[i].clone();
        if cur.name == "UnderlyingType" && i + 1 < fields.len() {
            if let FieldType::Enum { .. } = fields[i + 1].f_type {
                let mut enum_field = fields[i + 1].clone();
                if let FieldType::Enum { ref mut repr, .. } = enum_field.f_type {
                    *repr = Some(Box::new(cur.f_type.clone()));
                }
                out.push(enum_field);
                i += 2;
                continue;
            }
        }
        if matches!(cur.f_type, FieldType::Array(_))
            && !out.is_empty()
            && out.last().unwrap().name == cur.name
        {
            let element = out.pop().unwrap();
            cur.f_type = FieldType::Array(Box::new(element.f_type.clone()));
            out.push(cur);
            i += 1;
            continue;
        }
        out.push(cur);
        i += 1;
    }
    out
}

fn read_enum(mem: &Mem, entry: u64) -> Option<EnumDef> {
    let hdr = mem.read_bytes(entry, 56).ok()?;

    // Verify padding (Offset 8) is 0
    if LittleEndian::read_u64(&hdr[8..16]) != 0 {
        return None;
    }

    // Read Name pointers
    let name_ptr_raw = LittleEndian::read_u64(&hdr[16..24]);
    let name_dup_raw = LittleEndian::read_u64(&hdr[24..32]);
    let name_ptr = fixup_pointer(name_ptr_raw);
    let name_dup = fixup_pointer(name_dup_raw);

    if name_ptr != name_dup {
        return None;
    }

    println!("name: {:X}", name_dup);

    // Read Fields Array Pointer (Offset 32)
    let fields_ptr_raw = LittleEndian::read_u64(&hdr[32..40]);
    let fields_ptr = fixup_pointer(fields_ptr_raw);

    // Read Magic and Count (Offsets 40 and 44)
    // Based on dump: Magic is at 40, Count is at 44
    let magic = LittleEndian::read_u32(&hdr[40..44]);
    let field_cnt = (LittleEndian::read_u32(&hdr[44..48]) & 0xffff) as usize;

    println!("magic: {} field_cnt: {}", magic, field_cnt);

    // Verify Magic 'E' (0x45)
    if magic != 0x45 {
        return None;
    }

    let name = mem.get_ascii_string(name_ptr).ok()?;

    // Parse Fields
    let blob = mem.read_bytes(fields_ptr, field_cnt * 16).ok()?;
    let mut fields = Vec::with_capacity(field_cnt);

    for i in 0..field_cnt {
        let p = i * 16;
        
        // Field Name Pointer
        let fname_ptr_raw = LittleEndian::read_u64(&blob[p..p + 8]);
        let fname_ptr = fixup_pointer(fname_ptr_raw);
        
        // Field Value
        let value = LittleEndian::read_u64(&blob[p + 8..p + 16]);
        
        let mut fname = mem.get_ascii_string(fname_ptr).ok()?;
        
        // Strip "EnumName::" prefix if present
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

    Some(EnumDef { name, repr, fields })
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

fn arm64_store_imm(mem: &Mem, addr: u64) -> anyhow::Result<u32> {
    let bytes = mem.read_bytes(addr, 4)?;
    let cs = Capstone::new()
        .arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .detail(true)
        .build()?;
    let insns = cs.disasm_all(bytes, addr)?;
    let insn = insns
        .iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no insn"))?;

    match insn.id().0 {
        id if id == Arm64Insn::ARM64_INS_STR as u32
            || id == Arm64Insn::ARM64_INS_STRB as u32
            || id == Arm64Insn::ARM64_INS_STRH as u32 =>
        {
            let detail = cs.insn_detail(&insn)?;
            let arch_detail = detail.arch_detail();
            let arch = arch_detail
                .arm64()
                .ok_or_else(|| anyhow::anyhow!("no arm64 detail"))?;
            for op in arch.operands() {
                if let Arm64OperandType::Mem(ref m) = op.op_type {
                    return Ok(m.disp() as u32);
                }
            }
            Err(anyhow::anyhow!("store has no mem operand"))
        }
        _ => Err(anyhow::anyhow!("not a store insn at {:#x}", addr)),
    }
}

fn clean_uobject_sym(sym: &str) -> String {
    static RE_STRUCT: OnceLock<Regex> = OnceLock::new();
    static RE_ENUM: OnceLock<Regex> = OnceLock::new();

    let struct_re = RE_STRUCT.get_or_init(|| {
        Regex::new(r"^_Z\d+Z_Construct_UScriptStruct_([A-Za-z0-9_]+)v$").expect("struct regex")
    });
    if let Some(caps) = struct_re.captures(sym) {
        return caps[1].to_owned();
    }

    let enum_re = RE_ENUM.get_or_init(|| {
        Regex::new(r"^_Z\d+Z_Construct_UEnum_[A-Za-z0-9]+_([A-Za-z0-9]+)v$").expect("enum regex")
    });
    if let Some(caps) = enum_re.captures(sym) {
        return caps[1].to_owned();
    }

    sym.to_owned()
}

fn read_field(mem: &Mem, field_addr: u64) -> anyhow::Result<Field> {
    let rec = mem.read_bytes(field_addr, 0x38)?;
    let s_name_raw = LittleEndian::read_u64(&rec[0..8]);
    let s_name = fixup_pointer(s_name_raw);
    let unk1 = LittleEndian::read_u64(&rec[8..16]);
    let unk2 = LittleEndian::read_u32(&rec[16..20]);
    let unk3 = LittleEndian::read_u32(&rec[20..24]);
    let f_type = LittleEndian::read_u32(&rec[24..28]);
    let unk4 = LittleEndian::read_u32(&rec[28..32]);
    let unk5 = LittleEndian::read_u32(&rec[32..36]);
    let raw_offset = LittleEndian::read_u32(&rec[36..40]);
    let func_desc_raw = LittleEndian::read_u64(&rec[40..48]);
    let func_desc = fixup_pointer(func_desc_raw);
    let func_desc1 = LittleEndian::read_u64(&rec[48..56]); // code pointer — no fixup

    let name = mem.get_ascii_string(s_name)?;

    let (offset, ty_name_opt) = match f_type {
        25 | 30 => {
            let ty_name = mem.addr2name.get(&func_desc).cloned();
            (raw_offset, ty_name)
        }
        44 => {
            let off = arm64_store_imm(mem, func_desc1 + 4).unwrap_or(0);
            (off, None)
        }
        _ => (raw_offset, None),
    };

    let f_type = to_field_type(f_type, ty_name_opt.clone());

    Ok(Field {
        name,
        f_type,
        offset,
        ty_ptr: ty_name_opt,
        unk1,
        unk2,
        unk3,
        unk4,
        unk5,
    })
}

fn scan_for_enums(mem: &Mem, common_source: u64) -> Vec<EnumDef> {
    let mut map = BTreeMap::<String, EnumDef>::new();

    // Ensure the source we are looking for is in the "fixed" format
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
        let upper = seg_slice.len().saturating_sub(56); // Ensure space for full header

        for off in (0..upper).step_by(8) {
            // 1. Check Source Pointer (Offset 0)
            let q0_raw = LittleEndian::read_u64(&seg_slice[off..off + 8]);
            if fixup_pointer(q0_raw) != target_source {
                continue;
            }

            // 2. Check Padding (Offset 8) - Must be 0
            let q1 = LittleEndian::read_u64(&seg_slice[off + 8..off + 16]);
            if q1 != 0 {
                continue;
            }

            // 3. Check Name Pointer vs Name Duplicate (Offset 16 & 24)
            let name_ptr_raw = LittleEndian::read_u64(&seg_slice[off + 16..off + 24]);
            let name_dup_raw = LittleEndian::read_u64(&seg_slice[off + 24..off + 32]);

            if fixup_pointer(name_ptr_raw) != fixup_pointer(name_dup_raw) {
                continue;
            }

            let addr = base + off as u64;

            // DEBUG: Print candidate address
            println!("[DEBUG] Enum Candidate found at {:#x}", addr);

            if let Some(e) = read_enum(mem, addr) {
                map.entry(e.name.clone()).or_insert(e);
            }
        }
    }
    map.into_values().collect()
}

fn scan_all_segments_for_packets_and_structs(
    mem: &Mem,
) -> Result<(Vec<PacketInfo>, Vec<PacketInfo>), anyhow::Error> {
    let mut packets = Vec::new();
    let mut structs = Vec::new();
    let common_source = 0x0000_0001_05d1_f850u64;
    let packet_prologue = 0x0000_0001_060b_1e68u64; // Update if needed for your binary

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
            let q1 = LittleEndian::read_u64(&slice[off + 8..off + 16]);

            if let Ok((_, cls)) = read_packet(&mem, addr) {
                structs.push(cls);
            }
        }
    }

    //packets.sort_by_key(|p| p.name.clone());
    //packets.dedup_by_key(|p| p.name.clone());
    structs.sort_by_key(|p| p.name.clone());
    structs.dedup_by_key(|p| p.name.clone());

    Ok((packets, structs))
}

fn main() -> Result<(), anyhow::Error> {
    let path = std::env::args()
        .nth(1)
        .context("provide Mach-O path on the CLI")?;
    let file = File::open(Path::new(&path))?;
    let map = unsafe { Mmap::map(&file)? };
    let mem = Mem::new(&map)?;

    let common_source = 0x0000_0001_05d1_f850u64;
    let enums = scan_for_enums(&mem, common_source);
    println!("Found {} enums", enums.len());

    let (mut packets, mut structs) = scan_all_segments_for_packets_and_structs(&mem)?;
    println!(
        "Scan complete → {} packets, {} structs found",
        packets.len(),
        structs.len()
    );

    let json = serde_json::to_string_pretty(&packets)?;
    fs::write("packets.json", &json)?;
    let json = serde_json::to_string_pretty(&enums)?;
    fs::write("enums.json", &json)?;

    fs::create_dir_all("out").ok();
    packets.extend(structs);
    let per_part = (packets.len() + 63) / 64;

    for (idx, chunk) in packets.chunks(per_part).enumerate() {
        if chunk.is_empty() {
            break;
        }
        let fname = format!("out/packets_{:02}.ex", idx);
        let body = generate_elixir_chunk(chunk);
        fs::write(&fname, body)?;
    }

    Ok(())
}

fn elixir_atom(src: &str) -> String {
    let mut out = String::with_capacity(src.len() + 4);
    for (i, ch) in src.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if i != 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn elixir_type(ft: &FieldType) -> String {
    use FieldType::*;
    match ft {
        U8 => ":u8".into(),
        I32 => ":i32".into(),
        I64 => ":i64".into(),
        F32 => ":f32".into(),
        StringUtf16 => ":string_utf16".into(),
        Bool => ":bool".into(),
        Array(elem) => format!("list({})", elixir_type(elem)),
        Struct(raw) => format!("PacketDSL.struct({})", clean_uobject_sym(raw)),
        Enum { name, .. } => format!("PacketDSL.enum({})", clean_uobject_sym(name)),
        Unresolved => ":unresolved".into(),
        Unknown(code) => format!("PacketDSL.unknown({})", code),
    }
}

fn generate_elixir_chunk(packets: &[PacketInfo]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(2048);
    writeln!(out, "# Auto-generated: DO NOT EDIT").unwrap();
    writeln!(out, "import PacketDSL\n").unwrap();

    for pkt in packets {
        writeln!(out, "packet {} do", pkt.name).unwrap();
        for f in &pkt.fields {
            writeln!(
                out,
                "  field :{:<25}, {} # offset 0x{:X}",
                elixir_atom(&f.name),
                elixir_type(&f.f_type),
                f.offset
            )
            .unwrap();
        }
        writeln!(out, "end\n").unwrap();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    const TESTDATA_PATH: &str = "testdata/macho_fixture";
    const DATA_LEN: usize = 0x100000;
    const BASE_ADDR: u64 = 0x10c400000;
    const PACKET_ONE_ADDR: u64 = 0x10c4fecc8;
    const PACKET_TWO_ADDR: u64 = 0x10c4fee98;

    fn write_macho_fixture(path: &Path) -> anyhow::Result<()> {
        fs::create_dir_all(path.parent().unwrap())?;

        let mut file = vec![0u8; 0x1000 + DATA_LEN];
        // mach_header_64
        LittleEndian::write_u32(&mut file[0..4], 0xfeedfacf); // magic
        LittleEndian::write_u32(&mut file[4..8], 0x0100000c); // cputype arm64
        LittleEndian::write_u32(&mut file[8..12], 0); // cpusubtype
        LittleEndian::write_u32(&mut file[12..16], 2); // filetype: MH_EXECUTE
        LittleEndian::write_u32(&mut file[16..20], 2); // ncmds
        LittleEndian::write_u32(&mut file[20..24], 0x60); // sizeofcmds
        LittleEndian::write_u32(&mut file[24..28], 0); // flags
        LittleEndian::write_u32(&mut file[28..32], 0); // reserved

        // LC_SEGMENT_64
        let seg_off = 0x20;
        LittleEndian::write_u32(&mut file[seg_off..seg_off + 4], 0x19);
        LittleEndian::write_u32(&mut file[seg_off + 4..seg_off + 8], 0x48);
        file[seg_off + 8..seg_off + 18].copy_from_slice(b"__TEST_SEG");
        LittleEndian::write_u64(&mut file[seg_off + 24..seg_off + 32], BASE_ADDR);
        LittleEndian::write_u64(&mut file[seg_off + 32..seg_off + 40], DATA_LEN as u64);
        LittleEndian::write_u64(&mut file[seg_off + 40..seg_off + 48], 0x1000);
        LittleEndian::write_u64(&mut file[seg_off + 48..seg_off + 56], DATA_LEN as u64);
        LittleEndian::write_u32(&mut file[seg_off + 56..seg_off + 60], 7); // maxprot
        LittleEndian::write_u32(&mut file[seg_off + 60..seg_off + 64], 7); // initprot
        LittleEndian::write_u32(&mut file[seg_off + 64..seg_off + 68], 0); // nsects
        LittleEndian::write_u32(&mut file[seg_off + 68..seg_off + 72], 0); // flags

        // LC_SYMTAB
        let symtab_off = seg_off + 0x48;
        LittleEndian::write_u32(&mut file[symtab_off..symtab_off + 4], 0x2);
        LittleEndian::write_u32(&mut file[symtab_off + 4..symtab_off + 8], 0x18);
        LittleEndian::write_u32(&mut file[symtab_off + 8..symtab_off + 12], 0);
        LittleEndian::write_u32(&mut file[symtab_off + 12..symtab_off + 16], 0);
        LittleEndian::write_u32(&mut file[symtab_off + 16..symtab_off + 20], 0);
        LittleEndian::write_u32(&mut file[symtab_off + 20..symtab_off + 24], 0);

        let data_start = 0x1000;
        let name1_off = 0x20000;
        let name2_off = 0x20040;
        let name1_addr = BASE_ADDR + name1_off as u64;
        let name2_addr = BASE_ADDR + name2_off as u64;

        let name1_bytes = b"DevPacketData_GameServer_CharMoveStart_RQ\0";
        let name2_bytes = b"DevPacketData_GameServer_CharMoveUpdate_RQ\0";
        file[data_start + name1_off..data_start + name1_off + name1_bytes.len()]
            .copy_from_slice(name1_bytes);
        file[data_start + name2_off..data_start + name2_off + name2_bytes.len()]
            .copy_from_slice(name2_bytes);

        let packet1_off = data_start + (PACKET_ONE_ADDR - BASE_ADDR) as usize;
        let packet2_off = data_start + (PACKET_TWO_ADDR - BASE_ADDR) as usize;

        LittleEndian::write_u64(&mut file[packet1_off + 24..packet1_off + 32], name1_addr);
        LittleEndian::write_u64(&mut file[packet1_off + 32..packet1_off + 40], 0);
        LittleEndian::write_u32(&mut file[packet1_off + 40..packet1_off + 44], 0);

        LittleEndian::write_u64(&mut file[packet2_off + 24..packet2_off + 32], name2_addr);
        LittleEndian::write_u64(&mut file[packet2_off + 32..packet2_off + 40], 0);
        LittleEndian::write_u32(&mut file[packet2_off + 40..packet2_off + 44], 0);

        fs::write(path, file)?;
        Ok(())
    }

    #[test]
    fn loads_packets_from_testdata() -> anyhow::Result<()> {
        let path = Path::new(TESTDATA_PATH);
        write_macho_fixture(path)?;
        let data = fs::read(path)?;
        let mem = Mem::new(&data)?;

        let (_, pkt1) = read_packet(&mem, PACKET_ONE_ADDR)?;
        let (_, pkt2) = read_packet(&mem, PACKET_TWO_ADDR)?;

        println!("Packet 1: {:?}", pkt1);
        println!("Packet 2: {:?}", pkt2);

        assert_eq!(pkt1.name, "DevPacketData_GameServer_CharMoveStart_RQ");
        assert_eq!(pkt2.name, "DevPacketData_GameServer_CharMoveUpdate_RQ");
        Ok(())
    }
}

/// Follows the constructor chain to find the opcode.
/// Logic:
/// 1. Entry + 16 -> FuncA
/// 2. FuncA -> finding 'str x8, [x0]' (where x8 is calculated via adrp/add) -> VTable1
/// 3. VTable1 + 24 -> FuncB
/// 4. FuncB -> finding 'stp x8, x9, [x1]' (where x8 is calculated) -> VTable2
/// 5. VTable2 + 16 -> FuncOpcode
/// 6. FuncOpcode -> 'mov w0, #imm' -> Opcode
fn find_packet_opcode(mem: &Mem, entry: u64) -> Option<u32> {
    // 1. Read 3rd pointer (offset 16)
    let func_a_ptr = fixup_pointer(mem.read_u64(entry + 16).ok()?);

    // 2. Disasm FuncA to find VTable1.
    // The trace shows the result is stored in [x0].
    let vtable1_ptr = scan_for_vtable_ptr(mem, func_a_ptr, Arm64Reg::ARM64_REG_X0)?;

    // 3. Read 4th pointer (offset 24) from VTable1
    let func_b_ptr = fixup_pointer(mem.read_u64(vtable1_ptr + 24).ok()?);

    // 4. Disasm FuncB to find VTable2.
    // The trace shows the result is stored in [x1] (via stp x8, x9, [x1]).
    let vtable2_ptr = scan_for_vtable_ptr(mem, func_b_ptr, Arm64Reg::ARM64_REG_X1)?;

    // 5. Read 3rd pointer (offset 16) from VTable2
    let opcode_func = fixup_pointer(mem.read_u64(vtable2_ptr + 16).ok()?);

    // 6. Disasm OpcodeFunc to find 'mov w0, IMM'
    scan_return_imm(mem, opcode_func)
}

// FIX: Changed store_target_reg type to u32
fn scan_for_vtable_ptr(mem: &Mem, func_addr: u64, store_target_reg: u32) -> Option<u64> {
    let code = mem.read_bytes(func_addr, 128).ok()?;
    let cs = Capstone::new()
        .arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .detail(true)
        .build()
        .ok()?;

    let insns = cs.disasm_all(code, func_addr).ok()?;
    let mut reg_vals = HashMap::<u32, u64>::new();

    for insn in insns.iter() {
        let detail = cs.insn_detail(&insn).ok()?;
        let arch = detail.arch_detail();
        // Collect iterator into a Vec so we can index it
        let ops: Vec<_> = arch.arm64()?.operands().collect();
        let id = insn.id().0;

        if id == Arm64Insn::ARM64_INS_ADRP as u32 {
            if ops.len() >= 2 {
                if let (Some(dest), Some(imm)) = (get_reg(&ops[0]), get_imm(&ops[1])) {
                    reg_vals.insert(dest, imm as u64);
                }
            }
        } else if id == Arm64Insn::ARM64_INS_ADD as u32 {
            if ops.len() >= 3 {
                if let (Some(dest), Some(src), Some(imm)) =
                    (get_reg(&ops[0]), get_reg(&ops[1]), get_imm(&ops[2]))
                {
                    if let Some(base) = reg_vals.get(&src) {
                        reg_vals.insert(dest, base.wrapping_add(imm as u64));
                    }
                }
            }
        } else if id == Arm64Insn::ARM64_INS_STR as u32 || id == Arm64Insn::ARM64_INS_STP as u32 {
            for op in &ops {
                if let Arm64OperandType::Mem(m) = op.op_type {
                    // FIX: Compare u32 directly
                    if m.base().0 as u32 == store_target_reg {
                        if let Some(src_reg_code) = get_reg(&ops[0]) {
                            if let Some(val) = reg_vals.get(&src_reg_code) {
                                return Some(*val);
                            }
                        }
                    }
                }
            }
        } else if id == Arm64Insn::ARM64_INS_RET as u32 || id == Arm64Insn::ARM64_INS_B as u32 {
            break;
        }
    }
    None
}

fn scan_return_imm(mem: &Mem, func_addr: u64) -> Option<u32> {
    let code = mem.read_bytes(func_addr, 32).ok()?;
    let cs = Capstone::new()
        .arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .detail(true)
        .build()
        .ok()?;

    let insns = cs.disasm_all(code, func_addr).ok()?;

    for insn in insns.iter() {
        let detail = cs.insn_detail(&insn).ok()?;
        let arch = detail.arch_detail();
        // FIX: Collect iterator into a Vec
        let ops: Vec<_> = arch.arm64()?.operands().collect();
        let id = insn.id().0;

        if id == Arm64Insn::ARM64_INS_MOV as u32 || id == Arm64Insn::ARM64_INS_MOVZ as u32 {
            if ops.len() >= 2 {
                if let (Some(dest), Some(imm)) = (get_reg(&ops[0]), get_imm(&ops[1])) {
                    if dest == Arm64Reg::ARM64_REG_W0 as u32
                        || dest == Arm64Reg::ARM64_REG_X0 as u32
                    {
                        return Some(imm as u32);
                    }
                }
            }
        }
        if id == Arm64Insn::ARM64_INS_RET as u32 {
            break;
        }
    }
    None
}

// Helper to extract register ID
fn get_reg(op: &capstone::arch::arm64::Arm64Operand) -> Option<u32> {
    if let Arm64OperandType::Reg(r) = op.op_type {
        Some(r.0 as u32)
    } else {
        None
    }
}

// Helper to extract Immediate
fn get_imm(op: &capstone::arch::arm64::Arm64Operand) -> Option<i64> {
    if let Arm64OperandType::Imm(i) = op.op_type {
        Some(i)
    } else {
        None
    }
}

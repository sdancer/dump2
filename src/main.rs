use anyhow::{Context, bail};
use byteorder::{ByteOrder, LittleEndian};
use capstone::arch;
use capstone::arch::arm64::{Arm64Insn, Arm64OperandType};
use capstone::prelude::*;
use goblin::Object;
use goblin::mach::MachO;
use goblin::mach::{Mach, SingleArch};
use memmap2::Mmap;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
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
            segments.push(SegmentInfo {
                vmaddr: seg.vmaddr,
                vmsize: seg.vmsize,
                fileoff: seg.fileoff,
                filesize: seg.filesize,
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
    let s_name = mem.get_ascii_string(LittleEndian::read_u64(&rec[24..32]))?;

    let u_size = LittleEndian::read_u64(&rec[32..40]);
    let u_flags = LittleEndian::read_u64(&rec[40..48]);
    let p_fields = LittleEndian::read_u64(&rec[48..56]);
    let field_cnt = LittleEndian::read_u32(&rec[56..60]) as usize;

    let fields = read_fields(mem, p_fields, field_cnt)?;
    let mut fields = collapse_fields(fields);
    fields.sort_by_key(|f| f.offset);

    Ok((
        entry,
        PacketInfo {
            name: s_name,
            mem_size: u_size,
            flags: u_flags,
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
    if LittleEndian::read_u64(&hdr[8..16]) != 0 {
        return None;
    }

    let name_ptr = LittleEndian::read_u64(&hdr[16..24]);
    let name_dup = LittleEndian::read_u64(&hdr[24..32]);
    if name_ptr != name_dup {
        return None;
    }

    let fields_ptr = LittleEndian::read_u64(&hdr[32..40]);
    let field_cnt = LittleEndian::read_u32(&hdr[40..44]) as usize;
    if LittleEndian::read_u64(&hdr[44..52]) != 0x45 {
        return None;
    }

    let name = mem.get_ascii_string(name_ptr).ok()?;
    let blob = mem.read_bytes(fields_ptr, field_cnt * 16).ok()?;
    let mut fields = Vec::with_capacity(field_cnt);

    for i in 0..field_cnt {
        let p = i * 16;
        let fname_ptr = LittleEndian::read_u64(&blob[p..p + 8]);
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
        let field_addr = LittleEndian::read_u64(&ptrs[(i as usize) * 8..][..8]);
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
            let arch = detail
                .arch_detail()
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

    let s_name = LittleEndian::read_u64(&rec[0..8]);
    let unk1 = LittleEndian::read_u64(&rec[8..16]);
    let unk2 = LittleEndian::read_u32(&rec[16..20]);
    let unk3 = LittleEndian::read_u32(&rec[20..24]);
    let f_type = LittleEndian::read_u32(&rec[24..28]);
    let unk4 = LittleEndian::read_u32(&rec[28..32]);
    let unk5 = LittleEndian::read_u32(&rec[32..36]);
    let raw_offset = LittleEndian::read_u32(&rec[36..40]);
    let func_desc = LittleEndian::read_u64(&rec[40..48]);
    let func_desc1 = LittleEndian::read_u64(&rec[48..56]);

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
    use std::collections::BTreeMap;

    let mut map = BTreeMap::<String, EnumDef>::new();

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
        let upper = seg_slice.len().saturating_sub(40);

        for off in (0..upper).step_by(8) {
            let q0 = LittleEndian::read_u64(&seg_slice[off..off + 8]);
            if q0 != common_source {
                continue;
            }

            let q1 = LittleEndian::read_u64(&seg_slice[off + 8..off + 16]);
            if q1 != 0 {
                continue;
            }

            let q3 = LittleEndian::read_u64(&seg_slice[off + 16..off + 24]);
            let q4 = LittleEndian::read_u64(&seg_slice[off + 24..off + 32]);
            if q3 != q4 {
                continue;
            }

            let addr = base + off as u64;
            if let Some(e) = read_enum(mem, addr) {
                map.entry(e.name.clone()).or_insert(e);
            }
        }
    }

    map.into_values().collect()
}

fn main() -> Result<(), anyhow::Error> {
    let path = std::env::args()
        .nth(1)
        .context("provide Mach-O path on the CLI")?;
    let file = File::open(Path::new(&path))?;
    let map = unsafe { Mmap::map(&file)? };
    let mem = Mem::new(&map)?;

    let common_source = *mem
        .name2addr
        .get("_Z41Z_Construct_UPackage__Script_CommonSourcev")
        .context("symbol CommonSource not found")?;

    let protocol_base = *mem
        .name2addr
        .get("_Z39Z_Construct_UScriptStruct_FBaseProtocolv")
        .context("symbol FBaseProtocol not found")?;

    let enums = scan_for_enums(&mem, common_source);

    println!("{} {}", common_source, protocol_base);
    println!("Non-function symbols: {}", mem.data_symbols.len());

    let mut packets = Vec::<PacketInfo>::new();
    let mut structs = Vec::<PacketInfo>::new();

    for (_name, addr) in &mem.data_symbols {
        let q0 = match mem.read_u64(*addr) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if q0 != common_source {
            continue;
        }

        let q1 = mem.read_u64(addr + 8)?;
        if q1 != 0 {
            if let Ok((_, pkt)) = read_packet(&mem, *addr) {
                packets.push(pkt);
            }
            continue;
        }

        if let Ok(cls) = read_packet(&mem, *addr) {
            structs.push(cls.1);
        }
    }

    let json = serde_json::to_string_pretty(&packets)?;
    fs::write("packets.json", &json)?;

    let json = serde_json::to_string_pretty(&enums)?;
    fs::write("enums.json", &json)?;

    fs::create_dir_all("out").ok();

    packets.extend(structs);

    let parts = 64usize.max(1);
    let per_part = (packets.len() + parts - 1) / parts;

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

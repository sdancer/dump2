use crate::types::{EnumDef, FieldType, PacketInfo, clean_uobject_sym};
use std::fmt::Write;

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
        Map(name, name1) => format!(
            "PacketDSL.map({}, {})",
            elixir_type(name),
            elixir_type(name1)
        ),
        Unresolved => ":unresolved".into(),
        Unknown(code) => format!("PacketDSL.unknown({})", code),
    }
}

pub fn generate_opcodes_elixir(packets: &[PacketInfo]) -> String {
    let mut out = String::with_capacity(4096);
    writeln!(out, "# Auto-generated: DO NOT EDIT").unwrap();
    writeln!(out, "defmodule PacketOpcodes do").unwrap();
    writeln!(out, "  @opcodes %{{").unwrap();

    let mut pairs: Vec<_> = packets
        .iter()
        .filter_map(|p| p.opcode.map(|op| (op, &p.name)))
        .filter(|(op, _)| *op != 0)
        .collect();

    pairs.sort_by_key(|(op, _)| *op);

    for (opcode, name) in pairs {
        let stripped = name.strip_prefix("DevPacketData_").unwrap_or(name);
        writeln!(out, "    {} => :{},", opcode, elixir_atom(stripped)).unwrap();
    }

    writeln!(out, "  }}").unwrap();
    writeln!(out, "").unwrap();
    writeln!(out, "  def mapping, do: @opcodes").unwrap();
    writeln!(out, "end").unwrap();
    out
}

pub fn generate_enums_elixir(enums: &[EnumDef]) -> String {
    let mut out = String::with_capacity(8192);
    writeln!(out, "# Auto-generated: DO NOT EDIT").unwrap();
    writeln!(out, "import PacketDSL\n").unwrap();

    for e in enums {
        let stripped_name = e.name.strip_prefix("DevPacketData_").unwrap_or(&e.name);
        let atom_name = elixir_atom(stripped_name);
        let repr = format!(":{}", e.repr);

        writeln!(out, "enum :{}, {} do", atom_name, repr).unwrap();
        for (field_name, val) in &e.fields {
            writeln!(out, "  value :{}, {}", field_name, val).unwrap();
        }
        writeln!(out, "end\n").unwrap();
    }
    out
}

pub fn generate_elixir_chunk(packets: &[PacketInfo]) -> String {
    let mut out = String::with_capacity(2048);
    writeln!(out, "# Auto-generated: DO NOT EDIT").unwrap();
    writeln!(out, "import PacketDSL\n").unwrap();

    for pkt in packets {
        let name = pkt.name.strip_prefix("DevPacketData_").unwrap_or(&pkt.name);
        writeln!(out, "packet {} do", name).unwrap();
        if let Some(opc) = pkt.opcode {
            if opc != 0 {
                writeln!(out, "  opcode {}", opc).unwrap();
            }
        }
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

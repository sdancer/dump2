use crate::types::{EnumDef, FieldType, PacketInfo, clean_uobject_sym};
use std::fmt::Write;

/// Convert PascalCase/CamelCase to snake_case for Rust field names.
fn to_snake_case(name: &str) -> String {
    let mut s = String::with_capacity(name.len() + 4);
    for (i, ch) in name.chars().enumerate() {
        if ch.is_uppercase() {
            if i != 0 {
                s.push('_');
            }
            s.push(ch.to_ascii_lowercase());
        } else {
            s.push(ch);
        }
    }
    // Handle reserved keywords
    match s.as_str() {
        "type" => "r#type".to_string(),
        "struct" => "r#struct".to_string(),
        "enum" => "r#enum".to_string(),
        "match" => "r#match".to_string(),
        "use" => "r#use".to_string(),
        "fn" => "r#fn".to_string(),
        "mod" => "r#mod".to_string(),
        "crate" => "r#crate".to_string(),
        "super" => "r#super".to_string(),
        "self" => "r#self".to_string(),
        _ => s,
    }
}

/// Convert internal FieldType to Rust type signature.
fn rust_type(ft: &FieldType) -> String {
    use FieldType::*;
    match ft {
        U8 => "u8".into(),
        I32 => "i32".into(),
        I64 => "i64".into(),
        F32 => "f32".into(),
        StringUtf16 => "String".into(), // Assuming UTF-16 converted to UTF-8 String on deserialization
        Bool => "bool".into(),
        Array(elem) => format!("Vec<{}>", rust_type(elem)),
        Struct(raw) => clean_uobject_sym(raw),
        Enum { name, .. } => clean_uobject_sym(name),
        Map(key, val) => format!(
            "std::collections::HashMap<{}, {}>",
            rust_type(key),
            rust_type(val)
        ),
        Unresolved => "serde_json::Value".into(), // Fallback for unresolved types
        Unknown(_) => "serde_json::Value".into(),
    }
}

pub fn generate_enums_rust(enums: &[EnumDef]) -> String {
    let mut out = String::with_capacity(8192);
    writeln!(out, "// Auto-generated: DO NOT EDIT").unwrap();
    writeln!(out, "use serde::{{Serialize, Deserialize}};").unwrap();
    writeln!(out).unwrap();

    for e in enums {
        let name = clean_uobject_sym(&crate::types::SubType::Resolved(e.vaddr, e.name.clone()));

        // Determine representation (Rust requires specific integer types for #[repr])
        let repr_type = match e.repr.as_str() {
            "u8" => "u8",
            "i32" => "i32",
            "i64" => "i64",
            _ => "i32", // Default fallback
        };

        writeln!(
            out,
            "#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]"
        )
        .unwrap();
        writeln!(out, "#[repr({})]", repr_type).unwrap();
        writeln!(out, "pub enum {} {{", name).unwrap();

        for (field_name, val) in &e.fields {
            // Ensure variant name is valid (e.g., can't start with number)
            let variant_name = if field_name.chars().next().map_or(false, |c| c.is_numeric()) {
                format!("_{}", field_name)
            } else {
                field_name.clone()
            };

            writeln!(out, "    {} = {},", variant_name, val).unwrap();
        }
        writeln!(out, "}}").unwrap();
        writeln!(out).unwrap();
    }
    out
}

pub fn generate_structs_rust(packets: &[PacketInfo]) -> String {
    let mut out = String::with_capacity(16384);
    writeln!(out, "// Auto-generated: DO NOT EDIT").unwrap();
    writeln!(out, "use serde::{{Serialize, Deserialize}};").unwrap();
    writeln!(out, "use super::enums::*;").unwrap(); // Assuming enums are in a sibling module
    writeln!(out).unwrap();

    for pkt in packets {
        let struct_name = clean_uobject_sym(&crate::types::SubType::Resolved(
            pkt.vaddr,
            pkt.name.clone(),
        ));

        writeln!(out, "/// Opcode: {:?}", pkt.opcode).unwrap();
        writeln!(out, "/// VAddr: 0x{:X}", pkt.vaddr).unwrap();
        writeln!(out, "#[derive(Debug, Clone, Serialize, Deserialize)]").unwrap();
        writeln!(out, "pub struct {} {{", struct_name).unwrap();

        for f in &pkt.fields {
            let field_name_rust = to_snake_case(&f.name);
            let field_type_rust = rust_type(&f.f_type);

            // Add rename annotation to map JSON/Packet PascalCase to Rust snake_case
            writeln!(out, "    #[serde(rename = \"{}\")]", f.name).unwrap();
            writeln!(
                out,
                "    pub {}: {}, // offset 0x{:X}",
                field_name_rust, field_type_rust, f.offset
            )
            .unwrap();
        }

        writeln!(out, "}}").unwrap();
        writeln!(out).unwrap();
    }
    out
}

pub fn generate_opcodes_rust(packets: &[PacketInfo]) -> String {
    let mut out = String::with_capacity(4096);
    writeln!(out, "// Auto-generated: DO NOT EDIT").unwrap();
    writeln!(out, "use std::collections::HashMap;").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "pub fn get_opcode_map() -> HashMap<u32, &'static str> {{"
    )
    .unwrap();
    writeln!(out, "    let mut m = HashMap::new();").unwrap();

    let mut pairs: Vec<_> = packets
        .iter()
        .filter_map(|p| p.opcode.map(|op| (op, &p.name)))
        .filter(|(op, _)| *op != 0)
        .collect();

    pairs.sort_by_key(|(op, _)| *op);

    for (opcode, name) in pairs {
        let clean_name = clean_uobject_sym(&crate::types::SubType::Resolved(0, name.clone()));
        writeln!(out, "    m.insert({}, \"{}\");", opcode, clean_name).unwrap();
    }

    writeln!(out, "    m").unwrap();
    writeln!(out, "}}").unwrap();
    out
}

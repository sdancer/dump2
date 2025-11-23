use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SubType {
    None,
    Unresolved(u64),
    Resolved(u64, String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum FieldType {
    U8,
    I32,
    I64,
    F32,
    StringUtf16,
    Bool,
    Array(Box<FieldType>),
    Map(Box<FieldType>, Box<FieldType>),
    Struct(SubType),
    Enum {
        name: SubType,
        repr: Option<Box<FieldType>>,
    },
    Unresolved,
    Unknown(u32),
}

#[derive(Debug, Serialize)]
pub struct EnumDef {
    pub name: String,
    pub repr: String,
    pub fields: Vec<(String, u64)>,
    pub vaddr: u64,
}

#[derive(Debug, Serialize)]
pub struct PacketInfo {
    pub name: String,
    pub opcode: Option<u32>,
    pub mem_size: u64,
    pub flags: u64,
    pub fields: Vec<Field>,
    pub vaddr: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Field {
    pub name: String,
    pub f_type: FieldType,
    pub offset: u32,
    pub ty_ptr: SubType,
    pub unk1: u64,
    pub unk2: u32,
    pub unk3: u32,
    pub unk4: u32,
    pub unk5: u32,
}

pub fn to_field_type(code: u32, subtype: SubType) -> FieldType {
    use FieldType::*;
    match code {
        0 => U8,
        3 => I32,
        4 => I64,
        10 => F32,
        21 => StringUtf16,
        22 => Array(Box::new(Unresolved)),
        23 => Map(Box::new(Unresolved), Box::new(Unresolved)),
        25 => Struct(subtype),
        30 => Enum {
            name: subtype,
            repr: None,
        },
        76 => Bool,
        other => Unknown(other),
    }
}

pub fn clean_uobject_sym(sym: &SubType) -> String {
    let sym_str = match sym {
        SubType::Unresolved(a) => format!("unresolved {:X}", a),
        SubType::None => "".to_string(),
        SubType::Resolved(_a, b) => b.clone(),
    };

    if let Some(stripped) = sym_str.strip_prefix("DevPacketData_") {
        return stripped.to_string();
    }
    sym_str.to_owned()
}

pub fn collapse_fields(fields: Vec<Field>) -> Vec<Field> {
    // Pass 1: Collapse Enums (Enum + UnderlyingType)
    let mut with_enums = Vec::with_capacity(fields.len());
    let mut i = 0;
    while i < fields.len() {
        let cur = &fields[i];

        if matches!(cur.f_type, FieldType::Enum { .. }) {
            if i + 1 < fields.len() && fields[i + 1].name == "UnderlyingType" {
                let mut merged = cur.clone();
                if let FieldType::Enum { ref mut repr, .. } = merged.f_type {
                    *repr = Some(Box::new(fields[i + 1].f_type.clone()));
                }
                with_enums.push(merged);
                i += 2;
                continue;
            }
        }
        with_enums.push(cur.clone());
        i += 1;
    }

    // Pass 2: Collapse Maps (Map + Key + Value)
    let mut with_maps = Vec::with_capacity(with_enums.len());
    i = 0;
    while i < with_enums.len() {
        let cur = &with_enums[i];

        if matches!(cur.f_type, FieldType::Map(_, _)) {
            if i + 2 < with_enums.len() {
                let key_field = &with_enums[i + 1];
                let val_field = &with_enums[i + 2];
                let expected_key_name = format!("{}_Key", cur.name);

                if key_field.name == expected_key_name && val_field.name == cur.name {
                    let mut merged = cur.clone();
                    merged.f_type = FieldType::Map(
                        Box::new(key_field.f_type.clone()),
                        Box::new(val_field.f_type.clone()),
                    );
                    with_maps.push(merged);
                    i += 3;
                    continue;
                }
            }
        }
        with_maps.push(cur.clone());
        i += 1;
    }

    // Pass 3: Collapse Arrays (Array + Element with same name)
    let mut out = Vec::with_capacity(with_maps.len());
    i = 0;
    while i < with_maps.len() {
        let cur = &with_maps[i];

        if matches!(cur.f_type, FieldType::Array(_)) {
            if i + 1 < with_maps.len() && with_maps[i + 1].name == cur.name {
                let mut merged = cur.clone();
                merged.f_type = FieldType::Array(Box::new(with_maps[i + 1].f_type.clone()));
                out.push(merged);
                i += 2;
                continue;
            }
        }
        out.push(cur.clone());
        i += 1;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    // (You can paste the test_collapse_fields_map and test_collapse_fields_complex here)
}

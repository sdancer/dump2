use anyhow::Context;
use byteorder::{ByteOrder, LittleEndian};
use goblin::Object;
use goblin::mach::{Mach, MachO, SingleArch};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct SegmentInfo {
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub name: String,
}

pub struct Mem<'a> {
    pub data: &'a [u8],
    pub segments: Vec<SegmentInfo>,
    pub addr2name: HashMap<u64, String>,
    pub name2addr: HashMap<String, u64>,
    pub data_symbols: Vec<(String, u64)>,
}

impl<'a> Mem<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, anyhow::Error> {
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
        Ok(Self {
            data,
            segments,
            addr2name: HashMap::new(),
            name2addr: HashMap::new(),
            data_symbols: Vec::new(),
        })
    }

    pub fn with_additional_symbols(
        data: &'a [u8],
        segments: Vec<SegmentInfo>,
        mut data_symbols: Vec<(String, u64)>,
        new_symbols: &[(String, u64)],
    ) -> Self {
        data_symbols.extend_from_slice(new_symbols);
        let mut addr2name = HashMap::<u64, String>::new();
        let mut name2addr = HashMap::<String, u64>::new();

        for (name, addr) in &data_symbols {
            addr2name.entry(*addr).or_insert_with(|| name.clone());
            name2addr.entry(name.clone()).or_insert(*addr);
        }

        Self {
            data,
            segments,
            addr2name,
            name2addr,
            data_symbols,
        }
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

    pub fn read_bytes(&self, vaddr: u64, len: usize) -> Result<&'a [u8], anyhow::Error> {
        let off = self
            .vaddr_to_off(vaddr)
            .ok_or_else(|| anyhow::anyhow!("vaddr {:#x} outside mapped segments", vaddr))?;
        self.data
            .get(off..off + len)
            .with_context(|| format!("slice out of range (vaddr {:#x})", vaddr))
    }

    pub fn read_u64(&self, vaddr: u64) -> Result<u64, anyhow::Error> {
        Ok(LittleEndian::read_u64(self.read_bytes(vaddr, 8)?))
    }

    pub fn get_ascii_string(&self, vaddr: u64) -> anyhow::Result<String> {
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
pub fn fixup_pointer(ptr: u64) -> u64 {
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

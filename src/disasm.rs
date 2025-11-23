use crate::memory::{Mem, fixup_pointer};
use capstone::arch::BuildsCapstone;
use capstone::arch::DetailsArchInsn;
use capstone::arch::arm64::{Arm64Insn, Arm64OperandType, Arm64Reg};
use capstone::{Capstone, arch};
use std::collections::HashMap;

// ARM64 Registers X0-X7 for arguments
const REG_X0: u32 = Arm64Reg::ARM64_REG_X0 as u32;
const REG_X7: u32 = Arm64Reg::ARM64_REG_X7 as u32;

pub fn arm64_store_imm(mem: &Mem, addr: u64) -> anyhow::Result<u32> {
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

pub fn resolve_lazy_object(mem: &Mem, func_ptr: u64) -> Option<u64> {
    // 1. Disassemble the wrapper function to find the lazy init call
    let code_len = 64;
    let code = mem.read_bytes(func_ptr, code_len).ok()?;
    let cs = Capstone::new()
        .arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .detail(true)
        .build()
        .ok()?;

    let insns = cs.disasm_all(code, func_ptr).ok()?;
    let mut target_func = 0;

    for insn in insns.iter() {
        if insn.id().0 == Arm64Insn::ARM64_INS_CBZ as u32 {
            let detail = cs.insn_detail(insn).ok()?;
            let arch = detail.arch_detail();
            let arm64 = arch.arm64()?;
            for op in arm64.operands() {
                if let Arm64OperandType::Imm(imm) = op.op_type {
                    target_func = imm as u64;
                    break;
                }
            }
        }
    }

    if target_func == 0 {
        return None;
    }

    // 2. Disassemble the init function
    let code = mem.read_bytes(target_func, 256).ok()?;
    let insns = cs.disasm_all(code, target_func).ok()?;
    let mut reg_pages = HashMap::<u32, i64>::new();

    for insn in insns.iter() {
        let id = insn.id().0;

        if id == Arm64Insn::ARM64_INS_BL as u32 || id == Arm64Insn::ARM64_INS_RET as u32 {
            break;
        }

        let detail = cs.insn_detail(insn).ok()?;
        let arch = detail.arch_detail();
        let arm64 = arch.arm64()?;
        let ops: Vec<_> = arm64.operands().collect();

        if id == Arm64Insn::ARM64_INS_ADRP as u32 {
            if ops.len() == 2 {
                if let (Arm64OperandType::Reg(reg), Arm64OperandType::Imm(imm)) =
                    (ops[0].op_type.clone(), ops[1].op_type.clone())
                {
                    reg_pages.insert(reg.0.into(), imm);
                }
            }
        } else if id == Arm64Insn::ARM64_INS_ADD as u32 {
            if ops.len() >= 3 {
                if let (
                    Arm64OperandType::Reg(dst),
                    Arm64OperandType::Reg(src),
                    Arm64OperandType::Imm(imm),
                ) = (
                    ops[0].op_type.clone(),
                    ops[1].op_type.clone(),
                    ops[2].op_type.clone(),
                ) {
                    if dst == src {
                        if let Some(&page_base) = reg_pages.get(&src.0.into()) {
                            let final_addr = (page_base as u64).wrapping_add(imm as u64);
                            if u32::from(src.0) >= REG_X0 && u32::from(src.0) <= REG_X7 {
                                return Some(final_addr);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

pub fn find_packet_opcode(mem: &Mem, entry: u64) -> Option<u32> {
    let func_a_ptr = fixup_pointer(mem.read_u64(entry + 16).ok()?);
    let vtable1_ptr = scan_for_vtable_ptr(mem, func_a_ptr, Arm64Reg::ARM64_REG_X0 as u32)?;
    let func_b_ptr = fixup_pointer(mem.read_u64(vtable1_ptr + 24).ok()?);
    let vtable2_ptr = scan_for_vtable_ptr(mem, func_b_ptr, Arm64Reg::ARM64_REG_X1 as u32)?;
    let opcode_func = fixup_pointer(mem.read_u64(vtable2_ptr + 16).ok()?);
    scan_return_imm(mem, opcode_func)
}

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

fn get_reg(op: &capstone::arch::arm64::Arm64Operand) -> Option<u32> {
    if let Arm64OperandType::Reg(r) = op.op_type {
        Some(r.0 as u32)
    } else {
        None
    }
}

fn get_imm(op: &capstone::arch::arm64::Arm64Operand) -> Option<i64> {
    if let Arm64OperandType::Imm(i) = op.op_type {
        Some(i)
    } else {
        None
    }
}

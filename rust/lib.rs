//! Fast Decoder for x86-32 and x86-64 and Encoder for x86-64
//!
//! - Decoder: entry [`Instr::decode`], operands can be accessed with [`Instr`]
//!   member functions.
//! - Encoder: no Rust API, yet.
//!
//! `#[no_std]` is supported.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), fadec::Error> {
//! use fadec::{Instr, OpKind, Mode, Reg, RegType};
//! let inst = Instr::decode(&[0x49, 0x90], Mode::X86_64)?;
//! assert_eq!(format!("{}", inst), "xchg r8, rax");
//! assert_eq!(inst.size(), 2); // Decoded 2 bytes.
//! assert_eq!(inst.op_kind(0), OpKind::REG);
//! assert_eq!(inst.op_reg_type(0), RegType::GPL);
//! assert_eq!(inst.op_reg(0), Reg::R8);
//! assert_eq!(inst.op_size(0), 8);
//! assert_eq!(inst.op_kind(1), OpKind::REG);
//! assert_eq!(inst.op_reg_type(1), RegType::GPL);
//! assert_eq!(inst.op_reg(1), Reg::AX);
//! assert_eq!(inst.op_size(1), 8);
//! # Ok(())
//! # }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[repr(C)]
#[derive(Clone, Copy)]
struct Op {
    op_type: u8,
    size: u8,
    reg: u8,
    misc: u8,
}

include!(concat!(env!("OUT_DIR"), "/enums.rs"));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum OpKind {
    /// No operand, end of operand list.
    NONE = 0,
    /// Register operand.
    REG = 1,
    /// Immediate operand.
    IMM = 2,
    /// Memory operand. Note that memory operands are not always dereferenced
    /// (e.g. LEA), index operands are not always general-purpose registers
    /// (e.g. VSIB-encoded gather/scatter instructions), and that the effective
    /// address is not necessarily base+scale*idx+base (e.g. TILELOADD).
    MEM = 3,
    /// RIP-relative jump offset.
    OFF = 4,
    /// Broadcasted memory operand.
    MEMBCST = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum RegType {
    /// Vector (SSE/AVX) register XMMn/YMMn/ZMMn.
    VEC = 0,
    /// Low general purpose register.
    GPL = 1,
    /// High-byte general purpose register (AH/CH/DH/BH).
    GPH = 2,
    /// Segment register (ES/CS/SS/DS/FS/GS).
    SEG = 3,
    /// FPU register ST(n).
    FPU = 4,
    /// MMX register MMn.
    MMX = 5,
    /// TMM register TMMn.
    TMM = 6,
    /// Vector mask (AVX-512) register Kn.
    MASK = 7,
    /// Control Register CRn.
    CR = 9,
    /// Debug Register DRn.
    DR = 10,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum RoundControl {
    /// Round to nearest (even).
    RN = 1,
    /// Round down.
    RD = 3,
    /// Round up.
    RU = 5,
    /// Round to zero (truncate).
    RZ = 7,
    /// Rounding mode as specified in MXCSR.
    MXCSR = 0,
    /// Rounding mode irrelevant, but suppress all exceptions.
    SAE = 6,
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum Reg {
    R0 = 0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    R16,
    R17,
    R18,
    R19,
    R20,
    R21,
    R22,
    R23,
    R24,
    R25,
    R26,
    R27,
    R28,
    R29,
    R30,
    R31,
    R32,
}

impl Reg {
    pub const AL: Reg = Reg::R0;
    pub const CL: Reg = Reg::R1;
    pub const DL: Reg = Reg::R2;
    pub const BL: Reg = Reg::R3;
    pub const AH: Reg = Reg::R4;
    pub const CH: Reg = Reg::R5;
    pub const DH: Reg = Reg::R6;
    pub const BH: Reg = Reg::R7;
    pub const AX: Reg = Reg::R0;
    pub const CX: Reg = Reg::R1;
    pub const DX: Reg = Reg::R2;
    pub const BX: Reg = Reg::R3;
    pub const SP: Reg = Reg::R4;
    pub const BP: Reg = Reg::R5;
    pub const SI: Reg = Reg::R6;
    pub const DI: Reg = Reg::R7;
    pub const ES: Reg = Reg::R0;
    pub const CS: Reg = Reg::R1;
    pub const SS: Reg = Reg::R2;
    pub const DS: Reg = Reg::R3;
    pub const FS: Reg = Reg::R4;
    pub const GS: Reg = Reg::R5;
    // Note: will likely change to R32 due to APX.
    pub const IP: Reg = Reg::R16;
}

impl TryFrom<u8> for Reg {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > 32 {
            Err(())
        } else {
            Ok(unsafe { core::mem::transmute::<u8, Reg>(value) })
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Mode {
    /// Decode for 32-bit mode (CS.L=0, CS.D=1).
    X86_32 = 32,
    /// Decode for 64-bit mode (CS.L=1).
    X86_64 = 64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// The input is an undefined (or unsupported) instruction encoding.
    Undefined,
    /// The input marks the beginning of a possibly valid instruction encoding.
    /// Further bytes could make this a valid encoding.
    Partial,
}

impl core::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Error::Undefined => "undefined opcode",
                Error::Partial => "partial instruction",
            }
        )
    }
}

unsafe extern "C" {
    fn fd_decode(buf: *const u8, len: usize, mode: i32, _: usize, out_instr: *mut Instr) -> i32;
    fn fd_format_abs(instr: *const Instr, addr: u64, buf: *mut u8, len: usize) -> u32;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Instr {
    instr_type: u16,
    flags: u8,
    segment: u8,
    addrsz: u8,
    operandsz: u8,
    size: u8,
    evex: u8,
    ops: [Op; 4],
    disp: i64,
    imm: i64,
    address: i64,
}

impl Instr {
    /// Decode an instruction into an (uninitialized) location. mode specifies
    /// decoding mode as 32 or 64. The return value is the size of the decoded
    /// instruction in bytes. Compared to [`Instr::decode()`], this avoids
    /// copying the Instr struct (which is somewhat expensive to copy
    /// immediately after decoding as copying inhibits store-to-load
    /// forwarding from the bytewise-written struct).
    pub unsafe fn decode_into(buf: &[u8], mode: Mode, out: *mut Instr) -> Result<(), Error> {
        let res = unsafe { fd_decode(buf.as_ptr(), buf.len(), mode as i32, 0, out) };
        match res {
            x if x >= 0 => Ok(()),
            -1 => Err(Error::Undefined),
            -3 => Err(Error::Partial),
            // There's also -2 FD_ERR_INVALID, which can only occur for bad
            // modes -- we avoid this class of errors by having an enum.
            _ => unsafe { core::hint::unreachable_unchecked() },
        }
    }

    /// Decode an instruction. mode specifies decoding mode as 32 or 64.
    pub fn decode(buf: &[u8], mode: Mode) -> Result<Instr, Error> {
        let mut instr = core::mem::MaybeUninit::<Instr>::uninit();
        unsafe { Self::decode_into(buf, mode, instr.as_mut_ptr()).map(|_| instr.assume_init()) }
    }

    /// Gets the type/mnemonic of the instruction.
    pub fn kind(&self) -> InstrKind {
        unsafe { core::mem::transmute::<u16, InstrKind>(self.instr_type) }
    }

    /// Gets the size of the instruction in bytes.
    pub fn size(&self) -> usize {
        self.size.into()
    }

    /// Gets the specified segment override, or [`None`] for default segment.
    pub fn segment(&self) -> Option<Reg> {
        (self.segment & 0x3f).try_into().ok()
    }

    /// Gets the address size attribute of the instruction in bytes.
    pub fn addrsize(&self) -> usize {
        return 1 << self.addrsz;
    }

    /// Gets the logarithmic address size.
    pub fn addrsize_log(&self) -> usize {
        return self.addrsz.into();
    }

    /// Gets the operation width in bytes of the instruction if this is not
    /// encoded in the operands, for example for the string instruction
    /// (e.g. MOVS).
    pub fn opsize(&self) -> usize {
        1 << self.opsize_log()
    }

    /// Gets the logarithmic operation width. Only valid iff
    /// [`Instr::opsize()`] is valid.
    pub fn opsize_log(&self) -> usize {
        self.operandsz.into()
    }

    /// Indicates whether the instruction was encoded with a REP prefix. Needed for:
    /// 1. Handling the instructions MOVS, STOS, LODS, INS and OUTS.
    /// 2. Handling the instructions SCAS and CMPS, for which this means REPZ.
    pub fn has_rep(&self) -> bool {
        self.flags & (1 << 2) != 0
    }

    /// Indicates whether the instruction was encoded with a REPNZ prefix.
    pub fn has_repnz(&self) -> bool {
        self.flags & (1 << 1) != 0
    }

    /// Indicates whether the instruction was encoded with a LOCK prefix.
    pub fn has_lock(&self) -> bool {
        self.flags & (1 << 0) != 0
    }

    /// Indicates whether there is a meaningful 3E prefix used for indirect JMP
    /// (notrack prefix) and conditional branches (hint-taken prefix).
    pub fn has_3e(&self) -> bool {
        self.segment & 0x40 != 0
    }

    /// Gets the type of an operand at the given index. Index must be between 0
    /// and 3 (inclusive).
    pub fn op_kind(&self, idx: usize) -> OpKind {
        unsafe { core::mem::transmute::<u8, OpKind>(self.ops[idx].op_type) }
    }

    /// Gets the size in bytes of an operand. However, there are a few exceptions:
    /// - For some register types, e.g., segment registers or x87 registers,
    ///   the size is zero. (This allows some simplifications internally.)
    /// - On some vector instructions this may be only an approximation of the
    ///   actually needed operand size (that is, an instruction may/must only use
    ///   a smaller part than specified here). The real operand size is always
    ///   fully recoverable in combination with the instruction type.
    pub fn op_size(&self, idx: usize) -> usize {
        1usize << self.ops[idx].size >> 1
    }

    /// Gets the logarithmic size of an operand; see [`Instr::op_size`] for
    /// special cases. The following equality holds:
    /// `op_size() == 1 << (op_size_log().wrapping_add(1)) >> 1`.
    /// Note that typically `op_size() == 1 << op_size_log()` unless a
    /// zero-sized memory operand, FPU register, or mask register is involved.
    pub fn op_size_log(&self, idx: usize) -> usize {
        (self.ops[idx].size as usize).wrapping_sub(1)
    }

    /// Gets the accessed register index of a register operand. Note that /only/
    /// the index is returned, no further interpretation of the index
    /// (which depends on the instruction type) is done. The register type can
    /// be fetched using [`Instr::op_reg_type`], e.g. for distinguishing
    /// high-byte registers. Only valid for [`OpKind::REG`].
    pub fn op_reg(&self, idx: usize) -> Reg {
        assert!(self.op_kind(idx) == OpKind::REG);
        self.ops[idx].reg.try_into().unwrap()
    }

    /// Gets the type of the accessed register. Only valid for [`OpKind::REG`].
    pub fn op_reg_type(&self, idx: usize) -> RegType {
        assert!(self.op_kind(idx) == OpKind::REG);
        unsafe { core::mem::transmute::<u8, RegType>(self.ops[idx].misc) }
    }

    /// Gets the index of the base register from a memory operand. This is the
    /// only case where the 64-bit register RIP can be returned, in which case
    /// the operand also has no scaled index register. Only valid for
    /// [`OpKind::MEM`] and [`OpKind::MEMBCST`].
    pub fn op_base(&self, idx: usize) -> Option<Reg> {
        assert!(self.op_kind(idx) == OpKind::MEM || self.op_kind(idx) == OpKind::MEMBCST);
        self.ops[idx].reg.try_into().ok()
    }

    /// Gets the index of the index register from a memory operand. Only valid
    /// for [`OpKind::MEM`] and [`OpKind::MEMBCST`].
    pub fn op_index(&self, idx: usize) -> Option<Reg> {
        assert!(self.op_kind(idx) == OpKind::MEM || self.op_kind(idx) == OpKind::MEMBCST);
        (self.ops[idx].misc & 0x3f).try_into().ok()
    }

    /// Gets the scale of the index register from a memory operand when
    /// existent. This does /not/ return the scale in an absolute value but
    /// returns the amount of bits the index register is shifted to the left
    /// (i.e. the value in in the range 0-3). The actual scale can be computed
    /// easily using `1 << op_scale()`. Only valid for
    /// [`OpKind::MEM`] and [`OpKind::MEMBCST`] with `op_index() == Some(_)`.
    pub fn op_scale(&self, idx: usize) -> usize {
        assert!(self.op_kind(idx) == OpKind::MEM || self.op_kind(idx) == OpKind::MEMBCST);
        assert!(self.op_index(idx).is_some());
        (self.ops[idx].misc >> 6) as usize
    }

    /// Gets the sign-extended displacement of a memory operand. Only valid for
    /// [`OpKind::MEM`] and [`OpKind::MEMBCST`].
    pub fn op_disp(&self, idx: usize) -> i64 {
        assert!(self.op_kind(idx) == OpKind::MEM || self.op_kind(idx) == OpKind::MEMBCST);
        self.disp
    }

    /// Get memory broadcast source size in bytes. Only valid for
    /// [`OpKind::MEMBCST`].
    pub fn op_bcstsz(&self, idx: usize) -> usize {
        1 << self.op_bcstsz_log(idx)
    }

    /// Get logarithmic memory broadcast source size (1=2B; 2=4B; 3=8B). Only
    /// valid for[`OpKind::MEMBCST`].
    pub fn op_bcstsz_log(&self, idx: usize) -> usize {
        assert!(self.op_kind(idx) == OpKind::MEMBCST);
        self.operandsz.into()
    }

    /// Gets the (sign-extended) encoded constant for an immediate operand. Only
    /// valid for[`OpKind::IMM`] and [`OpKind::OFF`].
    pub fn op_imm(&self, idx: usize) -> i64 {
        assert!(self.op_kind(idx) == OpKind::IMM || self.op_kind(idx) == OpKind::OFF);
        self.imm
    }

    /// Returns the opmask register and zero-masking flag for AVX-512
    /// instructions.
    pub fn mask(&self) -> Option<(Reg, bool)> {
        match self.evex & 7 {
            0 => None,
            x => Some((x.try_into().unwrap(), self.evex & 0x80 != 0)),
        }
    }

    /// Gets the rounding mode for EVEX-encoded instructions.
    pub fn round_control(&self) -> RoundControl {
        unsafe { core::mem::transmute::<u8, RoundControl>((self.evex & 0x70) >> 4) }
    }

    /// Format instruction into a buffer. The buffer should have a capacity of
    /// at least 128 bytes. Returns the number of written bytes, if that number
    /// is smaller than the capacity, or the number of required bytes, in which
    /// case all bytes were written.
    pub unsafe fn format_into(&self, addr: u64, buf: *mut u8, cap: usize) -> usize {
        unsafe { fd_format_abs(self, addr, buf, cap) as usize - 1 }
    }

    /// Format an instruction to a string.
    #[cfg(feature = "std")]
    pub fn format(&self) -> String {
        self.format_abs(0)
    }

    /// Format an instruction to a string, relative to a non-zero base address.
    #[cfg(feature = "std")]
    pub fn format_abs(&self, addr: u64) -> String {
        let mut buf = Vec::<u8>::with_capacity(128);
        unsafe {
            let str_len = self.format_into(addr, buf.as_mut_ptr(), buf.capacity());
            buf.set_len(str_len);
            String::from_utf8_unchecked(buf)
        }
    }
}

impl core::fmt::Display for Instr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buf = [core::mem::MaybeUninit::<u8>::uninit(); 128];
        let len = unsafe { self.format_into(0, buf.as_mut_ptr() as *mut u8, buf.len()) };
        debug_assert!(len < buf.len());
        buf.iter_mut().take(len).for_each(|b| unsafe {
            b.assume_init_mut();
        });
        let formatted = unsafe { core::slice::from_raw_parts(buf.as_ptr() as *const u8, len) };
        f.write_str(unsafe { core::str::from_utf8_unchecked(formatted) })
    }
}

impl core::fmt::Debug for Instr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Instr {{ size: {}, \"{}\" }}", self.size(), self)
    }
}

// Note: every Rust API function should be tested in a way in which all possible
// outputs occur at least once. This is required to catch any case where the C
// accessor macros diverged from this implementation.
#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use super::*;

    #[test]
    fn errors() {
        assert!(Instr::decode(b"\x01\x00", Mode::X86_64).is_ok());
        assert_eq!(Instr::decode(b"\x01", Mode::X86_64).err(), Some(Error::Partial));
        assert_eq!(Instr::decode(b"\x8d\xc0", Mode::X86_64).err(), Some(Error::Undefined));
    }

    #[test]
    fn instr_attrs() -> Result<(), Error> {
        // Size.
        assert_eq!(Instr::decode(b"\x01\x00", Mode::X86_64)?.size(), 2);
        assert_eq!(Instr::decode(b"\x90\x90", Mode::X86_64)?.size(), 1);

        // Segment.
        assert_eq!(Instr::decode(b"\x01\x00", Mode::X86_32)?.segment(), None);
        assert_eq!(Instr::decode(b"\x01\x00", Mode::X86_64)?.segment(), None);
        assert_eq!(Instr::decode(b"\x64\x01\x00", Mode::X86_32)?.segment(), Some(Reg::FS));
        assert_eq!(Instr::decode(b"\x64\x01\x00", Mode::X86_64)?.segment(), Some(Reg::FS));
        assert_eq!(Instr::decode(b"\x65\x01\x00", Mode::X86_32)?.segment(), Some(Reg::GS));
        assert_eq!(Instr::decode(b"\x65\x01\x00", Mode::X86_64)?.segment(), Some(Reg::GS));
        assert_eq!(Instr::decode(b"\x26\x01\x00", Mode::X86_32)?.segment(), Some(Reg::ES));
        assert_eq!(Instr::decode(b"\x26\x01\x00", Mode::X86_64)?.segment(), None);
        assert_eq!(Instr::decode(b"\x2e\x01\x00", Mode::X86_32)?.segment(), Some(Reg::CS));
        assert_eq!(Instr::decode(b"\x2e\x01\x00", Mode::X86_64)?.segment(), None);
        assert_eq!(Instr::decode(b"\x64\x3e\x50", Mode::X86_32)?.segment(), Some(Reg::DS));
        assert_eq!(Instr::decode(b"\x64\x3e\x50", Mode::X86_64)?.segment(), Some(Reg::FS));
        assert_eq!(Instr::decode(b"\x3e\x64\x50", Mode::X86_32)?.segment(), Some(Reg::FS));
        assert_eq!(Instr::decode(b"\x2e\x64\x50", Mode::X86_64)?.segment(), Some(Reg::FS));
        assert_eq!(Instr::decode(b"\x2e\x36\x50", Mode::X86_32)?.segment(), Some(Reg::SS));
        assert_eq!(Instr::decode(b"\x3e\x36\x50", Mode::X86_64)?.segment(), None);
        assert_eq!(Instr::decode(b"\x26\x01\x00", Mode::X86_32)?.has_3e(), false);
        assert_eq!(Instr::decode(b"\x26\x01\x00", Mode::X86_64)?.has_3e(), false);
        assert_eq!(Instr::decode(b"\x3e\x01\x00", Mode::X86_32)?.has_3e(), true);
        assert_eq!(Instr::decode(b"\x3e\x01\x00", Mode::X86_64)?.has_3e(), true);
        assert_eq!(Instr::decode(b"\x64\x3e\x01\x00", Mode::X86_32)?.has_3e(), true);
        assert_eq!(Instr::decode(b"\x64\x3e\x01\x00", Mode::X86_64)?.has_3e(), false);
        assert_eq!(Instr::decode(b"\x3e\x64\x01\x00", Mode::X86_32)?.has_3e(), false);
        assert_eq!(Instr::decode(b"\x3e\x64\x01\x00", Mode::X86_64)?.has_3e(), false);
        assert_eq!(Instr::decode(b"\x3e\x36\x01\x00", Mode::X86_32)?.has_3e(), false);
        assert_eq!(Instr::decode(b"\x3e\x36\x01\x00", Mode::X86_64)?.has_3e(), true);

        // Address size.
        assert_eq!(Instr::decode(b"\x01\x00", Mode::X86_32)?.addrsize(), 4);
        assert_eq!(Instr::decode(b"\x01\x00", Mode::X86_32)?.addrsize_log(), 2);
        assert_eq!(Instr::decode(b"\x01\x00", Mode::X86_64)?.addrsize(), 8);
        assert_eq!(Instr::decode(b"\x01\x00", Mode::X86_64)?.addrsize_log(), 3);
        assert_eq!(Instr::decode(b"\x67\x01\x00", Mode::X86_32)?.addrsize(), 2);
        assert_eq!(Instr::decode(b"\x67\x01\x00", Mode::X86_32)?.addrsize_log(), 1);
        assert_eq!(Instr::decode(b"\x67\x01\x00", Mode::X86_64)?.addrsize(), 4);
        assert_eq!(Instr::decode(b"\x67\x01\x00", Mode::X86_64)?.addrsize_log(), 2);

        // Operand size.
        assert_eq!(Instr::decode(b"\xa4", Mode::X86_32)?.opsize(), 1);
        assert_eq!(Instr::decode(b"\xa4", Mode::X86_32)?.opsize_log(), 0);
        assert_eq!(Instr::decode(b"\xa4", Mode::X86_64)?.opsize(), 1);
        assert_eq!(Instr::decode(b"\xa4", Mode::X86_64)?.opsize_log(), 0);
        assert_eq!(Instr::decode(b"\xa5", Mode::X86_32)?.opsize(), 4);
        assert_eq!(Instr::decode(b"\xa5", Mode::X86_32)?.opsize_log(), 2);
        assert_eq!(Instr::decode(b"\xa5", Mode::X86_64)?.opsize(), 4);
        assert_eq!(Instr::decode(b"\xa5", Mode::X86_64)?.opsize_log(), 2);
        assert_eq!(Instr::decode(b"\x66\xa5", Mode::X86_32)?.opsize(), 2);
        assert_eq!(Instr::decode(b"\x66\xa5", Mode::X86_32)?.opsize_log(), 1);
        assert_eq!(Instr::decode(b"\x66\xa5", Mode::X86_64)?.opsize(), 2);
        assert_eq!(Instr::decode(b"\x66\xa5", Mode::X86_64)?.opsize_log(), 1);
        assert_eq!(Instr::decode(b"\x48\xa5", Mode::X86_64)?.opsize(), 8);
        assert_eq!(Instr::decode(b"\x48\xa5", Mode::X86_64)?.opsize_log(), 3);

        // Prefixes: REP/REPNZ/LOCK.
        assert_eq!(Instr::decode(b"\xa4", Mode::X86_64)?.has_rep(), false);
        assert_eq!(Instr::decode(b"\xa4", Mode::X86_64)?.has_repnz(), false);
        assert_eq!(Instr::decode(b"\xf3\xa4", Mode::X86_64)?.has_rep(), true);
        assert_eq!(Instr::decode(b"\xf3\xa4", Mode::X86_64)?.has_repnz(), false);
        assert_eq!(Instr::decode(b"\xf2\xa4", Mode::X86_64)?.has_rep(), false);
        assert_eq!(Instr::decode(b"\xf2\xa4", Mode::X86_64)?.has_repnz(), true);
        assert_eq!(Instr::decode(b"\xae", Mode::X86_64)?.has_rep(), false);
        assert_eq!(Instr::decode(b"\xae", Mode::X86_64)?.has_repnz(), false);
        assert_eq!(Instr::decode(b"\xf3\xae", Mode::X86_64)?.has_rep(), true);
        assert_eq!(Instr::decode(b"\xf3\xae", Mode::X86_64)?.has_repnz(), false);
        assert_eq!(Instr::decode(b"\xf2\xae", Mode::X86_64)?.has_rep(), false);
        assert_eq!(Instr::decode(b"\xf2\xae", Mode::X86_64)?.has_repnz(), true);
        assert_eq!(Instr::decode(b"\xff\x00", Mode::X86_64)?.has_lock(), false);
        assert_eq!(Instr::decode(b"\xf0\xff\x00", Mode::X86_64)?.has_lock(), true);

        // Mask.
        assert_eq!(Instr::decode(b"\x62\xf1\x74\x18\x58\x40\xff", Mode::X86_64)?.mask(), None);
        assert_eq!(Instr::decode(b"\x62\xf1\x74\x1a\x58\x40\xff", Mode::X86_64)?.mask(), Some((Reg::R2, false)));
        assert_eq!(Instr::decode(b"\x62\xf1\x74\x9a\x58\x40\xff", Mode::X86_64)?.mask(), Some((Reg::R2, true)));

        // Round control
        assert_eq!(Instr::decode(b"\x62\xf1\x74\x08\x58\xc2", Mode::X86_64)?.round_control(), RoundControl::MXCSR);
        assert_eq!(Instr::decode(b"\x62\xf1\x74\x18\x58\xc2", Mode::X86_64)?.round_control(), RoundControl::RN);
        assert_eq!(Instr::decode(b"\x62\xf1\x74\x38\x58\xc2", Mode::X86_64)?.round_control(), RoundControl::RD);
        assert_eq!(Instr::decode(b"\x62\xf1\x74\x58\x58\xc2", Mode::X86_64)?.round_control(), RoundControl::RU);
        assert_eq!(Instr::decode(b"\x62\xf1\x74\x78\x58\xc2", Mode::X86_64)?.round_control(), RoundControl::RZ);
        assert_eq!(Instr::decode(b"\x62\xf1\x7e\x18\x2c\xc0", Mode::X86_64)?.round_control(), RoundControl::SAE);

        Ok(())
    }

    #[test]
    fn op_reg() {
        let chk = |buf: &[u8], idx: usize, reg: Reg, reg_type: RegType, size: usize| {
            let inst = Instr::decode(buf, Mode::X86_64).expect("decode failure");
            assert_eq!(inst.op_kind(idx), OpKind::REG);
            assert_eq!(inst.op_reg(idx), reg);
            assert_eq!(inst.op_reg_type(idx), reg_type);
            assert_eq!(inst.op_size(idx), size);
        };
        chk(b"\xb0\x00", 0, Reg::AX, RegType::GPL, 1);
        chk(b"\xb4\x00", 0, Reg::AH, RegType::GPH, 1);
        chk(b"\x40\xb4\x00", 0, Reg::SP, RegType::GPL, 1);
        chk(b"\x66\xb9\x00\x00", 0, Reg::CX, RegType::GPL, 2);
        chk(b"\xba\x00\x00\x00\x00", 0, Reg::DX, RegType::GPL, 4);
        chk(b"\x48\xbb\x00\x00\x00\x00\x00\x00\x00\x00", 0, Reg::BX, RegType::GPL, 8);
        chk(b"\x8c\xc0", 0, Reg::AX, RegType::GPL, 2);
        chk(b"\x8c\xc0", 1, Reg::ES, RegType::SEG, 2);
        chk(b"\x8e\xc0", 0, Reg::ES, RegType::SEG, 2);
        chk(b"\x8e\xc0", 1, Reg::AX, RegType::GPL, 2);
        chk(b"\xd8\xc1", 0, Reg::R0, RegType::FPU, 0);
        chk(b"\xd8\xc1", 1, Reg::R1, RegType::FPU, 0);
        chk(b"\x0f\x70\xc0\x85", 0, Reg::R0, RegType::MMX, 8);
        chk(b"\x0f\x70\xc7\x85", 1, Reg::R7, RegType::MMX, 8);
        chk(b"\xc4\xe2\x68\x5e\xc8", 0, Reg::R1, RegType::TMM, 0);
        chk(b"\xc4\xe2\x68\x5e\xc8", 1, Reg::R0, RegType::TMM, 0);
        chk(b"\xc4\xe2\x68\x5e\xc8", 2, Reg::R2, RegType::TMM, 0);
        chk(b"\xc5\xed\x41\xcb", 0, Reg::R1, RegType::MASK, 1);
        chk(b"\xc5\xed\x41\xcb", 1, Reg::R2, RegType::MASK, 1);
        chk(b"\xc5\xed\x41\xcb", 2, Reg::R3, RegType::MASK, 1);
        chk(b"\x45\x0f\x20\x00", 1, Reg::R8, RegType::CR, 8);
        chk(b"\x0f\x21\xd0", 1, Reg::R2, RegType::DR, 8);
    }

    #[test]
    fn op_imm() {
        let chk = |buf: &[u8], idx: usize, kind: OpKind, imm: i64, size: usize| {
            let inst = Instr::decode(buf, Mode::X86_64).expect("decode failure");
            assert_eq!(inst.op_kind(idx), kind);
            assert_eq!(inst.op_imm(idx), imm);
            assert_eq!(inst.op_size(idx), size);
        };
        chk(b"\xcd\x7f", 0, OpKind::IMM, 0x7f, 1);
        chk(b"\xcd\x80", 0, OpKind::IMM, -0x80, 1);
        chk(b"\x48\xb8\xf0\xf0\xab\xff\x00\x12\x12\xcd", 1, OpKind::IMM, 0xcd121200ffabf0f0u64 as i64, 8);
        chk(b"\x70\xfe", 0, OpKind::OFF, -0x2, 8);
        chk(b"\x70\x04", 0, OpKind::OFF, 0x4, 8);
    }

    #[test]
    fn op_mem() {
        let chk = |buf: &[u8],
                   idx: usize,
                   base: Option<Reg>,
                   scale: usize,
                   index: Option<Reg>,
                   disp: i64,
                   size: usize| {
            let inst = Instr::decode(buf, Mode::X86_64).expect("decode failure");
            assert_eq!(inst.op_kind(idx), OpKind::MEM);
            assert_eq!(inst.op_base(idx), base);
            assert_eq!(inst.op_index(idx), index);
            if index.is_some() {
                assert_eq!(inst.op_scale(idx), scale);
            }
            assert_eq!(inst.op_disp(idx), disp);
            assert_eq!(inst.op_size(idx), size);
        };
        chk(b"\x0f\xae\x00", 0, Some(Reg::AX), 0, None, 0, 0);
        chk(b"\x01\x07", 0, Some(Reg::DI), 0, None, 0, 4);
        chk(b"\x01\x04\x25\x01\x00\x00\x00", 0, None, 0, None, 0x1, 4);
        chk(b"\x01\x05\xff\xff\xff\xff", 0, Some(Reg::IP), 0, None, -0x1, 4);
        chk(b"\x01\x84\x05\x11\x22\x33\x44", 0, Some(Reg::BP), 0, Some(Reg::AX), 0x44332211, 4);
        chk(b"\x01\x84\x45\x11\x22\x33\x44", 0, Some(Reg::BP), 1, Some(Reg::AX), 0x44332211, 4);
        chk(b"\x01\x84\x85\x11\x22\x33\x44", 0, Some(Reg::BP), 2, Some(Reg::AX), 0x44332211, 4);
        chk(b"\x01\x84\xc5\x11\x22\x33\x44", 0, Some(Reg::BP), 3, Some(Reg::AX), 0x44332211, 4);
        chk(b"\x62\xf2\x7d\x0a\xa2\x0c\xe7", 0, Some(Reg::DI), 3, Some(Reg::R4), 0, 4); // VSIB
        chk(b"\x62\xb2\x7d\x02\xa2\x0c\xe7", 0, Some(Reg::DI), 3, Some(Reg::R28), 0, 4); // VSIB
    }

    #[test]
    fn op_membcst() {
        let chk = |buf: &[u8],
                   idx: usize,
                   base: Option<Reg>,
                   scale: usize,
                   index: Option<Reg>,
                   disp: i64,
                   bcstsz: usize,
                   size: usize| {
            let inst = Instr::decode(buf, Mode::X86_64).expect("decode failure");
            assert_eq!(inst.op_kind(idx), OpKind::MEMBCST);
            assert_eq!(inst.op_base(idx), base);
            assert_eq!(inst.op_index(idx), index);
            if index.is_some() {
                assert_eq!(inst.op_scale(idx), scale);
            }
            assert_eq!(inst.op_disp(idx), disp);
            assert_eq!(inst.op_bcstsz(idx), bcstsz);
            assert_eq!(inst.op_size(idx), size);
        };
        chk(b"\x62\xf1\x74\x18\x58\x00", 2, Some(Reg::AX), 0, None, 0, 4, 16);
        chk(b"\x62\xf1\x74\x38\x58\x00", 2, Some(Reg::AX), 0, None, 0, 4, 32);
        chk(b"\x62\xf1\x74\x58\x58\x00", 2, Some(Reg::AX), 0, None, 0, 4, 64);
        chk(b"\x62\xf1\xf5\x18\x58\x00", 2, Some(Reg::AX), 0, None, 0, 8, 16);
        chk(b"\x62\xf1\xf5\x38\x58\x00", 2, Some(Reg::AX), 0, None, 0, 8, 32);
        chk(b"\x62\xf1\xf5\x58\x58\x00", 2, Some(Reg::AX), 0, None, 0, 8, 64);
        chk(b"\x62\xf5\x74\x18\x5c\x42\x01", 2, Some(Reg::DX), 0, None, 2, 2, 16);
        chk(b"\x62\xf5\x74\x38\x5c\x42\x01", 2, Some(Reg::DX), 0, None, 2, 2, 32);
        chk(b"\x62\xf5\x74\x58\x5c\x42\x01", 2, Some(Reg::DX), 0, None, 2, 2, 64);
    }
}

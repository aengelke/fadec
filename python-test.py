import fadec

nop = fadec.decode64(b"\x90")
assert str(nop) == "nop"
assert repr(nop) == '<fadec.Inst "nop",size=1>'
assert nop.size == 1
assert nop.type == fadec.Inst.NOP
assert nop.addrsize == 8
assert nop.has_rep is False
assert nop.has_repnz is False
assert nop.has_lock is False
assert nop.has_3e is False
assert nop.maskreg is None
assert nop.ops == ()

add_rr = fadec.decode64(b"\x01\xc1")
assert str(add_rr) == "add ecx, eax"
assert repr(add_rr) == '<fadec.Inst "add ecx, eax",size=2>'
assert add_rr.size == 2
assert add_rr.type == fadec.Inst.ADD
assert len(add_rr.ops) == 2
assert repr(add_rr.ops[0]) == '<fadec.Op "add ecx, eax",idx=0>'
assert add_rr.ops[0].is_reg
assert not add_rr.ops[0].is_imm
assert not add_rr.ops[0].is_mem
assert not add_rr.ops[0].is_off
assert not add_rr.ops[0].is_membcst
assert add_rr.ops[0].size == 4
assert str(add_rr.ops[0].reg) == "ecx"
assert repr(add_rr.ops[0].reg) == f'<fadec.Reg "ecx",size=2,type={fadec.Reg.GPL},idx=1>'
assert add_rr.ops[0].reg.sizelg == 2
assert add_rr.ops[0].reg.type == fadec.Reg.GPL
assert add_rr.ops[0].reg.idx == 1
assert repr(add_rr.ops[1]) == '<fadec.Op "add ecx, eax",idx=1>'
assert add_rr.ops[1].is_reg
assert add_rr.ops[1].size == 4
assert str(add_rr.ops[1].reg) == "eax"
assert repr(add_rr.ops[1].reg) == f'<fadec.Reg "eax",size=2,type={fadec.Reg.GPL},idx=0>'
assert add_rr.ops[1].reg.sizelg == 2
assert add_rr.ops[1].reg.type == fadec.Reg.GPL
assert add_rr.ops[1].reg.idx == 0

mov_mi = fadec.decode64(b"\x66\xc7\x00\x42\x00")
assert str(mov_mi) == "mov word ptr [rax], 0x42"
assert mov_mi.size == 5
assert mov_mi.type == fadec.Inst.MOV
assert len(mov_mi.ops) == 2
assert mov_mi.ops[0].size == 2
assert mov_mi.ops[0].is_mem
assert str(mov_mi.ops[0].base) == "rax"
assert mov_mi.ops[0].index is None
assert mov_mi.ops[0].disp == 0
assert mov_mi.ops[1].size == 2
assert mov_mi.ops[1].is_imm
assert mov_mi.ops[1].imm == 0x42

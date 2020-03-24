"""GameBoy (LR35902) Disassember."""

import disassembler as dis


class GBRegister(dis.Register):
    """GB register set."""

    A = 0
    F = 1
    B = 2
    C = 3
    D = 4
    E = 5
    H = 6
    L = 7
    AF = 8
    BC = 9
    DE = 10
    HL = 11
    SP = 12
    PC = 13


class GBToken(dis.Token):
    """GB tokens."""

    op0_8 = 0, 7
    op6_2 = 6, 7
    dRegPair4_2 = 4, 5
    sRegPair4_2 = 4, 5
    qRegPair4_2 = 4, 5
    reg3_3 = 3, 5
    bits3_3 = 3, 5
    bits0_4 = 0, 3
    reg0_3 = 0, 2
    bits0_3 = 0, 2
    imm8 = 0, 7
    sign8 = 7, 7
    simm8 = 0, 7, True
    imm16 = 0, 15


class GBAttachment(dis.Attachment):
    """GB attachments."""

    _8bit_registers = {0: GBRegister.B, 1: GBRegister.C, 2: GBRegister.D, 3: GBRegister.E,
                       4: GBRegister.H,
                       5: GBRegister.L, 7: GBRegister.A}
    _16bit_registers = {0: GBRegister.BC, 1: GBRegister.DE, 2: GBRegister.HL, 3: GBRegister.SP}
    _push_and_pop_registers = {0: GBRegister.BC, 1: GBRegister.DE, 2: GBRegister.HL,
                               3: GBRegister.AF}

    ATTACHMENTS = {
        GBToken.reg0_3: _8bit_registers,
        GBToken.reg3_3: _8bit_registers,
        GBToken.sRegPair4_2: _16bit_registers,
        GBToken.dRegPair4_2: _16bit_registers,
        GBToken.qRegPair4_2: _push_and_pop_registers,
    }


# Instruction Set
GB_COOKBOOK = [
    dis.Recipe('LD {dst},{src}', 4, [dis.Match(GBToken.op6_2, 0x1),
                                     GBAttachment(GBToken.reg3_3, 'dst'),
                                     GBAttachment(GBToken.reg0_3, 'src')]),
    dis.Recipe('LD {dst},{imm}', 8, [dis.Match(GBToken.op6_2, 0x0),
                                     GBAttachment(GBToken.reg3_3, 'dst'),
                                     dis.Match(GBToken.bits0_3, 0x6)],
               [dis.Immediate(GBToken.imm8, 'imm')])
]

if __name__ == '__main__':
    gb_dis = dis.Disassembler(GB_COOKBOOK)

    print(gb_dis.disassemble_one(b'\x53'))
    print(gb_dis.disassemble_one(b'\x06\x45'))
    print(list(gb_dis.disassembly(b'\x06\x45\x53')))
    print(gb_dis.disassemble(b'\x06\x45\x53', 10))
    print(list(gb_dis.disassembly(b'\x06\x45\x53\x06')))
    print(gb_dis.disassemble(b'\x06\x45\x53\x06', 10))

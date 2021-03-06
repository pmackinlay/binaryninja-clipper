import struct
import enum

from binaryninja.architecture import Architecture
from binaryninja.lowlevelil import LowLevelILLabel, ILRegister, LLIL_TEMP
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.log import log_error, log_warn
from binaryninja.enums import (BranchType, InstructionTextTokenType, LowLevelILOperation, LowLevelILFlagCondition, FlagRole)

class OperandType(enum.IntEnum):
    """
    CLIPPER instruction operand types
    """
    R1    = 1 # source integer register
    R2    = 2 # destination integer register
    F1    = 3 # source floating point register
    F2    = 4 # destination floating point register
    QUICK = 5 # 4 bit immediate value
    SR    = 6 # special register
    IMM   = 7 # 16 or 32 bit immediate value
    ADDR  = 8 # address using any of 9 addressing modes

class AddressMode(enum.IntEnum):
    """
    CLIPPER cpu addressing modes
    """
    RELATIVE = 0x00 # relative
    PC32     = 0x10 # pc relative with 32 bit displacement
    ABS32    = 0x30 # 32 bit absolute
    REL32    = 0x60 # relative with 32 bit displacement
    PC16     = 0x90 # pc relative with 16 bit displacement
    REL12    = 0xa0 # relative with 12 bit displacement
    ABS16    = 0xb0 # 16 bit absolute
    PCX      = 0xd0 # pc indexed
    RELX     = 0xe0 # relative indexed

# CLIPPER register names
IReg  = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'fp', 'sp']
FPReg = ['f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'f10', 'f11', 'f12', 'f13', 'f14', 'f15']
SReg  = ['psw', 'ssw', None, 'sswf']

# CLIPPER condition code names
ConditionCodeStrings = ['', 'clt', 'cle', 'ceq', 'cgt', 'cge', 'cne', 'cltu', 'cleu', 'cgtu', 'cgeu', 'v', 'nv', 'n', 'nn', 'fn']

# CLIPPER condition code names are based on a reversed operand sequence, so
# they are inverted here to give the correct/natural representation.
ConditionCodeMapping = [
    None,
    LowLevelILFlagCondition.LLFC_SGT,
    LowLevelILFlagCondition.LLFC_SGE,
    LowLevelILFlagCondition.LLFC_E,
    LowLevelILFlagCondition.LLFC_SLT,
    LowLevelILFlagCondition.LLFC_SLE,
    LowLevelILFlagCondition.LLFC_NE,
    LowLevelILFlagCondition.LLFC_UGT,
    LowLevelILFlagCondition.LLFC_UGE,
    LowLevelILFlagCondition.LLFC_ULT,
    LowLevelILFlagCondition.LLFC_ULE,
    LowLevelILFlagCondition.LLFC_O,
    LowLevelILFlagCondition.LLFC_NO,
    LowLevelILFlagCondition.LLFC_NEG,
    LowLevelILFlagCondition.LLFC_POS,
    None
]

"""
CLIPPER instruction decode functions, returning:
  length - total length of instruction operand and opcodes in bytes
  r1 - instruction R1 field
  r2 - instruction R2 field
  rx - instruction with address RX field
  constant - instruction immediate, quick, control or displacement integer value
  mode - instruction with address addressing mode
"""
def register(parcel0, data):
    return 2, (parcel0 & 0xf0) >> 4, parcel0 & 0xf, None, None, None

def control(parcel0, data):
    return 2, None, None, None, parcel0 & 0xff, None

def macro(parcel0, data):
    parcel1 = struct.unpack('<H', data[2:4])[0]
    return 4, (parcel1 & 0xf0) >> 4, parcel1 & 0xf, None, None, None

def imm_fixed16(parcel0, data):
    return 4, None, parcel0 & 0xf, None, struct.unpack('<h', data[2:4])[0], None

def imm_variable(parcel0, data):
    if parcel0 & 0x80:
        return 4, None, parcel0 & 0xf, None, struct.unpack('<h', data[2:4])[0], None
    else:
        return 6, None, parcel0 & 0xf, None, struct.unpack('<l', data[2:6])[0], None

def address(parcel0, data):
    if parcel0 & 0x100:
        if parcel0 & 0xf0 == AddressMode.PC32:
            # pc relative with 32 bit displacement
            return 6, None, parcel0 & 0xf, None, struct.unpack('<l', data[2:6])[0], AddressMode.PC32
        elif parcel0 & 0xf0 == AddressMode.ABS32:
            # 32 bit absolute
            return 6, None, parcel0 & 0xf, None, struct.unpack('<L', data[2:6])[0], AddressMode.ABS32
        elif parcel0 & 0xf0 == AddressMode.REL32:
            # relative with 32 bit displacement
            parcel1 = struct.unpack('<H', data[2:4])[0]
            return 8, parcel0 & 0xf, parcel1 & 0xf, None, struct.unpack('<l', data[4:8])[0], AddressMode.REL32
        elif parcel0 & 0xf0 == AddressMode.PC16:
            # pc relative with 16 bit displacement
            return 4, None, parcel0 & 0xf, None, struct.unpack('<h', data[2:4])[0], AddressMode.PC16
        elif parcel0 & 0xf0 == AddressMode.REL12:
            # relative with 12 bit displacement
            parcel1 = struct.unpack('<h', data[2:4])[0]
            return 4, parcel0 & 0xf, parcel1 & 0xf, None, parcel1 >> 4, AddressMode.REL12
        elif parcel0 & 0xf0 == AddressMode.ABS16:
            # 16 bit absolute
            return 4, None, parcel0 & 0xf, None, struct.unpack('<H', data[2:4])[0], AddressMode.ABS16
        elif parcel0 & 0xf0 == AddressMode.PCX:
            # pc indexed
            parcel1 = struct.unpack('<h', data[2:4])[0]
            return 4, None, parcel1 & 0xf, (parcel1 & 0xf0) >> 4, None, AddressMode.PCX
        elif parcel0 & 0xf0 == AddressMode.RELX:
            # relative indexed
            parcel1 = struct.unpack('<h', data[2:4])[0]
            return 4, parcel0 & 0xf, parcel1 & 0xf, (parcel1 & 0xf0) >> 4, None, AddressMode.RELX
        else:
            return None, None, None, None, None, None
    else:
        return 2, (parcel0 & 0xf0) >> 4, parcel0 & 0xf, None, None, AddressMode.RELATIVE

# CLIPPER standard instruction disassembly and decode map
Instructions = {
    0x00:['noop', control, []],

    0x10:['movwp', register, [OperandType.R2, OperandType.SR]],
    0x11:['movpw', register, [OperandType.SR, OperandType.R2]],
    0x12:['calls', control, [OperandType.IMM]],
    0x13:['ret', register, [OperandType.R2]],
    0x14:['pushw', register, [OperandType.R2, OperandType.R1]],
    0x16:['popw', register, [OperandType.R1, OperandType.R2]],

    0x20:['adds', register, [OperandType.F1, OperandType.F2]],
    0x21:['subs', register, [OperandType.F1, OperandType.F2]],
    0x22:['addd', register, [OperandType.F1, OperandType.F2]],
    0x23:['subd', register, [OperandType.F1, OperandType.F2]],
    0x24:['movs', register, [OperandType.F1, OperandType.F2]],
    0x25:['cmps', register, [OperandType.F1, OperandType.F2]],
    0x26:['movd', register, [OperandType.F1, OperandType.F2]],
    0x27:['cmpd', register, [OperandType.F1, OperandType.F2]],
    0x28:['muls', register, [OperandType.F1, OperandType.F2]],
    0x29:['divs', register, [OperandType.F1, OperandType.F2]],
    0x2a:['muld', register, [OperandType.F1, OperandType.F2]],
    0x2b:['divd', register, [OperandType.F1, OperandType.F2]],
    0x2c:['movsw', register, [OperandType.F1, OperandType.R2]],
    0x2d:['movws', register, [OperandType.R1, OperandType.F2]],
    0x2e:['movdl', register, [OperandType.F1, OperandType.R2]],
    0x2f:['movld', register, [OperandType.R1, OperandType.F2]],

    0x30:['shaw', register, [OperandType.R1, OperandType.R2]],
    0x31:['shal', register, [OperandType.R1, OperandType.R2]],
    0x32:['shlw', register, [OperandType.R1, OperandType.R2]],
    0x33:['shll', register, [OperandType.R1, OperandType.R2]],
    0x34:['rotw', register, [OperandType.R1, OperandType.R2]],
    0x35:['rotl', register, [OperandType.R1, OperandType.R2]],
    0x38:['shai', imm_fixed16, [OperandType.IMM, OperandType.R2]],
    0x39:['shali', imm_fixed16, [OperandType.IMM, OperandType.R2]],
    0x3a:['shli', imm_fixed16, [OperandType.IMM, OperandType.R2]],
    0x3b:['shlli', imm_fixed16, [OperandType.IMM, OperandType.R2]],
    0x3c:['roti', imm_fixed16, [OperandType.IMM, OperandType.R2]],
    0x3d:['rotli', imm_fixed16, [OperandType.IMM, OperandType.R2]],

    0x44:['call', address, [OperandType.R2, OperandType.ADDR]],
	0x45:['call', address, [OperandType.R2, OperandType.ADDR]],
	0x46:['loadd2', address, [OperandType.ADDR, OperandType.F2]],
	0x47:['loadd2', address, [OperandType.ADDR, OperandType.F2]],
	0x48:['b*', address, [OperandType.ADDR]],
	0x49:['b*', address, [OperandType.ADDR]],

    # The following instructions all require two branch delay slots.
    # See: https://github.com/Vector35/binaryninja-api/issues/866
    # 0x4a:['cdb', address],
    # 0x4b:['cdb', address],
    0x4c:['cdbeq', address, [OperandType.R2, OperandType.ADDR]],
    0x4d:['cdbeq', address, [OperandType.R2, OperandType.ADDR]],
    0x4e:['cdbne', address, [OperandType.R2, OperandType.ADDR]],
    0x4f:['cdbne', address, [OperandType.R2, OperandType.ADDR]], #59e726

    0x50:['db*', address, [OperandType.ADDR]],
    0x51:['db*', address, [OperandType.ADDR]],

    0x60:['loadw', address, [OperandType.ADDR, OperandType.R2]],
	0x61:['loadw', address, [OperandType.ADDR, OperandType.R2]],
	0x62:['loada', address, [OperandType.ADDR, OperandType.R2]],
	0x63:['loada', address, [OperandType.ADDR, OperandType.R2]],
	0x64:['loads', address, [OperandType.ADDR, OperandType.F2]],
	0x65:['loads', address, [OperandType.ADDR, OperandType.F2]],
	0x66:['loadd', address, [OperandType.ADDR, OperandType.F2]],
	0x67:['loadd', address, [OperandType.ADDR, OperandType.F2]],
	0x68:['loadb', address, [OperandType.ADDR, OperandType.R2]],
	0x69:['loadb', address, [OperandType.ADDR, OperandType.R2]],
	0x6a:['loadbu', address, [OperandType.ADDR, OperandType.R2]],
	0x6b:['loadbu', address, [OperandType.ADDR, OperandType.R2]],
	0x6c:['loadh', address, [OperandType.ADDR, OperandType.R2]],
	0x6d:['loadh', address, [OperandType.ADDR, OperandType.R2]],
	0x6e:['loadhu', address, [OperandType.ADDR, OperandType.R2]],
	0x6f:['loadhu', address, [OperandType.ADDR, OperandType.R2]],

    0x70:['storw', address, [OperandType.R2, OperandType.ADDR]],
	0x71:['storw', address, [OperandType.R2, OperandType.ADDR]],
	0x72:['tsts', address, [OperandType.ADDR, OperandType.R2]],
	0x73:['tsts', address, [OperandType.ADDR, OperandType.R2]],
	0x74:['stors', address, [OperandType.F2, OperandType.ADDR]],
	0x75:['stors', address, [OperandType.F2, OperandType.ADDR]],
	0x76:['stord', address, [OperandType.F2, OperandType.ADDR]],
	0x77:['stord', address, [OperandType.F2, OperandType.ADDR]],
	0x78:['storb', address, [OperandType.R2, OperandType.ADDR]],
	0x79:['storb', address, [OperandType.R2, OperandType.ADDR]],
	0x7c:['storh', address, [OperandType.R2, OperandType.ADDR]],
	0x7d:['storh', address, [OperandType.R2, OperandType.ADDR]],

    0x80:['addw', register, [OperandType.R1, OperandType.R2]],
	0x82:['addq', register, [OperandType.QUICK, OperandType.R2]],
	0x83:['addi', imm_variable, [OperandType.IMM, OperandType.R2]],
	0x84:['movw', register, [OperandType.R1, OperandType.R2]],
	0x86:['loadq', register, [OperandType.QUICK, OperandType.R2]],
	0x87:['loadi', imm_variable, [OperandType.IMM, OperandType.R2]],
	0x88:['andw', register, [OperandType.R1, OperandType.R2]],
	0x8b:['andi', imm_variable, [OperandType.IMM, OperandType.R2]],
	0x8c:['orw', register, [OperandType.R1, OperandType.R2]],
	0x8f:['ori', imm_variable, [OperandType.IMM, OperandType.R2]],

    0x90:['addwc', register, [OperandType.R1, OperandType.R2]],
	0x91:['subwc', register, [OperandType.R1, OperandType.R2]],
	0x93:['negw', register, [OperandType.R1, OperandType.R2]],
	0x98:['mulw', register, [OperandType.R1, OperandType.R2]],
	0x99:['mulwx', register, [OperandType.R1, OperandType.R2]],
	0x9a:['mulwu', register, [OperandType.R1, OperandType.R2]],
	0x9b:['mulwux', register, [OperandType.R1, OperandType.R2]],
	0x9c:['divw', register, [OperandType.R1, OperandType.R2]],
	0x9d:['modw', register, [OperandType.R1, OperandType.R2]],
	0x9e:['divwu', register, [OperandType.R1, OperandType.R2]],
	0x9f:['modwu', register, [OperandType.R1, OperandType.R2]],

    0xa0:['subw', register, [OperandType.R1, OperandType.R2]],
	0xa2:['subq', register, [OperandType.QUICK, OperandType.R2]],
	0xa3:['subi', imm_variable, [OperandType.IMM, OperandType.R2]],
	0xa4:['cmpw', register, [OperandType.R1, OperandType.R2]],
	0xa6:['cmpq', register, [OperandType.QUICK, OperandType.R2]],
	0xa7:['cmpi', imm_variable, [OperandType.IMM, OperandType.R2]],
	0xa8:['xorw', register, [OperandType.R1, OperandType.R2]],
	0xab:['xori', imm_variable, [OperandType.IMM, OperandType.R2]],
	0xac:['notw', register, [OperandType.R1, OperandType.R2]],
	0xae:['notq', register, [OperandType.QUICK, OperandType.R2]],

    0xb0:['abss', register, [OperandType.F1, OperandType.F2]],
    0xb2:['absd', register, [OperandType.F1, OperandType.F2]],

    0xbc:['waitd', register, []],

    0xc0:['s*', register, [OperandType.R1]]
}

# CLIPPER macro instruction disassembly and decode map
MacroInstructions = {
    0xb400:['savew0', macro, []],
	0xb401:['savew1', macro, []],
	0xb402:['savew2', macro, []],
	0xb403:['savew3', macro, []],
	0xb404:['savew4', macro, []],
	0xb405:['savew5', macro, []],
	0xb406:['savew6', macro, []],
	0xb407:['savew7', macro, []],
	0xb408:['savew8', macro, []],
	0xb409:['savew9', macro, []],
	0xb40a:['savew10', macro, []],
	0xb40b:['savew11', macro, []],
	0xb40c:['savew12', macro, []],
	0xb40d:['movc', macro, []],
	0xb40e:['initc', macro, []],
	0xb40f:['cmpc', macro, []],

    0xb410:['restw0', macro, []],
	0xb411:['restw1', macro, []],
	0xb412:['restw2', macro, []],
	0xb413:['restw3', macro, []],
	0xb414:['restw4', macro, []],
	0xb415:['restw5', macro, []],
	0xb416:['restw6', macro, []],
	0xb417:['restw7', macro, []],
	0xb418:['restw8', macro, []],
	0xb419:['restw9', macro, []],
	0xb41a:['restw10', macro, []],
	0xb41b:['restw11', macro, []],
	0xb41c:['restw12', macro, []],

    0xb420:['saved0', macro, []],
	0xb421:['saved1', macro, []],
	0xb422:['saved2', macro, []],
	0xb423:['saved3', macro, []],
	0xb424:['saved4', macro, []],
	0xb425:['saved5', macro, []],
	0xb426:['saved6', macro, []],
	0xb427:['saved7', macro, []],
	0xb428:['restd0', macro, []],
	0xb429:['restd1', macro, []],
	0xb42a:['restd2', macro, []],
	0xb42b:['restd3', macro, []],
	0xb42c:['restd4', macro, []],
	0xb42d:['restd5', macro, []],
	0xb42e:['restd6', macro, []],
	0xb42f:['restd7', macro, []],

    0xb430:['cnvsw', macro, [OperandType.F1, OperandType.R2]],
	0xb431:['cnvrsw', macro, [OperandType.F1, OperandType.R2]],
	0xb432:['cnvtsw', macro, [OperandType.F1, OperandType.R2]],
	0xb433:['cnvws', macro, [OperandType.R1, OperandType.F2]],
	0xb434:['cnvdw', macro, [OperandType.F1, OperandType.R2]],
	0xb435:['cnvrdw', macro, [OperandType.F1, OperandType.R2]],
	0xb436:['cnvtdw', macro, [OperandType.F1, OperandType.R2]],
	0xb437:['cnvwd', macro, [OperandType.R1, OperandType.F2]],
	0xb438:['cnvsd', macro, [OperandType.F1, OperandType.F2]],
	0xb439:['cnvds', macro, [OperandType.F1, OperandType.F2]],
	0xb43a:['negs', macro, [OperandType.F1, OperandType.F2]],
	0xb43b:['negd', macro, [OperandType.F1, OperandType.F2]],
	0xb43c:['scalbs', macro, [OperandType.R1, OperandType.F2]],
	0xb43d:['scalbd', macro, [OperandType.R1, OperandType.F2]],
	0xb43e:['trapfn', macro, []],
	0xb43f:['loadfs', macro, [OperandType.R1, OperandType.F2]],

	#0xb444:['cnvxsw', macro, [OperandType.F1, OperandType.F2]],
	#0xb446:['cnvxdw', macro, [OperandType.F1, OperandType.F2]],

    0xb600:['movus', macro, [OperandType.R1, OperandType.R2]],
    0xb601:['movsu', macro, [OperandType.R1, OperandType.R2]],
    0xb602:['saveur', macro, [OperandType.R1]],
    0xb603:['restur', macro, [OperandType.R1]],
    0xb604:['reti', macro, [OperandType.R1]],
    0xb605:['wait', macro, []],
    #0xb607:['loadts', macro, [OperandType.R1, OperandType.R2]]
}

def shift_helper(il, r1, r2, positive, negative, long, length):
    """
    Generate ILIL for rotw/shaw/shlw instructions.
    """
    left = LowLevelILLabel()
    right = LowLevelILLabel()

    done_found = True
    done = il.get_label_for_address(il.arch, il.current_address + length)
    if done is None:
        done = LowLevelILLabel()
        done_found = False

    # if r1 > 0, goto left, else goto right
    il.append(il.if_expr(il.compare_signed_greater_than(4, il.reg(4, IReg[r1]), il.const(4, 0)), left, right))

    # left
    il.mark_label(left)
    if long:
        il.append(il.set_reg_split(4, IReg[r2 + 1], IReg[r2 + 0], positive(
            8, 
            il.reg_split(4, IReg[r2 + 1], IReg[r2 + 0]),
            il.reg(4, IReg[r1]), 'vc'), 'nz'))
    else:
        il.append(il.set_reg(4, IReg[r2], positive(4, il.reg(4, IReg[r2]), il.reg(4, IReg[r1]), 'vc'), 'nz'))
    il.append(il.goto(done))

    # right
    il.mark_label(right)
    if long:
        il.append(il.set_reg_split(4, IReg[r2 + 1], IReg[r2 + 0], negative(
            8, 
            il.reg_split(4, IReg[r2 + 1], IReg[r2 + 0]),
            il.neg_expr(4, il.reg(4, IReg[r1])), 'vc'), 'nz'))
    else:
        il.append(il.set_reg(4, IReg[r2], negative(4, il.reg(4, IReg[r2]), il.neg_expr(4, il.reg(4, IReg[r1])), 'vc'), 'nz'))
    il.append(il.goto(done))

    if not done_found:
        il.mark_label(done)

def il_append(il, data):
    if isinstance(data, list):
        for i in [i for i in data if i is not None]:
            il.append(i)
    elif data is not None:
        il.append(data)

def branch_helper(il, cond, dest, length, ds1_il=None, ds2_il=None):
    """
    Generate LLIL for conditional and unconditional branch instructions.
    """

    # try to find a label for the branch target
    taken = None
    if il[dest].operation == LowLevelILOperation.LLIL_CONST:
        taken = il.get_label_for_address(il.arch, il[dest].constant)

    if cond != 0:
        # create taken target
        taken_found = True
        if taken is None:
            taken = LowLevelILLabel()
            taken_found = False

        # create untaken target
        untaken_found = True
        untaken = il.get_label_for_address(il.arch, il.current_address + length)
        if untaken is None:
            untaken = LowLevelILLabel()
            untaken_found = False

        # generate the conditional branch LLIL
        if ds1_il is not None and ds2_il is not None:
            # save the branch condition
            il.append(il.set_reg(0, LLIL_TEMP(0), il.flag_condition(ConditionCodeMapping[cond])))

            # delay slot instructions
            il_append(il, ds1_il)
            il_append(il, ds2_il)

            il.append(il.if_expr(il.reg(0, LLIL_TEMP(0)), taken, untaken))
        else:
            il.append(il.if_expr(il.flag_condition(ConditionCodeMapping[cond]), taken, untaken))

        # generate a jump to the branch target if a label couldn't be found
        if not taken_found:
            il.mark_label(taken)
            il.append(il.jump(dest))

        # generate a label for the untaken branch
        if not untaken_found:
            il.set_current_address(il.current_address + length)
            il.mark_label(untaken)
    else:
        # delay slot instructions
        if ds1_il is not None and ds2_il is not None:
            il_append(il, ds1_il)
            il_append(il, ds2_il)

        # unconditional branch
        if taken is not None:
            il.append(il.goto(taken))
        else:
            il.append(il.jump(dest))

def cdb_helper(il, cond, r2, dest, length, ds1_il, ds2_il):
    """
    Generate LLIL for compare and delayed branch instructions.
    """

    # try to find a label for the branch target
    taken = None
    if il[dest].operation == LowLevelILOperation.LLIL_CONST:
        taken = il.get_label_for_address(il.arch, il[dest].constant)

    # create taken target
    taken_found = True
    if taken is None:
        taken = LowLevelILLabel()
        taken_found = False

    # create untaken target
    untaken_found = True
    untaken = il.get_label_for_address(il.arch, il.current_address + length)
    if untaken is None:
        untaken = LowLevelILLabel()
        untaken_found = False

    # generate the condition LLIL
    if cond == 'eq':
        il.append(il.set_reg(0, LLIL_TEMP(0), il.compare_equal(4, il.reg(4, IReg[r2]), il.const(4, 0))))
    elif cond == 'ne':
        il.append(il.set_reg(0, LLIL_TEMP(0), il.compare_not_equal(4, il.reg(4, IReg[r2]), il.const(4, 0))))

    # insert the delay slot instructions
    il.append(ds1_il)
    il.append(ds2_il)

    # insert the branch
    il.append(il.if_expr(il.reg(0, LLIL_TEMP(0)), taken, untaken))

    # generate a jump to the branch target if a label couldn't be found
    if not taken_found:
        il.mark_label(taken)
        il.append(il.jump(dest))

    # generate a label for the untaken branch
    if not untaken_found:
        il.set_current_address(il.current_address + length)
        il.mark_label(untaken)

def s_helper(il, cond, r1, length):
    """
    Generate LLIL for set on condition instruction.
    """
    true = LowLevelILLabel()
    false = LowLevelILLabel()

    done_found = True
    done = il.get_label_for_address(il.arch, il.current_address + length)
    if done is None:
        done = LowLevelILLabel()
        done_found = False

    # if condition goto true else goto false
    il.append(il.if_expr(il.flag_condition(ConditionCodeMapping[cond]), true, false))

    # true
    il.mark_label(true)
    il.append(il.set_reg(4, IReg[r1], il.const(4, 1)))
    il.append(il.goto(done))

    # false
    il.mark_label(false)
    il.append(il.set_reg(4, IReg[r1], il.const(4, 0)))
    il.append(il.goto(done))

    if not done_found:
        il.mark_label(done)

def string_helper(il, body, length):
    """
    Generate LLIL for movc/initc macro instructions.
    """
    test = LowLevelILLabel()
    loop = LowLevelILLabel()

    done_found = True
    done = il.get_label_for_address(il.arch, il.current_address + length)
    if done is None:
        done = LowLevelILLabel()
        done_found = False

    # goto test
    il.append(il.goto(test))

    # if r0 == 0 goto done
    il.mark_label(test)
    il.append(il.if_expr(il.compare_equal(4, il.reg(4, IReg[0]), il.const(4, 0)), done, loop))

    # loop body
    il.mark_label(loop)
    for i in body:
        il.append(i)
    il.append(il.goto(test))

    # done
    if not done_found:
        il.mark_label(done)

def cmpc_helper(il, length):
    """
    Generate LLIL for cmpc macro instruction (compare r0 bytes at r1 with r2).
    """
    test = LowLevelILLabel()
    loop = LowLevelILLabel()
    match = LowLevelILLabel()

    done_found = True
    done = il.get_label_for_address(il.arch, il.current_address + length)
    if done is None:
        done = LowLevelILLabel()
        done_found = False

    # goto test
    il.append(il.goto(test))

    # if r0 == 0 goto done
    il.mark_label(test)
    il.append(il.if_expr(il.compare_equal(4, il.reg(4, IReg[0]), il.const(4, 0)), done, loop))

    # if *r2 != *r1 goto done
    il.mark_label(loop)
    il.append(il.sub(4, il.sign_extend(4, il.load(1, il.reg(4, IReg[2]))), il.sign_extend(4, il.load(1, il.reg(4, IReg[1]))), '*'))
    il.append(il.if_expr(il.flag_condition(LowLevelILFlagCondition.LLFC_NE), done, match))

    # else r1++, r2++, r0--
    il.mark_label(match)
    il.append(il.set_reg(4, IReg[1], il.add(4, il.reg(4, IReg[1]), il.const(4, 1))))
    il.append(il.set_reg(4, IReg[2], il.add(4, il.reg(4, IReg[2]), il.const(4, 1))))
    il.append(il.set_reg(4, IReg[0], il.sub(4, il.reg(4, IReg[0]), il.const(4, 1))))

    # goto test
    il.append(il.goto(test))

    # done
    if not done_found:
        il.mark_label(done)

def address_operand(il, pc, r1, rx, constant, mode):
    """
    Generate LLIL to compute an effective address.
    """
    if mode == AddressMode.RELATIVE:
        return il.reg(4, IReg[r1])
    elif mode == AddressMode.PC32 or mode == AddressMode.PC16:
        return il.const_pointer(4, pc + constant)
    elif mode == AddressMode.ABS32:
        return il.const_pointer(4, constant)
    elif mode == AddressMode.ABS16:
        return il.const_pointer(2, constant)
    elif mode == AddressMode.REL12:
        return il.add(4, il.reg(4, IReg[r1]), il.const(2, constant))
    elif mode == AddressMode.REL32:
        return il.add(4, il.reg(4, IReg[r1]), il.const_pointer(4, constant))
    elif mode == AddressMode.PCX:
        return il.add(4, il.const_pointer(4, pc), il.reg(4, IReg[rx]))
    elif mode == AddressMode.RELX:
        return il.add(4, il.reg(4, IReg[r1]), il.reg(4, IReg[rx]))

# CLIPPER instruction Low Level Intermediate Language map
InstructionIL = {
    'noop': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.nop(),
    'movwp': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, 'psw', il.reg(4, IReg[r2]), '*') if r1 == 0 else il.set_reg(4, 'ssw', il.reg(4, IReg[r2])),
    'movpw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.reg(4, 'psw' if r1 == 0 else 'ssw')),
    'calls': lambda il, pc, r1, r2, rx, constant, mode, length:
        # Should pass system call number (constant & 0x7f).
        # https://github.com/Vector35/binaryninja-api/issues/507
        [ 
            il.set_reg(1, '_sc', il.const(1, constant & 0x7f)),
            il.system_call()
        ],
    'ret': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.ret(il.pop(4)) if r2 == 15 else [
            il.ret(il.load(4, il.reg(4, IReg[r2]))),
            il.set_reg(4, IReg[r2], il.add(4, il.reg(4, IReg[r2]), il.const(4, 4)))
        ],
    'pushw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.push(4, il.reg(4, IReg[r2])) if r1 == 15 else [
            il.store(4, il.sub(4, il.reg(4, IReg[r1]), il.const(4, 4)), il.reg(4, IReg[r2])),
            il.set_reg(4, IReg[r1], il.sub(4, il.reg(4, IReg[r1]), il.const(4, 4)))            
        ],
    'popw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.pop(4)) if r1 == 15 else [
            il.set_reg(4, IReg[r2], il.load(4, il.reg(4, IReg[r1]))),
            il.set_reg(4, IReg[r1], il.add(4, il.reg(4, IReg[r1]), il.const(4, 4))) if not r1 == r2 else None
        ],

    # fp operations
    'adds': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, FPReg[r2], il.float_add(4, il.reg(4, FPReg[r2]), il.reg(4, FPReg[r1]), 'f*')),
    'subs': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, FPReg[r2], il.float_sub(4, il.reg(4, FPReg[r2]), il.reg(4, FPReg[r1]), 'f*')),
    'addd': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(8, FPReg[r2], il.float_add(8, il.reg(8, FPReg[r2]), il.reg(8, FPReg[r1]), 'f*')),
    'subd': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(8, FPReg[r2], il.float_sub(8, il.reg(8, FPReg[r2]), il.reg(8, FPReg[r1]), 'f*')),
    'movs': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, FPReg[r2], il.reg(4, FPReg[r1])),
    'cmps': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.float_sub(4, il.reg(4, FPReg[r2]), il.reg(4, FPReg[r1]), '*'),
    'movd': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(8, FPReg[r2], il.reg(8, FPReg[r1])),
    'cmpd': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.float_sub(8, il.reg(8, FPReg[r2]), il.reg(8, FPReg[r1]), '*'),
    'muls': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, FPReg[r2], il.float_mult(4, il.reg(4, FPReg[r2]), il.reg(4, FPReg[r1]), 'f*')),
    'divs': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, FPReg[r2], il.float_div(4, il.reg(4, FPReg[r2]), il.reg(4, FPReg[r1]), 'f*')),
    'muld': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(8, FPReg[r2], il.float_mult(8, il.reg(8, FPReg[r2]), il.reg(8, FPReg[r1]), 'f*')),
    'divd': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(8, FPReg[r2], il.float_div(8, il.reg(8, FPReg[r2]), il.reg(8, FPReg[r1]), 'f*')),
    'movsw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.reg(4, FPReg[r1])),
    'movws': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(8, FPReg[r2], il.reg(4, IReg[r1])),
    'movdl': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg_split(4, IReg[r2 + 1], IReg[r2 + 0], il.reg(8, FPReg[r1])),
    'movld': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(8, FPReg[r2], il.reg_split(4, IReg[r1 + 1], IReg[r1 + 0])),

    'shaw': lambda il, pc, r1, r2, rx, constant, mode, length:
        shift_helper(il, r1, r2, il.shift_left, il.arith_shift_right, False, length),
    'shal': lambda il, pc, r1, r2, rx, constant, mode, length:
        shift_helper(il, r1, r2, il.shift_left, il.arith_shift_right, True, length),
    'shlw': lambda il, pc, r1, r2, rx, constant, mode, length:
        shift_helper(il, r1, r2, il.shift_left, il.logical_shift_right, False, length),
    'shll': lambda il, pc, r1, r2, rx, constant, mode, length:
        shift_helper(il, r1, r2, il.shift_left, il.logical_shift_right, True, length),
    'rotw': lambda il, pc, r1, r2, rx, constant, mode, length:
        shift_helper(il, r1, r2, il.rotate_left, il.rotate_right, False, length),
    'rotl': lambda il, pc, r1, r2, rx, constant, mode, length:
        shift_helper(il, r1, r2, il.rotate_left, il.rotate_right, True, length),
    'shai': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], 
            il.shift_left(4, il.reg(4, IReg[r2]), il.const(4, constant), 'vc') if constant > 0 else
            il.arith_shift_right(4, il.reg(4, IReg[r2]), il.const(4, -constant), 'vc'), 'nz'),
    'shali': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg_split(4, IReg[r2 + 1], IReg[r2 + 0], 
            il.shift_left(
                8, 
                il.reg_split(4, IReg[r2 + 1], IReg[r2 + 0]),
                il.const(4, constant), 'vc') if constant > 0 else
            il.arith_shift_right(
                8, 
                il.reg_split(4, IReg[r2 + 1], IReg[r2 + 0]),
                il.const(4, -constant), 'vc'), 'nz'),
    'shli': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2],
            il.shift_left(4, il.reg(4, IReg[r2]), il.const(4, constant), 'vc') if constant > 0 else
            il.logical_shift_right(4, il.reg(4, IReg[r2]), il.const(4, -constant), 'vc'), 'nz'),
    'shlli': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg_split(4, IReg[r2 + 1], IReg[r2 + 0], 
            il.shift_left(
                8, 
                il.reg_split(4, IReg[r2 + 1], IReg[r2 + 0]),
                il.const(4, constant), 'vc') if constant > 0 else
            il.logical_shift_right(
                8, 
                il.reg_split(4, IReg[r2 + 1], IReg[r2 + 0]),
                il.const(4, -constant), 'vc'), 'nz'),
    'roti': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], 
            il.rotate_left(4, il.reg(4, IReg[r2]), il.const(4, constant), 'vc') if constant > 0 else
            il.rotate_right(4, il.reg(4, IReg[r2]), il.const(4, -constant), 'vc'), 'nz'),
    'rotli': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg_split(4, IReg[r2 + 1], IReg[r2 + 0], 
            il.rotate_left(
                8, 
                il.reg_split(4, IReg[r2 + 1], IReg[r2 + 0]),
                il.const(4, constant), 'vc') if constant > 0 else
            il.rotate_right(
                8, 
                il.reg_split(4, IReg[r2 + 1], IReg[r2 + 0]),
                il.const(4, -constant), 'vc'), 'nz'),
    
    'call': lambda il, pc, r1, r2, rx, constant, mode, length:
        # TODO: non-standard stack pointer
        il.call(address_operand(il, pc, r1, rx, constant, mode)) if r2 == 15 else il.unimplemented(),
    'loadd2': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg_split(8, FPReg[r2 + 1], FPReg[r2 + 0], il.load(16, address_operand(il, pc, r1, rx, constant, mode))),
    'b*': lambda il, pc, r1, r2, rx, constant, mode, length:
        branch_helper(il, r2, address_operand(il, pc, r1, rx, constant, mode), length),

    'cdbeq': lambda il, pc, r1, r2, rx, constant, mode, length, ds1_il, ds2_il:
        cdb_helper(il, 'eq', r2, address_operand(il, pc, r1, rx, constant, mode), length, ds1_il, ds2_il),
    'cdbne': lambda il, pc, r1, r2, rx, constant, mode, length, ds1_il, ds2_il:
        cdb_helper(il, 'ne', r2, address_operand(il, pc, r1, rx, constant, mode), length, ds1_il, ds2_il),
    'db*': lambda il, pc, r1, r2, rx, constant, mode, length, ds1_il, ds2_il:
        branch_helper(il, r2, address_operand(il, pc, r1, rx, constant, mode), length, ds1_il, ds2_il),

    'loadw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.load(4, address_operand(il, pc, r1, rx, constant, mode))),
    'loada': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], address_operand(il, pc, r1, rx, constant, mode)),
    'loads': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(8, FPReg[r2], il.load(4, address_operand(il, pc, r1, rx, constant, mode))),
    'loadd': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(8, FPReg[r2], il.load(8, address_operand(il, pc, r1, rx, constant, mode))),
    'loadb': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.sign_extend(4, il.load(1, address_operand(il, pc, r1, rx, constant, mode)))),
    'loadbu': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.zero_extend(4, il.load(1, address_operand(il, pc, r1, rx, constant, mode)))),
    'loadh': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.sign_extend(4, il.load(2, address_operand(il, pc, r1, rx, constant, mode)))),
    'loadhu': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.zero_extend(4, il.load(2, address_operand(il, pc, r1, rx, constant, mode)))),

    'storw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.store(4, address_operand(il, pc, r1, rx, constant, mode), il.reg(4, IReg[r2])),
    'tsts': lambda il, pc, r1, r2, rx, constant, mode, length: [
        il.set_reg(4, IReg[r2], il.load(4, address_operand(il, pc, r1, rx, constant, mode))),
        il.store(4, address_operand(il, pc, r1, rx, constant, mode), il.or_expr(4, il.reg(4, IReg[r2]), il.const(4, 0x80000000)))
    ],
    'stors': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.store(4, address_operand(il, pc, r1, rx, constant, mode), il.reg(4, FPReg[r2])),
    'stord': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.store(8, address_operand(il, pc, r1, rx, constant, mode), il.reg(8, FPReg[r2])),
    'storb': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.store(1, address_operand(il, pc, r1, rx, constant, mode), il.reg(1, IReg[r2])),
    'storh': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.store(2, address_operand(il, pc, r1, rx, constant, mode), il.reg(2, IReg[r2])),
        
    'addw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.add(4, il.reg(4, IReg[r2]), il.reg(4, IReg[r1]), 'vc'), 'nz'),
    'addq': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.add(4, il.reg(4, IReg[r2]), il.const(4, r1), 'vc'), 'nz'),
    'addi': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.add(4, il.reg(4, IReg[r2]), il.const(4, constant), 'vc'), 'nz'),
    'movw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.reg(4, IReg[r1]), '*'),
    'loadq': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.const(4, r1), '*'),
    'loadi': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.const(4, constant), '*'),
    'andw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.and_expr(4, il.reg(4, IReg[r2]), il.reg(4, IReg[r1])), '*'),
    'andi': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.and_expr(4, il.reg(4, IReg[r2]), il.const(4, constant)), '*'),
    'orw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.or_expr(4, il.reg(4, IReg[r2]), il.reg(4, IReg[r1])), '*'),
    'ori': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.or_expr(4, il.reg(4, IReg[r2]), il.const(4, constant)), '*'),

    'addwc': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.add_carry(4, il.reg(4, IReg[r2]), il.reg(4, IReg[r1]), il.flag('c'), 'vc'), 'nz'),
    'subwc': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.sub_borrow(4, il.reg(4, IReg[r2]), il.reg(4, IReg[r1]), il.flag('c'), 'vc'), 'nz'),
    'negw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.neg_expr(4, il.reg(4, IReg[r1]), 'vc'), 'nz'),
    'mulw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.mult(4, il.reg(4, IReg[r2]), il.reg(4, IReg[r1]), '*')),
    'mulwx': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg_split(4, IReg[r2 + 1], IReg[r2 + 0], il.mult_double_prec_signed(4, il.reg(4, IReg[r2]), il.reg(4, IReg[r1]), '*')),
    'mulwu': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.mult(4, il.reg(4, IReg[r2]), il.reg(4, IReg[r1]), '*')),
    'mulwux': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg_split(4, IReg[r2 + 1], IReg[r2 + 0], il.mult_double_prec_unsigned(4, il.reg(4, IReg[r2]), il.reg(4, IReg[r1]), '*')),
    'divw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.div_signed(4, il.reg(4, IReg[r2]), il.reg(4, IReg[r1]), '*')),
    'modw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.mod_signed(4, il.reg(4, IReg[r2]), il.reg(4, IReg[r1]), '*')),
    'divwu': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.div_unsigned(4, il.reg(4, IReg[r2]), il.reg(4, IReg[r1]), '*')),
    'modwu': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.mod_unsigned(4, il.reg(4, IReg[r2]), il.reg(4, IReg[r1]), '*')),
        
    'subw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.sub(4, il.reg(4, IReg[r2]), il.reg(4, IReg[r1]), 'vc'), 'nz'),
    'subq': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.sub(4, il.reg(4, IReg[r2]), il.const(4, r1), 'vc'), 'nz'),
    'subi': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.sub(4, il.reg(4, IReg[r2]), il.const(4, constant), 'vc'), 'nz'),
    'cmpw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.sub(4, il.reg(4, IReg[r2]), il.reg(4, IReg[r1]), '*'),
    'cmpq': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.sub(4, il.reg(4, IReg[r2]), il.const(4, r1), '*'),
    'cmpi': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.sub(4, il.reg(4, IReg[r2]), il.const(4, constant), '*'),
    'xorw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.xor_expr(4, il.reg(4, IReg[r2]), il.reg(4, IReg[r1]), 'vc'), 'nz'),
    'xori': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.xor_expr(4, il.reg(4, IReg[r2]), il.const(4, constant), 'vc'), 'nz'),
    'notw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.not_expr(4, il.reg(4, IReg[r1]), 'vc'), 'nz'),
    'notq': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.const(4, ~r1), '*'),

    'abss': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, FPReg[r2], il.float_abs(4, il.reg(4, FPReg[r1]))),
    'absd': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(8, FPReg[r2], il.float_abs(8, il.reg(8, FPReg[r1]))),

    'waitd': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.nop(),
    's*': lambda il, pc, r1, r2, rx, constant, mode, length:
        s_helper(il, r2, r1, length),

    # macro instructions
    'savew0': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(4, il.reg(4, IReg[i])) for i in range(14, -1, -1) ],
    'savew1': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(4, il.reg(4, IReg[i])) for i in range(14, 0, -1) ],
    'savew2': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(4, il.reg(4, IReg[i])) for i in range(14, 1, -1) ],
    'savew3': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(4, il.reg(4, IReg[i])) for i in range(14, 2, -1) ],
    'savew4': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(4, il.reg(4, IReg[i])) for i in range(14, 3, -1) ],
    'savew5': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(4, il.reg(4, IReg[i])) for i in range(14, 4, -1) ],
    'savew6': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(4, il.reg(4, IReg[i])) for i in range(14, 5, -1) ],
    'savew7': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(4, il.reg(4, IReg[i])) for i in range(14, 6, -1) ],
    'savew8': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(4, il.reg(4, IReg[i])) for i in range(14, 7, -1) ],
    'savew9': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(4, il.reg(4, IReg[i])) for i in range(14, 8, -1) ],
    'savew10': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(4, il.reg(4, IReg[i])) for i in range(14, 9, -1) ],
    'savew11': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(4, il.reg(4, IReg[i])) for i in range(14, 10, -1) ],
    'savew12': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(4, il.reg(4, IReg[i])) for i in range(14, 11, -1) ],
    'movc': lambda il, pc, r1, r2, rx, constant, mode, length:
        string_helper(il, [
            il.store(1, il.reg(4, IReg[2]), il.load(1, il.reg(4, IReg[1]))),
            il.set_reg(4, IReg[1], il.add(4, il.reg(4, IReg[1]), il.const(4, 1))),
            il.set_reg(4, IReg[2], il.add(4, il.reg(4, IReg[2]), il.const(4, 1))),
            il.set_reg(4, IReg[0], il.sub(4, il.reg(4, IReg[0]), il.const(4, 1)))
        ], length),
    'initc': lambda il, pc, r1, r2, rx, constant, mode, length:
        string_helper(il, [
            il.store(1, il.reg(4, IReg[1]), il.reg(1, IReg[2])),
            il.set_reg(4, IReg[1], il.add(4, il.reg(4, IReg[1]), il.const(4, 1))),
            il.set_reg(4, IReg[2], il.rotate_right(4, il.reg(4, IReg[2]), il.const(4, 8))),
            il.set_reg(4, IReg[0], il.sub(4, il.reg(4, IReg[0]), il.const(4, 1)))
        ], length),
    'cmpc': lambda il, pc, r1, r2, rx, constant, mode, length:
        cmpc_helper(il, length),
    'restw0': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(4, IReg[i], il.pop(4)) for i in range(0, 15) ],
    'restw1': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(4, IReg[i], il.pop(4)) for i in range(1, 15) ],
    'restw2': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(4, IReg[i], il.pop(4)) for i in range(2, 15) ],
    'restw3': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(4, IReg[i], il.pop(4)) for i in range(3, 15) ],
    'restw4': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(4, IReg[i], il.pop(4)) for i in range(4, 15) ],
    'restw5': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(4, IReg[i], il.pop(4)) for i in range(5, 15) ],
    'restw6': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(4, IReg[i], il.pop(4)) for i in range(6, 15) ],
    'restw7': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(4, IReg[i], il.pop(4)) for i in range(7, 15) ],
    'restw8': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(4, IReg[i], il.pop(4)) for i in range(8, 15) ],
    'restw9': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(4, IReg[i], il.pop(4)) for i in range(9, 15) ],
    'restw10': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(4, IReg[i], il.pop(4)) for i in range(10, 15) ],
    'restw11': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(4, IReg[i], il.pop(4)) for i in range(11, 15) ],
    'restw12': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(4, IReg[i], il.pop(4)) for i in range(12, 15) ],
    
    'saved0': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(8, il.reg(8, FPReg[i])) for i in range(7, -1, -1) ],
	'saved1': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(8, il.reg(8, FPReg[i])) for i in range(7, 0, -1) ],
	'saved2': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(8, il.reg(8, FPReg[i])) for i in range(7, 1, -1) ],
	'saved3': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(8, il.reg(8, FPReg[i])) for i in range(7, 2, -1) ],
	'saved4': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(8, il.reg(8, FPReg[i])) for i in range(7, 3, -1) ],
	'saved5': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(8, il.reg(8, FPReg[i])) for i in range(7, 4, -1) ],
	'saved6': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(8, il.reg(8, FPReg[i])) for i in range(7, 5, -1) ],
	'saved7': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.push(8, il.reg(8, FPReg[i])) for i in range(7, 6, -1) ],
	'restd0': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(8, FPReg[i], il.pop(8)) for i in range(0, 8) ],
	'restd1': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(8, FPReg[i], il.pop(8)) for i in range(1, 8) ],
	'restd2': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(8, FPReg[i], il.pop(8)) for i in range(2, 8) ],
	'restd3': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(8, FPReg[i], il.pop(8)) for i in range(3, 8) ],
	'restd4': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(8, FPReg[i], il.pop(8)) for i in range(4, 8) ],
	'restd5': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(8, FPReg[i], il.pop(8)) for i in range(5, 8) ],
	'restd6': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(8, FPReg[i], il.pop(8)) for i in range(6, 8) ],
	'restd7': lambda il, pc, r1, r2, rx, constant, mode, length:
        [il.set_reg(8, FPReg[i], il.pop(8)) for i in range(7, 8) ],

    # TODO: non-standard floating point rounding instructions
    'cnvsw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.float_to_int(4, il.reg(4, FPReg[r1]), 'fxi')),
	#'cnvrsw': lambda il, pc, r1, r2, rx, constant, mode, length:
	'cnvtsw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.float_trunc(4, il.reg(4, FPReg[r1]), 'fxi')),
	'cnvws': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, FPReg[r2], il.int_to_float(4, il.reg(4, IReg[r1]), 'fx')),
	'cnvdw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.float_to_int(4, il.reg(8, FPReg[r1]), 'fxi')),
	#'cnvrdw': lambda il, pc, r1, r2, rx, constant, mode, length:
	'cnvtdw': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, IReg[r2], il.float_trunc(4, il.reg(8, FPReg[r1]), 'fxi')),
	'cnvwd': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(8, FPReg[r2], il.int_to_float(8, il.reg(4, IReg[r1]))),
	'cnvsd': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(8, FPReg[r2], il.float_convert(8, il.reg(4, FPReg[r1]), 'fi')),
	'cnvds': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, FPReg[r2], il.float_convert(4, il.reg(8, FPReg[r1]), 'fxuvi')),
    'negs': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(4, FPReg[r2], il.float_neg(4, il.reg(4, FPReg[r1]))),
    'negd': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.set_reg(8, FPReg[r2], il.float_neg(8, il.reg(8, FPReg[r1]))),

    'movus': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.nop(),
    'movsu': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.nop(),
    'saveur': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.nop(),
    'restur': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.nop(),
    'reti': lambda il, pc, r1, r2, rx, constant, mode, length:
        [
            il.set_reg(4, SReg[0], il.pop(4)),
            il.set_reg(4, SReg[1], il.pop(4)),
            il.ret(il.pop(4))
        ] if r1 == 15 else [
            il.set_reg(4, SReg[0], il.load(4, il.reg(4, IReg[r1]))),
            il.set_reg(4, SReg[1], il.load(4, il.add(4, il.reg(4, IReg[r1]), il.const(4, 4)))),
            il.ret(4, il.load(4, il.add(4, il.reg(4, IReg[r1]), il.const(4, 8)))),
            il.set_reg(4, IReg[r1], il.add(4, il.reg(4, IReg[r1]), il.const(4, 12)))
        ],

    'wait': lambda il, pc, r1, r2, rx, constant, mode, length:
        il.nop(),
}

class CLIPPER(Architecture):
    name = 'clipper'
    address_size = 4
    instr_alignment = 2

    # FIXME: allow for up to 3 instructions (1 + 2 delay slots)
    max_instr_length = 8 * 3

    regs = {
        'r0': RegisterInfo('r0', 4),
        'r1': RegisterInfo('r1', 4),
        'r2': RegisterInfo('r2', 4),
        'r3': RegisterInfo('r3', 4),
        'r4': RegisterInfo('r4', 4),
        'r5': RegisterInfo('r5', 4),
        'r6': RegisterInfo('r6', 4),
        'r7': RegisterInfo('r7', 4),
        'r8': RegisterInfo('r8', 4),
        'r9': RegisterInfo('r9', 4),
        'r10': RegisterInfo('r10', 4),
        'r11': RegisterInfo('r11', 4),
        'r12': RegisterInfo('r12', 4),
        'r13': RegisterInfo('r13', 4),
        'fp': RegisterInfo('fp', 4),
        'sp': RegisterInfo('sp', 4),

        'f0': RegisterInfo('f0', 8),
        'f1': RegisterInfo('f1', 8),
        'f2': RegisterInfo('f2', 8),
        'f3': RegisterInfo('f3', 8),
        'f4': RegisterInfo('f4', 8),
        'f5': RegisterInfo('f5', 8),
        'f6': RegisterInfo('f6', 8),
        'f7': RegisterInfo('f7', 8),
        'f8': RegisterInfo('f8', 8),
        'f9': RegisterInfo('f9', 8),
        'f10': RegisterInfo('f10', 8),
        'f11': RegisterInfo('f11', 8),
        'f12': RegisterInfo('f12', 8),
        'f13': RegisterInfo('f13', 8),
        'f14': RegisterInfo('f14', 8),
        'f15': RegisterInfo('f15', 8),

        'pc': RegisterInfo('pc', 4),
        'psw': RegisterInfo('psw', 4),
        'ssw': RegisterInfo('ssw', 4),

        # fake _sc register holds the system call number
        '_sc': RegisterInfo('_sc', 1)
    }
    
    global_regs = ['pc','psw','ssw']

    flags = ['n', 'z', 'v', 'c', 'fx', 'fu', 'fd', 'fv', 'fi']

    # The first flag write type is ignored currently.
    # See: https://github.com/Vector35/binaryninja-api/issues/513
    flag_write_types = ['', '*', 'nz', 'vc', 'n', 'f*', 'fx', 'fi','fxi','fxuvi']

    flags_written_by_flag_write_type = {
        '*': ['n', 'z', 'v', 'c'],
        'nz': ['n', 'z'],
        'vc': ['v', 'c'],
        'n': ['n'],
        'f*': ['fx', 'fu', 'fd', 'fv', 'fi'],
        'fx': ['fx'],
        'fi': ['fi'],
        'fxi': ['fx','fi'],
        'fxuvi': ['fx','fu','fv','fi']
    }
    flag_roles = {
        'n': FlagRole.NegativeSignFlagRole,
        'z': FlagRole.ZeroFlagRole,
        'v': FlagRole.OverflowFlagRole,
        'c': FlagRole.CarryFlagRole
    }
    flags_required_for_flag_condition = {
        LowLevelILFlagCondition.LLFC_E:   ['n', 'z'],
        LowLevelILFlagCondition.LLFC_NE:  ['n', 'z'],
        LowLevelILFlagCondition.LLFC_SLT: ['n', 'z', 'v'],
        LowLevelILFlagCondition.LLFC_ULT: ['z', 'c'],
        LowLevelILFlagCondition.LLFC_SLE: ['n', 'z', 'v'],
        LowLevelILFlagCondition.LLFC_ULE: ['c'],
        LowLevelILFlagCondition.LLFC_SGE: ['n', 'z', 'v'],
        LowLevelILFlagCondition.LLFC_UGE: ['z', 'c'],
        LowLevelILFlagCondition.LLFC_SGT: ['n', 'z', 'v'],
        LowLevelILFlagCondition.LLFC_UGT: ['c'],
        LowLevelILFlagCondition.LLFC_NEG: ['n', 'z'],
        LowLevelILFlagCondition.LLFC_POS: ['n'],
        LowLevelILFlagCondition.LLFC_O:   ['v'],
        LowLevelILFlagCondition.LLFC_NO:  ['v']
    }

    stack_pointer = 'sp'

    # decode an instruction, returning:
    #   instruction name
    #   r1, r2, rx, constant instruction fields
    #   address mode
    #   list of operand types
    #   total length of opcode and operands
    def decode_instruction(self, data, addr):
        error_value = (None, None, None, None, None, None, None, None)

        # minimum instruction size is 2 bytes
        if len(data) < 2:
            return error_value

        # get the first 16 bit instruction parcel
        parcel0 = struct.unpack('<H', data[0:2])[0]

        # decode the instruction opcode
        if parcel0 & 0xfc00 == 0xb400:
            instr = MacroInstructions.get(parcel0)
        else:
            instr = Instructions.get(parcel0 >> 8)

        # check for invalid opcodes
        if instr is None:
            log_warn('[{:x}] Bad opcode: {:x}'.format(addr, parcel0))
            return error_value

        # decode the operands
        (length, r1, r2, rx, constant, mode) = instr[1](parcel0, data)

        # check for invalid operands
        if length is None:
            log_warn('[{:x}] Bad operands: {:x}'.format(addr, parcel0))
            return error_value

        return instr[0], r1, r2, rx, constant, mode, instr[2], length

    def get_instruction_info(self, data, addr):
        (instr, _, r2, _, constant, mode, _, length) = self.decode_instruction(data, addr)

        if instr is None:
            return None

        result = InstructionInfo()

        # FIXME: workaround for https://github.com/Vector35/binaryninja-api/issues/866
        # decode length of delay slot instructions
        if instr in ['db*', 'cdb', 'cdbeq', 'cdbne']:
            try:
                (ds1_instr, _, ds1_r2, _, ds1_constant, ds1_mode, _, ds1_length) = self.decode_instruction(data[length:], addr + length)
                (ds2_instr, ds2_r1, ds2_r2, _, _, _, _, ds2_length) = self.decode_instruction(data[length+ds1_length:], addr + length + ds1_length)

                result.length = length + ds1_length + ds2_length

                # handle 'db, loada, pushw' idiom as a call instruction
                if (ds1_instr == 'loada' and (ds1_mode == AddressMode.PC16 or ds1_mode == AddressMode.PC32) and ds1_constant == ds1_length + ds2_length and
                    ds2_instr == 'pushw' and ds1_r2 == ds2_r2 and ds2_r1 == 15):
                    instr = 'call'
            except:
                return None
        else:
            result.length = length

        # compute constant addresses
        address = None
        if mode == AddressMode.PC16 or mode == AddressMode.PC32:
            address = (addr + constant) & 0xffffffff
        elif mode == AddressMode.ABS16 or mode == AddressMode.ABS32:
            address = constant

        # add branches
        if instr in ['ret', 'reti']:
            result.add_branch(BranchType.FunctionReturn)
        elif instr in ['b*', 'db*']:
            if address is not None:
                result.add_branch(BranchType.UnconditionalBranch if r2 == 0 else BranchType.TrueBranch, address)
            else:
                result.add_branch(BranchType.UnresolvedBranch)
            if r2 != 0:
                result.add_branch(BranchType.FalseBranch, addr + result.length)
        elif instr in ['cdb', 'cdbeq', 'cdbne']:
            if address is not None:
                result.add_branch(BranchType.TrueBranch, address)
            else:
                result.add_branch(BranchType.UnresolvedBranch)
            result.add_branch(BranchType.FalseBranch, addr + result.length)
        elif instr == 'call':
            if address is not None:
                result.add_branch(BranchType.CallDestination, address)
            else:
                result.add_branch(BranchType.UnresolvedBranch)
        elif instr == 'calls':
            result.add_branch(BranchType.SystemCall, constant)

        return result

    def get_instruction_text(self, data, addr):
        (instr, r1, r2, rx, constant, mode, operand_list, length) = self.decode_instruction(data, addr)

        if instr is None:
            return None

        # inject condition code
        if '*' in instr:
            instr = instr.replace('*', ConditionCodeStrings[r2])

        tokens = [
            InstructionTextToken(InstructionTextTokenType.InstructionToken, '{:8}'.format(instr))
        ]

        first = True
        for operand in operand_list:
            # insert a comma for all but the first operand
            if first:
                first = False
            else:
                tokens += [InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ',')]

            if operand == OperandType.R1:
                tokens += [InstructionTextToken(InstructionTextTokenType.RegisterToken, IReg[r1])]
            elif operand == OperandType.R2:
                tokens += [InstructionTextToken(InstructionTextTokenType.RegisterToken, IReg[r2])]
            elif operand == OperandType.F1:
                tokens += [InstructionTextToken(InstructionTextTokenType.RegisterToken, FPReg[r1])]
            elif operand == OperandType.F2:
                tokens += [InstructionTextToken(InstructionTextTokenType.RegisterToken, FPReg[r2])]
            elif operand == OperandType.QUICK:
                tokens += [
                    InstructionTextToken(InstructionTextTokenType.TextToken, '$'),
                    InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(r1), r1)]
            elif operand == OperandType.SR:
                tokens += [InstructionTextToken(InstructionTextTokenType.RegisterToken, SReg[r1])]
            elif operand == OperandType.IMM:
                tokens += [
                    InstructionTextToken(InstructionTextTokenType.TextToken, '$'), 
                    InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(constant), constant)]
            elif operand == OperandType.ADDR:
                if mode == AddressMode.RELATIVE:
                    tokens += [
                        InstructionTextToken(InstructionTextTokenType.TextToken, '('),
                        InstructionTextToken(InstructionTextTokenType.RegisterToken, IReg[r1]),
                        InstructionTextToken(InstructionTextTokenType.TextToken, ')')]
                elif mode == AddressMode.PC32 or mode == AddressMode.PC16:
                    tokens += [InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex((addr + constant) & 0xffffffff), (addr + constant) & 0xffffffff)]
                elif mode == AddressMode.ABS32 or mode == AddressMode.ABS16:
                    tokens += [InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(constant), constant)]
                elif mode == AddressMode.REL32 or mode == AddressMode.REL12:
                    tokens += [
                        # stack-relative offsets are usually not addresses
                        InstructionTextToken(InstructionTextTokenType.PossibleAddressToken if r1 != 15 else InstructionTextTokenType.IntegerToken, hex(constant), constant),
                        InstructionTextToken(InstructionTextTokenType.TextToken, '('),
                        InstructionTextToken(InstructionTextTokenType.RegisterToken, IReg[r1]),
                        InstructionTextToken(InstructionTextTokenType.TextToken, ')')]
                elif mode == AddressMode.PCX:
                    tokens += [
                        InstructionTextToken(InstructionTextTokenType.TextToken, '['),
                        InstructionTextToken(InstructionTextTokenType.RegisterToken, IReg[rx]),
                        InstructionTextToken(InstructionTextTokenType.TextToken, ']'),
                        InstructionTextToken(InstructionTextTokenType.TextToken, '('),
                        InstructionTextToken(InstructionTextTokenType.RegisterToken, 'pc'),
                        InstructionTextToken(InstructionTextTokenType.TextToken, ')')
                    ]
                elif mode == AddressMode.RELX:
                    tokens += [
                        InstructionTextToken(InstructionTextTokenType.TextToken, '['),
                        InstructionTextToken(InstructionTextTokenType.RegisterToken, IReg[rx]),
                        InstructionTextToken(InstructionTextTokenType.TextToken, ']'),
                        InstructionTextToken(InstructionTextTokenType.TextToken, '('),
                        InstructionTextToken(InstructionTextTokenType.RegisterToken, IReg[r1]),
                        InstructionTextToken(InstructionTextTokenType.TextToken, ')')
                    ]

        return tokens, length

    def get_instruction_low_level_il(self, data, addr, il):
        (instr, r1, r2, rx, constant, mode, _, length) = self.decode_instruction(data, addr)

        if instr is None:
            return None

        if InstructionIL.get(instr) is not None:
            if instr in ['db*', 'cdb', 'cdbeq', 'cdbne']:
                # decode and lift delay slot instructions
                (ds1_instr, ds1_r1, ds1_r2, ds1_rx, ds1_constant, ds1_mode, _, ds1_length) = self.decode_instruction(data[length:], addr + length)
                (ds2_instr, ds2_r1, ds2_r2, ds2_rx, ds2_constant, ds2_mode, _, ds2_length) = self.decode_instruction(data[length+ds1_length:], addr + length + ds1_length)

                ds1_il = InstructionIL[ds1_instr](il, addr + length, ds1_r1, ds1_r2, ds1_rx, ds1_constant, ds1_mode, ds1_length)
                ds2_il = InstructionIL[ds2_instr](il, addr + length + ds1_length, ds2_r1, ds2_r2, ds2_rx, ds2_constant, ds2_mode, ds2_length)

                length += ds1_length + ds2_length

                # handle 'db, loada, pushw' idiom as a call instruction
                if (instr == 'db*' and r2 == 0 and 
                    ds1_instr == 'loada' and (ds1_mode == AddressMode.PC16 or ds1_mode == AddressMode.PC32) and ds1_constant == ds1_length + ds2_length and 
                    ds2_instr == 'pushw' and ds1_r2 == ds2_r2 and ds2_r1 == 15):
                    il_instr = InstructionIL['call'](il, il.current_address, r1, ds2_r1, rx, constant, mode, length)
                else:
                    il_instr = InstructionIL[instr](il, il.current_address, r1, r2, rx, constant, mode, length, ds1_il, ds2_il)
            else:
                il_instr = InstructionIL[instr](il, il.current_address, r1, r2, rx, constant, mode, length)

            il_append(il, il_instr)
        else:
            log_warn('[0x{:4x}]: {} not implemented'.format(addr, instr))
            il.append(il.unimplemented())

        return length

    def get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il):
        if flag == 'v' or flag == 'c':
            # clear overflow and carry flags for instructions which affect but don't compute them
            if op == LowLevelILOperation.LLIL_SET_REG or op == LowLevelILOperation.LLIL_FSUB:
                return il.const(0, 0)
        elif flag == 'n' and op == LowLevelILOperation.LLIL_FSUB:
            # compute the negative flag for floating point comparison
            return il.float_compare_greater_equal(
                size,
                il.reg(size, operands[1]) if isinstance(operands[1], ILRegister) else il.const(size, operands[1]),
                il.reg(size, operands[0]) if isinstance(operands[0], ILRegister) else il.const(size, operands[0]))
 
        return Architecture.perform_get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il)

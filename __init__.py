
from binaryninja.architecture import Architecture
from binaryninja.callingconvention import CallingConvention

from clipper import CLIPPER
from rom import ROM
from coff import COFF
from disk import BootFloppy

class DefaultCallingConvention(CallingConvention):
    int_arg_regs = ['r0', 'r1']
    int_return_reg = 'r0'

# the fake _sc register holds the system call number
class SystemCallingConvention(CallingConvention):
    int_arg_regs = ['_sc','r0', 'r1', 'r2', 'r3']
    int_return_reg = 'r0'

CLIPPER.register()
ROM.register()
COFF.register()
BootFloppy.register()

arch = Architecture['clipper']
arch.register_calling_convention(DefaultCallingConvention(arch, 'default'))
arch.register_calling_convention(SystemCallingConvention(arch, 'syscall'))

platform = arch.standalone_platform
platform.default_calling_convention = arch.calling_conventions['default']
platform.system_call_convention = arch.calling_conventions['syscall']
platform.register('clix')

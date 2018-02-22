
from binaryninja.architecture import Architecture
from binaryninja.callingconvention import CallingConvention

from clipper import CLIPPER
from rom import ROM
from coff import COFF

class DefaultCallingConvention(CallingConvention):
    int_arg_regs = ['r0', 'r1']
    int_return_reg = 'r0'

    global_pointer_reg = 'fp'

CLIPPER.register()
ROM.register()
COFF.register()

arch = Architecture['clipper']
arch.register_calling_convention(DefaultCallingConvention(arch, 'default'))
standalone = arch.standalone_platform
standalone.default_calling_convention = arch.calling_conventions['default']
standalone.register('CLIX')

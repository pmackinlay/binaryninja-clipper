
from binaryninja.architecture import Architecture
from binaryninja.platform import Platform
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

standalone = arch.standalone_platform
standalone.default_calling_convention = arch.calling_conventions['default']

# this platform represents the base InterPro hardware, used by the boot
# ROMs, diagnostic tools and CLIX kernel
class InterProPlatform(Platform):
    name = 'interpro-clipper'

interpro = InterProPlatform(arch)
interpro.default_calling_convention = arch.calling_conventions['default']
interpro.register('interpro')

# this platform represents CLIX user-mode, used by the COFF binary view
class CLIXPlatform(Platform):
    name = 'clix-clipper'

clix = CLIXPlatform(arch)
clix.default_calling_convention = arch.calling_conventions['default']
clix.system_call_convention = arch.calling_conventions['syscall']
clix.register('clix')

import struct
import traceback

from binaryninja.platform import Platform
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol
from binaryninja.log import log_error, log_info
from binaryninja.enums import (SegmentFlag, SymbolType, SectionSemantics)

from unpack import unpack

# CLIPPER executables loaded from disk images. Currently only supports the
# Sapphire rebuild boot floppy (I/O system monitor and blue screen utilities)
# but should be extended to support others such as FDMDISK, etc.

# TODO:
#   - inject unpacked data into parent view
#   - refactor and complete hardware symbols

class BootFloppy(BinaryView):
    name = 'InterPro Bootable Floppy'
    long_name = 'InterPro Bootable Floppy'

    def __init__(self, data):
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)

    @classmethod
    def is_valid_for_data(self, data):
        hdr = data.read(0, 4)
        if len(hdr) < 4:
            return False

        if hdr[0:4] == 'sane':
            return True

        return False

    def init(self):
        self.platform = Platform['interpro-clipper']
        self.unpacked = []

        try:
            # read floppy partition header: floppypar(4)
            (magic, partition_count) = struct.unpack('<4sH', self.parent_view.read(0, 6))

            for partition_number in range(partition_count):
                # read partition information
                (par, mod, start_block, end_block) = struct.unpack('<2B2H', self.parent_view.read(6 + partition_number * 6, 6))
                log_info('par {:x}.{:x} start_block {} end_block {}'.format(par, mod, start_block, end_block))

                # read partition boot block: bootheader(4)
                (b_magic, b_checksum, b_processor, b_loadaddr, b_loadsize, b_uinitaddr, b_uinitsize, b_entry, b_time) = struct.unpack(
                    '<L2H6L', self.parent_view.read(start_block * 512, 32))
                log_info('  b_magic 0x{:x} b_checksum 0x{:x} b_processor {} b_loadaddr 0x{:x} b_loadsize 0x{:x} b_uinitaddr 0x{:x} b_uinitsize 0x{:x} b_entry 0x{:x}'.format(
                    b_magic, b_checksum, b_processor, b_loadaddr, b_loadsize, b_uinitaddr, b_uinitsize, b_entry))

                if par == 8 and b_processor == 1:
                    if mod == 0: # i/o system monitor
                        self.add_auto_segment(b_loadaddr, b_loadsize, (start_block + 1) * 512, b_loadsize, SegmentFlag.SegmentContainsCode | SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
                        self.add_auto_section('{:x}.{:x}.text'.format(par, mod), b_loadaddr, b_loadsize, SectionSemantics.ReadOnlyCodeSectionSemantics)
                        self.add_auto_segment(b_uinitaddr, b_uinitaddr, 0, 0, SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
                        self.add_auto_section('{:x}.{:x}.bss'.format(par, mod), b_uinitaddr, b_uinitsize, SectionSemantics.ReadWriteDataSectionSemantics)
                        self.add_entry_point(b_entry)

                    elif mod == 2: # blue screen utility
                        # hard-coded lookup to find copied code block offset based on partition checksum
                        copy_lookup = {
                            0xe5c5:0x48d98, # C400
                            0xb0d0:0x4ed98  # CLIPPER
                        }
                        copy_offset = copy_lookup[b_checksum]
                        copy_size = b_loadsize - copy_offset
                        copy_address = 0x280000

                        self.add_auto_segment(b_loadaddr, b_loadsize, (start_block + 1) * 512, copy_offset, SegmentFlag.SegmentContainsCode | SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
                        self.add_auto_section('{:x}.{:x}.boot'.format(par, mod), b_loadaddr, b_loadsize, SectionSemantics.ReadOnlyCodeSectionSemantics)

                        # copy loaded text
                        self.add_auto_segment(copy_address, copy_size, (start_block + 1) * 512 + copy_offset, copy_size, SegmentFlag.SegmentContainsCode | SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable)
                        self.add_auto_section('{:x}.{:x}.text'.format(par, mod), copy_address, copy_size, SectionSemantics.ReadOnlyCodeSectionSemantics)

                        # FIXME: for CLIPPER, the erased size should be copy_size + 0x69b00, unknown why

                        # create an unitialised data section directly after the copied data
                        self.add_auto_segment(copy_address + copy_size, 0x71450, 0, 0, SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
                        self.add_auto_section('{:x}.{:x}.bss'.format(par, mod), copy_address + copy_size, 0x71450, SectionSemantics.ReadWriteDataSectionSemantics)

                        # the first 8 pages contain vectors and hard-coded page mappings
                        #self.add_auto_segment(0, 0x8000, 0, 0, SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
                        #self.add_auto_section('vectors', 0x0, 0x8000, SectionSemantics.ReadWriteDataSectionSemantics)

                        self.add_entry_point(0x8000)

                elif par == 0xa:
                    # Diagnostic disk partition allocation is as follows:
                    #
                    #   mod   content
                    #     0   FDMDISK
                    #     2   Video
                    #     3   Digitizer
                    #     4   Token Ring
                    #     5   Hard PC
                    #    11   CLIPPER
                    #    12   Clock/Calendar
                    #    13   Ethernet
                    #    15   I/O Gate Array
                    #    16   Memory
                    #    17   Plotter
                    #    18   SCSI
                    #    19   Serial

                    if b_uinitsize > 0: # unpacked fdmdisk module
                        self.add_auto_segment(b_loadaddr, b_loadsize, (start_block + 1) * 512, b_loadsize, SegmentFlag.SegmentContainsCode | SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
                        self.add_auto_section('{:x}.{:x}.text'.format(par, mod), b_loadaddr, b_loadsize, SectionSemantics.ReadOnlyCodeSectionSemantics)
                        self.add_auto_segment(b_uinitaddr, b_uinitsize, 0, 0, SegmentFlag.SegmentContainsData | SegmentFlag.SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
                        self.add_auto_section('{:x}.{:x}.bss'.format(par, mod), b_uinitaddr, b_uinitsize, SectionSemantics.ReadWriteDataSectionSemantics)
                        self.add_entry_point(b_entry)

                    elif mod not in [3,4,5]: # packed fdmdisk module (3, 4, and 5 use the same address range, so can't be loaded together)
                        # temporarily map the boot segment
                        self.add_auto_segment(b_loadaddr, b_loadsize, (start_block + 1) * 512, b_loadsize, SegmentFlag.SegmentContainsCode | SegmentFlag.SegmentReadable)

                        # read packed data offset, unpacked entry point and unpacked bss address/size
                        (packed_addr, unpacked_entry, unpacked_bss_addr, unpacked_bss_size) = struct.unpack('<4L', self.read(b_loadaddr, 16))

                        # read unpacked start address and packed length
                        (unpacked_addr, packed_size) = struct.unpack('<2L', self.read(packed_addr, 8))

                        sections = []
                        while packed_size > 0:
                            # unpack a block of packed data
                            unpacked_data = unpack(self.read(packed_addr + 8, packed_size))

                            log_info('  unpacked data addr 0x{:x} size 0x{:x}'.format(unpacked_addr, len(unpacked_data)))

                            # record the unpacked start address/end addresses and data
                            section = [x for x in sections if x[0] + len(x[1]) == unpacked_addr]
                            if len(section) == 1:
                                log_info('    merging with existing unpacked data {:x}'.format(section[0][0]))
                                section[0][1] += unpacked_data
                            else:
                                log_info('    creating new unpacked data range {:x} length {:x}'.format(unpacked_addr, len(unpacked_data)))
                                sections += [[unpacked_addr, unpacked_data]]
                            
                            # find the next packed data block
                            packed_addr += (packed_size + 0x17) & ~0xf
                            (unpacked_addr, packed_size) = struct.unpack('<2L', self.read(packed_addr, 8))

                        # create sections
                        self.unpacked += sections
                        for unpacked in sections:
                            self.add_auto_section('{:x}.{:x}.text'.format(par, mod), unpacked[0], len(unpacked[1]), SectionSemantics.ReadOnlyCodeSectionSemantics)
                            
                        # unmap the boot segment
                        self.remove_auto_segment(b_loadaddr, b_loadsize)

                        self.add_auto_segment(unpacked_bss_addr, unpacked_bss_size, 0, 0, SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
                        self.add_auto_section('{:x}.{:x}.bss'.format(par, mod), unpacked_bss_addr, unpacked_bss_size, SectionSemantics.ReadWriteDataSectionSemantics)
                        self.add_entry_point(unpacked_entry)

            # test symbol creation
            for name,address in [
                ('timer2',     0x7f0fff5c),
                ('timer3',     0x7f0fff5e),
                ('scsi',       0x7f0fff60),
                ('floppy',     0x7f0fff62),
                ('plotter',    0x7f0fff64),
                ('cbus0',      0x7f0fff66),
                ('cbus1',      0x7f0fff68),
                ('cbus2',      0x7f0fff6a),
                ('vb',         0x7f0fff6c),
                ('ext7',       0x7f0fff6e),
                ('cbus3',      0x7f0fff70),
                ('rtc',        0x7f0fff72),
                ('60Hz',       0x7f0fff74),
                ('mouse',      0x7f0fff76),
                ('timer0',     0x7f0fff78),
                ('timer1',     0x7f0fff7a),
                ('serial_dma', 0x7f0fff7c),
                ('serial',     0x7f0fff7e),
                ('ethernet',   0x7f0fff80)]:
                self.define_auto_symbol(Symbol(SymbolType.ImportedDataSymbol, address + 0, 'ioga_icr_' + name))
                self.define_auto_symbol(Symbol(SymbolType.ImportedDataSymbol, address + 1, 'ioga_icr_' + name + '_ctrl'))

            for name,address in [
                ('prescaler',  0x7f0fff88),
                ('timer0',     0x7f0fff8c),
                ('timer1',     0x7f0fff90)]:
                self.define_auto_symbol(Symbol(SymbolType.ImportedDataSymbol, address, 'ioga_' + name))

            return True

        except:
			log_error(traceback.format_exc())
			return False

    def perform_is_executable(self):
    	return True

    def perform_get_length(self):
        return sum(len(x[1]) for x in self.unpacked)

    def perform_get_start(self):
        return min(x[0] for x in self.unpacked)

    def perform_read(self, addr, length):
        unpacked_range = [x for x in self.unpacked if x[0] <= addr < x[0] + len(x[1]) and x[0] <= addr + length <= x[0] + len(x[1])]

        if len(unpacked_range) == 1:
            start_offset = addr - unpacked_range[0][0]
            end_offset = start_offset + length

            return unpacked_range[0][1][start_offset:end_offset]
        else:
            return ''

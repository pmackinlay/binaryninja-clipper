import struct
import traceback

from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.log import log_error
from binaryninja.enums import (SegmentFlag, SymbolType, SectionSemantics)

# CLIPPER executables loaded from disk images. Currently only supports the
# Sapphire rebuild boot floppy (I/O system monitor and blue screen utilities)
# but should be extended to support others such as FDMDISK, etc.

class BootFloppy(BinaryView):
    name = 'InterPro Bootable Floppy'
    long_name = 'InterPro Bootable Floppy'

    def __init__(self, data):
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)

        self.platform = Architecture['clipper'].standalone_platform

    @classmethod
    def is_valid_for_data(self, data):
        hdr = data.read(0, 4)
        if len(hdr) < 4:
            return False

        if hdr[0:4] == 'sane':
            return True

        return False

    def init(self):
        try:
            (magic, partition_count) = struct.unpack('<4sH', self.parent_view.read(0, 6))
            for partition_number in range(partition_count):
                (par, mod, start_block, end_block) = struct.unpack('<2B2H', self.parent_view.read(6 + partition_number * 6, 6))

                # compute partition start and size based on 512 byte block size
                start = start_block * 512 + 512
                length = (end_block - start_block) * 512

                # TODO: use BN API to figure out the addresses and sizes of the bss and copied code sections
                # instead of hard-coding it here. The relevant figures are present as fixed immediate values
                # in the entry point code in each partition.

                if par == 8:
                    if mod == 0: # i/o system monitor
                        self.add_auto_segment(0x400000, length, start, length, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)

                        # bss start 0x42e778 size 0xcfa8
                        self.add_auto_section('par8mod0bss', 0x42e778, 0xcfa8, SectionSemantics.ReadWriteDataSectionSemantics)

                        self.add_entry_point(0x400000)

                    elif mod == 2: # blue screen utilities
                        self.add_auto_segment(0x8000, length - 0x8000, start + 0x8000, length - 0x8000, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
                        self.entry = 0x8000

                        # copy 0x25ad0 bytes from 0x48d98 to 0x280000
                        self.add_auto_segment(0x280000, 0x25ad0, start + 0x48d98, 0x25ad0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)

                        # clear the copied data
                        self.add_auto_section('erased', 0x48d98, 0x25ad0, SectionSemantics.ReadWriteDataSectionSemantics)

                        # bss start 0x71450 size 0x2a5ad0
                        self.add_auto_section('par8mod2bss', 0x2a5ad0, 0x71450, SectionSemantics.ReadWriteDataSectionSemantics)

                        self.add_entry_point(0x8000)

            return True

        except:
			log_error(traceback.format_exc())
			return False

    def perform_is_executable(self):
    	return True

    def perform_get_entry_point(self):
        return self.entry

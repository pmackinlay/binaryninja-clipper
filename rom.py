import struct
import traceback

from binaryninja.architecture import Architecture
from binaryninja.platform import Platform
from binaryninja.binaryview import BinaryView
from binaryninja.log import log_error
from binaryninja.enums import (SegmentFlag, SymbolType, SectionSemantics)

class ROM(BinaryView):
    name = 'InterPro ROM'
    long_name = 'InterPro ROM'

    def __init__(self, data):
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)

    @classmethod
    def is_valid_for_data(self, data):
        hdr = data.read(0, 16)
        if len(hdr) < 16:
            return False

        if hdr[4:8] == 'BoB!':
            self.rom_start = 0x7f100000
            self.rom_size = 0x40000
            return True

        if hdr[8:12] == 'SapH':
            self.rom_start = 0x7f100000
            self.rom_size = len(data)
            return True

        if hdr[8:12] == 'sAP4':
            self.rom_start = 0x7f180000
            self.rom_size = 0x40000
            return True

        return False

    def init(self):
        self.platform = Platform['interpro-clipper']

        try:
            self.add_auto_segment(self.rom_start, self.rom_size, 0, self.rom_size, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
            self.add_entry_point(self.rom_start)

            return True

        except:
			log_error(traceback.format_exc())
			return False

    def perform_is_executable(self):
    	return True

    def perform_get_entry_point(self):
        return self.rom_start

import struct
import traceback

from binaryninja.platform import Platform
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol
from binaryninja.log import log_error
from binaryninja.enums import (SegmentFlag, SymbolType, SectionSemantics)

from unpack import unpack

class ROM(BinaryView):
    name = 'InterPro ROM'
    long_name = 'InterPro ROM'

    def __init__(self, data):
        if data.read(0,16)[8:12] == 'sAP4':
            # read and unpack the packed data
            packed_offset = 0x37e70
            packed_size = struct.unpack('<L', data.read(packed_offset, 4))[0]
            unpacked_data = unpack(data.read(packed_offset + 4, packed_size))

            # substitute a new parent view with the unpacked data appended
            replacement_parent = BinaryView.new(data = data.read(0, len(data)) + unpacked_data)
            BinaryView.__init__(self, file_metadata=data.file, parent_view = replacement_parent)

            self.data = data
        else:
            BinaryView.__init__(self, parent_view = data, file_metadata = data.file)

    @classmethod
    def is_valid_for_data(self, data):
        header = data.read(0, 16)
        if len(header) < 16:
            return False

        if header[4:8] == 'Kate': # Emerald EPROM
            return True
        elif header[4:8] == 'BoB!': # Turquoise EPROM
            return True
        elif header[8:12] == 'SapH': # Sapphire EPROM
            return True
        elif header[8:12] == 'sAP4': # Sapphire flash
            return True
        else:
            return False

    def init(self):
        self.platform = Platform['interpro-clipper']

        try:
            # determine key parameters based on signature
            header = self.parent_view.read(0, 16)
            if header[4:8] == 'Kate':
                # Emerald EPROM
                self.rom_start = 0x7f100000
                self.rom_size = 0x40000
            elif header[4:8] == 'BoB!':
                # Turquoise EPROM
                self.rom_start = 0x7f100000
                self.rom_size = 0x40000
            elif header[8:12] == 'SapH':
                # Sapphire EPROM
                self.rom_start = 0x7f100000
                self.rom_size = len(self.parent_view)
            elif header[8:12] == 'sAP4':
                # Sapphire FLASH
                self.rom_start = 0x7f180000
                self.rom_size = 0x40000

                self.packed_addr = 0x7f1b7e70
                self.unpacked_addr = 0x7a0000
                self.unpacked_size = 0x20000
            else:
                return False

            actual_unpacked_size = len(self.parent_view) - self.rom_size

            # create the ROM segment, section and entry point
            self.add_auto_segment(self.rom_start, self.rom_size, 0, self.rom_size, SegmentFlag.SegmentContainsCode | SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
            self.add_auto_section('.rom', self.rom_start, self.rom_size, SectionSemantics.ReadOnlyCodeSectionSemantics)
            self.add_entry_point(self.rom_start)

            # create an unpacked segment and section if necessary
            if hasattr(self, 'unpacked_size'):
                self.add_auto_segment(self.unpacked_addr, self.unpacked_size, self.rom_size, actual_unpacked_size, SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
                self.add_auto_section('.unpacked', self.unpacked_addr, self.unpacked_size, SectionSemantics.ReadWriteDataSectionSemantics)

                self.define_auto_symbol(Symbol(SymbolType.DataSymbol, self.packed_addr, 'packed_data'))

            return True

        except:
			log_error(traceback.format_exc())
			return False

    def perform_is_executable(self):
    	return True

    def perform_get_entry_point(self):
        return self.rom_start

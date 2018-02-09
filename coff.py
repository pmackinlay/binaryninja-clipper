import struct
import traceback

from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView
from binaryninja.log import log_error
from binaryninja.enums import (SegmentFlag, SymbolType, SectionSemantics)

class COFF(BinaryView):
    name = 'CLIX COFF'
    long_name = 'CLIX COFF'

    def __init__(self, data):
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)

        self.platform = Architecture['clipper'].standalone_platform
        self.raw = data

    @classmethod
    def is_valid_for_data(self, data):
        header = data.read(0,20)
        if len(header) < 20:
            return False

        # check magic number
        if struct.unpack('<H', header[0:2])[0] == 0x017f:
            return True

        return False

    def init(self):
        try:
            #self.add_auto_segment(self.rom_start, self.rom_size, 0, self.rom_size, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)

            # header
            (f_magic, f_nscns, f_timdat, f_symptr, f_nsyms, f_opthdr, f_flags) = struct.unpack('<2H3L2H', self.raw.read(0, 20))
            log_error('header: {:x} {} {} {}'.format(f_magic, f_nscns, f_nsyms, f_opthdr))

            # optional header
            if f_opthdr == 36:
                (magic, version, tsize, dsize, bsize, self.entry, text_start, data_start, clipper) = struct.unpack('<2H6L8s', self.raw.read(20, 36))
                log_error('optional header: magic {:x} version {:x} tsize {:x} dsize {:x} bsize {:x} entry {:x} text_start {:x} data_start {:x}'.format(
                    magic, version, tsize, dsize, bsize, self.entry, text_start, data_start))

                self.add_entry_point(self.entry)

            # section headers
            for section in range(f_nscns):
                (s_name, s_paddr, s_vaddr, s_size, s_scnptr, s_relptr, s_lnnoptr, s_nreloc, s_nlnno, s_flags) = struct.unpack('<8s6L2HL', self.raw.read(20 + f_opthdr + section * 40, 40))
                s_name = s_name.split('\0', 1)[0]
                
                log_error('section header: name {} s_paddr {:x} s_vaddr {:x} s_size {:x} s_scnptr {:x} s_nreloc {} s_flags {:x}'.format(s_name, s_paddr, s_vaddr, s_size, s_scnptr, s_nreloc, s_flags))

                segment_flags = SegmentFlag.SegmentReadable
                section_flags = SectionSemantics.DefaultSectionSemantics

                # .text
                if s_flags & 0x20:
                    segment_flags |= SegmentFlag.SegmentExecutable | SegmentFlag.SegmentContainsCode
                    section_flags = SectionSemantics.ReadOnlyCodeSectionSemantics

                # .data
                if s_flags & 0x40:
                    segment_flags |= SegmentFlag.SegmentWritable | SegmentFlag.SegmentContainsData
                    section_flags = SectionSemantics.ReadWriteDataSectionSemantics

                # .bss
                if s_flags & 0x80:
                    segment_flags |= SegmentFlag.SegmentWritable
                    section_flags |= SectionSemantics.ReadWriteDataSectionSemantics

                # .comment, .lib
                if s_flags & 0x200 or s_flags & 0x800:
                    segment_flags |= SegmentFlag.SegmentContainsData
                    section_flags = SectionSemantics.ReadOnlyDataSectionSemantics

                # map segments which have a virtual address, a section pointer and are not marked noload
                if s_vaddr and s_scnptr and not s_flags & 0x2:
                    self.add_auto_segment(s_vaddr, s_size, s_scnptr, s_size, segment_flags)

                # map segments which exist in the file to the parent view
                if s_scnptr:
                    self.parent_view.add_auto_segment(s_scnptr, s_size, s_scnptr, s_size, segment_flags)

                # create the section entry
                if s_vaddr:
                    self.add_auto_section(s_name, s_vaddr, s_size, section_flags)
            self.store_metadata
            # section + reloc data
            # symbols

            return True


        except:
			log_error(traceback.format_exc())
			return False

    def perform_is_executable(self):
    	return True

    def perform_get_entry_point(self):
        return self.entry

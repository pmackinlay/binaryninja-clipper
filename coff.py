import struct
import traceback
import enum
import types
import os.path

from binaryninja.architecture import Architecture
from binaryninja.platform import Platform
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol
from binaryninja.log import log_error, log_info
from binaryninja.enums import (SegmentFlag, SymbolType, SectionSemantics)

class ElementSize(enum.IntEnum):
    """
    COFF file element sizes.
    """
    FILE      = 20
    OPTIONAL  = 36
    SECTION   = 40
    SYMBOL    = 18

class FileHeaderMagic(enum.IntEnum):
    CLIPPER = 0x017f

class FileHeaderFlags(enum.IntEnum):
    """
    COFF file header f_flags field bits.
    """
    RELFLG = 0x0001 # relocation info stripped from file
    EXEC   = 0x0002 # file is executable  (i.e. no unresolved externel references)
    LNNO   = 0x0004 # line nunbers stripped from file
    LSYMS  = 0x0008 # local symbols stripped from file
    MINMAL = 0x0010 # this is a minimal object file (".m") output of fextract
    UPDATE = 0x0020 # this is a fully bound update file, output of ogen
    SWABD  = 0x0040 # this file has had its bytes swabbed (in names)
    AR16WR = 0x0080 # this file has the byte ordering of an AR16WR (e.g. 11/70) machine (it was created there, or was produced by conv)
    AR32WR = 0x0100 # this file has the byte ordering of an AR32WR machine(e.g. vax)
    AR32W  = 0x0200 # this file has the byte ordering of an AR32W machine (e.g. 3b,maxi)
    PATCH  = 0x0400 # file contains "patch" list in optional header
    NODF   = 0x0800 # (minimal file only) no decision functions for replaced functions

class SectionType(enum.IntEnum):
    """
    COFF section header s_flags field bits.
    """
    NOLOAD = 0x0002
    TEXT   = 0x0020
    DATA   = 0x0040
    BSS    = 0x0080
    INFO   = 0x0200
    LIB    = 0x0800

class COFF(BinaryView):
    name = 'CLIPPER COFF'
    long_name = 'CLIPPER COFF'

    def __init__(self, data):
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)

    @classmethod
    def is_valid_for_data(self, data):
        header = data.read(0,20)
        if len(header) < 20:
            return False

        # check magic number
        if struct.unpack('<H', header[0:2])[0] == FileHeaderMagic.CLIPPER:
            return True

        return False

    def init(self):
        self.platform = Platform['clix-clipper']

        try:
            # file header
            (f_magic, f_nscns, f_timdat, f_symptr, f_nsyms, f_opthdr, self.f_flags) = struct.unpack('<2H3L2H', self.parent_view.read(0, ElementSize.FILE))
            log_info('file header: f_magic 0x{:x} f_nscns {} f_symptr 0x{:x} f_nsyms {} f_opthdr {} f_flags 0x{:x}'.format(
                f_magic, f_nscns, f_symptr, f_nsyms, f_opthdr, self.f_flags))

            # optional header (not present in object files)
            if f_opthdr == ElementSize.OPTIONAL:
                (magic, version, tsize, dsize, bsize, self.entry, text_start, data_start, clipper_flags) = struct.unpack(
                    '<2H6L8s', self.parent_view.read(ElementSize.FILE, ElementSize.OPTIONAL))
                log_info('optional header: magic 0x{:x} version 0x{:x} tsize 0x{:x} dsize 0x{:x} bsize 0x{:x} entry 0x{:x} text_start 0x{:x} data_start 0x{:x}'.format(
                    magic, version, tsize, dsize, bsize, self.entry, text_start, data_start))

                self.add_entry_point(self.entry)

            # section headers
            for section_number in range(f_nscns):
                (s_name, s_paddr, s_vaddr, s_size, s_scnptr, s_relptr, s_lnnoptr, s_nreloc, s_nlnno, s_flags) = struct.unpack(
                    '<8s6L2HL', self.parent_view.read(ElementSize.FILE + f_opthdr + section_number * ElementSize.SECTION, ElementSize.SECTION))
                s_name = s_name.split('\0', 1)[0]
                
                log_info('section header: section {} name {} s_paddr 0x{:x} s_vaddr 0x{:x} s_size 0x{:x} s_scnptr 0x{:x} s_nreloc {} s_flags 0x{:x}'.format(
                    section_number + 1, s_name, s_paddr, s_vaddr, s_size, s_scnptr, s_nreloc, s_flags))

                map_section = False
                segment_flags = SegmentFlag.SegmentReadable
                section_flags = SectionSemantics.DefaultSectionSemantics

                # .text
                if s_flags & SectionType.TEXT:
                    map_section = True
                    segment_flags |= SegmentFlag.SegmentExecutable | SegmentFlag.SegmentContainsCode
                    section_flags = SectionSemantics.ReadOnlyCodeSectionSemantics

                # .data
                if s_flags & SectionType.DATA:
                    map_section = True
                    segment_flags |= SegmentFlag.SegmentWritable | SegmentFlag.SegmentContainsData
                    section_flags = SectionSemantics.ReadWriteDataSectionSemantics

                # .bss
                if s_flags & SectionType.BSS:
                    map_section = True
                    segment_flags |= SegmentFlag.SegmentWritable | SegmentFlag.SegmentContainsData
                    section_flags |= SectionSemantics.ReadWriteDataSectionSemantics

                # .comment
                if s_flags & SectionType.INFO:
                    segment_flags |= SegmentFlag.SegmentContainsData
                    section_flags = SectionSemantics.ReadOnlyDataSectionSemantics

                    log_info('  content: {}'.format(self.parent_view.read(s_scnptr, s_size).split('\0', 1)[0]))

                # .lib
                if s_flags & SectionType.LIB:
                    segment_flags |= SegmentFlag.SegmentContainsData
                    section_flags = SectionSemantics.ReadOnlyDataSectionSemantics

                    offset = s_scnptr
                    for library_number in range(s_paddr):
                        (entsize, entoff) = struct.unpack('<LL', self.parent_view.read(offset, 8))
                        lib_path = self.parent_view.read(offset + 8 + (entoff - 2) * 4, (entsize - entoff) * 4)
                        offset += entsize * 4

                        self.load_library_symbols(lib_path.split('\0', 1)[0])

                # load segments which have a virtual address and are not marked noload
                if map_section and not s_flags & SectionType.NOLOAD:
                    self.add_auto_segment(s_vaddr, s_size, s_scnptr, s_size if s_scnptr else 0, segment_flags)

                # load segments which exist in the file to the parent view
                if s_scnptr:
                    self.parent_view.add_auto_segment(s_scnptr, s_size, s_scnptr, s_size, segment_flags)

                # create the section entry
                if map_section:
                    self.add_auto_section(s_name, s_vaddr, s_size, section_flags)

            # TODO: relocations

            # symbols
            if not self.f_flags & FileHeaderFlags.LSYMS and f_symptr and f_nsyms:
                # read the string table
                stable_size = struct.unpack('<L', self.parent_view.read(f_symptr + f_nsyms * ElementSize.SYMBOL, 4))[0]
                string_table = self.parent_view.read(f_symptr + f_nsyms * ElementSize.SYMBOL, stable_size)

                log_info('symbol table')
                log_info('{:32}    n_value n_scnum n_type n_sclass n_numaux'.format('n_name'))
                n_name = ''
                n_scnum = 0
                n_numaux = 0

                for symbol_number in range(f_nsyms):
                    # handle auxiliary entries
                    if n_numaux:
                        # x_sym type
                        #(x_tagndx, x_lnno, x_size, x_lnnoptr, x_endndx, x_tvndx) = struct.unpack('<lHHllH', self.parent_view.read(f_symptr + symbol_number * ElementSize.AUXILIARY, ElementSize.AUXILIARY))
                        #log_info('auxent {}: x_tagndx {} x_lnno {} x_size {} x_lnnoptr {} x_endndx {} x_tvndx {}'.format(symbol_number, x_tagndx, x_lnno, x_size, x_lnnoptr, x_endndx, x_tvndx))

                        # x_file type
                        if n_scnum == -2:
                            x_fname = self.parent_view.read(f_symptr + symbol_number * ElementSize.SYMBOL, ElementSize.SYMBOL)
                            log_info('  x_fname: {}'.format(x_fname.split('\0', 1)[0]))
                        # x_scn type
                        elif n_name[0] == '.':
                            (x_scnlen, x_nreloc, x_nlinno) = struct.unpack('<lHH', self.parent_view.read(
                                f_symptr + symbol_number * ElementSize.SYMBOL, 8))
                            log_info('  x_scnlen 0x{:x} x_nreloc {} x_nlinno {}'.format(x_scnlen, x_nreloc, x_nlinno))

                        # x_tv type (transfer vector)
                        #(x_tvfill, x_tvlen, x_tvran0, x_tvran1) = struct.unpack('<lHHH', self.parent_view.read(f_symptr + symbol_number * ElementSize.AUXILIARY, ElementSize.AUXILIARY))

                        n_numaux -= 1
                        continue

                    (n_name, n_value, n_scnum, n_type, n_sclass, n_numaux) = struct.unpack('<8sLhHbb', self.parent_view.read(
                        f_symptr + symbol_number * ElementSize.SYMBOL, ElementSize.SYMBOL))

                    # use the name as-is or look it up in the string table
                    (n_zeros, n_offset) = struct.unpack('<ll', n_name)
                    name = (string_table[n_offset:] if n_zeros == 0 else n_name).split('\0', 1)[0]

                    log_info('{:32} 0x{:08x} {:7} 0x{:04x}     0x{:02x}     0x{:02x}'.format(
                        name, n_value, n_scnum, n_type, n_sclass, n_numaux))

                    if n_numaux == 0 and (n_sclass == 2 or n_sclass == 3): # extern or static
                        if n_scnum == 0: # undefined section (imported symbol)
                            #sym = Symbol(SymbolType.ImportAddressSymbol, n_value, name)
                            #self.define_auto_symbol(sym)
                            pass
                        elif n_scnum > 0: # regular section
                            # find the first matching section for the symbol value
                            sections = self.get_sections_at(n_value)
                            if len(sections) == 0:
                                continue

                            # define a code or data symbol depending on the section
                            sym = Symbol(
                                SymbolType.FunctionSymbol if sections[0].semantics & SectionSemantics.ReadOnlyCodeSectionSemantics else SymbolType.DataSymbol, 
                                n_value, 
                                name)

                            # HACK: try to avoid making functions for local labels
                            #if n_sclass == 2 or sym.type == SymbolType.DataSymbol:
                            #    self.define_auto_symbol_and_var_or_function(sym, None)
                            #else:
                            self.define_auto_symbol(sym)

            return True

        except:
			log_error(traceback.format_exc())
			return False

    def perform_is_executable(self):
    	return self.f_flags & FileHeaderFlags.EXEC

    def perform_is_relocatable(self):
    	return not self.f_flags & FileHeaderFlags.RELFLG

    def perform_get_entry_point(self):
        return self.entry

    def load_library_symbols(self, path):
        log_info('  shared library: {}'.format(path))

        try:
            # try to load the shared library from the same path as the main file
            library_filename = os.path.normpath(
                os.path.join(os.path.dirname(self.file.filename), os.path.basename(path)))
            log_info('    loading from {}'.format(library_filename))
            library = open(library_filename, 'rb')

            # file header
            (f_magic, f_nscns, f_timdat, f_symptr, f_nsyms, f_opthdr, f_flags) = struct.unpack('<2H3L2H', library.read(ElementSize.FILE))

            # symbols
            if not f_flags & FileHeaderFlags.LSYMS and f_symptr and f_nsyms:
                # read the string table
                library.seek(f_symptr + f_nsyms * ElementSize.SYMBOL)
                stable_size = struct.unpack('<L', library.read(4))[0]
                library.seek(f_symptr + f_nsyms * ElementSize.SYMBOL)
                string_table = library.read(stable_size)

                # process the symbol table
                library.seek(f_symptr)
                n_numaux = 0
                for symbol_number in range(f_nsyms):

                    # read a symbol
                    symbol_data = library.read(ElementSize.SYMBOL)

                    # skip auxiliary entries
                    if n_numaux:
                        n_numaux -= 1
                        continue

                    # unpack symbol fields
                    (n_name, n_value, n_scnum, n_type, n_sclass, n_numaux) = struct.unpack('<8sLhHbb', symbol_data)

                    # use the name as-is or look it up in the string table
                    (n_zeros, n_offset) = struct.unpack('<ll', n_name)
                    name = (string_table[n_offset:] if n_zeros == 0 else n_name).split('\0', 1)[0]

                    # only consider exported extern symbols
                    if n_sclass == 2 and n_scnum > 0:
                        section = self.get_sections_at(n_value)[0]

                        sym = Symbol(
                            SymbolType.ImportedFunctionSymbol if section.semantics & SectionSemantics.ReadOnlyCodeSectionSemantics else SymbolType.ImportedDataSymbol, 
                            n_value, 
                            name)

                        self.define_auto_symbol(sym)

            library.close()

        except:
            log_error('    failed to load symbols from {}'.format(library_filename))
            log_error(traceback.format_exc())

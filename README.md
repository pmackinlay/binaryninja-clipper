# CLIPPER Architecture Plugin (v0.3)
Author: **Patrick Mackinlay**

_A disassembler and lifter for the CLIPPER architecture, and loaders for
CLIPPER ROM images and COFF object/executable files._

## Description

[This plugin](clipper.py) disassembles CLIPPER assembly code and generates LLIL.

The plugin also contains three binary views, the [first](rom.py) of which is able
to load InterPro computer system boot and flash ROM images. The [second](coff.py) is
designed to handle COFF executable and object files as used by CLIX (UNIX SYSVR3
for CLIPPER systems). The [third](disk.py) binary view handles disk partition
images, specifically the REBUILD boot floppy disk image (and the I/O system monitor
and blue screen utility code contained).

The CLIPPER architecture plugin has the following known issues:

* Stack operations using registers other than r15 are not implemented.
* Incomplete handling of condition codes/flags.
* System calls are not fully implemented.
* Some C400 instructions are unimplemented, especially delayed branches.

The COFF binary view has the following known issues:

* Does not properly support relocatable files or imported symbols.
* Non-exported code symbols do not create functions; this is a workaround
until some method of disambiguating functions from simple local labels
can be identified.
* Produces quite a lot of logging "noise", dumping information decoded from
the input file such as section information and the symbol table. This will
be toned down when testing on a broader range of input files has been completed.

## Installation

To install this plugin, navigate to your Binary Ninja plugins directory, and run:

```git clone https://github.com/pmackinlay/binaryninja-clipper.git clipper```

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * 1.1.1073

## License

This plugin is released under a [MIT](LICENSE) license.

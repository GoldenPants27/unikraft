#!/usr/bin/env python3

import argparse
import subprocess
import os
import re

ELF64_EHDR_LEN = 64
MS_DOS_SIGNATURE = 0x5a4d
MS_DOS_STUB_SZ = 0x40
PE_SEC_SZ = 40
# All sections that we obtain from the PT_LOAD Program Headers must be
# writable, since we have to apply initial relocations. We are going to
# change permissions ourselves afterwards anyway.
PE_SEC_CHARACTERISTICS = (
                                0x00000040 |  # IMAGE_SCN_CNT_INITIALIZED_DATA
                                0x00d00000 |  # IMAGE_SCN_ALIGN_4096BYTES
                                0x20000000 |  # IMAGE_SCN_MEM_EXECUTE
                                0x40000000 |  # IMAGE_SCN_MEM_READ
                                0x80000000    # IMAGE_SCN_MEM_WRITE
                         )

# Get the absolute value of symbol, as seen through `nm`
def get_sym_val(elf, sym):
    exp = r'^\s*' + r'([a-f0-9]+)' + r'\s+[A-Za-z]\s+' + sym + r'$'
    out = subprocess.check_output(['nm', elf])

    re_out = re.findall(exp, out.decode('ASCII'), re.MULTILINE)
    if len(re_out) != 1:
        raise Exception('Found no ' + sym + ' symbol.')

    return int(re_out[0], 16)

# Get a list of all the PT_LOAD Program Headers
HEXNUM_EXP = r'0x[a-f0-9]+'
def get_loadable_phdrs(elf):
    exp = (r'^\s*' + r'LOAD' + r'\s*' +
           r'(' + HEXNUM_EXP + r')' + r'\s*' +
           r'(' + HEXNUM_EXP + r')' + r'\s*' +
           HEXNUM_EXP + r'\s*' +
           r'(' + HEXNUM_EXP + r')' + r'\s*' +
           r'(' + HEXNUM_EXP + r')' + r'\s*' +
           r'(' + r'[RWE ]+' + r')' + r'\s*' +
           HEXNUM_EXP + r'$')
    out = subprocess.check_output(["readelf", "-l", elf],
                                   stderr=subprocess.DEVNULL)
    re_out = re.findall(exp, out.decode('ASCII'), re.MULTILINE)

    return [{
                "Offset"    : int(r[0], 16),
                "VirtAddr"  : int(r[1], 16),
                "FileSiz"   : int(r[2], 16),
                "MemSiz"    : int(r[3], 16),
                "Flags"     : r[4].replace(' ', '')
            } for r in re_out]

def main():
    parser = argparse.ArgumentParser(
    description='Update the fake PE32 header with the required metadata to'
                'be bootable by a UEFI environment and overwrite the ELF64'
                'Header with an empty MS-DOS stub.')
    parser.add_argument('elf', help='path to ELF64 binary to process')
    opt = parser.parse_args()

    # We need to operate on the debug image for symbol values. But as far as
    # ELF sections go, using the final image is enough.
    elf_dbg = opt.elf + ".dbg"

    # Consider the first PT_LOAD Segment as the first in the file.
    ld_phdrs = get_loadable_phdrs(opt.elf)
    # Make sure they are sorted by their addresses
    ld_phdrs = sorted(ld_phdrs, key=lambda x: x['VirtAddr'])

    # Make sure that we can fit all of the sections. Do not forget to include
	# the implicit `.reloc` PE section.
    pe_hdr_sz = (get_sym_val(elf_dbg, r'pe_hdr_end') -
				 get_sym_val(elf_dbg, r'pe_hdr_start'))
    if (len(ld_phdrs) + 1) * PE_SEC_SZ > pe_hdr_sz:
        raise Exception("PE Header to small to fit all the required sections")

    # Again, all addresses relative to the very base of the file, because PE
    # loading considers the PE header as the first thing loaded.
    # Use the first function in our EFI stub as the entry point.
    entry_rva = get_sym_val(elf_dbg, r'uk_efi_entry64')
    entry_rva += ld_phdrs[0]['Offset'] - ld_phdrs[0]['VirtAddr']

    # Image size in memory is equal to the last PT_LOAD + its size, so to get
    # the final size of the loaded image in memory subtract the base_address.
    # Thus: Image Size = .bss vaddr + .bss size in memory - _base_addr
    img_sz = ld_phdrs[-1]['VirtAddr'] + ld_phdrs[-1]['MemSiz']
    img_sz -= get_sym_val(elf_dbg, r'_base_addr')

    # Since it is a PE, the Header and MS-DOS stub will also get loaded, so add
    # the stub's size (in-file offset to first PT_LOAD) as well.
    img_sz += ld_phdrs[0]['Offset']

    # Re-adjust start addresses of the PT_LOAD's.
    for lp in ld_phdrs[1:]:
        lp['VirtAddr'] += ld_phdrs[0]['Offset'] - ld_phdrs[0]['VirtAddr']
    ld_phdrs[0]['VirtAddr'] = ld_phdrs[0]['Offset'] + pe_hdr_sz
    ld_phdrs[0]['MemSiz'] -= pe_hdr_sz
    pe_hdr_off = MS_DOS_STUB_SZ + ld_phdrs[0]['Offset']
    ld_phdrs[0]['Offset'] += pe_hdr_sz

    # PE is loaded by sections, thus the fake PE Header encodes the PT_LOAD's
    # as follows:
    # - dummy .reloc section since UEFI wants relocatable PE's
    # - all the other ELF Program Headers as PE sections with all permissions
    # enabled (RWX)
    with open(opt.elf, 'r+b') as f:
        elf_file = f.read()

        # Write the MS-DOS signature
        f.seek(0)
        f.write(MS_DOS_SIGNATURE.to_bytes(2, 'little'))

        # Jump to the end of the MS-DOS stub, where the value of the offset to
        # the actual PE Header is expected.
        f.seek(MS_DOS_STUB_SZ - 4)
        f.write(pe_hdr_off.to_bytes(4, 'little'))

        # Finished prepending MS-DOS stub, now copy initial ELF file
        f.write(elf_file)

        # Jump to the PE Header and skip over MS-DOS stub
        f.seek(pe_hdr_off)
        # Jump to NumberOfSections and update number of sections
        f.seek(6, 1)
        f.write((len(ld_phdrs) + 1).to_bytes(2, 'little'))
        # Skip to optional_header
        f.seek(16, 1)
        # Skip to SizeOfCode
        f.seek(4, 1)
        f.write(ld_phdrs[0]['FileSiz'].to_bytes(4, 'little'))# SizeOfCode
        # Skip to AddressOfEntryPoint
        f.seek(8, 1)
        f.write(entry_rva.to_bytes(4, 'little'))             # AddressOfEntryPoint
        f.write(ld_phdrs[0]['Offset'].to_bytes(4, 'little')) # BaseOfCode

        # Jump to xhdr_fields from PE Header and skip optional_header
        f.seek(pe_hdr_off + 48)
        # Skip to SizeOfImage
        f.seek(32, 1)
        f.write(img_sz.to_bytes(4, 'little'))                # SizeOfImage

        # Jump to .reloc section header.
        # We are writing a dummy .reloc. We will make UEFI overwrite the
        # unneeded last fields of the header (PointerToRelocations,
        # PointerToLineNumbers, NumberOfRelocations, NumberOfLineNumbers and
        # Characteristics) thinking of it as a relocation by overwriting
        # VirtualAddress and PointerToRawData to point to these sections.
        f.seek(pe_hdr_off + 184)
        # Skip Name and VirtualSize and go to Virtual Address
        f.seek(8 + 4, 1)
        f.write((f.tell() + 12).to_bytes(4, 'little'))       # VirtualAddress
        # Skip SizeOfRawData and go to PointerToRawData
        f.seek(4, 1)
        f.write((f.tell() + 4).to_bytes(4, 'little'))        # PointerToRawData

        def apply_phdr_to_sec(p, sec_off):
            f.seek(sec_off)

            f.write(b"UK_PHDR\0")
            f.write(p['MemSiz'].to_bytes(4, 'little'))       # VirtualSize
            f.write(p['VirtAddr'].to_bytes(4, 'little'))     # VirtualAddress
            f.write(p['FileSiz'].to_bytes(4, 'little'))      # SizeOfRawData
            p_off = MS_DOS_STUB_SZ + p['Offset']             # Update file offset
            f.write(p_off.to_bytes(4, 'little'))             # PointerToRawData

            # Skip the other fields of the .text section header:
            # PointerToRelocations, PointerToLineNumbers, NumberOfRelocations,
            # NumberOfLineNumbers.
            f.seek(12, 1)
            # Update Characteristics of PE sections
            f.write(PE_SEC_CHARACTERISTICS.to_bytes(4, 'little'))

        # Jump to .text section (offset to PE header + offset to .reloc section
        # header + size of .reloc section header).
        f.seek(pe_hdr_off + 184 + 40)

        # Now encapsulate the PT_LOAD's into PE sections
        for p in ld_phdrs:
            apply_phdr_to_sec(p, f.tell())

if __name__ == '__main__':
    main()

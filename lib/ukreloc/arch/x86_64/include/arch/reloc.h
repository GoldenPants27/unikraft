/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#ifndef __X86_64_UK_RELOC_H__
#define __X86_64_UK_RELOC_H__

#include "../../../include/uk/reloc.h"

#ifdef __ASSEMBLY__

/* Relocation friendly ur_mov to replace mov instructions incompatible with
 * a PIE binary. Usage example:
 * ```
 * ur_mov	gdt64_ptr, %eax, 4
 * ```
 * The above will make mkukreloc.py process the symbol gdt64_ptr_ukeloc_imm4
 * representing in memory where this data is placed and the following entry:
 * struct ukreloc {
 *        __u64 r_mem_off = gdt64_ptr_ukeloc_imm4 - __BASE_ADDR
 *        __u64 r_addr = gdt64_ptr - __BASE_ADDR
 *        __u32 r_sz = 4 from gdt64_ptr_ukeloc_imm[4]
 *        __u32 flags = 0
 * } __packed;
 *
 * If CONFIG_OPTIMIZE_PIE is not enabled then it will be simply resolved to
 * ```
 * mov	$gdt64_ptr, %eax
 * ```
 *
 * @param sym The symbol to relocate
 * @param req The register into which to place the value
 * @param bytes The size in bytes of the relocation
 * @param flags Optional, if value is _phys, UKRELOC_FLAGS_PHYS_REL is set
 */
.macro ur_mov	sym:req, reg:req, bytes:req, flags
#ifdef CONFIG_OPTIMIZE_PIE
/* UKRELOC_PLACEHODER is 16 bits, so in 64-bit code we must force a `movabs`
 * to ensure that the last amount of opcodes are meant for the immediate
 */
.ifeq  (8 - \bytes)
	movabs	$UKRELOC_PLACEHOLDER, \reg
.endif
.ifgt  (8 - \bytes)
	mov	$UKRELOC_PLACEHOLDER, \reg
.endif
	ur_sym	\sym\()_ukreloc_imm\bytes\()\flags\(), (. - \bytes)
	nop
	ur_sec_updt	\sym
#else
	mov	$\sym, \reg
#endif
.endm

#endif /* __ASSEMBLY__ */

#endif /* __X86_64_UK_RELOC_H__ */

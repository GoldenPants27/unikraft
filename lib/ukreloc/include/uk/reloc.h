/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#ifndef __UKRELOC_H__
#define __UKRELOC_H__

#define UKRELOC_FLAGS_PHYS_REL		(1 << 0)
#define UKRELOC_PLACEHOLDER		0xB00B
#define UKRELOC_SIGNATURE		0xBADB0111
#define UKRELOC_ALIGNMENT		0x1000

#ifdef __ASSEMBLY__

/* Used to append an entry to the initial .ukreloc section, before mkukreloc.py
 * adds the .rela.dyn entries. Furthermore, also append an entry to
 * .rela.dyn to ensure the symbol is not discarded and is seen as a relocation
 * by the linker.
 *
 * @param sym
 *   The symbol to use for the relocation.
 */
#if defined(__X86_64__)
#define RELA_DYN_ENTRY_TYPE R_X86_64_64
#elif defined(__ARM_64__)
#define RELA_DYN_ENTRY_TYPE R_AARCH64_ABS64
#endif
.macro ur_sec_updt	sym:req
.pushsection .ukreloc
	.quad	0x0			/* r_mem_off */
	.quad	0x0			/* r_addr */
	.reloc	., RELA_DYN_ENTRY_TYPE, \sym
	.long	0x0			/* r_sz */
	.long	0x0			/* flags */
.popsection
.endm

/*
 * Generate a unique ukreloc symbol.
 *
 * @param sym
 *   The base symbol off which we generate the ukreloc symbol.
 * @param val
 *   The value of the symbol to generate.
 */
.macro ur_sym	sym:req, val:req
.globl \sym
.set \sym\()_\@\(), \val
.endm

/* If CONFIG_OPTIMIZE_PIE is enabled, this will create a ukreloc symbol that
 * mkukreloc.py will process. Example usage:
 * ```
 * ur_data	quad, gdt64, 8, _phys
 * ```
 * The above will make mkukreloc.py process the symbol gdt64_ukeloc_data8_phys
 * representing in memory where this data is placed and the following entry:
 * struct ukreloc {
 *        __u64 r_mem_off = gdt64_ukeloc_data8_phys - __BASE_ADDR
 *        __u64 r_addr = gdt64 - __BASE_ADDR
 *        __u32 r_sz = 8 from gdt64_ukeloc_data[8]_phys
 *        __u32 flags = UKRELOC_FLAGS_PHYS_REL from gdt64_ukreloc_data8[_phys]
 * } __packed;
 *
 * If CONFIG_OPTIMIZE_PIE is not enabled then it will be simply resolved to
 * ```
 * .quad gdt64
 * ```
 * @param type The type GAS directive, i.e. quad, long, short, etc.
 * @param sym The symbol to relocate
 * @param bytes The size in bytes of the relocation
 * @param flags Optional, if value is _phys, UKRELOC_FLAGS_PHYS_REL is set
 */
.macro ur_data	type:req, sym:req, bytes:req, flags
#ifdef CONFIG_OPTIMIZE_PIE
	ur_sym	\sym\()_ukreloc_data\bytes\()\flags\(), .
	.\type	UKRELOC_PLACEHOLDER
	ur_sec_updt	\sym
#else
	.\type	\sym
#endif
.endm

#else  /* __ASSEMBLY__ */

#include <uk/arch/types.h>
#include <uk/essentials.h>

struct ukreloc {
	/* Offset relative to runtime base address where to apply relocation */
	__u64 r_mem_off;
	/* Relative address value of the relocation */
	__u64 r_addr;
	/* Size of the relocation */
	__u32 r_sz;
	/* Relocation flags to change relocator behavior for this entry */
	__u32 flags;
} __packed;

UK_CTASSERT(sizeof(struct ukreloc) == 24);

#define UKRELOC_ENTRY(ur_r_mem_off, ur_r_addr, ur_r_sz, ur_flags)	\
	{								\
		.r_mem_off	= (ur_r_mem_off),			\
		.r_addr		= (ur_r_addr),				\
		.r_sz		= (ur_r_sz),				\
		.flags		= (ur_flags),				\
	}

struct ukreloc_hdr {
	/* Signature of the .ukreloc section */
	__u32 signature;
	/* The ukreloc entries to be iterated upon by the relocator */
	struct ukreloc urs[];
} __packed;

UK_CTASSERT(sizeof(struct ukreloc_hdr) == 4);

#endif /* !__ASSEMBLY__ */

#endif /* __UKRELOC_H__ */

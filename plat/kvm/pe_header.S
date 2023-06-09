#include <uk/config.h>
#include <uk/asm.h>
#include <uk/arch/limits.h>

/* Signature (Image Only) */
#define PE_MAGIC					0x00004550

/* COFF File Header (Object and Image) */
#define	IMAGE_FILE_MACHINE_AMD64			0x8664
#define IMAGE_FILE_MACHINE_ARM64			0xaa64

/* Characteristics
 * Flags for attributes of the object or image file
 */
#define IMAGE_FILE_DEBUG_STRIPPED			0x0200
#define IMAGE_FILE_EXECUTABLE_IMAGE			0x0002
#define IMAGE_FILE_LINE_NUMS_STRIPPED			0x0004

/* Optional Header Standard Fields (Image Only) */
#define PE_OPT_HDR_MAGIC_PE32PLUS			0x020b
#define IMAGE_SUBSYSTEM_EFI_APPLICATION			10

#define IMAGE_SCN_MEM_SHARED				0x10000000
#define IMAGE_SCN_MEM_EXECUTE				0x20000000
#define IMAGE_SCN_MEM_READ				0x40000000
#define IMAGE_SCN_MEM_WRITE				0x80000000
#define IMAGE_SCN_CNT_CODE				0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA			0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA		0x00000080
#define IMAGE_SCN_ALIGN_1BYTES				0x00100000
#define IMAGE_SCN_ALIGN_4096BYTES			0x00d00000
#define IMAGE_SCN_MEM_DISCARDABLE			0x02000000

#if defined(__X86_64__)
#define PE_ARCH						IMAGE_FILE_MACHINE_AMD64
#elif defined(__ARM_64__)
#define PE_ARCH						IMAGE_FILE_MACHINE_ARM64
#endif

.section .data.boot
pe_hdr_start:
	.long PE_MAGIC

coff_header:
	.short	PE_ARCH				/* Machine */
	.short	0				/* NumberOfSections */
	.long	0				/* TimeDateStamp */
	.long	0				/* PointerToSymbolTable */
	.long	0				/* NumberOfSymbols */
	.short	section_tab - opt_hdr		/* SizeOfOptionalHeader */
	.short	IMAGE_FILE_EXECUTABLE_IMAGE	| \
		IMAGE_FILE_DEBUG_STRIPPED	| \
		IMAGE_FILE_LINE_NUMS_STRIPPED	/* Characteristics */

opt_hdr:
	.short	PE_OPT_HDR_MAGIC_PE32PLUS	/* Magic */
	.byte	0				/* MajorLinkerVersion */
	.byte	0				/* MinorLinkerVersion */
	.long	0				/* SizeOfCode */
	.long	0				/* SizeOfInitializedData */
	.long	0				/* SizeOfUninitializedData */
	.long	0				/* AddressOfEntryPoint */
	.long	0				/* BaseOfCode */

xhdr_fields:
	.quad	_base_addr			/* ImageBase */
	.long	__PAGE_SIZE			/* SectionAlignment */
	.long	__PAGE_SIZE			/* FileAlignment */
	.short	0				/* MajorOperatingSystemVersion */
	.short	0				/* MinorOperatingSystemVersion */
	.short	0				/* MajorImageVersion */
	.short	0				/* MinorImageVersion */
	.short	0				/* MajorSubsystemVersion */
	.short	0				/* MinorSubsystemVersion */
	.long	0				/* Win32VersionValue */
	.long	0				/* SizeOfImage */
	.long	0x2000				/* SizeOfHeaders */
	.long	0				/* CheckSum */
	.short	IMAGE_SUBSYSTEM_EFI_APPLICATION	/* Subsystem */
	.short	0				/* DllCharacteristics */
	.quad	0				/* SizeOfStackReserve */
	.quad	0				/* SizeOfStackCommit */
	.quad	0				/* SizeOfHeapReserve */
	.quad	0				/* SizeOfHeapCommit */
	.long	0				/* LoaderFlags */
	.long	(section_tab - .) / 8		/* NumberOfRvaAndSizes */
	.quad	0				/* ExportTable */
	.quad	0				/* ImportTable */
	.quad	0				/* ResourceTable */
	.quad	0				/* ExceptionTable */
	.quad	0				/* CertificationTable */
	.quad	0				/* BaseRelocationTable */

section_tab:
	.ascii	".reloc\0\0"			/* Name */
	.long	0				/* VirtualSize */
	.long	. - pe_hdr_start + 0xc		/* VirtualAddress */
	.long	0				/* SizeOfRawData */
	.long	. - pe_hdr_start + 0x4		/* PointerToRawData */
	.long	0				/* PointerToRelocations */
	.long	0				/* PointerToLineNumbers */
	.short	0				/* NumberOfRelocations */
	.short	0				/* NumberOfLineNumbers */
	.long	IMAGE_SCN_CNT_INITIALIZED_DATA	| \
		IMAGE_SCN_MEM_READ		| \
		IMAGE_SCN_MEM_DISCARDABLE	| \
		IMAGE_SCN_ALIGN_1BYTES		/* Characteristics */

.balign __PAGE_SIZE
.set pe_hdr_end, .

/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#include <string.h>
#include <x86/cpu.h>
#include <x86/traps.h>
#include <uk/plat/common/acpi.h>
#include <uk/arch/limits.h>
#include <uk/arch/types.h>
#include <uk/arch/paging.h>
#include <uk/asm/cfi.h>
#include <uk/plat/console.h>
#include <uk/assert.h>
#include <uk/essentials.h>
#include <uk/reloc.h>

#include <kvm/console.h>
#include <kvm/intctrl.h>

#include <uk/plat/lcpu.h>
#include <uk/plat/common/lcpu.h>
#include <uk/plat/common/sections.h>
#include <uk/plat/common/bootinfo.h>

#include <fcntl.h>
#include <unistd.h>

#include <libelf.h>

static char *cmdline;
static __sz cmdline_len;
static __vaddr_t new_baddr;
static __u32 random_value;
static unsigned long old_baddr = __BASE_ADDR;
static unsigned long old_eaddr;
static unsigned long image_size;

static inline int cmdline_init(struct ukplat_bootinfo *bi)
{
	char *cmdl;

	if (bi->cmdline_len) {
		cmdl = (char *)bi->cmdline;
		cmdline_len = bi->cmdline_len;
	} else {
		cmdl = CONFIG_UK_NAME;
		cmdline_len = sizeof(CONFIG_UK_NAME) - 1;
	}

	/* This is not the original command-line, but one that will be thrashed
	 * by `ukplat_entry_argp` to obtain argc/argv. So mark it as a kernel
	 * resource instead.
	 */
	cmdline = ukplat_memregion_alloc(cmdline_len + 1, UKPLAT_MEMRT_KERNEL,
					 UKPLAT_MEMRF_READ | UKPLAT_MEMRF_WRITE
					     | UKPLAT_MEMRF_MAP);
	if (unlikely(!cmdline))
		return -ENOMEM;

	memcpy(cmdline, cmdl, cmdline_len);
	cmdline[cmdline_len] = 0;

	return 0;
}

static void __noreturn _ukplat_entry2(void)
{
	/* Apply relocations after ASLR */
	// do_ukreloc(0, new_baddr);

	/* It's not possible to unwind past this function, because the stack
	 * pointer was overwritten in lcpu_arch_jump_to. Therefore, mark the
	 * previous instruction pointer as undefined, so that debuggers or
	 * profilers stop unwinding here.
	 */
	ukarch_cfi_unwind_end();

	uk_pr_info("got here\n");

	ukplat_entry_argp(NULL, cmdline, cmdline_len);

	ukplat_lcpu_halt();
}

static void _post_aslr_ukreloc(void)
{
	void *new_stack;
	uk_pr_info("In post_aslr\n");

	uk_pr_info("_ukplat_entry2() before ASLR = 0x%x\n", _ukplat_entry2);

	/* Jump to the next entry function on the new stack */
	lcpu_arch_jump_to(NULL, _ukplat_entry2);
}

static void elf_loader(struct ukplat_memregion_desc *initrd)
{
	// elf_loader(ehdr_baddr = ukplat_memregion_get_initrd):
	//     foreach phdr in ehdr_baddr->ph_off:
	//     memcpy(new_baddr + seed, ehdr_baddr + phdr->off, phdr->len)
	// ehdr_baddr = _BASE_ADDRESS (for second image) (0x00100000)

	Elf32_Ehdr *ehdr;
	Elf32_Phdr *current_phdr;
	void *mapped_address;
	int i;

	uk_pr_info("initrd->vbase = 0x%x\n", initrd->vbase);
	uk_pr_info("initrd->pbase = 0x%x\n", initrd->pbase);
	uk_pr_info("initrd->len = 0x%x\n", initrd->len);
	uk_pr_info("initrd->flags = 0x%x\n", initrd->flags);
	uk_pr_info("initrd->type = 0x%x\n", initrd->type);

	ehdr = initrd->pbase;
	uk_pr_info("ehdr = 0x%x\n", ehdr);
	uk_pr_info("ehdr->e_phoff = 0x%x\n", ehdr->e_phoff);
	uk_pr_info("ehdr->e_phnum = 0x%x\n", ehdr->e_phnum);
	uk_pr_info("ehdr->e_shnum = 0x%x\n", ehdr->e_shnum);

	i = 0;
	while (i < ehdr->e_phnum) {
		if (i == 0)
			current_phdr = (Elf32_Phdr *)((unsigned long)ehdr + ehdr->e_phoff);
		else
			current_phdr = (Elf32_Phdr *)((unsigned long)current_phdr + sizeof(Elf32_Phdr));

		uk_pr_info("==============================\n");
		uk_pr_info("\tProgram Header 0x%x\n", i);
		uk_pr_info("==============================\n");
		uk_pr_info("current_phdr->p_vaddr = 0x%x\n", current_phdr->p_vaddr);
		uk_pr_info("current_phdr->p_memsz = 0x%x\n", current_phdr->p_memsz);

		mapped_address = memcpy(new_baddr, current_phdr->p_vaddr, current_phdr->p_memsz);
		new_baddr += current_phdr->p_memsz + random_value;
		uk_pr_info("mapped at address = 0x%x\n\n", mapped_address);

		i++;
	}
}

void _ukplat_entry(struct lcpu *lcpu, struct ukplat_bootinfo *bi)
{
	int rc;
	void *bstack;
	struct ukplat_memregion_desc *initrd;

	old_eaddr = __END;
	image_size = old_eaddr - old_baddr;

	_libkvmplat_init_console();

	/* Initialize trap vector table */
	traps_table_init();

	/* Initialize LCPU of bootstrap processor */
	rc = lcpu_init(lcpu);
	if (unlikely(rc))
		UK_CRASH("Bootstrap processor init failed: %d\n", rc);

	/* Initialize IRQ controller */
	intctrl_init();

	/* Initialize command line */
	rc = cmdline_init(bi);
	if (unlikely(rc))
		UK_CRASH("Cmdline init failed: %d\n", rc);

	/* Allocate boot stack */
	bstack = ukplat_memregion_alloc(__STACK_SIZE, UKPLAT_MEMRT_STACK,
					UKPLAT_MEMRF_READ |
					UKPLAT_MEMRF_WRITE |
					UKPLAT_MEMRF_MAP);
	if (unlikely(!bstack))
		UK_CRASH("Boot stack alloc failed\n");

	bstack = (void *)((__uptr)bstack + __STACK_SIZE);

	/* We are using 2 unikraft images for chainloading, one that prepares
	 * for ASLR and the second one that is loaded by the first. The memory
	 * segments of the second one are loaded at random addresses.
	 */

	/* Get the current time-stamp and extract the lower 32bits for seed.
	 * Align the value to the next page.
	 */
	random_value = (__u32)(rdtsc() & 0xffffffff);
	random_value = ALIGN_UP(random_value, PAGE_SIZE);

	/* Generate the new base address */
	new_baddr = (__vaddr_t)ukplat_memregion_alloc(
							(__sz)(20 * (image_size + random_value)),
							UKPLAT_MEMRT_KERNEL,
	    					UKPLAT_MEMRF_MAP);
	if (new_baddr == NULL)
		uk_pr_crit("ukplat_memregion_alloc() failed!\nRandom seed is: "
			   "0x%x\nImage size is: 0x%x\n", random_value, image_size);
	uk_pr_err("\nRandom seed is: 0x%x\nImage size is: 0x%x\n", random_value,
		  image_size);
	uk_pr_err("Old base address: 0x%x\nNew base address: 0x%x\n", old_baddr,
		  new_baddr);

	/* Initialize memory */
	rc = ukplat_mem_init();
	if (unlikely(rc))
		UK_CRASH("Mem init failed: %d\n", rc);

	rc = ukplat_memregion_find_initrd0(&initrd);
	if (rc < 0)
		UK_CRASH("No initrd file!\n");
	uk_pr_info("Initrd file pointer: %p\nInitrd memregion number: %d\n",
		   initrd, rc);

	uk_pr_info("_post_aslr_ukreloc before ASLR = 0x%x\n", _post_aslr_ukreloc);

	elf_loader(initrd);

	uk_pr_info("_post_aslr_ukreloc after ASLR = 0x%x\n", _post_aslr_ukreloc);

	/* Print boot information */
	ukplat_bootinfo_print();

#if defined(CONFIG_HAVE_SMP) && defined(CONFIG_UKPLAT_ACPI)
	rc = acpi_init();
	if (likely(rc == 0)) {
		rc = lcpu_mp_init(CONFIG_UKPLAT_LCPU_RUN_IRQ,
				  CONFIG_UKPLAT_LCPU_WAKEUP_IRQ, NULL);
		if (unlikely(rc))
			uk_pr_err("SMP init failed: %d\n", rc);
	} else {
		uk_pr_err("ACPI init failed: %d\n", rc);
	}
#endif /* CONFIG_HAVE_SMP && CONFIG_UKPLAT_ACPI */

#ifdef CONFIG_HAVE_SYSCALL
	_init_syscall();
#endif /* CONFIG_HAVE_SYSCALL */

#if CONFIG_HAVE_X86PKU
	_check_ospke();
#endif /* CONFIG_HAVE_X86PKU */

	/* Switch away from the bootstrap stack */
	uk_pr_err("Switch from bootstrap stack to stack @%p\n", bstack);
	// lcpu_arch_jump_to(bstack, new_baddr + (_post_aslr_ukreloc - old_baddr));
	lcpu_arch_jump_to(bstack, _ukplat_entry2);
	// lcpu_arch_jump_to(bstack, _ukplat_entry2);
}

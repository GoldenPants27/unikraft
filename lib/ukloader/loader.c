/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <libelf.h>
#include <gelf.h>
#include <uk/loader.h>
#include <uk/arch/paging.h>
#include <uk/arch/random.h>

#define ukloader_crash()	ukplat_crash()

static struct ps_pair {
	int phdr_index;
	int shdr_index;
};

static struct ps_pair matched_pairs[20];
static size_t pair_count;
static __u32 rvaddrs[20];
static size_t rvaddr_count;
static __u32 mem_limit;

static unsigned int aslr_get_random_long(void)
{
	__u32 val;
	ukarch_random_u32(&val);

	return (unsigned int)val;
}

void uk_choose_random_location(unsigned long input,
							   unsigned long input_size,
							   unsigned long *output,
							   unsigned long output_size,
							   unsigned long *virt_address)
{
	unsigned long min_addr, random_addr;

	mem_limit = KERNEL_IMAGE_SIZE;

	/* Low end of the randomization range is the smallest value between
	 * the initial image location and 512MB
	 */
	min_addr = MIN(*output, 512UL << 20);
	min_addr = PAGE_ALIGN_UP(min_addr);

	random_addr = find_random_addr(min_addr, output_size);

	*virt_address = random_addr;
}

static unsigned int extract_ehdr(Elf *e, GElf_Ehdr *ehdr)
{
	if (gelf_getehdr(e, ehdr) != NULL) {
		uk_printd("gelf_getehdr() failed!\n");
		return 0;
	}

	return 1;
}

static size_t extract_phdrs(Elf *e, GElf_Phdr phdrs[])
{
	size_t n;

	if (elf_getphdrnum(e, &n) != 0) {
		uk_printd("elf_getphdrnum() failed!\n");
		return 0;
	}

	for (int i = 0; i < n; i++) {
		if (gelf_getphdr(e, i, &phdrs[i]) != &phdrs[i]) {
			uk_printd("gelf_getphdr() failed!\n");
			return 0;
		}
	}

	return n;
}

static size_t extract_shdrs(Elf *e, size_t *shstrndx, GElf_Shdr shdrs[])
{
	Elf_Scn *scn;
	size_t n;
	int i;

	if (elf_getshdrstrndx(e, &shstrndx) != 0)

	i = 0;
	scn = NULL;

	while ((scn = elf_nextscn(e, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdrs[i]) != &shdrs[i]) {
			uk_printd("gelf_getshdr() failed!\n");
			return 0;
		}

		i++;
	}

	return n;
}

static void match_phdr_shdr(GElf_Phdr phdrs[],
							size_t phdr_count,
							GElf_Shdr shdrs[],
							size_t shdr_count)
{
	for (int i = 0; i < phdr_count; i++) {
		for	(int j = 0; j < shdr_count; j++) {
			if (phdrs[i].p_paddr == shdrs[j].sh_addr) {
				matched_pairs[pair_count].phdr_index = i;
				matched_pairs[pair_count].shdr_index = j;
				pair_count++;
			}
		}
	}
}

void uk_load_elf(char *uk_image)
{
	int i_fd, o_fd, ret;
	size_t phdr_count, shdr_count, shstrndx;
	Elf *input_elf, *output_elf;
	GElf_Ehdr i_ehdr;
	GElf_Phdr i_phdrs[10];
	GElf_Shdr i_shdrs[20];

	if ((i_fd = open(uk_image, O_RDONLY, 0)) < 0) {
		uk_printd("Error opening the file: %s!\n", uk_image);
		ukloader_crash();
	}

	if ((input_elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		close(i_fd);
		uk_printd("Error initializing the elf structure!\n");
		ukloader_crash();
	}

	ret = extract_ehdr(input_elf, &i_ehdr);
	if (ret != 0) {
		elf_end(input_elf);
		close(i_fd);
		uk_printd("Error extracting executable header!\n");
		ukloader_crash();
	}

	phdr_count = extract_phdrs(input_elf, i_phdrs);
	if (phdr_count == 0) {
		elf_end(input_elf);
		close(i_fd);
		uk_printd("Error extracting program headers!\n");
		ukloader_crash();
	}

	shdr_count = extract_shdrs(input_elf, &shstrndx, i_shdrs);
	if (shdr_count == 0) {
		elf_end(input_elf);
		close(i_fd);
		uk_printd("Error extracting section headers!\n");
		ukloader_crash();
	}

	/* Match the phdr entries to the shdr entries */
	match_phdr_shdr(i_phdrs, phdr_count, i_shdrs, shdr_count);

	/* Iterate through the segments and apply aslr to each of them */
	for (int i = 0; i < shdr_count; i++) {
		apply_aslr(i_shdrs[i], );
	}

	elf_end(input_elf);
	close(i_fd);
}

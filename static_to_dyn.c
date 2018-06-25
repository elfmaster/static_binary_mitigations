#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/types.h>
#include <search.h>
#include <sys/time.h>
#include <fcntl.h>
#include <link.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define HUGE_PAGE 0x200000

int main(int argc, char **argv)
{
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	ElfW(Shdr) *shdr;
	uint8_t *mem;
	int fd;
	int i;
	struct stat st;
	uint64_t old_base; /* original text base */
	uint64_t new_data_base; /* new data base */
	char *StringTable;

	fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		perror("open");
		goto fail;
	}

	fstat(fd, &st);

	mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED ) {
		perror("mmap");
		goto fail;
	}

	ehdr = (ElfW(Ehdr) *)mem;
	phdr = (ElfW(Phdr) *)&mem[ehdr->e_phoff];
	shdr = (ElfW(Shdr) *)&mem[ehdr->e_shoff];
	StringTable = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];

	printf("Marking e_type to ET_DYN\n");
	ehdr->e_type = ET_DYN;

	printf("Updating PT_LOAD segments to become relocatable from base 0\n");
	for (i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_offset == 0) {
			old_base = phdr[i].p_vaddr;
			phdr[i].p_vaddr = 0UL;
			phdr[i].p_paddr = 0UL;
			phdr[i + 1].p_vaddr = HUGE_PAGE + phdr[i + 1].p_offset;
			phdr[i + 1].p_paddr = HUGE_PAGE + phdr[i + 1].p_offset;
		} else if (phdr[i].p_type == PT_NOTE) {
			phdr[i].p_vaddr = phdr[i].p_offset;
			phdr[i].p_paddr = phdr[i].p_offset;
		} else if (phdr[i].p_type == PT_TLS) {
			phdr[i].p_vaddr = HUGE_PAGE + phdr[i].p_offset;
			phdr[i].p_paddr = HUGE_PAGE + phdr[i].p_offset;
			new_data_base = phdr[i].p_vaddr;
		}
	}
	/*
	 * If we don't update the section headers to reflect the new address
	 * space then GDB and objdump will be broken with this binary.
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!(shdr[i].sh_flags & SHF_ALLOC))
			continue;
		shdr[i].sh_addr = (shdr[i].sh_addr < old_base + HUGE_PAGE) ?
		    0UL + shdr[i].sh_offset : new_data_base + shdr[i].sh_offset;
		printf("Setting %s sh_addr to %#lx\n", &StringTable[shdr[i].sh_name],
		    shdr[i].sh_addr);
	}
	printf("Setting new entry point: %#lx\n", ehdr->e_entry - old_base);
	ehdr->e_entry = ehdr->e_entry - old_base;
	munmap(mem, st.st_size);
	exit(0);
	fail:
		exit(-1);
}

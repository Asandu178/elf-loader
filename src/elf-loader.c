// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <elf.h>

void *map_elf(const char *filename)
{
	// This part helps you store the content of the ELF file inside the buffer.
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	// Contents of the ELF file are in the buffer: elf_contents[x] is the x-th byte of the ELF file.
	void *elf_contents = map_elf(filename);
	char *byte = (char*)elf_contents;

	Elf64_Ehdr *elfHeader = (Elf64_Ehdr*)elf_contents;

	/**
	 * TODO: ELF Header Validation
	 * Validate ELF magic bytes - "Not a valid ELF file" + exit code 3 if invalid.
	 * Validate ELF class is 64-bit (ELFCLASS64) - "Not a 64-bit ELF" + exit code 4 if invalid.
	 */

	if (elfHeader->e_ident[EI_MAG0] != ELFMAG0 || elfHeader->e_ident[EI_MAG1] != ELFMAG1 || elfHeader->e_ident[EI_MAG2] != ELFMAG2 || elfHeader->e_ident[EI_MAG3] != ELFMAG3) {
		fprintf(stderr,"Not a valid ELF file\n");
		exit(3);
	}

	if (elfHeader->e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "Not a 64-bit ELF\n");
		exit(4);
	}

	Elf64_Half progHeaderCount = elfHeader->e_phnum;
	Elf64_Phdr *progHeader = (Elf64_Phdr*)(byte + elfHeader->e_phoff);

	/**
	 * TODO: Load PT_LOAD segments
	 * For minimal syscall-only binaries.
	 * For each PT_LOAD segment:
	 * - Map the segments in memory. Permissions can be RWX for now.
	 */


	for (Elf64_Half i = 0 ; i < progHeaderCount ; i++) {
		if (progHeader->p_type == PT_LOAD) {
			Elf64_Word protection = 0;
			if (progHeader->p_flags & PF_W)
				protection |= PROT_WRITE;
			if (progHeader->p_flags & PF_R)
				protection |= PROT_READ;
			if (progHeader->p_flags & PF_X)
				protection |= PROT_EXEC;

			mmap(progHeader->p_vaddr, progHeader->p_memsz, PROT_WRITE | PROT_EXEC | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			memcpy(progHeader->p_vaddr, byte + progHeader->p_offset, progHeader->p_memsz);
			mprotect(progHeader->p_vaddr, progHeader->p_memsz, protection);
		}
		progHeader++;
	}

	/**
	 * TODO: Load Memory Regions with Correct Permissions
	 * For each PT_LOAD segment:
	 *	- Set memory permissions according to program header p_flags (PF_R, PF_W, PF_X).
	 *	- Use mprotect() or map with the correct permissions directly using mmap().
	 */

	/**
	 * TODO: Support Static Non-PIE Binaries with libc
	 * Must set up a valid process stack, including:
	 *	- argc, argv, envp
	 *	- auxv vector (with entries like AT_PHDR, AT_PHENT, AT_PHNUM, etc.)
	 * Note: Beware of the AT_RANDOM, AT_PHDR entries, the application will crash if you do not set them up properly.
	 */

	void *sp = mmap(NULL, 4096, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	/**
	 * TODO: Support Static PIE Executables
	 * Map PT_LOAD segments at a random load base.
	 * Adjust virtual addresses of segments and entry point by load_base.
	 * Stack setup (argc, argv, envp, auxv) same as above.
	 */

	// TODO: Set the entry point and the stack pointer
	void (*entry)() = elfHeader->e_entry;

	// Transfer control
	__asm__ __volatile__(
			"mov %0, %%rsp\n"
			"xor %%rbp, %%rbp\n"
			"jmp *%1\n"
			:
			: "r"(sp + 4096), "r"(entry)
			: "memory"
			);
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}

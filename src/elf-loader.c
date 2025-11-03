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
#include <sys/resource.h>
#include <sys/auxv.h>
#include <limits.h>
#include <time.h>
#define alignmentPageValue 4095

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
	char *byte = (char *)elf_contents;

	Elf64_Ehdr *elfHeader = (Elf64_Ehdr *)elf_contents;
	// random seed based on current time for AT_RANDOM and baseAddr
	srand(time(NULL));

	if (elfHeader->e_ident[EI_MAG0] != ELFMAG0 || elfHeader->e_ident[EI_MAG1] != ELFMAG1 || elfHeader->e_ident[EI_MAG2] != ELFMAG2 || elfHeader->e_ident[EI_MAG3] != ELFMAG3) {
		fprintf(stderr, "Not a valid ELF file\n");
		exit(3);
	}

	if (elfHeader->e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "Not a 64-bit ELF\n");
		exit(4);
	}

	Elf64_Half progHeaderCount = elfHeader->e_phnum;
	Elf64_Phdr *progHeader = (Elf64_Phdr *)(byte + elfHeader->e_phoff);

	// for Pie
	Elf64_Addr loadBase = 0;

	// for Non-PIE binaries
	if (elfHeader->e_type == ET_EXEC) {

		for (Elf64_Half i = 0 ; i < progHeaderCount ; i++) {
			if (progHeader->p_type == PT_LOAD) {
				Elf64_Word protection = 0;

				if (progHeader->p_flags & PF_W)
					protection |= PROT_WRITE;

				if (progHeader->p_flags & PF_R)
					protection |= PROT_READ;

				if (progHeader->p_flags & PF_X)
					protection |= PROT_EXEC;

				// to align values to be multiples of page size
				Elf64_Addr align = ~(alignmentPageValue);
				Elf64_Addr alignedAddr = progHeader->p_vaddr & align;
				Elf64_Addr endAddress = progHeader->p_vaddr + progHeader->p_memsz;
				Elf64_Addr alignedEndAddress = (endAddress + alignmentPageValue) & align;
				// calculate the totalSize which is page alligned in order to ensure
				// that i dont give permisions outside the correct range
				Elf64_Xword totalsize = alignedEndAddress - alignedAddr;

				void *map = mmap((void *)alignedAddr, totalsize, PROT_WRITE | PROT_EXEC | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

				memmove((void *)progHeader->p_vaddr, (void *)(byte + progHeader->p_offset), progHeader->p_filesz);

				if (progHeader->p_filesz < progHeader->p_memsz) {
					// this case can happen so we have to zero out the difference
					memset((void *)progHeader->p_vaddr + progHeader->p_filesz, 0, progHeader->p_memsz - progHeader->p_filesz);
				}

				mprotect(map, totalsize, protection);
			}
			progHeader++;
		}

	} else if (elfHeader->e_type == ET_DYN) {

		// generate a random loadBase
		// also page align it
		struct rlimit memlimit;

		getrlimit(RLIMIT_AS, &memlimit);

		Elf64_Addr magic = 0xdeadbeef;

		// random gods please choose well
		loadBase = ((magic + rand()) % magic) & ~(alignmentPageValue);

		Elf64_Addr lowVAddr = progHeader->p_vaddr;

		// find the lowest vaddr

		for (Elf64_Half i = 0 ; i < progHeaderCount ; i++) {
			if (progHeader->p_type == PT_LOAD) {
				if (progHeader->p_vaddr < lowVAddr)
					lowVAddr = progHeader->p_vaddr;
			}
			progHeader++;
		}

		progHeader = (Elf64_Phdr *)(byte + elfHeader->e_phoff);

		for (Elf64_Half i = 0 ; i < progHeaderCount ; i++) {
			if (progHeader->p_type == PT_LOAD) {
				Elf64_Word protection = 0;

				if (progHeader->p_flags & PF_W)
					protection |= PROT_WRITE;

				if (progHeader->p_flags & PF_R)
					protection |= PROT_READ;

				if (progHeader->p_flags & PF_X)
					protection |= PROT_EXEC;

				// to align values to be multiples of page size
				Elf64_Addr align = ~(alignmentPageValue);
				Elf64_Addr addr = loadBase + (progHeader->p_vaddr - lowVAddr);
				Elf64_Addr alignedAddr = addr & align;
				Elf64_Addr endAddress = addr + progHeader->p_memsz;
				Elf64_Addr alignedEndAddress = (endAddress + alignmentPageValue) & align;
				// calculate the totalSize which is page alligned in order to ensure
				// that i dont give permisions outside the correct range
				Elf64_Xword totalsize = alignedEndAddress - alignedAddr;

				void *map = mmap((void *)alignedAddr, totalsize, PROT_WRITE | PROT_EXEC | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

				memmove((void *)addr, (void *)(byte + progHeader->p_offset), progHeader->p_filesz);

				if (progHeader->p_filesz < progHeader->p_memsz) {
					// this case can happen so we have to zero out the difference
					memset((void *)addr + progHeader->p_filesz, 0, progHeader->p_memsz - progHeader->p_filesz);
				}

				mprotect(map, totalsize, protection);
			}
			progHeader++;
		}
	}

	struct rlimit rlimit;

	getrlimit(RLIMIT_STACK, &rlimit);
	int stackSize = rlimit.rlim_cur;

	void *sp = mmap(NULL, stackSize, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	// to help with null on when copying strings onto stack
	memset(sp, 0, stackSize);

	// find number of env variables
	char **Env = envp;

	int numEnv = 0;

	while (*Env) {
		numEnv++;
		Env++;
	}

	// build stack from top to bot

	char *stack = (char *)sp + stackSize;

	// insert the values on the stack using strcpy

	// keep track of pointers for argv and envp
	char *argvPointers[argc];

	char *envpPointers[numEnv];

	// copy the argv strings onto stack

	for (int i = argc - 1; i >= 0 ; i--) {
		// + 1 for NULL
		int len = strlen(argv[i]) + 1;

		stack -= len;
		memcpy(stack, argv[i], len);
		argvPointers[i] = stack;
		// align stack
		stack = (char *)((ulong)stack & (~15));
	}

	// copy the argc strings onto stack

	for (int i = numEnv - 1 ; i >= 0 ; i--) {
		// + 1 for NULL
		int len = strlen(envp[i]) + 1;

		stack -= len;
		memcpy(stack, envp[i], len);
		envpPointers[i] = stack;
		// align stack
		stack = (char *)((ulong)stack & (~15));
	}

	// continue with ulong* as not to deal with alignment since its going to be aligned everytime
	ulong *sptr = (ulong *)((ulong)stack);

	--sptr;

	// setup auxv

	// AT_NULL first
	*sptr = 0;
	sptr--;
	*sptr = AT_NULL;
	sptr--;

	// AT_PHDR

	*sptr = (ulong)(byte + elfHeader->e_phoff);
	sptr--;
	*sptr = AT_PHDR;
	sptr--;

	// AT_PHENT
	*sptr = elfHeader->e_phentsize;
	sptr--;
	*sptr = AT_PHENT;
	sptr--;

	// AT_PHNUM

	*sptr = elfHeader->e_phnum;
	sptr--;
	*sptr = AT_PHNUM;
	sptr--;

	// AT_RANDOM

	// generate 16 bytes with random values

	char random[16] = {0};

	for (int i = 0; i < 16 ; i++)
		random[i] = (rand() % 255);

	// pass the address
	*sptr = (ulong)random;
	sptr--;
	*sptr = AT_RANDOM;
	sptr--;

	// AT_PAGESZ

	*sptr = 4096;
	sptr--;
	*sptr = AT_PAGESZ;
	sptr--;

	// SET NULL
	*sptr = 0;
	sptr--;

	// set envp

	for (int i = numEnv - 1 ; i >= 0 ; i--) {
		*sptr = (ulong)envpPointers[i];
		sptr--;
	}
	// set NULL;
	*sptr = 0;
	sptr--;

	for (int i = argc - 1 ; i >= 0 ; i--) {
		*sptr = (ulong)argvPointers[i];
		sptr--;
	}
	//set argc
	*sptr = (ulong)argc;




	void (*entry)() = (void(*)())(elfHeader->e_entry + loadBase);

	// Transfer control
	__asm__ __volatile__(
			"mov %0, %%rsp\n"
			"xor %%rbp, %%rbp\n"
			"jmp *%1\n"
			:
			: "r"(sptr), "r"(entry)
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

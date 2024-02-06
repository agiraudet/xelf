#include "xelf.h"
#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int xelf_open(struct xelf *xelf, const char *path) {
  if (!xelf || !path)
    return 1;
  int fd = open(path, O_RDWR);
  if (fd == -1)
    return 2;
  struct stat file_stat;
  /* fstat() needed for size, size needed for map() */
  fstat(fd, &file_stat);
  xelf->size = file_stat.st_size;
  // xelf->elf = mmap(0, xelf->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  /*0 kernel choses address, size, right to read and write.
   * Updates  to  the mapping are not visible to other processes mapping the same
              file, and are not carried through to the  underlying  file. */
  xelf->elf = mmap(0, xelf->size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  close(fd);
  if (xelf->elf == MAP_FAILED)
    return 3;
  /* Since the file is mapped in virtual memory
   * we have access to information and data
   * such as ELF headers and sections 
   */
  xelf->header = (Elf64_Ehdr *)xelf->elf;
  // IDENTIFYING THE FILE
  if (xelf->header->e_ident[EI_MAG0] != ELFMAG0 ||  // 0x7f
      xelf->header->e_ident[EI_MAG1] != ELFMAG1 || // 'E'
      xelf->header->e_ident[EI_MAG2] != ELFMAG2 ||// 'L'
      xelf->header->e_ident[EI_MAG3] != ELFMAG3) { // 'F'
    return 4;
  }
  /*arithmetic pointer*/
 /* e_[sh/ph]off holds the section [section/prog header] table's file offset in bytes */
 /* e_shstrndx This member holds the section header table index of the entry associated with the 
  * section name string table */
  xelf->sec_header_tab = (Elf64_Shdr *)(xelf->elf + xelf->header->e_shoff);
  xelf->prog_header_tab = (Elf64_Phdr *)(xelf->elf + xelf->header->e_phoff);
  xelf->sec_header_strtab = &xelf->sec_header_tab[xelf->header->e_shstrndx];
  /* at [X] offsets specified by [e_shstrndx] added to sec_header_tab 
   * we reach the table index of the section header  that contains the section name string table 
   * it is easier to load the address directly in sec_header_strtab 
   * avoiding complicated pointer arithmetics */
  return 0;
}

int xelf_close(struct xelf *xelf) { return munmap(xelf->elf, xelf->size); }

int xelf_close_write(struct xelf *xelf) {
  int outputFile = open("woody", O_CREAT | O_WRONLY | O_TRUNC,
                        S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
  if (outputFile == -1) {
    perror("Error creating output file");
  } else {
    if (write(outputFile, xelf->elf, xelf->size) < 0) {
      fprintf(stderr, "Could not write output file");
    }
    close(outputFile);
  }
  return munmap(xelf->elf, xelf->size);
}

struct xelf *xelf_create(const char *path) {
  struct xelf *xelf;
  xelf = malloc(sizeof(struct xelf));
  if (!xelf)
    return 0;
  if (xelf_open(xelf, path)) {
    fprintf(stderr, "Could not open/map the elf file\n");
    free(xelf);
    return 0;
  }
  if (xelf->header->e_ident[EI_CLASS] != ELFCLASS64) {
    fprintf(stderr, "Only 64bit elf are accepted\n");
    xelf_close(xelf);
    free(xelf);
    return 0;
  }
  // ET_DYN : SHARED FILES 
  if (xelf->header->e_type != ET_EXEC && xelf->header->e_type != ET_DYN) {
    fprintf(stderr, "Elf file is not an executable\n");
    xelf_close(xelf);
    free(xelf);
    return 0;
  }
  return xelf;
}

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
  fstat(fd, &file_stat);
  xelf->size = file_stat.st_size;
  xelf->elf = mmap(0, xelf->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  close(fd);
  if (xelf->elf == MAP_FAILED)
    return 3;
  xelf->header = (Elf64_Ehdr *)xelf->elf;
  if (xelf->header->e_ident[EI_MAG0] != ELFMAG0 ||
      xelf->header->e_ident[EI_MAG1] != ELFMAG1 ||
      xelf->header->e_ident[EI_MAG2] != ELFMAG2 ||
      xelf->header->e_ident[EI_MAG3] != ELFMAG3) {
    return 4;
  }
  xelf->sec_header_tab = (Elf64_Shdr *)(xelf->elf + xelf->header->e_shoff);
  xelf->prog_header_tab = (Elf64_Phdr *)(xelf->elf + xelf->header->e_phoff);
  xelf->sec_header_strtab = &xelf->sec_header_tab[xelf->header->e_shstrndx];
  return 0;
}

int xelf_close(struct xelf *xelf) { return munmap(xelf->elf, xelf->size); }

Elf64_Phdr *xelf_find_seg_by_charac(struct xelf *xelf, uint32_t type,
                                    uint32_t flags) {
  if (!xelf)
    return 0;
  for (unsigned int i = 0; i < xelf->header->e_phnum; i++) {
    Elf64_Phdr *seg = &xelf->prog_header_tab[i];
    if (seg->p_type == type && seg->p_flags == flags) {
      return seg;
    }
  }
  return 0;
}

void xelf_seg_set_flags(Elf64_Phdr *seg, uint32_t flags) {
  if (seg)
    seg->p_flags = flags;
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
  if (xelf->header->e_type != ET_EXEC && xelf->header->e_type != ET_DYN) {
    fprintf(stderr, "Elf file is not an executable\n");
    xelf_close(xelf);
    free(xelf);
    return 0;
  }
  return xelf;
}

int xelf_pack(const char *path) {
  struct xelf *xelf;
  struct cypher *cypher;
  struct inject inject;

  xelf = xelf_create(path);
  if (!xelf)
    return 1;
  cypher = xelf_cypher_create();
  if (!cypher) {
    xelf_close(xelf);
    return 2;
  }
  Elf64_Shdr *text_sec = xelf_find_sec_by_name(xelf, ".text");
  xelf_sec_encrypt_xor(xelf, text_sec, cypher);
  Elf64_Phdr *code_seg = xelf_find_seg_by_charac(xelf, PT_LOAD, (PF_R | PF_X));
  if (!code_seg) {
    fprintf(stderr, "Could not find a code segment !\n");
    xelf_close(xelf);
    return 3;
  }
  xelf_seg_set_flags(code_seg, (PF_R | PF_X | PF_W));

  // TODO replace with headers, not from file
  if (xelf->header->e_type == ET_DYN)
    xelf_inject_load_from_file(&inject, "so_payload");
  else if (xelf->header->e_type == ET_EXEC)
    xelf_inject_load_from_file(&inject, "payload");
  ///////
}

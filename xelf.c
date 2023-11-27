#include "xelf.h"
#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
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

Elf64_Shdr *xelf_find_sec_by_name(struct xelf *xelf, const char *name) {
  if (!xelf || !name)
    return 0;
  char *sec_names = (char *)(xelf->elf + xelf->sec_header_strtab->sh_offset);
  for (unsigned int i = 0; i < xelf->header->e_shnum; i++) {
    char *sec_name = &sec_names[xelf->sec_header_tab[i].sh_name];
    if (strcmp(name, sec_name) == 0)
      return &xelf->sec_header_tab[i];
  }
  return 0;
}

void xelf_sec_set_perm(Elf64_Shdr *sec, uint64_t perm) {
  if (sec)
    sec->sh_flags = perm;
}

void xelf_sec_show_perm(Elf64_Shdr *sec) {
  if (!sec)
    return;
  printf("%c%c%c\n", sec->sh_flags & SHF_ALLOC ? 'a' : '-',
         sec->sh_flags & SHF_WRITE ? 'w' : '-',
         sec->sh_flags & SHF_EXECINSTR ? 'x' : '-');
}

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

void xelf_seg_inject_code(Elf64_Phdr *seg, int8_t *parasite,
                          size_t parasite_size) {}

#ifndef XELF_H
#define XELF_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>

struct cypher;

struct xelf {
  void *elf;
  Elf64_Ehdr *header;
  Elf64_Shdr *sec_header_tab;
  Elf64_Phdr *prog_header_tab;
  Elf64_Shdr *sec_header_strtab;
  size_t size;
};

int xelf_open(struct xelf *xelf, const char *path);
int xelf_close(struct xelf *xelf);
int xelf_close_write(struct xelf *xelf);
struct xelf *xelf_create(const char *path);

#endif

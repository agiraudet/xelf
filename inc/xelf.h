#ifndef XELF_H
#define XELF_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>

typedef struct payload t_payload;

enum e_xelf_error {
  XELF_CODERESET = -1,
  XELF_SUCCESS = 0,
  XELF_NULLPTR = 1,
  XELF_OPEN = 2,
  XELF_MAPFAIL = 3,
  XELF_ELFMAGIC = 4,
  XELF_WRITE = 5,
  XELF_CLOSE = 6,
  XELF_MALLOC = 7,
  XELF_NOTFOUND = 8,
  XELF_ELFCLASS = 9,
  XELF_ELFEXEC = 10,
  XELF_NOPHDR = 11,
  XELF_NOSHDR = 12,
  XELF_PAYLOADSIZE = 13,
  XELF_PLACEHOLDER = 14,
  XELF_PAYLOAD = 15
};

typedef struct xelf {
  void *map;
  Elf64_Ehdr *ehdr;
  Elf64_Shdr *shdr;
  Elf64_Phdr *phdr;
  Elf64_Shdr *shdr_strtab;
  size_t size;
} t_xelf;

int xelf_error(void);
int xelf_errorcode(int set);
int xelf_open(t_xelf *xelf, const char *path);
int xelf_close(t_xelf *xelf);
int xelf_check(t_xelf *xelf);
t_xelf *xelf_create(const char *path);
void xelf_destroy(t_xelf *xelf);
int xelf_hijack(t_xelf *xelf, const char *outfile, t_payload *payload);
int xelf_inject(t_xelf *xelf, const char *outfile, t_payload *payload);

#endif

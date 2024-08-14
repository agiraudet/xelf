#ifndef XELF_H
#define XELF_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>

enum e_xelf_error {
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
  XELF_PAYLOADSIZE = 13
};

typedef struct xelf {
  void *map;
  Elf64_Ehdr *ehdr;
  Elf64_Shdr *shdr;
  Elf64_Phdr *phdr;
  Elf64_Shdr *shdr_strtab;
  size_t size;
} t_xelf;

typedef uint64_t t_placeholder;

typedef struct payload {
  uint8_t *data;
  size_t size;
  t_placeholder entrypoint;
  t_placeholder key_addr;
  t_placeholder key_size;
  t_placeholder key;
} t_payload;

int xelf_open(t_xelf *xelf, const char *path);
int xelf_close(t_xelf *xelf);
int xelf_close_write(t_xelf *xelf);
t_xelf *xelf_create(const char *path);

#endif

#ifndef INJECT_H
#define INJECT_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>

struct xelf;
struct cypher;

struct inject {
  int8_t *code;
  size_t size;
  Elf64_Off offset;
  Elf64_Addr addr;
  Elf64_Addr og_entry;
};

int inject_load_from_file(struct inject *inject, const char *filepath);
int inject_set_entrypoint(Elf64_Phdr *seg, struct inject *inject);
void inject_patch_header(struct xelf *xelf, struct inject *inject);
void inject_find_and_replace(struct inject *inject, long old, long current);
void inject_find_and_replace_32(struct inject *inject, uint32_t old,
                                uint32_t current);
void inject_set_exitpoint(struct inject *inject);
int inject_cypher(struct xelf *xelf, Elf64_Phdr *code_segment,
                  struct cypher *cypher);

#endif

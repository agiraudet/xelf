#ifndef CYPHER_H
#define CYPHER_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>

struct cypher {
  size_t key_len;
  uint8_t *key;
  Elf64_Addr start;
  Elf64_Addr addr;
  Elf64_Off offset;
  size_t len;
};

uint8_t *cypher_genkey(size_t len);
void cypher_init(struct cypher *cypher);
void cypher_printkey(struct cypher *cypher);
struct cypher *cypher_create(void);

#endif

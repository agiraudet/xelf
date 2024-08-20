#ifndef CYPHER_H
#define CYPHER_H

#include "xelf.h"
#include <elf.h>
#include <stddef.h>
#include <stdint.h>

#define KEY_PLACEHOLDER "0123456789ABCDEF"

typedef struct cypher {
  size_t key_len;
  uint8_t *key;
  Elf64_Addr addr;
  Elf64_Off offset;
  size_t len;
} t_cypher;

uint8_t *cypher_genkey(size_t len);
void cypher_init(t_cypher *cypher, size_t key_len);
void cypher_printkey(t_cypher *cypher);
t_cypher *cypher_create(size_t key_len);
void cypher_destroy(t_cypher *cypher);
int cypher_encrypt_shdr(t_xelf *xelf, t_cypher *cypher, Elf64_Shdr *shdr,
                        void (*encrypt)(uint8_t *, size_t, uint8_t *, size_t));
void (*cypher_get_encrypt_func())(uint8_t *, size_t, uint8_t *, size_t);
void cypher_xor(uint8_t *data, size_t data_len, uint8_t *key, size_t key_len);
void cypher_aes(uint8_t *data, size_t data_len, uint8_t *key, size_t key_len);

#endif

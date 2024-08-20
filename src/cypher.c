#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "clarg.h"
#include "cypher.h"
#include "xelf.h"

uint8_t *cypher_genkey(size_t len) {
  // return (uint8_t *)strdup("0123456789ABCDEF");
  int random_data = open("/dev/urandom", O_RDONLY);
  if (random_data < 0)
    return 0;
  uint8_t *key = malloc(sizeof(uint8_t) * len);
  if (!key) {
    close(random_data);
    return 0;
  }
  size_t rb = 0;
  while (rb < len) {
    int res = read(random_data, key + rb, 1);
    if (res < 0) {
      close(random_data);
      free(key);
      return 0;
    }
    if (key[rb] != 0)
      rb++;
  }
  close(random_data);
  return key;
}

void cypher_init(t_cypher *cypher, size_t key_len) {
  if (!cypher)
    return;
  cypher->key_len = key_len;
  cypher->key = cypher_genkey(cypher->key_len);
  cypher->len = 0;
  cypher->addr = 0;
}

void cypher_printkey(t_cypher *cypher) {
  if (!cypher || !cypher->key)
    return;
  for (size_t i = 0; i < cypher->key_len; i++) {
    printf("%02X ", cypher->key[i]);
  }
  printf("\n");
}

t_cypher *cypher_create(size_t key_len) {
  t_cypher *cypher = malloc(sizeof(t_cypher));
  if (!cypher)
    return 0;
  cypher_init(cypher, key_len);
  return cypher;
}

void cypher_destroy(t_cypher *cypher) {
  if (!cypher)
    return;
  free(cypher->key);
  free(cypher);
}

int cypher_encrypt_shdr(t_xelf *xelf, t_cypher *cypher, Elf64_Shdr *shdr,
                        void (*encrypt)(uint8_t *, size_t, uint8_t *, size_t)) {
  if (!xelf || !cypher || !shdr)
    return xelf_errorcode(XELF_NULLPTR);
  Elf64_Phdr *phdr = xelf_phdr_from_shdr(xelf, shdr);
  if (!phdr)
    return xelf_errorcode(XELF_NOPHDR);
  phdr->p_flags |= PF_W;
  cypher->addr = shdr->sh_addr;
  cypher->len = shdr->sh_size;
  cypher->offset = shdr->sh_offset;
  encrypt(xelf->map + cypher->offset, cypher->len, cypher->key,
          cypher->key_len);
  if (cla_provided('v')) {
    printf("Encrypted section %s\n", xelf_shdr_name(xelf, shdr));
    printf("\taddress: 0x%lx\n", cypher->addr);
    printf("\tsize: %lx\n", cypher->len);
    printf("\toffset: %lx\n", cypher->offset);
  }
  return 0;
}

void (*cypher_get_encrypt_func())(uint8_t *, size_t, uint8_t *, size_t) {
  if (cla_provided('e')) {
    const char *protocol = cla_value('e');
    if (strcmp(protocol, "xor") == 0)
      return cypher_xor;
    if (strcmp(protocol, "aes") == 0)
      return cypher_aes;
  }
  if (cla_provided('v'))
    printf("No encryption protocol provided, using default XOR\n");
  return cypher_xor;
}

void cypher_xor(uint8_t *data, size_t data_len, uint8_t *key, size_t key_len) {
  for (size_t i = 0; i < data_len; i++) {
    data[i] ^= key[i % key_len];
  }
}

void cypher_aes(uint8_t *data, size_t data_len, uint8_t *key, size_t key_len) {}

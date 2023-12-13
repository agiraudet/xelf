#include "cypher.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

uint8_t *cypher_genkey(size_t len) {
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
    size_t res = read(random_data, key + rb, len - rb);
    if (res < 0) {
      close(random_data);
      free(key);
      return 0;
    }
    rb += res;
  }
  close(random_data);
  return key;
}

void cypher_init(struct cypher *cypher) {
  if (!cypher)
    return;
  cypher->key_len = 16;
  // TODO
  /* cypher->key = cypher_genkey(cypher->key_len); */
  cypher->key = (uint8_t *)strdup("0123456789ABCDEF");
  cypher->len = 0;
  cypher->start = 0;
  cypher->addr = 0;
}

void cypher_printkey(struct cypher *cypher) {
  if (!cypher || !cypher->key)
    return;
  for (size_t i = 0; i < cypher->key_len; i++) {
    printf("%X", cypher->key[i]);
  }
  printf("\n");
}

struct cypher *cypher_create(void) {
  struct cypher *cypher = malloc(sizeof(struct cypher));
  if (!cypher)
    return 0;
  cypher_init(cypher);
  cypher_printkey(cypher);
  return cypher;
}

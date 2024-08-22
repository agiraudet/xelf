#include "payload.h"
#include "aes.h"
#include "clarg.h"
#include "cypher.h"
#include "hello.h"
#include "xor.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "entry_dynamic.h"
#include "entry_static.h"
#include "exit_dynamic.h"
#include "exit_static.h"
#include "xelf.h"

void placeholder_init(t_placeholder *placeholder, uint64_t key, uint64_t value,
                      const char *label) {
  placeholder->key = key;
  placeholder->value = value;
  placeholder->label = strdup(label);
}

void placeholder_destroy(t_placeholder *placeholder) {
  if (!placeholder)
    return;
  free(placeholder->label);
}

t_placeholder *placeholder_get_by_label(t_payload *payload, const char *label) {
  if (!payload || !label)
    return NULL;
  for (unsigned int i = 0; i < payload->n_placeholders; i++) {
    if (strcmp(payload->placeholders[i].label, label) == 0)
      return payload->placeholders + i;
  }
  return NULL;
}

int payload_add_placeholder(t_payload *payload, t_placeholder *placeholder) {
  if (!payload)
    return xelf_errorcode(XELF_NULLPTR);
  if (payload->n_placeholders >= payload->cap_placeholders) {
    payload->cap_placeholders *= 2;
    payload->placeholders =
        realloc(payload->placeholders,
                payload->cap_placeholders * sizeof(t_placeholder));
    if (!payload->placeholders)
      return xelf_errorcode(XELF_MALLOC);
  }
  payload->placeholders[payload->n_placeholders++] = *placeholder;
  return XELF_SUCCESS;
}

t_payload *payload_create(uint8_t *data, size_t size, uint16_t e_type) {
  if (!data || size == 0) {
    xelf_errorcode(XELF_NULLPTR);
    return NULL;
  }
  t_payload *payload = malloc(sizeof(t_payload));
  if (!payload) {
    xelf_errorcode(XELF_MALLOC);
    return NULL;
  }
  uint8_t *entry_data = NULL;
  uint8_t *exit_data = NULL;
  size_t entry_size = 0;
  size_t exit_size = 0;
  if (e_type == ET_EXEC) {
    if (cla_provided('v'))
      printf("Creating payload for ET_EXEC\n");
    entry_data = entry_static;
    entry_size = entry_static_len;
    exit_data = exit_static;
    exit_size = exit_static_len;
  } else if (e_type == ET_DYN) {
    if (cla_provided('v'))
      printf("Creating payload for ET_DYN\n");
    entry_data = entry_dynamic;
    entry_size = entry_dynamic_len;
    exit_data = exit_dynamic;
    exit_size = exit_dynamic_len;
  } else {
    if (cla_provided('v'))
      printf("Creating naked payload\n");
    entry_data = 0;
    entry_size = 0;
    exit_data = 0;
    exit_size = 0;
  }
  payload->size = entry_size + size + exit_size;
  payload->data = malloc(payload->size);
  if (!payload->data) {
    free(payload);
    xelf_errorcode(XELF_MALLOC);
    return NULL;
  }
  if (entry_data)
    memcpy(payload->data, entry_data, entry_size);
  memcpy(payload->data + entry_size, data, size);
  if (exit_data)
    memcpy(payload->data + entry_size + size, exit_data, exit_size);
  payload->placeholders = malloc(sizeof(t_placeholder));
  if (!payload->placeholders) {
    xelf_errorcode(XELF_MALLOC);
    free(payload);
    return NULL;
  }
  payload->n_placeholders = 1;
  payload->cap_placeholders = 1;
  payload->placeholders[0].key = 0;
  payload->placeholders[0].value = 0;
  payload->placeholders[0].label = strdup("entrypoint");
  return payload;
}

t_payload *payload_create_from_file(const char *filename, uint16_t e_type) {
  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    xelf_errorcode(XELF_OPEN);
    return NULL;
  }
  size_t size = lseek(fd, 0, SEEK_END);
  if (size == 0) {
    close(fd);
    xelf_errorcode(XELF_PAYLOAD);
    return NULL;
  }
  lseek(fd, 0, SEEK_SET);
  uint8_t *data = malloc(size);
  if (!data) {
    close(fd);
    xelf_errorcode(XELF_MALLOC);
    return NULL;
  }
  if (read(fd, data, size) < 0) {
    close(fd);
    free(data);
    xelf_errorcode(XELF_PAYLOAD);
    return NULL;
  }
  return payload_create(data, size, e_type);
}

void payload_destroy(t_payload *payload) {
  if (!payload)
    return;
  if (payload->data)
    free(payload->data);
  for (unsigned int i = 0; i < payload->n_placeholders; i++)
    placeholder_destroy(payload->placeholders + i);
  free(payload->placeholders);
  free(payload);
}

int payload_replace_placeholder(t_payload *payload, uint64_t key,
                                uint64_t value) {
  int ret = 0;
  if (!payload || !payload->data)
    return xelf_errorcode(XELF_NULLPTR);
  for (unsigned int i = 0; i < payload->size; i++) {
    long current_QWORD = *((long *)(payload->data + i));
    if (!(key ^ current_QWORD)) {
      *((long *)(payload->data + i)) = value;
      ret++;
    }
  }
  return ret;
}

int payload_replace_placeholders(t_payload *payload) {
  if (!payload)
    return xelf_errorcode(XELF_NULLPTR);
  xelf_errorcode(XELF_CODERESET);
  for (unsigned int i = 0; i < payload->n_placeholders; i++) {
    if (payload_replace_placeholder(payload, payload->placeholders[i].key,
                                    payload->placeholders[i].value) !=
        XELF_SUCCESS)
      xelf_errorcode(XELF_PLACEHOLDER);
  }
  return xelf_errorcode(XELF_SUCCESS);
}

int payload_set_placeholder(t_payload *payload, const char *label, uint64_t key,
                            uint64_t value) {
  if (!payload || !label)
    return xelf_errorcode(XELF_NULLPTR);
  t_placeholder *placeholder = placeholder_get_by_label(payload, label);
  if (placeholder) {
    placeholder->key = key;
    placeholder->value = value;
    return XELF_SUCCESS;
  } else {
    t_placeholder placeholder;
    placeholder_init(&placeholder, key, value, label);
    return payload_add_placeholder(payload, &placeholder);
  }
}

int payload_set_placeholder_key(t_payload *payload, const char *label,
                                uint64_t key) {
  if (!payload || !label)
    return xelf_errorcode(XELF_NULLPTR);
  t_placeholder *placeholder = placeholder_get_by_label(payload, label);
  if (placeholder) {
    placeholder->key = key;
    return XELF_SUCCESS;
  } else {
    t_placeholder placeholder;
    placeholder_init(&placeholder, key, 0, label);
    return payload_add_placeholder(payload, &placeholder);
  }
}

int payload_set_placeholder_value(t_payload *payload, const char *label,
                                  uint64_t value) {
  if (!payload || !label)
    return xelf_errorcode(XELF_NULLPTR);
  t_placeholder *placeholder = placeholder_get_by_label(payload, label);
  if (placeholder) {
    placeholder->value = value;
    return XELF_SUCCESS;
  } else {
    t_placeholder placeholder;
    placeholder_init(&placeholder, 0, value, label);
    return payload_add_placeholder(payload, &placeholder);
  }
}

t_payload *payload_pick(t_xelf *xelf) {
  if (cla_provided('p')) {
    if (cla_provided('v'))
      printf("Loading payload from file %s\n", cla_value('p'));
    if (cla_provided('n'))
      return payload_create_from_file(cla_value('p'), ET_NONE);
    return payload_create_from_file(cla_value('p'), xelf->ehdr->e_type);
  } else if (cla_provided('n')) {
    fprintf(stderr, "Default payload cannot be naked. Use -p.\n");
    return NULL;
  }
  if (cla_provided('x')) {
    if (cla_provided('e')) {
      const char *protocol = cla_value('e');
      if (strcmp(protocol, "xor") == 0)
        return payload_create(xor, xor_len, xelf->ehdr->e_type);
      if (strcmp(protocol, "aes") == 0)
        return payload_create(aes, aes_len, xelf->ehdr->e_type);
    }
    if (cla_provided('v'))
      printf("No payload provided, using default XOR\n");
    return payload_create(xor, xor_len, xelf->ehdr->e_type);
  }
  if (cla_provided('v'))
    printf("No payload provided, using default Hello\n");
  return payload_create(hello, hello_len, xelf->ehdr->e_type);
}

int ft_memcmp(const void *s1, const void *s2, size_t n) {
  const unsigned char *p1 = s1, *p2 = s2;
  while (n--) {
    if (*p1 != *p2)
      return *p1 - *p2;
    p1++;
    p2++;
  }
  return 0;
}

uint8_t *payload_set_key(t_payload *payload, t_cypher *cypher) {
  if (!payload || !cypher)
    return NULL;
  const char *key_placeholder = KEY_PLACEHOLDER;
  for (size_t i = 0; i < payload->size; i++) {
    if (payload->data[i] == *key_placeholder &&
        ft_memcmp(payload->data + i, KEY_PLACEHOLDER, 16) == 0) {
      memcpy(payload->data + i, cypher->key, cypher->key_len);
      return payload->data + i;
    }
  }
  return NULL;
}

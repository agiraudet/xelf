#include "payload.h"
#include <fcntl.h>
#include <stdint.h>
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
    entry_data = entry_static;
    entry_size = entry_static_len;
    exit_data = exit_static;
    exit_size = exit_static_len;
  } else if (e_type == ET_DYN) {
    entry_data = entry_dynamic;
    entry_size = entry_dynamic_len;
    exit_data = exit_dynamic;
    exit_size = exit_dynamic_len;
  }
  payload->size = entry_size + size + exit_size;
  payload->data = malloc(payload->size);
  if (!payload->data) {
    free(payload);
    xelf_errorcode(XELF_MALLOC);
    return NULL;
  }
  memcpy(payload->data, entry_data, entry_size);
  memcpy(payload->data + entry_size, data, size);
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
  if (!payload || !payload->data)
    return xelf_errorcode(XELF_NULLPTR);
  for (unsigned int i = 0; i < payload->size; i++) {
    long current_QWORD = *((long *)(payload->data + i));
    if (!(key ^ current_QWORD)) {
      *((long *)(payload->data + i)) = value;
      return XELF_SUCCESS;
    }
  }
  return xelf_errorcode(XELF_PLACEHOLDER);
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

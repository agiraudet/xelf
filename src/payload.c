#include "payload.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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

t_payload *payload_create(uint8_t *data, size_t size) {
  t_payload *payload = malloc(sizeof(t_payload));
  if (!payload) {
    xelf_errorcode(XELF_MALLOC);
    return NULL;
  }
  payload->placeholders = malloc(sizeof(t_placeholder));
  if (!payload->placeholders) {
    xelf_errorcode(XELF_MALLOC);
    free(payload);
    return NULL;
  }
  payload->data = data;
  payload->size = size;
  payload->n_placeholders = 1;
  payload->cap_placeholders = 1;
  payload->placeholders[0].key = 0;
  payload->placeholders[0].value = 0;
  payload->placeholders[0].label = strdup("entrypoint");
  return payload;
}

void payload_destroy(t_payload *payload) {
  if (!payload)
    return;
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

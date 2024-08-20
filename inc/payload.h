#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <stddef.h>
#include <stdint.h>

typedef struct xelf t_xelf;
typedef struct cypher t_cypher;

typedef struct s_placeholder {
  char *label;
  uint64_t key;
  uint64_t value;
} t_placeholder;

typedef struct payload {
  uint8_t *data;
  size_t size;
  size_t n_placeholders;
  size_t cap_placeholders;
  t_placeholder *placeholders;
} t_payload;

void placeholder_init(t_placeholder *placeholder, uint64_t key, uint64_t value,
                      const char *label);
void placeholder_destroy(t_placeholder *placeholder);
t_placeholder *placeholder_get_by_label(t_payload *payload, const char *label);
int payload_add_placeholder(t_payload *payload, t_placeholder *placeholder);
t_payload *payload_create(uint8_t *data, size_t size, uint16_t e_type);
t_payload *payload_create_from_file(const char *filename, uint16_t e_type);
void payload_destroy(t_payload *payload);
int payload_replace_placeholder(t_payload *payload, uint64_t key,
                                uint64_t value);
int payload_replace_placeholders(t_payload *payload);
int payload_set_placeholder(t_payload *payload, const char *label, uint64_t key,
                            uint64_t value);
int payload_set_placeholder_key(t_payload *payload, const char *label,
                                uint64_t key);
int payload_set_placeholder_value(t_payload *payload, const char *label,
                                  uint64_t value);
t_payload *payload_pick(t_xelf *xelf);
uint8_t *payload_set_key(t_payload *payload, t_cypher *cypher);

#endif // !#ifndef PAYLOAD_H

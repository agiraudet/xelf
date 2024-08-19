#include "clarg.h"
#include "cypher.h"
#include "hello.h"
#include "payload.h"
#include "test.h"
#include "xelf.h"
#include "xor.h"
#include <stdio.h>

int cleanup(t_xelf *xelf, t_payload *payload) {
  if (xelf)
    xelf_destroy(xelf);
  if (payload)
    payload_destroy(payload);
  return xelf_error();
}

void cla_compose(void) {
  cla_add_description("ELF injection/packing tool");
  cla_add_required_input("<elf>");
  t_clarg *o = cla_arg('o', "output", "output file");
  o->value_required = true;
  cla_arg('v', "verbose", "verbose mode");
  t_clarg *p = cla_arg('p', "payload", "specify payload file for injection");
  p->value_required = true;
  cla_arg('x', "pack", "pack the elf");
  t_clarg *e = cla_arg('e', "encryption", "specify encryption protocol");
  e->value_required = true;
  clarg_add_allowed_value(e, "xor");
  clarg_add_allowed_value(e, "aes");
  cla_arg('c', "cave", "Allow code caving only");
  cla_arg('s', "section", "Extend section size in header to fit payload");
}

t_payload *load_payload(t_xelf *xelf) {
  // return payload_create(test, test_len, xelf->ehdr->e_type);
  if (!cla_provided('p')) {
    if (cla_provided('x')) {
      if (cla_provided('v'))
        printf("No payload provided, using default XOR\n");
      return payload_create(xor, xor_len, xelf->ehdr->e_type);
    }
    if (cla_provided('v'))
      printf("No payload provided, using default\n");
    return payload_create(hello, hello_len, xelf->ehdr->e_type);
  }
  if (cla_provided('v'))
    printf("Loading payload from file %s\n", cla_value('p'));
  return payload_create_from_file(cla_value('p'), xelf->ehdr->e_type);
}

t_cypher *load_cypher(void) {
  t_cypher *cypher = cypher_create(16);
  if (!cypher)
    return NULL;
  if (cla_provided('v'))
    cypher_printkey(cypher);
  return cypher;
}

int main(int argc, char **argv) {
  cla_init(argc, argv);
  cla_compose();
  if (cla_parse() < 0)
    return 1;
  if (cla_provided('h')) {
    cla_usage();
    return 0;
  }

  t_xelf *xelf = NULL;
  xelf = xelf_create(cla_get_input(0));
  if (xelf_check(xelf) != XELF_SUCCESS)
    return cleanup(NULL, NULL);
  t_payload *payload = load_payload(xelf);
  if (!payload)
    return cleanup(xelf, NULL);
  if (cla_provided('x')) {
    t_cypher *cypher = load_cypher();
    if (!cypher)
      return cleanup(xelf, payload);
    cypher_encrypt_shdr(xelf, cypher, xelf_shdr_from_name(xelf, ".text"),
                        cypher_xor);
    payload_set_placeholder_key(payload, "code_len", 0xBBBBBBBBBBBBBBBB);
    payload_set_placeholder_value(payload, "code_len", cypher->len);
    payload_set_placeholder_key(payload, "code_addr", 0xCCCCCCCCCCCCCCCC);
    if (xelf->ehdr->e_type == ET_EXEC)
      payload_set_placeholder_value(payload, "code_addr", cypher->addr);
    else {
      payload_set_placeholder_value(payload, "code_addr", cypher->offset);
      payload_set_placeholder_key(payload, "is_dyn", 0xDDDDDDDDDDDDDDDD);
      payload_set_placeholder_value(payload, "is_dyn", 0x1);
    }
  }
  if (payload_set_placeholder_key(payload, "entrypoint", 0xAAAAAAAAAAAAAAAA) !=
      XELF_SUCCESS)
    return cleanup(xelf, payload);
  for (size_t i = 0; i < payload->size; i++)
    printf("%x", payload->data[i]);
  printf("\n");
  if (xelf_inject(xelf, cla_provided('o') ? cla_value('o') : "woody",
                  payload) != XELF_SUCCESS)
    return cleanup(xelf, payload);
  payload_destroy(payload);
  xelf_destroy(xelf);
  return XELF_SUCCESS;
}

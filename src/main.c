#include "clarg.h"
#include "hello.h"
#include "payload.h"
#include "xelf.h"
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
}

t_payload *load_payload(t_xelf *xelf) {
  if (!cla_provided('p')) {
    if (cla_provided('v'))
      printf("No payload provided, using default\n");
    return payload_create(hello, hello_len, xelf->ehdr->e_type);
  }
  if (cla_provided('v'))
    printf("Loading payload from file %s\n", cla_value('p'));
  return payload_create_from_file(cla_value('p'), xelf->ehdr->e_type);
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
  if (payload_set_placeholder_key(payload, "entrypoint", 0xAAAAAAAAAAAAAAAA) !=
      XELF_SUCCESS)
    return cleanup(xelf, payload);
  if (xelf_inject(xelf, cla_provided('o') ? cla_value('o') : "woody",
                  payload) != XELF_SUCCESS)
    return cleanup(xelf, payload);
  payload_destroy(payload);
  xelf_destroy(xelf);
  return XELF_SUCCESS;
}

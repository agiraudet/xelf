#include "hello_dyn.h"
#include "hello_exec.h"
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

int main(int argc, char **argv) {
  t_xelf *xelf = NULL;
  t_payload *payload = NULL;
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <elf-in> <elf-out>\n", argv[0]);
    return 1;
  }
  xelf = xelf_create(argv[1]);
  if (xelf_check(xelf) != XELF_SUCCESS)
    return cleanup(NULL, NULL);
  if (xelf->ehdr->e_type == ET_EXEC)
    payload = payload_create(hello_exec, hello_exec_len);
  else if (xelf->ehdr->e_type == ET_DYN)
    payload = payload_create(hello_dyn, hello_dyn_len);
  if (!payload)
    return cleanup(xelf, NULL);
  if (payload_set_placeholder_key(payload, "entrypoint", 0xAAAAAAAAAAAAAAAA) !=
      XELF_SUCCESS)
    return cleanup(xelf, payload);
  if (xelf_inject(xelf, argv[2], payload) != XELF_SUCCESS)
    return cleanup(xelf, payload);
  payload_destroy(payload);
  xelf_destroy(xelf);
  return XELF_SUCCESS;
}

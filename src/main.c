#include "cypher.h"
#include "inject.h"
#include "segc.h"
#include "xelf.h"
#include <stdio.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <elf_file\n", argv[0]);
    return 1;
  }
  struct xelf *xelf;
  struct cypher *cypher;

  xelf = xelf_create(argv[1]);
  if (!xelf)
    return 1;
  cypher = cypher_create();
  if (!cypher) {
    xelf_close(xelf);
    return 2;
  }
  Elf64_Shdr *text_sec = sec_find_by_name(xelf, ".text");
  sec_encrypt_xor(xelf, text_sec, cypher);
  Elf64_Phdr *code_seg = seg_find_by_charac(xelf, PT_LOAD, (PF_R | PF_X));
  if (!code_seg) {
    fprintf(stderr, "Could not find a code segment !\n");
    xelf_close(xelf);
    return 3;
  }
  seg_set_flags(code_seg, (PF_R | PF_X | PF_W));
  inject_cypher(xelf, code_seg, cypher);
  xelf_close_write(xelf);
  // TODO clean memory leaks
  return 0;
}

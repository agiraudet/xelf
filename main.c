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

  //////////////////////////////////////////////////
  struct cypher cypher;
  xelf_wip_cypher(&cypher);

  Elf64_Shdr *text_sec = xelf_find_sec_by_name(&xelf, ".text");
  xelf_sec_encrypt_xor(&xelf, text_sec, &cypher);
  xelf_sec_set_perm(text_sec, (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR));

  //////////////////////////////////////////////////

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
  xelf_seg_set_flags(code_seg, (PF_R | PF_X | PF_W));

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

  printf("%lu\n", cypher.len);
  xelf_inject_find_and_replace(&inject, 0xCCCCCCCCCCCCCCCC, cypher.addr);
  xelf_inject_find_and_replace(&inject, 0xBBBBBBBBBBBBBBBB, cypher.len);

  // Actual injection
  xelf_inject(&xelf, &inject);

  xelf_close(&xelf);
  return 0;
}

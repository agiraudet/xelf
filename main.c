#include "xelf.h"
#include <elf.h>
#include <stdio.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <elf_file\n", argv[0]);
    return 1;
  }

  struct xelf xelf;
  if (xelf_open(&xelf, argv[1])) {
    fprintf(stderr, "Could not open/map the elf file\n");
    return 2;
  }

  if (xelf.header->e_ident[EI_CLASS] != ELFCLASS64) {
    fprintf(stderr, "Only 64bit elfs are accepted\n");
    xelf_close(&xelf);
    return 3;
  }

  Elf64_Shdr *text_sec = xelf_find_sec_by_name(&xelf, ".text");
  if (!text_sec) {
    fprintf(stderr, "Could not find the .text section\n");
    xelf_close(&xelf);
    return 4;
  }

  xelf_sec_show_perm(text_sec);

  // ADD WRITE PERMISSION TO .text section
  xelf_sec_set_perm(text_sec, (SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR));

  xelf_sec_show_perm(text_sec);

  printf(".text size: %lu bytes\n", text_sec->sh_size);

  Elf64_Phdr *code_seg = xelf_find_seg_by_charac(&xelf, PT_LOAD, (PF_R | PF_X));
  if (!code_seg) {
    fprintf(stderr, "Could not find a code segment !\n");
    xelf_close(&xelf);
    return 5;
  }

  xelf_seg_set_flags(code_seg, (PF_R | PF_X | PF_W));

  xelf_close(&xelf);
  return 0;
}

#include "cypher.h"
#include "segc.h"
#include "xelf.h"
#include <stdio.h>
#include <string.h>

Elf64_Shdr *sec_find_by_name(struct xelf *xelf, const char *name) {
  if (!xelf || !name)
    return 0;
  char *sec_names = (char *)(xelf->elf + xelf->sec_header_strtab->sh_offset);
  for (unsigned int i = 0; i < xelf->header->e_shnum; i++) {
    char *sec_name = &sec_names[xelf->sec_header_tab[i].sh_name];
    if (strcmp(name, sec_name) == 0)
      return &xelf->sec_header_tab[i];
  }
  return 0;
}

void sec_set_perm(Elf64_Shdr *sec, uint64_t perm) {
  if (sec)
    sec->sh_flags = perm;
}

void sec_show_perm(Elf64_Shdr *sec) {
  if (!sec)
    return;
  printf("%c%c%c\n", sec->sh_flags & SHF_ALLOC ? 'a' : '-',
         sec->sh_flags & SHF_WRITE ? 'w' : '-',
         sec->sh_flags & SHF_EXECINSTR ? 'x' : '-');
}

void sec_encrypt_xor(struct xelf *xelf, Elf64_Shdr *sec,
                     struct cypher *cypher) {
  uint8_t *code_start = xelf->elf + sec->sh_offset;
  for (unsigned int i = 0; i < sec->sh_size; i++) {
    code_start[i] ^= cypher->key[i % cypher->key_len];
  }
  cypher->len = sec->sh_size;
  cypher->start = (Elf64_Addr)code_start;
  cypher->addr = sec->sh_addr;
  cypher->offset = sec->sh_offset;
}

Elf64_Phdr *seg_find_by_charac(struct xelf *xelf, uint32_t type,
                               uint32_t flags) {
  if (!xelf)
    return 0;
  for (unsigned int i = 0; i < xelf->header->e_phnum; i++) {
    Elf64_Phdr *seg = &xelf->prog_header_tab[i];
    if (seg->p_type == type && seg->p_flags == flags) {
      return seg;
    }
  }
  return 0;
}

void seg_set_flags(Elf64_Phdr *seg, uint32_t flags) {
  if (seg)
    seg->p_flags = flags;
}

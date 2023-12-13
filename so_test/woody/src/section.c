
Elf64_Shdr *xelf_find_sec_by_name(struct xelf *xelf, const char *name) {
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

void xelf_sec_set_perm(Elf64_Shdr *sec, uint64_t perm) {
  if (sec)
    sec->sh_flags = perm;
}

void xelf_sec_show_perm(Elf64_Shdr *sec) {
  if (!sec)
    return;
  printf("%c%c%c\n", sec->sh_flags & SHF_ALLOC ? 'a' : '-',
         sec->sh_flags & SHF_WRITE ? 'w' : '-',
         sec->sh_flags & SHF_EXECINSTR ? 'x' : '-');
}

void xelf_sec_encrypt_xor(struct xelf *xelf, Elf64_Shdr *sec,
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

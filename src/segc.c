#include "segc.h"
#include "cypher.h"
#include "xelf.h"
#include <stdio.h>
#include <string.h>

Elf64_Shdr *sec_find_by_name(struct xelf *xelf, const char *name)
{
  if (!xelf || !name)
    return 0;
 
  /* sh_offset value holds the byte offset from the
              beginning of the file to the first byte in the section 
	      one long string, names are spaced by null-terminated char*/
  char *sec_names = (char *)(xelf->elf + xelf->sec_header_strtab->sh_offset);
 
  /* e_shnum holds the number of entries in the section
              header table */
  for (unsigned int i = 0; i < xelf->header->e_shnum; i++)
  {
	  /*  sh_name specifies the name of the section.  Its value
              is an index into the section header string table section,
              giving the location of a null-terminated string.   */
    char *sec_name = &sec_names[xelf->sec_header_tab[i].sh_name];
    if (strcmp(name, sec_name) == 0)
	return &xelf->sec_header_tab[i];
  }
  /*iteration over sec_names one string containing all the sec names
   * */
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
  /*   e_phnum holds the number of entries in the program
              header table.  Thus the product of e_phentsize and e_phnum
              gives the table's size in bytes. */ 
  for (unsigned int i = 0; i < xelf->header->e_phnum; i++)
  {
    Elf64_Phdr *seg = &xelf->prog_header_tab[i];
    if (seg->p_type == type && seg->p_flags == flags) 
    {
      return seg;
    }
  }
  return 0;
}

void seg_set_flags(Elf64_Phdr *seg, uint32_t flags) {
  if (seg)
    seg->p_flags = flags;
}

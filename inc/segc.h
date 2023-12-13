#ifndef SEGC_H
#define SEGC_H

#include <elf.h>
#include <stddef.h>

struct xelf;
struct cypher;

Elf64_Shdr *sec_find_by_name(struct xelf *xelf, const char *name);
void sec_set_perm(Elf64_Shdr *sec, uint64_t perm);
void sec_show_perm(Elf64_Shdr *sec);
void sec_encrypt_xor(struct xelf *xelf, Elf64_Shdr *sec, struct cypher *cypher);
Elf64_Phdr *seg_find_by_charac(struct xelf *xelf, uint32_t type,
                               uint32_t flags);
void seg_set_flags(Elf64_Phdr *seg, uint32_t flags);

#endif

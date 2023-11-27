#include <elf.h>
#include <stddef.h>

struct xelf {
  void *elf;
  Elf64_Ehdr *header;
  Elf64_Shdr *sec_header_tab;
  Elf64_Phdr *prog_header_tab;
  Elf64_Shdr *sec_header_strtab;
  size_t size;
};

int xelf_open(struct xelf *xelf, const char *path);
int xelf_close(struct xelf *xelf);
Elf64_Shdr *xelf_find_sec_by_name(struct xelf *xelf, const char *name);
void xelf_sec_set_perm(Elf64_Shdr *sec, uint64_t perm);
void xelf_sec_show_perm(Elf64_Shdr *sec);
Elf64_Phdr *xelf_find_seg_by_charac(struct xelf *xelf, uint32_t type,
                                    uint32_t flags);
void xelf_seg_set_flags(Elf64_Phdr *seg, uint32_t flags);

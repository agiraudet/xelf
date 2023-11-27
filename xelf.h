#include <elf.h>
#include <stddef.h>
#include <stdint.h>

struct xelf {
  void *elf;
  Elf64_Ehdr *header;
  Elf64_Shdr *sec_header_tab;
  Elf64_Phdr *prog_header_tab;
  Elf64_Shdr *sec_header_strtab;
  size_t size;
};

struct inject {
  int8_t *code;
  size_t size;
  Elf64_Off offset;
  Elf64_Addr addr;
  Elf64_Addr og_entry;
};

int xelf_open(struct xelf *xelf, const char *path);
int xelf_close(struct xelf *xelf);
Elf64_Shdr *xelf_find_sec_by_name(struct xelf *xelf, const char *name);
void xelf_sec_set_perm(Elf64_Shdr *sec, uint64_t perm);
void xelf_sec_show_perm(Elf64_Shdr *sec);
Elf64_Phdr *xelf_find_seg_by_charac(struct xelf *xelf, uint32_t type,
                                    uint32_t flags);
void xelf_seg_set_flags(Elf64_Phdr *seg, uint32_t flags);
int xelf_inject_load_from_file(struct inject *inject, const char *filepath);
int xelf_inject_set_entrypoint(Elf64_Phdr *seg, struct inject *inject);
void xelf_inject_patch_header(struct xelf *xelf, struct inject *inject);
void xelf_inject_set_exitpoint(struct inject *inject);
void xelf_inject(struct xelf *xelf, struct inject *inject);

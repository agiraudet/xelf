#include "xelf.h"
#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int xelf_open(struct xelf *xelf, const char *path) {
  if (!xelf || !path)
    return 1;
  int fd = open(path, O_RDWR);
  if (fd == -1)
    return 2;
  struct stat file_stat;
  fstat(fd, &file_stat);
  xelf->size = file_stat.st_size;
  xelf->elf = mmap(0, xelf->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  close(fd);
  if (xelf->elf == MAP_FAILED)
    return 3;
  xelf->header = (Elf64_Ehdr *)xelf->elf;
  if (xelf->header->e_ident[EI_MAG0] != ELFMAG0 ||
      xelf->header->e_ident[EI_MAG1] != ELFMAG1 ||
      xelf->header->e_ident[EI_MAG2] != ELFMAG2 ||
      xelf->header->e_ident[EI_MAG3] != ELFMAG3) {
    return 4;
  }
  xelf->sec_header_tab = (Elf64_Shdr *)(xelf->elf + xelf->header->e_shoff);
  xelf->prog_header_tab = (Elf64_Phdr *)(xelf->elf + xelf->header->e_phoff);
  xelf->sec_header_strtab = &xelf->sec_header_tab[xelf->header->e_shstrndx];
  return 0;
}

int xelf_close(struct xelf *xelf) { return munmap(xelf->elf, xelf->size); }

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

uint8_t *xelf_cypher_genkey(size_t len) {
  int random_data = open("/dev/urandom", O_RDONLY);
  if (random_data < 0)
    return 0;
  uint8_t *key = malloc(sizeof(uint8_t) * len);
  if (!key) {
    close(random_data);
    return 0;
  }
  size_t rb = 0;
  while (rb < len) {
    size_t res = read(random_data, key + rb, len - rb);
    if (res < 0) {
      close(random_data);
      free(key);
      return 0;
    }
    rb += res;
  }
  close(random_data);
  return key;
}

void xelf_cypher_init(struct cypher *cypher) {
  if (!cypher)
    return;
  cypher->key_len = 16;
  cypher->key = xelf_cypher_genkey(cypher->key_len);
  cypher->len = 0;
  cypher->start = 0;
  cypher->addr = 0;
}

void xelf_cypher_printkey(struct cypher *cypher) {
  if (!cypher || !cypher->key)
    return;
  for (size_t i = 0; i < cypher->key_len; i++) {
    printf("%X", cypher->key[i]);
  }
  printf("\n");
}

void xelf_wip_cypher(struct cypher *cypher) {
  if (!cypher)
    return;
  cypher->key = (uint8_t *)strdup("0123456789ABCDEF");
  cypher->key_len = strlen((char *)cypher->key);
  cypher->len = 0;
  cypher->start = 0;
  cypher->addr = 0;
}

struct cypher *xelf_cypher_create(void) {
  struct cypher *cypher = malloc(sizeof(struct cypher));
  if (!cypher)
    return 0;
  xelf_cypher_init(cypher);
  xelf_cypher_printkey(cypher);
  return cypher;
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

Elf64_Phdr *xelf_find_seg_by_charac(struct xelf *xelf, uint32_t type,
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

void xelf_seg_set_flags(Elf64_Phdr *seg, uint32_t flags) {
  if (seg)
    seg->p_flags = flags;
}

int xelf_inject_load_from_file(struct inject *inject, const char *filepath) {
  if (!inject || !filepath)
    return 1;
  int fd = open(filepath, O_RDONLY);
  if (fd < 0)
    return 2;
  struct stat file_stat;
  lstat(filepath, &file_stat);
  inject->size = file_stat.st_size;
  inject->code = (int8_t *)malloc(inject->size);
  if (!inject->code) {
    close(fd);
    return 3;
  }
  if (read(fd, inject->code, inject->size) < 0) {
    close(fd);
    return 4;
  }
  close(fd);
  return 0;
}

int xelf_inject_set_entrypoint(Elf64_Phdr *seg, struct inject *inject) {
  if (!seg || !inject)
    return -1;
  inject->offset = seg->p_offset + seg->p_filesz;
  inject->addr = seg->p_vaddr + seg->p_filesz;
  seg->p_filesz += inject->size;
  seg->p_memsz += inject->size;
  // TODO check that we dont overwrite the next segment !
  return 0;
}

void xelf_inject_patch_header(struct xelf *xelf, struct inject *inject) {
  if (!xelf || !inject)
    return;
  inject->og_entry = xelf->header->e_entry;

  if (xelf->header->e_type == ET_EXEC) {
    xelf->header->e_entry = inject->addr;
    printf("exec\n");
  } else if (xelf->header->e_type == ET_DYN) {
    xelf->header->e_entry = inject->offset;
    printf("dyn\n");
  } else
    fprintf(stderr, "elf is neither ET_EXEC nor ET_DYN\n");

  for (unsigned int i = 0; i < xelf->header->e_shnum; i++) {
    Elf64_Shdr *sec = &xelf->sec_header_tab[i];
    Elf64_Off sec_end = sec->sh_offset + sec->sh_size;
    if (inject->offset == sec_end) {
      sec->sh_size += inject->size;
      return;
    }
  }
}

void xelf_inject_find_and_replace(struct inject *inject, long old,
                                  long current) {
  if (!inject)
    return;
  uint8_t *ptr = (uint8_t *)inject->code;
  for (unsigned int i = 0; i < inject->size; i++) {
    long current_QWORD = *((long *)(ptr + i));
    if (!(old ^ current_QWORD)) {
      *((long *)(ptr + i)) = current;
      return;
    }
  }
}

void xelf_inject_find_and_replace_32(struct inject *inject, uint32_t old,
                                     uint32_t current) {
  if (!inject)
    return;
  uint8_t *ptr = (uint8_t *)inject->code;
  for (unsigned int i = 0; i < inject->size; i++) {
    long current_QWORD = *((long *)(ptr + i));
    if (!(old ^ current_QWORD)) {
      *((long *)(ptr + i)) = current;
      return;
    }
  }
}

void xelf_inject_set_exitpoint(struct inject *inject) {
  if (!inject)
    return;
  long replace = 0xAAAAAAAAAAAAAAAA;
  uint8_t *ptr = (uint8_t *)inject->code;
  for (unsigned int i = 0; i < inject->size; i++) {
    long current_QWORD = *((long *)(ptr + i));
    if (!(replace ^ current_QWORD)) {
      *((long *)(ptr + i)) = inject->og_entry;
      return;
    }
  }
}

void xelf_inject(struct xelf *xelf, struct inject *inject) {
  memcpy(xelf->elf + inject->offset, inject->code, inject->size);
}

struct xelf *xelf_create(const char *path) {
  struct xelf *xelf;
  xelf = malloc(sizeof(struct xelf));
  if (!xelf)
    return 0;
  if (xelf_open(xelf, path)) {
    fprintf(stderr, "Could not open/map the elf file\n");
    free(xelf);
    return 0;
  }
  if (xelf->header->e_ident[EI_CLASS] != ELFCLASS64) {
    fprintf(stderr, "Only 64bit elf are accepted\n");
    xelf_close(xelf);
    free(xelf);
    return 0;
  }
  if (xelf->header->e_type != ET_EXEC && xelf->header->e_type != ET_DYN) {
    fprintf(stderr, "Elf file is not an executable\n");
    xelf_close(xelf);
    free(xelf);
    return 0;
  }
  return xelf;
}

int xelf_pack(const char *path) {
  struct xelf *xelf;
  struct cypher *cypher;
  struct inject inject;

  xelf = xelf_create(path);
  if (!xelf)
    return 1;
  cypher = xelf_cypher_create();
  if (!cypher) {
    xelf_close(xelf);
    return 2;
  }
  Elf64_Shdr *text_sec = xelf_find_sec_by_name(xelf, ".text");
  xelf_sec_encrypt_xor(xelf, text_sec, cypher);
  Elf64_Phdr *code_seg = xelf_find_seg_by_charac(xelf, PT_LOAD, (PF_R | PF_X));
  if (!code_seg) {
    fprintf(stderr, "Could not find a code segment !\n");
    xelf_close(xelf);
    return 3;
  }
  xelf_seg_set_flags(code_seg, (PF_R | PF_X | PF_W));

  // TODO replace with headers, not from file
  if (xelf->header->e_type == ET_DYN)
    xelf_inject_load_from_file(&inject, "so_payload");
  else if (xelf->header->e_type == ET_EXEC)
    xelf_inject_load_from_file(&inject, "payload");
  ///////
}

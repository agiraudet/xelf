#include "inject.h"
#include "xelf.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int inject_load_from_file(struct inject *inject, const char *filepath) {
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

int inject_set_entrypoint(Elf64_Phdr *seg, struct inject *inject) {
  if (!seg || !inject)
    return -1;
  inject->offset = seg->p_offset + seg->p_filesz;
  inject->addr = seg->p_vaddr + seg->p_filesz;
  seg->p_filesz += inject->size;
  seg->p_memsz += inject->size;
  // TODO check that we dont overwrite the next segment !
  return 0;
}

void inject_patch_header(struct xelf *xelf, struct inject *inject) {
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

void inject_find_and_replace(struct inject *inject, long old, long current) {
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

void inject_find_and_replace_32(struct inject *inject, uint32_t old,
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

void inject_set_exitpoint(struct inject *inject) {
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

void inject(struct xelf *xelf, struct inject *inject) {
  memcpy(xelf->elf + inject->offset, inject->code, inject->size);
}

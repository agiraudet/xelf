#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef struct s_melf {
  int fd;
  void *map;
  off_t size;
  Elf64_Ehdr *ehdr;
  Elf64_Shdr *shdr;
  Elf64_Phdr *phdr;
} t_melf;

Elf64_Phdr *melf_get_phdr_by_type(t_melf *melf, uint32_t p_type) {
  if (!melf || !melf->map)
    return NULL;
  for (size_t i = 0; i < melf->ehdr->e_phnum; i++) {
    if (melf->phdr[i].p_type == p_type)
      return melf->phdr + i;
  }
  return NULL;
}

Elf64_Shdr *melf_get_shdr_by_name(t_melf *melf, const char *name) {
  if (!melf || !melf->map)
    return NULL;
  for (size_t i = 0; i < melf->ehdr->e_shnum; i++) {
    char *sh_name = melf->map + melf->shdr[melf->ehdr->e_shstrndx].sh_offset +
                    melf->shdr[i].sh_name;
    if (strcmp(sh_name, name) == 0)
      return melf->shdr + i;
  }
  return NULL;
}

void melf_destroy(t_melf *melf) {
  if (melf->map) {
    munmap(melf->map, melf->size);
    melf->map = NULL;
  }
  if (melf->fd >= 0) {
    close(melf->fd);
    melf->fd = -1;
  }
}

int melf_open(t_melf *melf, const char *filename) {
  int fd = open(filename, O_RDWR);
  if (fd < 0) {
    return -1;
  }
  size_t size = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);
  void *map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  if (map == MAP_FAILED) {
    close(fd);
    return -1;
  }
  melf->fd = fd;
  melf->map = map;
  melf->size = size;
  melf->ehdr = (Elf64_Ehdr *)melf->map;
  melf->shdr = (Elf64_Shdr *)(melf->map + melf->ehdr->e_shoff);
  melf->phdr = (Elf64_Phdr *)(melf->map + melf->ehdr->e_phoff);
  return 0;
}

Elf64_Shdr *melf_section_find_from_segment(t_melf *melf, Elf64_Phdr *phdr) {
  if (!melf || !melf->map)
    return NULL;
  for (size_t i = 0; i < melf->ehdr->e_shnum; i++) {
    if (melf->shdr[i].sh_addr == phdr->p_vaddr)
      return melf->shdr + i;
  }
  return NULL;
}

char *melf_section_find_name(t_melf *melf, Elf64_Shdr *shdr) {
  if (!melf || !melf->map)
    return NULL;
  return melf->map + melf->shdr[melf->ehdr->e_shstrndx].sh_offset +
         shdr->sh_name;
}

int melf_segment_add(t_melf *melf, uint32_t p_type, uint32_t p_flag,
                     size_t size) {
  if (!melf || !melf->map)
    return -1;

  // Align the new segment's virtual address and file offset
  Elf64_Addr last_vaddr = 0x0;
  for (size_t i = 0; i < melf->ehdr->e_phnum; i++) {
    Elf64_Phdr *phdr = melf->phdr + i;
    if (phdr->p_type == PT_LOAD || phdr->p_type == PT_DYNAMIC) {
      Elf64_Addr vaddr = phdr->p_vaddr + phdr->p_memsz;
      if (vaddr > last_vaddr)
        last_vaddr = vaddr;
    }
  }
  Elf64_Addr addr =
      (last_vaddr + 0xFFF) & ~0xFFF; // Align to the next page boundary (0x1000)

  size_t new_file_offset =
      (melf->size + 0xFFF) &
      ~0xFFF; // Align file offset to the next page boundary (0x1000)

  // Find the segment to hijack
  Elf64_Phdr *hijacked_phdr = melf_get_phdr_by_type(melf, PT_NOTE);
  if (!hijacked_phdr)
    return -1;

  // Find the section corresponding to the hijacked segment
  Elf64_Shdr *sec = melf_section_find_from_segment(melf, hijacked_phdr);
  if (!sec)
    return -1;

  // Update section name and attributes
  char *sec_name = melf_section_find_name(melf, sec);
  strncpy(sec_name, ".woody", strlen(sec_name));
  sec->sh_size = size;
  sec->sh_type = SHT_PROGBITS;
  sec->sh_addr = addr;
  sec->sh_offset = new_file_offset;
  sec->sh_addralign = 0x10;
  // sec->sh_addralign = 0;
  sec->sh_flags = SHF_EXECINSTR | SHF_ALLOC | SHF_WRITE;

  // Update the hijacked program header
  hijacked_phdr->p_offset = new_file_offset;
  hijacked_phdr->p_filesz = size;
  hijacked_phdr->p_memsz = size;
  hijacked_phdr->p_type = p_type;
  hijacked_phdr->p_flags = p_flag;
  hijacked_phdr->p_align = 0x1000;
  hijacked_phdr->p_paddr = addr;
  hijacked_phdr->p_vaddr = addr;

  // Write the modified ELF to a new file
  int fd = open("out", O_RDWR | O_CREAT | O_TRUNC, 0755);
  if (fd < 0) {
    return -1;
  }

  // Write the original ELF data up to the last segment
  write(fd, melf->map, melf->size);

  // Pad with zeros up to the aligned offset
  size_t padding_size = new_file_offset - melf->size;
  void *padding_buffer = calloc(1, padding_size);
  if (padding_buffer == NULL) {
    close(fd);
    return -1;
  }
  write(fd, padding_buffer, padding_size);
  free(padding_buffer);

  // Write the new segment data (zero-initialized for now)
  void *zero_buffer = calloc(1, size);
  if (zero_buffer == NULL) {
    close(fd);
    return -1;
  }
  memset(zero_buffer, 0x90, size);
  write(fd, zero_buffer, size);
  free(zero_buffer);

  close(fd);
  return 0;
}

Elf64_Phdr *melf_segment_find_biggest(t_melf *melf) {
  if (!melf || !melf->map)
    return NULL;
  Elf64_Phdr *biggest_phdr = NULL;
  for (size_t i = 0; i < melf->ehdr->e_phnum; i++) {
    if (!biggest_phdr || melf->phdr[i].p_memsz > biggest_phdr->p_memsz)
      biggest_phdr = melf->phdr + i;
  }
  return biggest_phdr;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("Usage: %s <elf>\n", argv[0]);
    return -1;
  }
  t_melf melf = {0};
  if (melf_open(&melf, argv[1]) < 0) {
    return -1;
  }
  Elf64_Phdr *biggest_phdr = melf_segment_find_biggest(&melf);
  melf_segment_add(&melf, PT_LOAD, PF_R | PF_X, biggest_phdr->p_memsz);
  melf_destroy(&melf);
  return 0;
}

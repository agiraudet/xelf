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

int xelf_errorcode(int set) {
  static int code = XELF_SUCCESS;
  if (set)
    code = set;
  return code;
}

int xelf_open(t_xelf *xelf, const char *path) {
  if (!xelf || !path)
    return xelf_errorcode(XELF_NULLPTR);
  int fd = open(path, O_RDWR);
  if (fd == -1)
    return xelf_errorcode(XELF_OPEN);
  xelf->size = lseek(fd, 0, SEEK_END);
  xelf->map = mmap(0, xelf->size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  close(fd);
  if (xelf->map == MAP_FAILED)
    return xelf_errorcode(XELF_MAPFAIL);
  xelf->ehdr = (Elf64_Ehdr *)xelf->map;
  if (xelf->ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
      xelf->ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
      xelf->ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
      xelf->ehdr->e_ident[EI_MAG3] != ELFMAG3) {
    munmap(xelf->map, xelf->size);
    return xelf_errorcode(XELF_ELFMAGIC);
  }
  xelf->shdr = (Elf64_Shdr *)(xelf->map + xelf->ehdr->e_shoff);
  xelf->phdr = (Elf64_Phdr *)(xelf->map + xelf->ehdr->e_phoff);
  xelf->shdr_strtab = &xelf->shdr[xelf->ehdr->e_shstrndx];
  return XELF_SUCCESS;
}

int xelf_close(t_xelf *xelf) { return munmap(xelf->map, xelf->size); }

int xelf_close_write(t_xelf *xelf) {
  int outputFile = open("woody", O_CREAT | O_WRONLY | O_TRUNC,
                        S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
  if (outputFile == -1)
    return XELF_OPEN;
  if (write(outputFile, xelf->map, xelf->size) < 0)
    return XELF_WRITE;
  close(outputFile);
  return munmap(xelf->map, xelf->size);
}

int xelf_check(t_xelf *xelf) {
  if (!xelf)
    return xelf_errorcode(XELF_NULLPTR);
  if (xelf->ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
      xelf->ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
      xelf->ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
      xelf->ehdr->e_ident[EI_MAG3] != ELFMAG3)
    return xelf_errorcode(XELF_ELFMAGIC);
  else if (xelf->ehdr->e_ident[EI_CLASS] != ELFCLASS64)
    return xelf_errorcode(XELF_ELFCLASS);
  else if (xelf->ehdr->e_type != ET_EXEC && xelf->ehdr->e_type != ET_DYN)
    return xelf_errorcode(XELF_ELFEXEC);
  return XELF_SUCCESS;
}

t_xelf *xelf_create(const char *path) {
  t_xelf *xelf;
  xelf = malloc(sizeof(t_xelf));
  if (!xelf) {
    xelf_errorcode(XELF_MALLOC);
    return NULL;
  }
  if (xelf_open(xelf, path) != XELF_SUCCESS) {
    free(xelf);
    return NULL;
  }
  if (xelf_check(xelf) != XELF_SUCCESS) {
    xelf_close(xelf);
    free(xelf);
    return NULL;
  }
  return xelf;
}

Elf64_Shdr *xelf_shdr_from_name(t_xelf *xelf, const char *name) {
  if (!xelf)
    return NULL;
  for (size_t i = 0; i < xelf->ehdr->e_shnum; i++) {
    char *sh_name =
        xelf->map + xelf->shdr_strtab->sh_offset + xelf->shdr[i].sh_name;
    if (strcmp(sh_name, name) == 0)
      return xelf->shdr + i;
  }
  return NULL;
}

Elf64_Shdr *xelf_shdr_from_phdr(t_xelf *xelf, Elf64_Phdr *phdr) {
  if (!xelf)
    return NULL;
  for (size_t i = 0; i < xelf->ehdr->e_shnum; i++) {
    if (xelf->shdr[i].sh_addr == phdr->p_vaddr)
      return xelf->shdr + i;
  }
  return NULL;
}

char *xelf_shdr_name(t_xelf *xelf, Elf64_Shdr *shdr) {
  if (!xelf || !shdr)
    return NULL;
  return xelf->map + xelf->shdr_strtab->sh_offset + shdr->sh_name;
}

Elf64_Phdr *xelf_phdr_from_type(t_xelf *xelf, uint32_t p_type) {
  if (!xelf)
    return NULL;
  for (size_t i = 0; i < xelf->ehdr->e_phnum; i++) {
    if (xelf->phdr[i].p_type == p_type)
      return xelf->phdr + i;
  }
  return NULL;
}

Elf64_Phdr *xelf_phdr_biggest(t_xelf *xelf) {
  if (!xelf)
    return NULL;
  Elf64_Phdr *biggest = NULL;
  for (size_t i = 0; i < xelf->ehdr->e_phnum; i++) {
    if (!biggest || xelf->phdr[i].p_memsz > biggest->p_memsz)
      biggest = xelf->phdr + i;
  }
  return biggest;
}

int xelf_hijack_write(t_xelf *xelf, const char *outfile, off_t offest,
                      uint8_t *data, size_t data_size) {
  int fd = open(outfile, O_CREAT | O_WRONLY | O_TRUNC,
                S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
  if (fd == -1)
    return xelf_errorcode(XELF_OPEN);
  write(fd, xelf->map, xelf->size);
  size_t padding_size = offest - xelf->size;
  void *padding = calloc(padding_size, 1);
  if (!padding) {
    close(fd);
    return xelf_errorcode(XELF_MALLOC);
  }
  write(fd, padding, padding_size);
  free(padding);
  write(fd, data, data_size);
  close(fd);
  return XELF_SUCCESS;
}

Elf64_Addr xelf_vaddr_last(t_xelf *xelf) {
  Elf64_Addr last_vaddr = 0x0;
  for (size_t i = 0; i < xelf->ehdr->e_phnum; i++) {
    Elf64_Phdr *phdr = xelf->phdr + i;
    if (phdr->p_type == PT_LOAD || phdr->p_type == PT_DYNAMIC) {
      Elf64_Addr vaddr = phdr->p_vaddr + phdr->p_memsz;
      if (vaddr > last_vaddr)
        last_vaddr = vaddr;
    }
  }
  return last_vaddr;
}

Elf64_Shdr *xelf_shdr_hijack_update(t_xelf *xelf, Elf64_Shdr *hijacked_shdr,
                                    size_t size, off_t offset,
                                    Elf64_Addr addr) {
  if (!hijacked_shdr) {
    xelf_errorcode(XELF_NOSHDR);
    return NULL;
  }
  char *section_name = xelf_shdr_name(xelf, hijacked_shdr);
  if (!section_name) {
    xelf_errorcode(XELF_NOSHDR);
    return NULL;
  }
  strncpy(section_name, ".woody", strlen(section_name));
  hijacked_shdr->sh_type = SHT_PROGBITS;
  hijacked_shdr->sh_size = size;
  hijacked_shdr->sh_offset = offset;
  hijacked_shdr->sh_addr = addr;
  hijacked_shdr->sh_flags = SHF_ALLOC | SHF_EXECINSTR | SHF_WRITE;
  hijacked_shdr->sh_addralign = 0x10;
  return hijacked_shdr;
}

int xelf_phdr_hijack(t_xelf *xelf, uint32_t new_type, uint32_t new_flag,
                     size_t new_size, const char *outfile, uint8_t *data) {
  if (!xelf)
    return NULL;
  Elf64_Addr new_addr = (xelf_vaddr_last(xelf) + 0xFFF) & ~0xFFF;
  off_t new_offset = (xelf->size + 0xFFF) & ~0xFFF;
  Elf64_Phdr *hijacked_phdr = xelf_phdr_from_type(xelf, PT_NOTE);
  if (!hijacked_phdr)
    return xelf_errorcode(XELF_NOPHDR);
  Elf64_Shdr *hijacked_shdr = xelf_shdr_from_phdr(xelf, hijacked_phdr);
  if (!hijacked_shdr)
    return xelf_errorcode(XELF_NOSHDR);
  xelf_shdr_hijack_update(xelf, hijacked_shdr, new_size, new_offset, new_addr);
  hijacked_phdr->p_type = new_type;
  hijacked_phdr->p_flags = new_flag;
  hijacked_phdr->p_filesz = new_size;
  hijacked_phdr->p_memsz = new_size;
  hijacked_phdr->p_offset = new_offset;
  hijacked_phdr->p_vaddr = new_addr;
  hijacked_phdr->p_paddr = new_addr;
  hijacked_phdr->p_align = 0x1000;
  return xelf_hijack_write(xelf, outfile, new_offset, data, new_size);
}

int xelf_hijack(t_xelf *xelf, const char *outfile, t_payload *payload) {
  if (!xelf || !payload)
    return xelf_errorcode(XELF_NULLPTR);
  if (payload->size > 0x1000)
    return xelf_errorcode(XELF_PAYLOADSIZE);
  Elf64_Phdr *hijacked_phdr = xelf_phdr_from_type(xelf, PT_NOTE);
  if (!hijacked_phdr)
    return xelf_errorcode(XELF_NOPHDR);
  xelf_phdr_hijack(xelf, PT_LOAD, PF_X | PF_R | PF_W, 0x1000, outfile, payload);
  xelf_close(xelf);
  return xelf_open(xelf, outfile);
}

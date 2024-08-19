#include "xelf.h"
#include "clarg.h"
#include "payload.h"
#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define PAGE_SIZE 0x1000

int xelf_errorcode(int set) {
  static int code = XELF_SUCCESS;
  if (set == XELF_CODERESET)
    code = XELF_SUCCESS;
  if (set > 0)
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

void xelf_destroy(t_xelf *xelf) {
  if (xelf) {
    xelf_close(xelf);
    free(xelf);
  }
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

Elf64_Phdr *xelf_phdr_from_shdr(t_xelf *xelf, Elf64_Shdr *shdr) {
  if (!xelf)
    return NULL;
  for (size_t i = 0; i < xelf->ehdr->e_phnum; i++) {
    if (xelf->phdr[i].p_vaddr < shdr->sh_addr &&
        xelf->phdr[i].p_vaddr + xelf->phdr[i].p_memsz >= shdr->sh_addr)
      return xelf->phdr + i;
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

Elf64_Phdr *xelf_phdr_from_characteristics(t_xelf *xelf, uint32_t type,
                                           uint32_t flags) {
  if (!xelf)
    return NULL;
  for (size_t i = 0; i < xelf->ehdr->e_phnum; i++) {
    Elf64_Phdr *phdr = xelf->phdr + i;
    if (phdr->p_type == type && (phdr->p_flags & flags) == flags)
      return phdr;
  }
  return NULL;
}

Elf64_Phdr *xelf_find_cave(t_xelf *xelf, size_t payload_size) {
  if (!xelf)
    return NULL;
  for (size_t i = 0; i < xelf->ehdr->e_phnum; i++) {
    Elf64_Phdr *phdr = xelf->phdr + i;
    if (phdr->p_type == PT_LOAD &&
        (phdr->p_flags & (PF_R | PF_X)) == (PF_R | PF_X)) {
      size_t cave_size =
          (xelf->phdr + i + 1)->p_offset - (phdr->p_offset + phdr->p_filesz);
      if (cave_size >= payload_size) {
        return phdr;
      }
    }
  }
  return NULL;
}

int xelf_hijack_write(t_xelf *xelf, const char *outfile, off_t offest,
                      t_payload *payload, size_t size) {
  int fd = open(outfile, O_CREAT | O_WRONLY | O_TRUNC,
                S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
  if (fd == -1)
    return xelf_errorcode(XELF_OPEN);
  if (write(fd, xelf->map, xelf->size) < 0) {
    close(fd);
    return xelf_errorcode(XELF_WRITE);
  }
  size_t padding_size = offest - xelf->size;
  void *padding = calloc(padding_size, 1);
  if (!padding) {
    close(fd);
    return xelf_errorcode(XELF_MALLOC);
  }
  if (write(fd, padding, padding_size) < 0) {
    free(padding);
    close(fd);
    return xelf_errorcode(XELF_WRITE);
  }
  free(padding);
  padding = NULL;
  size_t extra_size = size;
  if (payload) {
    if (write(fd, payload->data, payload->size) < 0) {
      close(fd);
      return xelf_errorcode(XELF_WRITE);
      extra_size -= payload->size;
    }
  }
  if (extra_size) {
    padding = calloc(extra_size, 1);
    if (!padding) {
      close(fd);
      return xelf_errorcode(XELF_MALLOC);
    }
    if (write(fd, padding, extra_size) < 0) {
      free(padding);
      close(fd);
      return xelf_errorcode(XELF_WRITE);
    }
    free(padding);
  }
  close(fd);
  return XELF_SUCCESS;
}

int xelf_inject_write(t_xelf *xelf, const char *outfile, off_t offset,
                      t_payload *payload) {
  int fd = open(outfile, O_CREAT | O_WRONLY | O_TRUNC,
                S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
  if (fd == -1)
    return xelf_errorcode(XELF_OPEN);
  if (write(fd, xelf->map, xelf->size) < 0) {
    close(fd);
    return xelf_errorcode(XELF_WRITE);
  }
  lseek(fd, offset, SEEK_SET);
  if (write(fd, payload->data, payload->size) < 0) {
    close(fd);
    return xelf_errorcode(XELF_WRITE);
  }
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

int xelf_phdr_hijack(t_xelf *xelf, Elf64_Phdr *hijacked_phdr, size_t new_size) {
  if (!xelf || !hijacked_phdr)
    return xelf_errorcode(XELF_NULLPTR);
  Elf64_Addr new_addr = (xelf_vaddr_last(xelf) + 0xFFF) & ~0xFFF;
  off_t new_offset = (xelf->size + 0xFFF) & ~0xFFF;
  Elf64_Shdr *hijacked_shdr = xelf_shdr_from_phdr(xelf, hijacked_phdr);
  if (!hijacked_shdr)
    return xelf_errorcode(XELF_NOSHDR);
  xelf_shdr_hijack_update(xelf, hijacked_shdr, new_size, new_offset, new_addr);
  hijacked_phdr->p_type = PT_LOAD;
  hijacked_phdr->p_flags = PF_X | PF_R | PF_W;
  hijacked_phdr->p_filesz = new_size;
  hijacked_phdr->p_memsz = new_size;
  hijacked_phdr->p_offset = new_offset;
  hijacked_phdr->p_vaddr = new_addr;
  hijacked_phdr->p_paddr = new_addr;
  hijacked_phdr->p_align = 0x1;
  return XELF_SUCCESS;
}

int xelf_hijack(t_xelf *xelf, const char *outfile, t_payload *payload) {
  if (!xelf)
    return xelf_errorcode(XELF_NULLPTR);
  if (payload && payload->size > PAGE_SIZE)
    return xelf_errorcode(XELF_PAYLOADSIZE);
  Elf64_Phdr *hijacked_phdr = xelf_phdr_from_type(xelf, PT_NOTE);
  if (!hijacked_phdr)
    return xelf_errorcode(XELF_NOPHDR);
  if (xelf_phdr_hijack(xelf, hijacked_phdr, payload->size) != XELF_SUCCESS)
    return xelf_errorcode(0);
  payload_set_placeholder_value(payload, "entrypoint", xelf->ehdr->e_entry);
  payload_replace_placeholders(payload);
  xelf->ehdr->e_entry = hijacked_phdr->p_vaddr;
  if (cla_provided('s'))
    xelf_shdr_from_phdr(xelf, hijacked_phdr)->sh_size += payload->size;
  if (xelf_hijack_write(xelf, outfile, hijacked_phdr->p_offset, payload,
                        payload->size) != XELF_SUCCESS)
    return xelf_errorcode(0);
  xelf_close(xelf);
  return xelf_open(xelf, outfile);
}

int xelf_extend(t_xelf *xelf, const char *outfile) {
  if (!xelf)
    return xelf_errorcode(XELF_NULLPTR);
  Elf64_Phdr *hijacked_phdr = xelf_phdr_from_type(xelf, PT_NOTE);
  if (!hijacked_phdr)
    return xelf_errorcode(XELF_NOPHDR);
  if (!xelf_phdr_hijack(xelf, hijacked_phdr, PAGE_SIZE))
    return xelf_errorcode(0);
  if (xelf_hijack_write(xelf, outfile, hijacked_phdr->p_offset, NULL,
                        PAGE_SIZE) != XELF_SUCCESS)
    return xelf_errorcode(0);
  xelf_close(xelf);
  return xelf_open(xelf, outfile);
}

int xelf_inject(t_xelf *xelf, const char *outfile, t_payload *payload) {
  Elf64_Phdr *cave = xelf_find_cave(xelf, payload->size);
  if (!cave) {
    if (cla_provided('v'))
      printf("No cave big enough in the original file\n");
    if (cla_provided('c'))
      return 0;
    return (xelf_hijack(xelf, outfile, payload) != XELF_SUCCESS);
  }
  if (cla_provided('v'))
    printf("Cave found at 0x%lx\n", cave->p_vaddr);
  payload_set_placeholder_value(payload, "entrypoint", xelf->ehdr->e_entry);
  payload_replace_placeholders(payload);
  if (xelf->ehdr->e_type == ET_EXEC)
    xelf->ehdr->e_entry = cave->p_vaddr + cave->p_filesz;
  else if (xelf->ehdr->e_type == ET_DYN)
    xelf->ehdr->e_entry = cave->p_offset + cave->p_filesz;
  if (cla_provided('s'))
    xelf_shdr_from_phdr(xelf, cave)->sh_size += payload->size;
  if (xelf_inject_write(xelf, outfile, cave->p_offset + cave->p_filesz,
                        payload) != XELF_SUCCESS)
    return xelf_errorcode(0);
  xelf_close(xelf);
  return xelf_open(xelf, outfile);
}

int xelf_error(void) {
  int code = xelf_errorcode(0);
  switch (code) {
  case XELF_SUCCESS:
    break;
  case XELF_NULLPTR:
    fprintf(stderr, "Error: NULL pointer\n");
    break;
  case XELF_OPEN:
    fprintf(stderr, "Error: open failed\n");
    break;
  case XELF_MAPFAIL:
    fprintf(stderr, "Error: mmap failed\n");
    break;
  case XELF_ELFMAGIC:
    fprintf(stderr, "Error: invalid ELF magic\n");
    break;
  case XELF_ELFCLASS:
    fprintf(stderr, "Error: invalid ELF class\n");
    break;
  case XELF_ELFEXEC:
    fprintf(stderr, "Error: invalid ELF type\n");
    break;
  case XELF_MALLOC:
    fprintf(stderr, "Error: malloc failed\n");
    break;
  case XELF_NOSHDR:
    fprintf(stderr, "Error: no section header found\n");
    break;
  case XELF_NOPHDR:
    fprintf(stderr, "Error: no program header found\n");
    break;
  case XELF_PAYLOADSIZE:
    fprintf(stderr, "Error: payload size too big\n");
    break;
  case XELF_WRITE:
    fprintf(stderr, "Error: write failed\n");
    break;
  case XELF_NOTFOUND:
    fprintf(stderr, "Error: not found\n");
    break;
  case XELF_PLACEHOLDER:
    fprintf(stderr, "Error: placeholder not found\n");
    break;
  case XELF_PAYLOAD:
    fprintf(stderr, "Error: payload not found\n");
    break;
  default:
    fprintf(stderr, "Error: unknown error: %d\n", code);
    break;
  }
  return code;
}

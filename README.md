# XELF

Wip Woody project

## Usage

compile both the payloads (for staticly vs dynamically linked):
```
nasm -f bin src/payload_dyn.asm -o playload_dyn
nasm -f bin src/payload_exec.asm -o playload_exec
```

compile the packer:
```
gcc -Iinc src/*.c -o woody
```

## TODO

* Add payloads to a .h via makefile
* Add fct to add sections/segments to elf, and put the decryption routine in there (might be needed for more complexe algos)
* Add a proper encryption/decryption algo (maybe blowfish ?)
* Add compression algo (pack the code from .text to a whole new section, set filesz of .text to 0, but memsz to actual size, then inflate only when in memory)

## Notes

`grep -rni TODO` to see whats still need to be done.

Yes I will add a makefile.

Run `xxd -i payload_exec` to see how to add the payload opcode to a C header file.

packer.c is the code from [this serie of medium articles](https://medium.com/analytics-vidhya/malware-engineering-part-0x2-finding-shelter-for-parasite-751145dd18d0)

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

## Notes

`grep -rni TODO` to see whats still need to be done.
Yes I will add a makefile.
Run `xxd -i payload_exec` to see how to add the payload opcode to a C header file.
packer.c is the code from [this serie of medium articles](https://medium.com/analytics-vidhya/malware-engineering-part-0x2-finding-shelter-for-parasite-751145dd18d0)

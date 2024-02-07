# XELF

Wip Woody project

## Usage


Compile with make

'nasm -f bin' : no metadata, headers, or any other information that would be added by formats targeting specific operating systems or executable formats (like ELF for Unix/Linux or PE for Windows).

```
./woody <target_elf>
```

## TODO

* Add fct to add sections/segments to elf, and put the decryption routine in there (might be needed for more complexe algos)
* Add a proper encryption/decryption algo (maybe blowfish ?)
* Add compression algo (pack the code from .text to a whole new section, set filesz of .text to 0, but memsz to actual size, then inflate only when in memory)
* Add error checking for all fct + extensive checks for elfs file (make sure it's not a lib ?)
* fix mem leaks

## Notes

`grep -rni TODO` to see whats still need to be done.


packer.c is the code from [this serie of medium articles](https://medium.com/analytics-vidhya/malware-engineering-part-0x2-finding-shelter-for-parasite-751145dd18d0)

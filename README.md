# XELF

Elf utility collection to make woody easier

## Usage

compile the payload :
```
nasm -f bin payload.asm -o playload
```
compile the example :
```
gcc main.c xelf.c -o demo
```

compile the target :
```
gcc hello.c -o hello
```

Run the target, to test it, then inject it :
```
./hello
./demo hello
```

Then run it to test the result :
```
./hello
```

## Notes

Currently the injector only work on executables type: ET_EXEC.
It can be easily adapted to work on shared objects as well (ET_DYN)

packer.c is the code from [this serie of medium articles](https://medium.com/analytics-vidhya/malware-engineering-part-0x2-finding-shelter-for-parasite-751145dd18d0)

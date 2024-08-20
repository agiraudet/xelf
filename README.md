# XELF

XELF is an ELF injection/packing tool written in C. It allows you to inject payloads into ELF binaries and pack them with different encryption protocols.

## Features

- Load payload from file or use default payloads
- Support for XOR and AES encryption protocols
- Option to pack the ELF
- Code caving and section extension support

Currently, only 64-bit ELF binaries are supported.

## Usage

```bash
./xelf <elf> [-o output] [-v] [-p payload] [-x] [-e encryption] [-c] [-s]
```

- `<elf>`: The ELF file to be injected.
- `-o`, `--output`: The output file.
- `-v`, `--verbose`: Enable verbose mode.
- `-p`, `--payload`: Specify the payload file for injection.
- `-x`, `--pack`: Pack the ELF.
- `-e`, `--encryption`: Specify the encryption protocol (xor, aes).
- `-c`, `--cave`: Allow code caving only.
- `-C`, `--nocave`: Don't attempt code caving.
- `-s`, `--section`: Extend section size in header to fit payload.

If no option are specified, xelf will inject the target with a hello world payload.
If a payload is given and not other option, that payload will be injected.
Given the choice, xelf will look for "caves". These are empty spaces in the binary where the payload can be injected.
This allow to inject code while not modifying the size of the binary, and be more stealthy.
If no caves are found, xelf will extend the file and hijack a note segment header to make it point to this new space.
Extending section size in header is useful for debugging, but is less stealthy.

## Building

### Dependencies

You will need xxd and nasm installed on your system. You can install them using the following commands:

```bash
sudo apt install xxd nasm
```

### Build

To build the project, you need a C compiler (like gcc) and make. Run the following command in the project root directory:

```bash
make
```

## Extending

### Adding Payloads

Write your playloads in 64bits asm, and compile them using :

```bash
nasm -f bin -o <payload> <payload>.asm
```

Then you can use the `-p` flag to inject your payload.
A stub will be added at the beginning and the end of you payload to make it injectable (hijacking entry point for example) for both static and dynamic binaries.
If needed, to access some other part of the code for example, you can use registers setup by the stub:

- `r11` holds 1 if the binary is dynamic, 0 if static
- `r8` holds the address of the binary in memory if it is dynamic.

Check the `payloads` directory for examples.

### Adding Encryption Protocols

Add your encryption functions to cypher.c with the following signature:

```c
void cypher_xor(uint8_t *data, size_t data_len, uint8_t *key, size_t key_len);
```

Then modify the `cypher_get_encrypt_func()` function in cypher.c to return your function when the encryption protocol is selected:

```c
    if (strcmp(protocol, "<your_protocol_name>") == 0)
      return cypher_my_encrypt_func;
```

Finally, add the option to the -e flag by adding this line to `cla_compose()` in main.c:

```c
clarg_add_allowed_value(e, "<your_protocol_name>");
```

### Tips

Check the encrypted data with `objdum -d -j .text <outfile>`

## Demo

Inject a hello world payload into a binary:

```bash
user@debian:~/xelf$ make hello
echo -e '#include <unistd.h>\nint main(){write(1,"Hello World!\\n",13);return 0;}' | gcc -xc - -o hello
user@debian:~/xelf$ ./hello 
Hello World!
user@debian:~/xelf$ ./xelf hello -o injected_hello
user@debian:~/xelf$ ./injected_hello 
...WOODY...
Hello World!
user@debian:~/xelf$ 
```

Packing a binary:

```bash
user@debian:~/xelf$ ./hello
Hello World!
user@debian:~/xelf$ ./xelf -x hello -o packed_hello
user@debian:~/xelf$ ./packed_hello 
...WOODY...
Hello World!
user@debian:~/xelf$ objdump -d -j .text hello
hello:     file format elf64-x86-64

Disassembly of section .text:
  /* ... */
0000000000401126 <main>:
  401126: 55                    push   %rbp
  401127: 48 89 e5              mov    %rsp,%rbp
  40112a: ba 0d 00 00 00        mov    $0xd,%edx
  40112f: be 10 20 40 00        mov    $0x402010,%esi
  401134: bf 01 00 00 00        mov    $0x1,%edi
  401139: e8 f2 fe ff ff        call   401030 <write@plt>
  40113e: b8 00 00 00 00        mov    $0x0,%eax
  401143: 5d                    pop    %rbp
  401144: c3                    ret
user@debian:~/xelf$ objdump -d -j .text packed_hello 
packed_hello:     file format elf64-x86-64

Disassembly of section .text:
  /* ... */
0000000000401126 <main>:
  401126: 26 9b                 es fwait
  401128: b2 e7                 mov    $0xe7,%dl
  40112a: 9e                    sahf
  40112b: 83 71 a5 9c           xorl   $0xffffff9c,-0x5b(%rcx)
  40112f: d5 0e 8b 2b           {rex2 0xe} mov (%rbx),%r13
  401133: 4c fe                 rex.WR (bad)
  401135: 5e                    pop    %rsi
  401136: 73 d3                 jae    40110b <__do_global_dtors_aux+0x1b>
  401138: 3b ea                 cmp    %edx,%ebp
  40113a: d6                    (bad)
  40113b: 70 8e                 jo     4010cb <register_tm_clones+0x1b>
  40113d: 5a                    pop    %rdx
  40113e: 24 6b                 and    $0x6b,%al
  401140: 1e                    (bad)
  401141: ab                    stos   %eax,%es:(%rdi)
  401142: 6b 11 82              imul   $0xffffff82,(%rcx),%edx
```

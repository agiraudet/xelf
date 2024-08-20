# XELF

XELF is an ELF injection/packing tool written in C. It allows you to inject payloads into ELF binaries and pack them with different encryption protocols.

## Features

- Load payload from file or use default payloads
- Support for XOR and AES encryption protocols
- Verbose mode for detailed output
- Option to pack the ELF
- Code caving and section extension support

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

```

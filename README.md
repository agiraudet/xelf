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

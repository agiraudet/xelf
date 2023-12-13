BITS 64

global _start

section .text

_start:

	; Save register state, RBX can be safely used
	push rax
	push rcx
	push rdx
	push rsi
	push rdi
	push r11
	
  jmp print_woody
	message:	db	"...WOODY...", 0xa
  procpath: db "/proc/self/maps", 0x0
  key: db 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x00

decrypt_init:
  mov rcx, 0xBBBBBBBBBBBBBBBB ; Set the loop counter to the length of the ciphertext

reset_edi:
  lea rdi, [rel key]          ; Load the address of the key
  jmp decrypt_loop

decrypt_loop:
    cmp byte [rdi], 0
    je reset_edi

    mov al, [rsi]             ; Load a byte from the ciphertext
    xor al, [rdi]             ; XOR with the corresponding byte from the key
    mov [rsi], al             ; Store the result back in the ciphertext
    inc rsi                   ; Move to the next byte in the ciphertext
    inc rdi                   ; Move to the next byte in the key
    loop decrypt_loop         ; Repeat the loop until ecx becomes zero
    jmp exit_woody

print_woody:
	xor	rax, rax                ; Zero out RAX
	add	rax, 0x1                ; Syscall number of write() - 0x1
	mov rdi, rax                ; File descriptor - 0x1 (STDOUT)
	lea rsi, [rel message]      ; Addresses the label relative to RIP (Instruction Pointer), i.e. 
	xor rdx, rdx
	mov dl, 0xC                 ; message size
	syscall

;This following section find the original entry point :
; - read the file /proc/self/map which contains the memory adress of the current mapped process
; - read from the beginning to the first '-' character, because thats how the file works.
; - convert that to hex, then add it to 0xAAAAAAAAAAAAAAAA, because in ET_DYN adrress like entry_points are offset and not actual Addresses
; (since the file will be dynamically linked and you cant know the adress in advance)
  xor rax, rax
  xor rdi, rdi
  lea rdi, [rel procpath]     ;load procpath
  xor rsi, rsi                ; 0 for O_RDONLY
  mov al, 0x2                 ; syscall open
  syscall

  xor r10, r10
  xor r8, r8
  xor rdi, rdi
  xor rbx, rbx
  mov dil, al
  sub sp, 0x20                ; 16 bytes, size of procpath

  lea rsi, [rsp]              ; *buf
  xor rdx, rdx
  mov dx, 0x1                 ; read 0x1 byte at a time
  xor rax, rax

read_char:
  xor rax, rax                ;syscall for read: 0
  syscall
  cmp BYTE [rsp], 0x2d        ;if read_byte == '-'
  je done
  add r10b, 0x1
  mov r8b, BYTE [rsp]         ;move read_byte to r8

  cmp r8b, 0x39
  jle digit_found

alpha_found:
  sub r8b, 0x57               ; convert char to hex: ex: 0x67('b') - 0x57 = 0xb
  jmp load_into_rbx

digit_found:
  sub r8b, 0x30

load_into_rbx:
  shl rbx, 0x4
  or  rbx, r8

loop:
  add rsp, 0x1
  lea rsi, [rsp]
  jmp read_char

done:
  sub sp, r10w                ;sub stack pointer by num of char (which are pushed on the stack)
  add sp, 0x20
  xor r8, r8
  mov r8, rbx
  mov r10, 0xAAAAAAAAAAAAAAAA
  add r8, r10

  mov r9, r8
  mov r8, rbx
  mov r10, 0xCCCCCCCCCCCCCCCC ;use same technique to find og entry point (0xCC...C is offset)
  add r8, r10
  mov rsi, r8
  jmp decrypt_init

exit_woody:
	; Restoring register state
	pop r11
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rax
	
  jmp r9

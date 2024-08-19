BITS 64
section .text
	jmp	print_woody
  key: db 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x00
	message:	db	"...WOODY...", 0xa

print_woody:
	xor	rax, rax					; Zero out RAX
	add	rax, 0x1					; Syscall number of write() - 0x1
	mov rdi, rax					; File descriptor - 0x1 (STDOUT)
	lea rsi, [rel message]			; Addresses the label relative to RIP (Instruction Pointer), i.e. 
	xor rdx, rdx
	mov dl, 0xC					; message size = 57 bytes (0x39)
	syscall					

decrypt_init:
  mov rcx, 0xBBBBBBBBBBBBBBBB          ; Set the loop counter to the length of the ciphertext
  mov rsi, 0xCCCCCCCCCCCCCCCC   ; Load the address of the ciphertext

reset_edi:
  lea rdi, [rel key]           ; Load the address of the key

decrypt_loop:
    cmp byte [rdi], 0
    je reset_edi
    mov al, [rsi]            ; Load a byte from the ciphertext
    xor al, [rdi]            ; XOR with the corresponding byte from the key
    mov [rsi], al            ; Store the result back in the ciphertext
    inc rsi                  ; Move to the next byte in the ciphertext
    inc rdi                  ; Move to the next byte in the key
    loop decrypt_loop        ; Repeat the loop until ecx becomes zero

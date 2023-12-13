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

	
	jmp	decrypt_init
	message:	db	"...WOODY...", 0xa
  ; key:  db "0123456789ABCDEF"
  key: db 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x00

decrypt_init:
  mov rcx, 0xBBBBBBBBBBBBBBBB          ; Set the loop counter to the length of the ciphertext
  ; mov ecx, 0xFB
  mov rsi, 0xCCCCCCCCCCCCCCCC   ; Load the address of the ciphertext

reset_edi:
  lea rdi, [rel key]           ; Load the address of the key
  jmp decrypt_loop

decrypt_loop:
    cmp byte [rdi], 0
    je reset_edi

    mov al, [rsi]            ; Load a byte from the ciphertext
    xor al, [rdi]            ; XOR with the corresponding byte from the key
    mov [rsi], al            ; Store the result back in the ciphertext
    inc rsi                  ; Move to the next byte in the ciphertext
    inc rdi                  ; Move to the next byte in the key
    loop decrypt_loop        ; Repeat the loop until ecx becomes zero

; Print our message
print_woody:
	xor	rax, rax					; Zero out RAX
	add	rax, 0x1					; Syscall number of write() - 0x1
	mov rdi, rax					; File descriptor - 0x1 (STDOUT)
	lea rsi, [rel message]			; Addresses the label relative to RIP (Instruction Pointer), i.e. 
									; dynamically identifying the address of the 'message' label.
	xor rdx, rdx
	mov dl, 0xC					; message size = 57 bytes (0x39)
	syscall					
  ; 


	; Restoring register state
	pop r11
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rax
	
	mov	rbx, 0xAAAAAAAAAAAAAAAA		
	jmp	rbx

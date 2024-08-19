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
  mov r11, 0x0

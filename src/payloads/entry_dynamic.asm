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

	
	jmp	whereami
  procpath: db "/proc/self/maps", 0x0

; TODO: this following section find the original entry point. It should do it at the beginning not the end, and use the same base to find the real adress of the cypher text (by adding it to 0xCCCCCCCCCCCCCCCC, similary to what is done with 0xAAAAAAAAAAAAAAAA)
; What is does is:
; - read the file /proc/self/map which contains the memory adress of the current mapped process
; - read from the beginning to the first '-' character, because thats how the file works.
; - convert that to hex, then add it to 0xAAAAAAAAAAAAAAAA, because in ET_DYN adrress like entry_points are offset and not actual addresses (since the file will be dynamically linked and you cant know the adress in advance)
; 
; ET_DYN 
whereami:
  xor rax, rax
  xor rdi, rdi
  lea rdi, [rel procpath] ;load procpath
  xor rsi, rsi            ; 0 for O_RDONLY
  mov al, 0x2             ; syscall open
  syscall

  xor r10, r10
  xor r8, r8
  xor rdi, rdi
  xor rbx, rbx
  mov dil, al
  sub sp, 0x20; 16 bytes, size of procpath

  lea rsi, [rsp] ; *buf
  xor rdx, rdx
  mov dx, 0x1   ; read 0x1 byte at a time
  xor rax, rax

read_char:
  xor rax, rax  ;syscall for read: 0
  syscall
  cmp BYTE [rsp], 0x2d ;if read_byte == '-'
  je done
  add r10b, 0x1
  mov r8b, BYTE [rsp] ;move read_byte to r8

  cmp r8b, 0x39
  jle digit_found

alpha_found:
  sub r8b, 0x57 ; convert char to hex: ex: 0x67('b') - 0x57 = 0xb
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
  sub sp, r10w  ;sub stack pointer by num of char (which are pushed on the stack)
  add sp, 0x20
  xor r8, r8
  mov r8, rbx
  mov r10, 0xAAAAAAAAAAAAAAAA
  add r8, r10

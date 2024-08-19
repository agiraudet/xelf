BITS 64
	; Restoring register state
	pop r11
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rax
	
	mov	rbx, 0xAAAAAAAAAAAAAAAA		
	jmp	rbx

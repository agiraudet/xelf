BITS 64
	; Restoring register state
  ;mov rbx, r9
	;pop r11
	 pop rbx
  pop r11
  pop r10
  pop r9
  pop r8
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	
  mov rax, 0xAAAAAAAAAAAAAAAA
  add rbx, rax

	pop rax
	; mov	rbx, 0xAAAAAAAAAAAAAAAA		
	jmp	rbx

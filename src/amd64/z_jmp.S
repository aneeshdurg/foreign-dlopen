# setjmp/longjmp that also unwind the shadow stack (CET), which musl's
# don't: z_longjmp() pops the abandoned frames' entries, so the ret that
# z_setjmp() "returns" through again matches. With no shadow stack, rdsspq
# leaves its register 0 and nothing is popped (incsspq would #UD).
# Buffer: rbx, rbp, r12-r15, rsp, rip, ssp.
	.text
	.align	4
	.globl	z_setjmp
	.hidden	z_setjmp
	.type	z_setjmp,@function
z_setjmp:
	mov	%rbx,	(%rdi)
	mov	%rbp,	8(%rdi)
	mov	%r12,	16(%rdi)
	mov	%r13,	24(%rdi)
	mov	%r14,	32(%rdi)
	mov	%r15,	40(%rdi)
	lea	8(%rsp),	%rdx
	mov	%rdx,	48(%rdi)
	mov	(%rsp),	%rdx
	mov	%rdx,	56(%rdi)
	xor	%edx,	%edx
	rdsspq	%rdx
	# As it will be once this returns.
	test	%rdx,	%rdx
	jz	1f
	add	$8,	%rdx
1:
	mov	%rdx,	64(%rdi)
	xor	%eax,	%eax
	ret

	.align	4
	.globl	z_longjmp
	.hidden	z_longjmp
	.type	z_longjmp,@function
z_longjmp:
	mov	64(%rdi),	%rdx
	test	%rdx,	%rdx
	jz	3f
	xor	%ecx,	%ecx
	rdsspq	%rcx
	sub	%rcx,	%rdx
	shr	$3,	%rdx
	# incsspq uses the low 8 bits of its count: pop at most 255 at a time.
2:
	mov	$255,	%ecx
	cmp	%rcx,	%rdx
	cmovb	%rdx,	%rcx
	incsspq	%rcx
	sub	%rcx,	%rdx
	jnz	2b
3:
	xor	%eax,	%eax
	cmp	$1,	%esi
	adc	%esi,	%eax
	mov	(%rdi),	%rbx
	mov	8(%rdi),	%rbp
	mov	16(%rdi),	%r12
	mov	24(%rdi),	%r13
	mov	32(%rdi),	%r14
	mov	40(%rdi),	%r15
	mov	48(%rdi),	%rsp
	jmp	*56(%rdi)

	.section .note.GNU-stack,"",@progbits

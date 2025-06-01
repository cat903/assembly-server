# memory.asm
# Bump allocator for managing a pre-allocated memory pool.

.section .bss
    .align 8
    pool_start_address:     .quad 0
    pool_end_address:       .quad 0
    current_alloc_pointer:  .quad 0

.section .rodata
.L_ALIGNMENT_VALUE = 8
.L_ALIGNMENT_MASK  = .L_ALIGNMENT_VALUE - 1

.section .text
    .global init_memory_manager
    .global mem_alloc
    .global mem_free
    .global mem_reset_pool

init_memory_manager:
    push %rbp
    mov %rsp, %rbp

    test %rdi, %rdi
    jz .init_failed
    test %rsi, %rsi
    jz .init_failed
    cmp %rdi, %rsi
    jge .init_failed

    mov %rdi, pool_start_address(%rip)
    mov %rsi, pool_end_address(%rip)

    mov %rdi, %rax
    add $.L_ALIGNMENT_MASK, %rax
    and $(-.L_ALIGNMENT_VALUE), %rax

    cmp %rax, %rsi
    jge .init_failed

    mov %rax, current_alloc_pointer(%rip)
    jmp .init_finished
.init_failed:
    movq $0, pool_start_address(%rip)
.init_finished:
    pop %rbp
    ret

mem_alloc:
    push %rbp
    mov %rsp, %rbp
    push %r12
    push %r13
    push %r14

    mov pool_start_address(%rip), %r12
    test %r12, %r12
    jz .alloc_failed

    test %rdi, %rdi
    jz .alloc_failed

    mov %rdi, %r13

    mov current_alloc_pointer(%rip), %rax
    add $.L_ALIGNMENT_MASK, %rax
    and $(-.L_ALIGNMENT_VALUE), %rax

    mov %rax, %r14
    add %r13, %r14

    mov pool_end_address(%rip), %r12
    cmp %r14, %r12
    jg .alloc_failed

    mov %rax, %rdi
    mov %r14, current_alloc_pointer(%rip)
    mov %rdi, %rax
    jmp .alloc_finished

.alloc_failed:
    xor %rax, %rax

.alloc_finished:
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    ret

mem_free:
    ret

mem_reset_pool:
    push %rbp
    mov %rsp, %rbp

    mov pool_start_address(%rip), %rax
    test %rax, %rax
    jz .reset_finished

    add $.L_ALIGNMENT_MASK, %rax
    and $(-.L_ALIGNMENT_VALUE), %rax

    mov %rax, current_alloc_pointer(%rip)

.reset_finished:
    pop %rbp
    ret

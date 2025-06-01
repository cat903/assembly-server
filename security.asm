# security.asm
# Security-related functions for the AsmHTTPd web server

.section .text

.global validate_path
validate_path:
    push %rbp
    mov %rsp, %rbp

    mov %rsi, %rcx      # rcx = path_len (from arg %rsi)
                        # %rdi = path_ptr (from arg %rdi)
.validate_loop:
    test %rcx, %rcx     # Check if remaining length is zero
    jz .validate_ok     # If zero, path is processed and considered okay

    cmpb $'.', (%rdi)   # Is the current character a '.'?
    jne .validate_next_char

    cmp $1, %rcx        # Is it the last character in the path?
    je .validate_next_char

    cmpb $'.', 1(%rdi)  # Is the next character also a '.'? (Found '..')
    jne .validate_next_char

    cmp $2, %rcx        # Is the remaining path exactly ".."?
    je .validate_fail

    cmpb $'/', 2(%rdi)  # Is the character after ".." a '/'? (e.g., "../")
    je .validate_fail

.validate_next_char:
    inc %rdi
    dec %rcx
    jmp .validate_loop

.validate_ok:
    mov $1, %rax
    jmp .validate_exit

.validate_fail:
    mov $0, %rax

.validate_exit:
    pop %rbp
    ret

.global sanitize_null_bytes_inplace
sanitize_null_bytes_inplace:
    push %rbp
    mov %rsp, %rbp
    push %r12           # Callee-saved register
    push %r13           # Callee-saved register

    mov %rdi, %r12      # %r12 = buffer pointer
    mov %rsi, %r13      # %r13 = buffer length
    xor %rax, %rax      # %rax = count of sanitized bytes, initialize to 0
    xor %rcx, %rcx      # %rcx = loop index, initialize to 0

.sanitize_loop:
    cmp %rcx, %r13      # Compare index with length
    jae .sanitize_done  # If index >= length, all bytes processed

    movb (%r12, %rcx), %r8b # Get current byte into %r8b
    test %r8b, %r8b         # Check if the byte is null
    jnz .next_byte          # If not null, skip replacement

    movb $'_', (%r12, %rcx) # Replace null byte with '_'
    inc %rax                # Increment count of sanitized bytes

.next_byte:
    inc %rcx
    jmp .sanitize_loop

.sanitize_done:
    pop %r13
    pop %r12
    pop %rbp
    ret

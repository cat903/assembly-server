# mime.asm
# MIME type determination module for AsmHTTPd web server

.section .rodata
.Lext_html: .asciz "html"
.Lext_css:  .asciz "css"
.Lext_js:   .asciz "js"
.Lext_json: .asciz "json"
.Lext_png:  .asciz "png"
.Lext_jpg:  .asciz "jpg"
.Lext_jpeg: .asciz "jpeg"
.Lext_txt:  .asciz "txt"

.Lmime_str_html:    .ascii "text/html; charset=utf-8\r\n"
.Lmime_str_css:     .ascii "text/css; charset=utf-8\r\n"
.Lmime_str_js:      .ascii "application/javascript; charset=utf-8\r\n"
.Lmime_str_json:    .ascii "application/json; charset=utf-8\r\n"
.Lmime_str_png:     .ascii "image/png\r\n"
.Lmime_str_jpeg:    .ascii "image/jpeg\r\n"
.Lmime_str_txt:     .ascii "text/plain; charset=utf-8\r\n"
.Lmime_str_default: .ascii "application/octet-stream\r\n"

.Lmime_len_html:    .quad 27
.Lmime_len_css:     .quad 26
.Lmime_len_js:      .quad 39
.Lmime_len_json:    .quad 34
.Lmime_len_png:     .quad 11
.Lmime_len_jpeg:    .quad 12
.Lmime_len_txt:     .quad 28
.Lmime_len_default: .quad 26

.Lmime_lookup_table:
    .quad .Lext_html, .Lmime_str_html, .Lmime_len_html
    .quad .Lext_css,  .Lmime_str_css,  .Lmime_len_css
    .quad .Lext_js,   .Lmime_str_js,   .Lmime_len_js
    .quad .Lext_json, .Lmime_str_json, .Lmime_len_json
    .quad .Lext_png,  .Lmime_str_png,  .Lmime_len_png
    .quad .Lext_jpg,  .Lmime_str_jpeg, .Lmime_len_jpeg
    .quad .Lext_jpeg, .Lmime_str_jpeg, .Lmime_len_jpeg
    .quad .Lext_txt,  .Lmime_str_txt,  .Lmime_len_txt
    .quad 0

.Lext_buffer_size = 17

.section .bss
    .comm .Llowercase_ext_buffer, .Lext_buffer_size

.section .text
    .global get_mime_type
get_mime_type: # Args: %rdi (filename_ptr), %rsi (filename_len)
               # Returns: %rax (mime_str_ptr), %rdx (mime_len_qword)
    push %rbp; mov %rsp, %rbp
    push %r12; push %r13; push %r14; push %r15

    test %rdi, %rdi; jz .return_default_mime_gmt
    test %rsi, %rsi; jz .return_default_mime_gmt
    cmpq $0, %rsi; jle .return_default_mime_gmt # If filename_len <=0

    mov %rdi, %r12      # r12 = filename_ptr
    mov %rsi, %r13      # r13 = filename_len

    # Find the last '.'
    mov %r13, %rcx      # Use rcx as counter, from filename_len down to 1
    xor %r14, %r14      # r14 = pointer to extension (after dot)
    xor %r15, %r15      # r15 = length of extension

.find_dot_loop_gmt:
    test %rcx, %rcx
    jz .no_dot_found_gmt # If counter is 0, no dot found

    dec %rcx            # Current index = rcx (0 to len-1 from end)
    movb (%r12, %rcx), %al # Get character: filename[rcx]
    cmpb $'.', %al
    jne .find_dot_loop_gmt

    # Dot found at index %rcx
    # Extension starts at index %rcx + 1
    # Extension length = filename_len - (dot_index + 1)

    # Check if dot is the first char (e.g. ".htaccess") or last char ("file.")
    test %rcx, %rcx
    jz .return_default_mime_gmt # Dot is first character

    mov %r13, %rax      # rax = filename_len
    dec %rax
    cmp %rcx, %rax      # if dot_index == filename_len - 1 (dot is last char)
    je .return_default_mime_gmt

    # Valid dot for extension found
    lea 1(%r12, %rcx), %r14 # r14 = pointer to start of extension string

    mov %r13, %rax          # rax = filename_len
    sub %rcx, %rax          # rax = filename_len - dot_index
    dec %rax                # rax = filename_len - dot_index - 1 = extension_length
    mov %rax, %r15          # r15 = extension_len

    test %r15, %r15         # If extension len is 0
    jz .return_default_mime_gmt
    cmpq $.Lext_buffer_size - 1, %r15
    ja .return_default_mime_gmt # Extension too long for buffer

    jmp .process_extension_gmt

.no_dot_found_gmt:
    jmp .return_default_mime_gmt

.process_extension_gmt:
    lea .Llowercase_ext_buffer(%rip), %rdi
    mov %r14, %rsi      # src (actual extension in filename)
    mov %r15, %rdx      # len
    call .copy_to_lower_and_terminate_gmt

    lea .Lmime_lookup_table(%rip), %r12
.lookup_mime_loop_gmt:
    mov (%r12), %rdi
    test %rdi, %rdi
    jz .return_default_mime_gmt
    lea .Llowercase_ext_buffer(%rip), %rsi
    call .strcmp_simple_gmt
    test %rax, %rax
    jz .mime_match_found_gmt
    add $24, %r12
    jmp .lookup_mime_loop_gmt

.mime_match_found_gmt:
    mov 8(%r12), %rax
    mov 16(%r12), %rdi
    mov (%rdi), %rdx
    jmp .get_mime_type_exit_gmt

.return_default_mime_gmt:
    lea .Lmime_str_default(%rip), %rax
    mov .Lmime_len_default(%rip), %rdx

.get_mime_type_exit_gmt:
    pop %r15; pop %r14; pop %r13; pop %r12
    pop %rbp
    ret

.copy_to_lower_and_terminate_gmt:
    push %rbp; mov %rsp, %rbp
    mov %rdi, %r8
    mov %rdx, %rcx
    xor %rax, %rax
.copy_loop_gmt:
    test %rcx, %rcx
    jz .copy_done_terminate_gmt
    movb (%rsi), %al
    cmpb $'A', %al; jl .not_uppercase_char_gmt
    cmpb $'Z', %al; jg .not_uppercase_char_gmt
    add $32, %al
.not_uppercase_char_gmt:
    movb %al, (%rdi)
    inc %rdi; inc %rsi; dec %rcx
    jmp .copy_loop_gmt
.copy_done_terminate_gmt:
    movb $0, (%rdi); mov %r8, %rax
    pop %rbp; ret

.strcmp_simple_gmt:
    push %rbp; mov %rsp, %rbp
.strcmp_char_loop_gmt:
    movb (%rdi), %r8b; movb (%rsi), %r9b
    cmpb %r8b, %r9b; jne .strcmp_not_equal_gmt
    test %r8b, %r8b; jz .strcmp_equal_gmt
    inc %rdi; inc %rsi; jmp .strcmp_char_loop_gmt
.strcmp_equal_gmt: xor %rax,%rax; jmp .strcmp_return_gmt
.strcmp_not_equal_gmt: mov $1,%rax
.strcmp_return_gmt: pop %rbp; ret

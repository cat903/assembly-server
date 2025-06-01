# main.asm
# High-Performance Web Server in x86_64 Assembly

.section .data
    PORT:           .word 3000
    BACKLOG:        .quad 128
    BUFFER_SIZE:    .quad 8192

    .global HTTP_200, HTTP_200_LEN
    HTTP_200:       .ascii "HTTP/1.1 200 OK\r\n"
    HTTP_200_LEN:   .quad 17

    .global HTTP_400, HTTP_400_LEN
    HTTP_400:       .ascii "HTTP/1.1 400 Bad Request\r\n"
    HTTP_400_LEN:   .quad 28

    .global HTTP_404, HTTP_404_LEN
    HTTP_404:       .ascii "HTTP/1.1 404 Not Found\r\n"
    HTTP_404_LEN:   .quad 26

    .global HTTP_500, HTTP_500_LEN
    HTTP_500:       .ascii "HTTP/1.1 500 Internal Server Error\r\n"
    HTTP_500_LEN:   .quad 38

    .global SEC_HEADERS, SEC_HEADERS_LEN
    SEC_HEADERS:    .ascii "Server: AsmHTTPd/1.0\r\n"
                    .ascii "X-Frame-Options: DENY\r\n"
                    .ascii "X-Content-Type-Options: nosniff\r\n"
                    .ascii "X-XSS-Protection: 1; mode=block\r\n"
                    .ascii "Strict-Transport-Security: max-age=31536000\r\n"
                    .ascii "Content-Security-Policy: default-src 'self'\r\n"
    SEC_HEADERS_LEN: .quad 196

    .global MEM_POOL, MEM_POOL_END
    MEM_POOL:       .skip 1048576
    MEM_POOL_END:   .quad MEM_POOL + 1048576

    DOC_ROOT:       .asciz "www"
    DOC_ROOT_LEN:   .quad 3
    INDEX_HTML_NAME: .asciz "index.html"
    INDEX_HTML_NAME_LEN: .quad 10
    SLASH_CHAR:     .byte '/'

    REQUESTS_SERVED: .quad 0
    BYTES_SENT:     .quad 0
    CONNECTIONS:    .quad 0

    sigaction_ignore_struct:
        .quad 1
        .quad 0
        .long 0
        .long 0
        .quad 0
    SIGPIPE_NUM: .quad 13

.section .bss
    .comm request_buffer, 8192
    .comm socket_fd, 8
    .comm epoll_fd, 8

.section .text
    .global _start

    .extern init_memory_manager
    .extern validate_path
    .extern get_mime_type
    .extern send_400_response
    .extern send_404_response
    .extern send_500_response
    .extern send_file_response

_start:
    mov $13, %rax
    mov SIGPIPE_NUM(%rip), %rdi
    lea sigaction_ignore_struct(%rip), %rsi
    mov $0, %rdx
    mov $8, %r10
    syscall

    lea MEM_POOL(%rip), %rdi
    lea MEM_POOL_END(%rip), %rsi
    call init_memory_manager

    call init_server; test %rax, %rax; jz .exit_init_server_failed
    call create_epoll; test %rax, %rax; js .exit_create_epoll_failed
    call server_loop
    call cleanup_server
    mov $60,%rax; mov $0,%rdi; syscall

.exit_init_server_failed: mov $60,%rax; mov $2,%rdi; syscall
.exit_create_epoll_failed: mov $60,%rax; mov $3,%rdi; syscall
exit_error: mov $60,%rax; mov $1,%rdi; syscall

init_server:
    push %rbp; mov %rsp, %rbp
    mov $41,%rax; mov $2,%rdi; mov $1,%rsi; mov $0,%rdx; syscall
    test %rax,%rax; js .init_error_path_is; mov %rax,socket_fd(%rip)
    sub $8,%rsp; movl $1,(%rsp); mov %rsp,%r10
    mov $54,%rax; mov socket_fd(%rip),%rdi; mov $1,%rsi; mov $2,%rdx
    mov $4,%r8; syscall # %r10 has pointer to optval
    add $8,%rsp
    sub $16,%rsp; movw $2,(%rsp); mov PORT(%rip),%ax; xchg %al,%ah
    movw %ax,2(%rsp); movl $0,4(%rsp)
    mov $49,%rax; mov socket_fd(%rip),%rdi; mov %rsp,%rsi; mov $16,%rdx; syscall
    add $16,%rsp; test %rax,%rax; js .init_error_path_is
    mov $50,%rax; mov socket_fd(%rip),%rdi; mov BACKLOG(%rip),%rsi; syscall
    test %rax,%rax; js .init_error_path_is
    mov $1,%rax; jmp .init_exit_path_is
.init_error_path_is: mov $0,%rax
.init_exit_path_is: pop %rbp; ret

create_epoll:
    push %rbp; mov %rsp, %rbp
    mov $213,%rax; mov $1,%rdi; syscall
    test %rax,%rax; js .epoll_error_path_ce; mov %rax,epoll_fd(%rip)
    sub $16,%rsp; movl $1,(%rsp); mov socket_fd(%rip),%eax
    movl %eax,4(%rsp); movq $0,8(%rsp)
    mov $233,%rax; mov epoll_fd(%rip),%rdi; mov $1,%rsi
    mov socket_fd(%rip),%rdx; mov %rsp,%r10; syscall
    add $16,%rsp; test %rax,%rax; js .epoll_error_path_after_create_ce
    mov epoll_fd(%rip),%rax; jmp .epoll_exit_path_ce
.epoll_error_path_after_create_ce:
    mov epoll_fd(%rip),%rdi; mov $3,%rax; syscall
.epoll_error_path_ce:
    movq $0, epoll_fd(%rip); mov $-1,%rax
.epoll_exit_path_ce: pop %rbp; ret

server_loop:
    push %rbp; mov %rsp, %rbp; sub $800,%rsp; lea -800(%rbp),%r15
.server_loop_start_sl:
    mov $232,%rax; mov epoll_fd(%rip),%rdi; mov %r15,%rsi
    mov $64,%rdx; mov $-1,%r10; syscall
    test %rax,%rax; jle .server_loop_start_sl
    mov %rax,%r12; xor %r13,%r13
.process_events_loop_sl:
    cmp %r13,%r12; je .server_loop_start_sl
    mov %r13,%rax; mov $12,%rbx; mul %rbx; add %r15,%rax
    mov 4(%rax),%ecx
    cmp %ecx,socket_fd(%rip); je ._accept_new_conn_lbl_sl
    mov %ecx,%edi; call handle_client_request; jmp ._next_event_lbl_sl
._accept_new_conn_lbl_sl: call accept_new_connection
._next_event_lbl_sl: inc %r13; jmp .process_events_loop_sl

accept_new_connection:
    push %rbp; mov %rsp, %rbp
    mov $43,%rax; mov socket_fd(%rip),%rdi; mov $0,%rsi
    mov $0,%rdx; mov $524288,%r10; syscall # SOCK_CLOEXEC
    test %rax,%rax; js ._accept_err_anc; mov %eax,%r14d
    sub $16,%rsp; movl $1,(%rsp); movl %r14d,4(%rsp); movq $0,8(%rsp)
    mov $233,%rax; mov epoll_fd(%rip),%rdi; mov $1,%rsi
    mov %r14d,%edx; mov %rsp,%r10; syscall
    add $16,%rsp; lock incq CONNECTIONS(%rip)
._accept_err_anc: pop %rbp; ret

handle_client_request: # Arg: %edi = client_fd
    push %rbp; mov %rsp, %rbp
    push %r12; push %r13; push %r14; push %r15
    mov %edi, %r15d
    mov $0,%rax; mov %r15d,%edi; lea request_buffer(%rip),%rsi
    mov BUFFER_SIZE(%rip),%rdx; syscall
    test %rax,%rax; jle ._client_err_close_hcr
    mov %rax,%r13
    lea request_buffer(%rip),%rdi; mov %r13,%rsi
    call parse_http_request
    test %rax,%rax; jz ._hcr_400_hcr
    mov %r15d,%edi; mov %r14,%rsi; mov %rcx,%rdx
    call process_request
    jmp ._client_cleanup_hcr
._hcr_400_hcr:
    mov %r15d,%edi; call send_400_response
._client_err_close_hcr:
._client_cleanup_hcr:
    mov $233,%rax; mov epoll_fd(%rip),%rdi; mov $2,%rsi
    mov %r15d,%edx; mov $0,%r10; syscall
    mov $3,%rax; mov %r15d,%edi; syscall
    lock decq CONNECTIONS(%rip)
    pop %r15; pop %r14; pop %r13; pop %r12; pop %rbp; ret

parse_http_request: # Args: %rdi(buf_ptr),%rsi(buf_len). Out: %rax(stat),%r14(path_ptr),%rcx(path_len)
    push %rbp; mov %rsp, %rbp
    cmpb $'G',(%rdi); jne ._prs_fail_phr
    cmpb $'E',1(%rdi); jne ._prs_fail_phr
    cmpb $'T',2(%rdi); jne ._prs_fail_phr
    cmpb $' ',3(%rdi); jne ._prs_fail_phr
    add $4,%rdi; mov %rdi,%r14
    mov %rsi,%rcx; sub $4,%rcx; js ._prs_fail_phr
    mov $' ',%al; repne scasb
    jnz ._prs_fail_phr
    mov %rdi,%rax; dec %rax; sub %r14,%rax
    cmpq $0,%rax; jle ._prs_fail_phr; mov %rax,%rcx
    mov %r14,%rdi; mov %rcx,%rsi; call validate_path
    test %rax,%rax; jz ._prs_fail_phr
    mov $1,%rax; jmp ._prs_exit_phr
._prs_fail_phr: xor %rax,%rax
._prs_exit_phr: pop %rbp; ret

process_request: # Args: %edi(client_fd), %rsi(req_path_ptr), %rdx(req_path_len)
    call serve_static_file
    ret

serve_static_file: # Args: %edi(client_fd),%rsi(req_path_ptr),%rdx(req_path_len)
    push %rbp; mov %rsp, %rbp
    push %r12; push %r13; push %r14; push %r15; push %rbx
    sub $512, %rsp      # Buffer for full_path[512] on stack

    mov %edi, %r14d     # Save client_fd (from %edi, 32-bit)
    mov %rsi, %r12      # Save req_path_ptr (from %rsi)
    mov %rdx, %r13      # Save req_path_len (from %rdx)

    lea (%rsp), %rdi    # %rdi = current_pos_in_local_path_buffer (start of 512-byte buffer)
    mov %rdi, %rbx      # %rbx stores start of constructed path (for first open attempt)

    lea DOC_ROOT(%rip), %rsi
    mov DOC_ROOT_LEN(%rip), %rcx
    rep movsb

    movb SLASH_CHAR(%rip), %al
    movb %al, (%rdi)
    inc %rdi

    mov %r13, %rax      # req_path_len
    cmp $1, %rax
    jne ._ssf_append_actual_req_path_ssf3
    movb (%r12), %al
    cmpb $'/', %al
    jne ._ssf_append_actual_req_path_ssf3
    lea INDEX_HTML_NAME(%rip), %rsi
    mov INDEX_HTML_NAME_LEN(%rip), %rcx
    rep movsb
    jmp ._ssf_path_constructed_ssf3

._ssf_append_actual_req_path_ssf3:
    mov %r12, %rsi
    mov %r13, %rcx
    test %rcx, %rcx
    jz ._ssf_path_constructed_ssf3
    cmpb $'/', (%rsi)
    jne ._ssf_no_leading_slash_in_req_path3
    inc %rsi
    dec %rcx
._ssf_no_leading_slash_in_req_path3:
    test %rcx, %rcx
    jle ._ssf_path_constructed_ssf3
    rep movsb

._ssf_path_constructed_ssf3:
    movb $0, (%rdi)

    mov %rbx, %r15      # %r15 = pointer to constructed path string for open/mime

._ssf_try_open_path3:
    mov $2, %rax
    mov %r15, %rdi
    mov $0, %rsi
    mov $0, %rdx
    syscall

    mov %eax, %r12d     # fd in %r12d
    cmp $0, %r12d
    jl ._ssf_open_failed_is_404_path3

    sub $144, %rsp
    mov %rsp, %rsi
    mov $5, %rax
    mov %r12d, %edi
    syscall

    mov %rax, %r10      # Save fstat syscall result in %r10
    mov 24(%rsi), %eax  # %eax = st_mode from stat_buf
    mov 48(%rsi), %r13  # %r13 = st_size (qword) from stat_buf
    add $144, %rsp

    test %r10, %r10     # Check fstat syscall result (from %r10)
    jnz ._ssf_fstat_error_path3

    # Now %eax has st_mode, %r13 has st_size for the item in %r12d
    mov $0xF000, %ecx   # S_IFMT mask
    and %ecx, %eax      # Isolate file type bits from st_mode in %eax
    cmp $0x4000, %eax   # Compare with S_IFDIR (0x4000)
    jne ._ssf_is_a_file_final3 # Not a directory, original fd (%r12d) is a file, proceed

    # ---- It IS a directory ----
    mov $3,%rax; mov %r12d,%edi; syscall # Close the directory fd

    mov %r15, %rdi # %rdi will be end of current path string in buffer ("www/somedir" or "www/")
._ssf_find_end_for_idx3: cmpb $0,(%rdi); je ._ssf_do_append_idx3; inc %rdi; jmp ._ssf_find_end_for_idx3
._ssf_do_append_idx3:
    mov -1(%rdi), %al
    cmpb $'/', %al
    je ._ssf_idx_path_has_trailing_slash3
    movb SLASH_CHAR(%rip), %al; movb %al,(%rdi); inc %rdi
._ssf_idx_path_has_trailing_slash3:
    mov %rdi, %rax; sub %r15, %rax
    add INDEX_HTML_NAME_LEN(%rip), %rax
    inc %rax
    cmp $512, %rax
    jae ._ssf_open_failed_is_404_path3

    lea INDEX_HTML_NAME(%rip), %rsi
    mov INDEX_HTML_NAME_LEN(%rip), %rcx
    rep movsb
    movb $0,(%rdi)

    mov $2, %rax; mov %r15, %rdi; mov $0, %rsi; mov $0, %rdx; syscall
    mov %eax, %r12d
    cmp $0, %r12d; jl ._ssf_open_failed_is_404_path3

    sub $144, %rsp; mov %rsp, %rsi
    mov $5, %rax; mov %r12d, %edi; syscall
    mov %rax, %r10
    mov 48(%rsi), %r13
    mov 24(%rsi), %eax
    add $144, %rsp
    test %r10, %r10; jnz ._ssf_fstat_error_idx3

    mov $0xF000, %ecx; and %ecx, %eax; cmp $0x4000, %eax
    je ._ssf_index_is_dir_err_final3

._ssf_is_a_file_final3:
    mov %r15, %rdi
    mov %r15, %rax
._ssf_strlen_mime_loop_final3: cmpb $0,(%rax); je ._ssf_strlen_mime_done_final3; inc %rax; jmp ._ssf_strlen_mime_loop_final3
._ssf_strlen_mime_done_final3: sub %r15,%rax; mov %rax,%rsi
    call get_mime_type

    push %rax
    push %rdx

    mov %r14d, %edi
    mov %r12d, %esi
    mov %r13, %rdx      # file_size (qword)
    pop %r8             # mime_len_qword (restored into %r8)
    pop %rcx            # mime_type_ptr (restored into %rcx)
    call send_file_response

    mov $3,%rax; mov %r12d,%edi; syscall
    jmp ._ssf_exit_final_ok_path3

._ssf_fstat_error_path3:
    mov $3,%rax; mov %r12d,%edi; syscall
    jmp ._ssf_serve_500_final_path3
._ssf_fstat_error_idx3:
    # Stack for stat_buf already cleaned by add $144, %rsp
    mov $3,%rax; mov %r12d,%edi; syscall
    jmp ._ssf_serve_500_final_path3

._ssf_index_is_dir_err_final3:
    mov $3,%rax; mov %r12d,%edi; syscall
._ssf_open_failed_is_404_path3:
    mov %r14d,%edi; call send_404_response; jmp ._ssf_exit_final_ok_path3
._ssf_serve_500_final_path3:
    mov %r14d,%edi; call send_500_response
._ssf_exit_final_ok_path3:
    add $512,%rsp; pop %rbx; pop %r15; pop %r14; pop %r13; pop %r12; pop %rbp; ret

cleanup_server:
    push %rbp; mov %rsp, %rbp
    mov $3,%rax; mov epoll_fd(%rip),%rdi; syscall
    mov $3,%rax; mov socket_fd(%rip),%rdi; syscall
    pop %rbp; ret

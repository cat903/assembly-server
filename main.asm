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
    MEM_POOL:       .skip 1048576 # 1MB memory pool
    MEM_POOL_END:   .quad MEM_POOL + 1048576

    DOC_ROOT:       .asciz "www"
    DOC_ROOT_LEN:   .quad 3
    INDEX_HTML_NAME: .asciz "index.html"
    INDEX_HTML_NAME_LEN: .quad 10
    SLASH_CHAR:     .byte '/'

    REQUESTS_SERVED: .quad 0
    .global BYTES_SENT              # <<< MODIFICATION: Added .global directive
    BYTES_SENT:     .quad 0
    CONNECTIONS:    .quad 0

    sigaction_ignore_struct:
        .quad 1                 # sa_handler = SIG_IGN
        .quad 0                 # sa_mask
        .long 0                 # sa_flags
        .long 0                 # padding
        .quad 0                 # sa_restorer (obsolete)
    SIGPIPE_NUM: .quad 13           # SIGPIPE signal number

.section .bss
    .comm request_buffer, 8192  # Buffer for HTTP requests
    .comm socket_fd, 8          # Server listening socket FD
    .comm epoll_fd, 8           # epoll instance FD

.section .text
    .global _start

    # External function declarations
    .extern init_memory_manager # from memory.asm
    .extern validate_path       # from security.asm
    .extern get_mime_type       # from mime.asm
    .extern send_400_response   # from response.asm
    .extern send_404_response   # from response.asm
    .extern send_500_response   # from response.asm
    .extern send_file_response  # from response.asm

_start:
    # Ignore SIGPIPE
    # int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
    # rax=13 (sigaction), rdi=signum, rsi=act, rdx=oldact (NULL), r10=sigsetsize (8 for x86_64)
    mov $13, %rax                       # syscall number for rt_sigaction
    mov SIGPIPE_NUM(%rip), %rdi         # signum = SIGPIPE
    lea sigaction_ignore_struct(%rip), %rsi # act = {SIG_IGN}
    mov $0, %rdx                        # oldact = NULL
    mov $8, %r10                        # sigsetsize (size of sa_mask, typically 8 on x86_64 for NSIG_BYTES)
    syscall

    # Initialize memory manager
    lea MEM_POOL(%rip), %rdi
    lea MEM_POOL_END(%rip), %rsi
    call init_memory_manager

    # Initialize server
    call init_server
    test %rax, %rax
    jz .exit_init_server_failed

    # Create epoll instance
    call create_epoll
    test %rax, %rax                     # epoll_create returns fd or -1 on error
    js .exit_create_epoll_failed        # If negative (error), jump

    # Start server loop
    call server_loop

    # Cleanup and exit
    call cleanup_server
    mov $60,%rax    # syscall: exit
    mov $0,%rdi     # exit code 0
    syscall

.exit_init_server_failed:
    # Print some error or log, then exit
    mov $60,%rax; mov $2,%rdi; syscall # Exit code 2
.exit_create_epoll_failed:
    # Print some error or log, then exit
    mov $60,%rax; mov $3,%rdi; syscall # Exit code 3
exit_error: # Generic error exit
    mov $60,%rax
    mov $1,%rdi     # exit code 1
    syscall

init_server:
    push %rbp; mov %rsp, %rbp
    # socket(AF_INET, SOCK_STREAM, 0)
    mov $41,%rax; mov $2,%rdi; mov $1,%rsi; mov $0,%rdx; syscall
    test %rax,%rax; js .init_error_path_is; mov %rax,socket_fd(%rip)
    # setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, optlen)
    sub $8,%rsp             # Make space for optval (int = 4 bytes, but use 8 for alignment/simplicity)
    movl $1,(%rsp)          # optval = 1
    mov %rsp,%r10           # r10 = &optval for syscall
    mov $54,%rax            # syscall: setsockopt
    mov socket_fd(%rip),%rdi # sockfd
    mov $1,%rsi             # level = SOL_SOCKET
    mov $2,%rdx             # optname = SO_REUSEADDR
                            # r10 already has &optval
    mov $4,%r8              # optlen = sizeof(int)
    syscall
    add $8,%rsp             # Clean up stack
    # bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))
    sub $16,%rsp            # sizeof(struct sockaddr_in) = 16
    movw $2,(%rsp)          # sin_family = AF_INET (2)
    mov PORT(%rip),%ax
    xchg %al,%ah            # Convert port to big-endian
    movw %ax,2(%rsp)        # sin_port
    movl $0,4(%rsp)         # sin_addr.s_addr = INADDR_ANY (0.0.0.0)
                            # 나머지 8바이트는 0으로 채워짐 (sin_zero)
    mov $49,%rax            # syscall: bind
    mov socket_fd(%rip),%rdi # sockfd
    mov %rsp,%rsi           # &serv_addr
    mov $16,%rdx            # sizeof(serv_addr)
    syscall
    add $16,%rsp            # Clean up stack
    test %rax,%rax; js .init_error_path_is
    # listen(sockfd, backlog)
    mov $50,%rax            # syscall: listen
    mov socket_fd(%rip),%rdi # sockfd
    mov BACKLOG(%rip),%rsi  # backlog
    syscall
    test %rax,%rax; js .init_error_path_is
    mov $1,%rax; jmp .init_exit_path_is # Success
.init_error_path_is:
    mov $0,%rax # Failure
.init_exit_path_is:
    pop %rbp; ret

create_epoll:
    push %rbp; mov %rsp, %rbp
    # epoll_create1(EPOLL_CLOEXEC)
    mov $213,%rax           # syscall: epoll_create (using 213 for epoll_create1 flags if available, else 291 for epoll_create)
                            # For epoll_create1: %rdi = flags. For epoll_create: %rdi = size hint (ignored > 2.6.8)
                            # Assuming epoll_create1 with 0 flags, or epoll_create with size 1
    mov $1,%rdi             # size hint for epoll_create, or flags=0 for epoll_create1(0)
                            # For EPOLL_CLOEXEC with epoll_create1, flags would be 0x80000
    syscall
    test %rax,%rax; js .epoll_error_path_ce; mov %rax,epoll_fd(%rip)

    # Add listening socket to epoll
    # struct epoll_event ev; ev.events = EPOLLIN; ev.data.fd = sockfd;
    sub $16,%rsp            # sizeof(struct epoll_event) is typically 12, use 16 for alignment
    movl $1,(%rsp)          # ev.events = EPOLLIN (0x001)
    mov socket_fd(%rip),%eax
    movl %eax,4(%rsp)       # ev.data.fd = sockfd (assuming .fd is at offset 4, could be .u32 or part of .u64)
    movq $0,8(%rsp)         # Zero out rest of data union if needed, or specific part of ev.data
    # epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event)
    mov $233,%rax           # syscall: epoll_ctl (or 217 if older kernel)
    mov epoll_fd(%rip),%rdi # epfd
    mov $1,%rsi             # op = EPOLL_CTL_ADD
    mov socket_fd(%rip),%rdx # fd
    mov %rsp,%r10           # &event
    syscall
    add $16,%rsp            # Clean up stack
    test %rax,%rax; js .epoll_error_path_after_create_ce # If epoll_ctl fails

    mov epoll_fd(%rip),%rax # Success, return epoll_fd
    jmp .epoll_exit_path_ce
.epoll_error_path_after_create_ce: # epoll_ctl failed, close epoll_fd
    mov epoll_fd(%rip),%rdi
    mov $3,%rax             # syscall: close
    syscall
.epoll_error_path_ce: # epoll_create failed
    movq $0, epoll_fd(%rip) # Ensure epoll_fd is 0 if creation failed
    mov $-1,%rax            # Return -1 to indicate error
.epoll_exit_path_ce:
    pop %rbp; ret

server_loop:
    push %rbp; mov %rsp, %rbp
    sub $800,%rsp           # Buffer for epoll_event array (e.g., 64 events * 12 bytes ~ 768)
    lea -800(%rbp),%r15     # %r15 = pointer to event buffer
.server_loop_start_sl:
    # epoll_wait(epfd, events, maxevents, timeout)
    mov $232,%rax           # syscall: epoll_wait (or 281 if older kernel)
    mov epoll_fd(%rip),%rdi # epfd
    mov %r15,%rsi           # &events
    mov $64,%rdx            # maxevents
    mov $-1,%r10            # timeout = -1 (infinite)
    syscall
    test %rax,%rax; jle .server_loop_start_sl # If num_events <= 0 (error or timeout), loop again

    mov %rax,%r12           # %r12 = number of events returned
    xor %r13,%r13           # %r13 = event_idx = 0
.process_events_loop_sl:
    cmp %r13,%r12; je .server_loop_start_sl # If event_idx == num_events, wait for more

    # Get current event: events[event_idx]
    # Assuming struct epoll_event { uint32_t events; epoll_data_t data; }; epoll_data_t can be 8 bytes.
    # So, each event is ~12 bytes.
    mov %r13,%rax
    mov $12,%rbx            # Size of struct epoll_event (approx)
    mul %rbx
    add %r15,%rax           # %rax = &events[event_idx]

    mov 4(%rax),%ecx        # Get fd from event.data.fd (assuming offset 4 for fd in epoll_data_t)
                            # This might be event.data.u32 or similar. Check struct layout.

    cmp %ecx,socket_fd(%rip)
    je ._accept_new_conn_lbl_sl

    # It's an existing connection with data
    mov %ecx,%edi           # client_fd for handle_client_request
    call handle_client_request
    jmp ._next_event_lbl_sl

._accept_new_conn_lbl_sl:
    call accept_new_connection
._next_event_lbl_sl:
    inc %r13
    jmp .process_events_loop_sl

accept_new_connection:
    push %rbp; mov %rsp, %rbp
    # accept4(sockfd, addr, addrlen, flags) - use accept4 for SOCK_CLOEXEC
    mov $43,%rax            # syscall: accept (or 288 for accept4)
    mov socket_fd(%rip),%rdi # sockfd
    mov $0,%rsi             # addr = NULL
    mov $0,%rdx             # addrlen = NULL
    # Use accept4 if possible for SOCK_CLOEXEC, else just accept.
    # mov $524288, %r10       # flags = SOCK_CLOEXEC (0x80000) for accept4
    # For plain accept, r10 is not used. If accept4, then r10 is flags.
    # Let's assume accept is used here based on the lack of r10 for accept4 in original snippet.
    syscall                 # For accept, last 3 args are addr, addrlen. For accept4, it's addr, addrlen, flags.
                            # The snippet had r10 set but using syscall accept (43)
                            # If this is accept4 (syscall 288), r10 should be flags.
                            # If syscall 43 (accept), r10 is ignored.

    test %rax,%rax; js ._accept_err_anc; mov %eax,%r14d # client_fd in %r14d

    # Add new client_fd to epoll
    sub $16,%rsp
    movl $1,(%rsp)          # ev.events = EPOLLIN
    movl %r14d,4(%rsp)      # ev.data.fd = client_fd
    movq $0,8(%rsp)
    mov $233,%rax           # syscall: epoll_ctl
    mov epoll_fd(%rip),%rdi
    mov $1,%rsi             # op = EPOLL_CTL_ADD
    mov %r14d,%edx          # fd = client_fd
    mov %rsp,%r10           # &event
    syscall
    add $16,%rsp
    # If epoll_ctl fails, we might want to close client_fd %r14d

    lock incq CONNECTIONS(%rip)
._accept_err_anc:
    pop %rbp; ret

handle_client_request: # Arg: %edi = client_fd
    push %rbp; mov %rsp, %rbp
    # Save callee-saved registers
    push %r12; push %r13; push %r14; push %r15
    mov %edi, %r15d         # Save client_fd in %r15d (32-bit part of %r15)

    # read(client_fd, request_buffer, BUFFER_SIZE)
    mov $0,%rax             # syscall: read
    mov %r15d,%edi          # client_fd
    lea request_buffer(%rip),%rsi
    mov BUFFER_SIZE(%rip),%rdx
    syscall
    test %rax,%rax; jle ._client_err_close_hcr # If bytes_read <= 0 (error or closed)

    mov %rax,%r13           # %r13 = bytes_read

    # Parse request
    lea request_buffer(%rip),%rdi # buf_ptr
    mov %r13,%rsi           # buf_len
    call parse_http_request
    # Output of parse_http_request: %rax(status: 1=ok,0=fail), %r14(path_ptr), %rcx(path_len)
    test %rax,%rax; jz ._hcr_400_hcr # If parse failed (status=0), send 400

    # Process request
    mov %r15d,%edi          # client_fd
    mov %r14,%rsi           # path_ptr
    mov %rcx,%rdx           # path_len
    call process_request
    jmp ._client_cleanup_hcr

._hcr_400_hcr:
    mov %r15d,%edi          # client_fd for send_400_response
    call send_400_response
    # Fall through to cleanup

._client_err_close_hcr: # Error during read or client closed connection
    # Cleanup will happen next

._client_cleanup_hcr:
    # Remove client_fd from epoll
    mov $233,%rax           # syscall: epoll_ctl
    mov epoll_fd(%rip),%rdi # epfd
    mov $2,%rsi             # op = EPOLL_CTL_DEL
    mov %r15d,%edx          # fd = client_fd
    mov $0,%r10             # event pointer is NULL for DEL
    syscall

    # Close client socket
    mov $3,%rax             # syscall: close
    mov %r15d,%edi          # client_fd
    syscall

    lock decq CONNECTIONS(%rip)
    pop %r15; pop %r14; pop %r13; pop %r12
    pop %rbp; ret

# parse_http_request: Parses "GET /path HTTP/1.1"
# Args: %rdi (buffer_ptr), %rsi (buffer_len)
# Returns: %rax (status: 1=success, 0=failure)
#          %r14 (path_ptr - points into original buffer)
#          %rcx (path_len)
parse_http_request:
    push %rbp; mov %rsp, %rbp
    # Check for "GET "
    cmpb $'G',(%rdi); jne ._prs_fail_phr
    cmpb $'E',1(%rdi); jne ._prs_fail_phr
    cmpb $'T',2(%rdi); jne ._prs_fail_phr
    cmpb $' ',3(%rdi); jne ._prs_fail_phr
    add $4,%rdi             # Skip "GET "
    mov %rdi,%r14           # %r14 = start of path

    # Find space after path
    mov %rsi,%rcx           # Max length to scan is remaining buf_len
    sub $4,%rcx             # Subtract length of "GET "
    js ._prs_fail_phr       # If remaining length < 0, fail

    mov $' ',%al            # Char to search for
    repne scasb             # Scan for space, %rdi points one byte *after* space
    jnz ._prs_fail_phr      # If space not found within %rcx bytes, fail

    # Calculate path length
    mov %rdi,%rax           # %rax = one byte after space
    dec %rax                # %rax = position of space
    sub %r14,%rax           # %rax = (pos of space) - (start of path) = path_len
    cmpq $0,%rax; jle ._prs_fail_phr # path_len must be > 0
    mov %rax,%rcx           # %rcx = path_len

    # Validate path (e.g., no ".." components)
    mov %r14,%rdi           # path_ptr for validate_path
    mov %rcx,%rsi           # path_len for validate_path
    call validate_path
    test %rax,%rax; jz ._prs_fail_phr # If validate_path returns 0, fail

    mov $1,%rax             # Success
    jmp ._prs_exit_phr
._prs_fail_phr:
    xor %rax,%rax           # Failure (status = 0)
._prs_exit_phr:
    pop %rbp; ret

process_request: # Args: %edi(client_fd), %rsi(req_path_ptr), %rdx(req_path_len)
    # For now, only serving static files
    call serve_static_file
    ret

# serve_static_file: Constructs full path and serves the file or sends error
# Args: %edi(client_fd), %rsi(req_path_ptr), %rdx(req_path_len)
serve_static_file:
    push %rbp; mov %rsp, %rbp
    push %r12; push %r13; push %r14; push %r15; push %rbx
    sub $512, %rsp      # Local buffer for full_path[512] on stack

    mov %edi, %r14d     # Save client_fd (passed in %edi) into %r14d
    mov %rsi, %r12      # Save req_path_ptr into %r12
    mov %rdx, %r13      # Save req_path_len into %r13

    # Construct full path: DOC_ROOT + (optional '/') + req_path
    lea (%rsp), %rdi    # %rdi = pointer to start of local_path_buffer
    mov %rdi, %rbx      # %rbx will hold the start of the fully constructed path for open

    # Copy DOC_ROOT
    lea DOC_ROOT(%rip), %rsi
    mov DOC_ROOT_LEN(%rip), %rcx
    rep movsb           # %rdi now points after DOC_ROOT in buffer

    # Add initial '/' if DOC_ROOT doesn't end with one AND req_path doesn't start with one.
    # Or, always add one here, and then skip leading '/' from req_path.
    # Current logic: adds '/' after DOC_ROOT.
    movb SLASH_CHAR(%rip), %al
    movb %al, (%rdi)
    inc %rdi

    # Handle request for "/" (root) -> serve index.html
    mov %r13, %rax      # req_path_len
    cmp $1, %rax
    jne ._ssf_append_actual_req_path_ssf3
    movb (%r12), %al    # First char of req_path
    cmpb $'/', %al
    jne ._ssf_append_actual_req_path_ssf3
    # Path is exactly "/", append "index.html"
    lea INDEX_HTML_NAME(%rip), %rsi
    mov INDEX_HTML_NAME_LEN(%rip), %rcx
    rep movsb
    jmp ._ssf_path_constructed_ssf3

._ssf_append_actual_req_path_ssf3:
    mov %r12, %rsi      # req_path_ptr
    mov %r13, %rcx      # req_path_len
    test %rcx, %rcx
    jz ._ssf_path_constructed_ssf3 # If req_path_len is 0, path is just DOC_ROOT + "/"
    cmpb $'/', (%rsi)   # Check if req_path starts with '/'
    jne ._ssf_no_leading_slash_in_req_path3
    inc %rsi            # Skip leading '/' from req_path
    dec %rcx
._ssf_no_leading_slash_in_req_path3:
    test %rcx, %rcx
    jle ._ssf_path_constructed_ssf3 # If remaining length is 0 or less
    rep movsb           # Append sanitized req_path; %rdi points after appended path

._ssf_path_constructed_ssf3:
    movb $0, (%rdi)     # Null-terminate the constructed path in the buffer

    mov %rbx, %r15      # %r15 = pointer to the full constructed path string for open/stat/mime

._ssf_try_open_path3:
    # open(pathname, flags, mode)
    mov $2, %rax        # syscall: open
    mov %r15, %rdi      # pathname
    mov $0, %rsi        # flags = O_RDONLY
    mov $0, %rdx        # mode (not used for O_RDONLY)
    syscall

    mov %eax, %r12d     # file_descriptor in %r12d (32-bit part of %r12)
    cmp $0, %r12d       # Test if fd is valid (>=0)
    jl ._ssf_open_failed_is_404_path3 # If fd < 0, open failed (e.g. not found)

    # File/Dir opened successfully, now fstat it
    sub $144, %rsp      # Make space for stat_buf (struct stat is ~144 bytes)
    mov %rsp, %rsi      # %rsi = &stat_buf
    mov $5, %rax        # syscall: fstat
    mov %r12d, %edi     # file_descriptor
    syscall             # %rax = 0 on success, -1 on error

    mov %rax, %r10      # Save fstat syscall result in %r10
    mov 24(%rsi), %eax  # %eax = st_mode from stat_buf
    mov 48(%rsi), %r13  # %r13 = st_size (qword) from stat_buf
    add $144, %rsp      # Clean up stack space for stat_buf

    test %r10, %r10     # Check fstat syscall result (should be 0 if OK)
    jnz ._ssf_fstat_error_path3 # If fstat failed

    # Check if it's a directory (st_mode & S_IFMT) == S_IFDIR
    mov $0xF000, %ecx   # S_IFMT mask (file type)
    and %ecx, %eax      # Isolate file type bits from st_mode in %eax
    cmp $0x4000, %eax   # Compare with S_IFDIR (0x4000)
    jne ._ssf_is_a_file_final3 # Not a directory, so it's a file to serve

    # ---- It IS a directory: try to serve DOC_ROOT/DIR/index.html ----
    mov $3,%rax; mov %r12d,%edi; syscall # Close the directory fd (%r12d)

    # %r15 still points to "www/somedir". Need to append "/index.html"
    # Find end of current path in buffer (pointed to by %r15)
    mov %r15, %rdi      # %rdi = start of "www/somedir"
._ssf_find_end_for_idx3:
    cmpb $0,(%rdi)
    je ._ssf_do_append_idx3
    inc %rdi
    jmp ._ssf_find_end_for_idx3
._ssf_do_append_idx3: # %rdi points to the null terminator of "www/somedir"
    # Check if path buffer has enough space for "/index.html"
    # current_len = %rdi - %r15
    # required_total_len = current_len + 1 (for '/') + INDEX_HTML_NAME_LEN + 1 (for null)
    # Compare with 512 (buffer size)
    mov %rdi, %rax
    sub %r15, %rax      # rax = current length of "www/somedir"
    add $1, %rax        # for '/'
    add INDEX_HTML_NAME_LEN(%rip), %rax # for "index.html"
    inc %rax            # for null terminator
    cmp $512, %rax      # Compare with buffer size
    jae ._ssf_open_failed_is_404_path3 # Path too long

    # Append '/' if not already present
    mov -1(%rdi), %al   # Get last char of "www/somedir"
    cmpb $'/', %al
    je ._ssf_idx_path_has_trailing_slash3
    movb SLASH_CHAR(%rip), %al
    movb %al,(%rdi)
    inc %rdi
._ssf_idx_path_has_trailing_slash3:
    # Append "index.html"
    lea INDEX_HTML_NAME(%rip), %rsi
    mov INDEX_HTML_NAME_LEN(%rip), %rcx
    rep movsb
    movb $0,(%rdi)      # Null-terminate "www/somedir/index.html"

    # Try to open "www/somedir/index.html"
    mov $2, %rax; mov %r15, %rdi; mov $0, %rsi; mov $0, %rdx; syscall # open O_RDONLY
    mov %eax, %r12d     # fd for "index.html"
    cmp $0, %r12d; jl ._ssf_open_failed_is_404_path3 # If index.html not found or error

    # fstat "index.html"
    sub $144, %rsp; mov %rsp, %rsi
    mov $5, %rax; mov %r12d, %edi; syscall # fstat
    mov %rax, %r10      # Save fstat result
    mov 48(%rsi), %r13  # %r13 = st_size for index.html
    mov 24(%rsi), %eax  # %eax = st_mode for index.html
    add $144, %rsp      # Clean up stat_buf
    test %r10, %r10; jnz ._ssf_fstat_error_idx3 # fstat error for index.html

    # Check if "index.html" itself is a directory (should not happen, but good check)
    mov $0xF000, %ecx; and %ecx, %eax
    cmp $0x4000, %eax   # S_IFDIR
    je ._ssf_index_is_dir_err_final3 # index.html is a directory, error

    # Now %r12d is fd for index.html, %r13 is its size. Proceed to serve.
    # Path string for MIME is still in %r15 ("www/somedir/index.html")

._ssf_is_a_file_final3: # Path in %r15 is a file, fd in %r12d, size in %r13
    # Get MIME type
    mov %r15, %rdi      # path_ptr for get_mime_type
    mov %r15, %rax      # Temp for strlen
._ssf_strlen_mime_loop_final3:
    cmpb $0,(%rax)
    je ._ssf_strlen_mime_done_final3
    inc %rax
    jmp ._ssf_strlen_mime_loop_final3
._ssf_strlen_mime_done_final3:
    sub %r15,%rax       # %rax = path_len
    mov %rax,%rsi       # path_len for get_mime_type
    call get_mime_type
    # Returns: %rax (mime_str_ptr), %rdx (mime_len_qword)

    push %rax           # Save mime_type_ptr
    push %rdx           # Save mime_len_qword

    # Prepare arguments for send_file_response
    mov %r14d, %edi     # client_fd (original, saved in %r14d)
    mov %r12d, %esi     # file_fd (current file, in %r12d)
    mov %r13, %rdx      # file_size (qword)
    pop %r8             # mime_len_qword (restored into %r8 for call)
    pop %rcx            # mime_type_ptr (restored into %rcx for call)
    call send_file_response

    # Close file descriptor
    mov $3,%rax; mov %r12d,%edi; syscall
    jmp ._ssf_exit_final_ok_path3

._ssf_fstat_error_path3: # fstat failed for initial open
    mov $3,%rax; mov %r12d,%edi; syscall # Close fd if it was opened
    jmp ._ssf_serve_500_final_path3
._ssf_fstat_error_idx3: # fstat failed for index.html
    mov $3,%rax; mov %r12d,%edi; syscall # Close index.html fd
    jmp ._ssf_serve_500_final_path3

._ssf_index_is_dir_err_final3: # index.html was unexpectedly a directory
    mov $3,%rax; mov %r12d,%edi; syscall # Close index.html fd
    # Fall through to 404, as we can't serve a directory as index.html content
._ssf_open_failed_is_404_path3: # File or index.html not found or open error
    mov %r14d,%edi; call send_404_response
    jmp ._ssf_exit_final_ok_path3
._ssf_serve_500_final_path3: # Generic 500 error path
    mov %r14d,%edi; call send_500_response
    # Fall through to exit

._ssf_exit_final_ok_path3:
    add $512,%rsp       # Deallocate local path buffer
    pop %rbx; pop %r15; pop %r14; pop %r13; pop %r12
    pop %rbp; ret

cleanup_server:
    push %rbp; mov %rsp, %rbp
    # Close epoll_fd
    mov $3,%rax
    mov epoll_fd(%rip),%rdi
    syscall
    # Close socket_fd
    mov $3,%rax
    mov socket_fd(%rip),%rdi
    syscall
    pop %rbp; ret
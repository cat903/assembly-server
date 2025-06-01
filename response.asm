# response.asm
# Contains response-sending functions for AsmHTTPd

.section .rodata
.L_CONTENT_TYPE_PREFIX:
    .ascii "Content-Type: "
.L_CONTENT_TYPE_PREFIX_LEN = . - .L_CONTENT_TYPE_PREFIX

.L_CONTENT_LENGTH_PREFIX:
    .ascii "Content-Length: "
.L_CONTENT_LENGTH_PREFIX_LEN = . - .L_CONTENT_LENGTH_PREFIX

.L_CRLF:
    .ascii "\r\n"
.L_CRLF_LEN = . - .L_CRLF

.L_ERROR_BODY_HEADERS:
    .ascii "Content-Length: 0\r\n"
    .ascii "Connection: close\r\n\r\n" # Empty line to end headers
.L_ERROR_BODY_HEADERS_LEN = . - .L_ERROR_BODY_HEADERS

.section .text
    .global send_file_response
    .global send_400_response
    .global send_404_response
    .global send_500_response

    # Extern declarations for symbols defined in other files (e.g., main.asm)
    .extern HTTP_200, HTTP_200_LEN
    .extern HTTP_400, HTTP_400_LEN
    .extern HTTP_404, HTTP_404_LEN
    .extern HTTP_500, HTTP_500_LEN
    .extern SEC_HEADERS, SEC_HEADERS_LEN
    .extern BYTES_SENT

# Function: send_file_response
# (Content from previous correct version)
send_file_response:
    push %rbp
    mov %rsp, %rbp
    sub $48, %rsp                       # Allocate stack space

    push %rbx                           # Save callee-saved registers
    push %r12
    push %r13
    push %r14
    push %r15

    mov %rdi, %r12                      # %r12 = client_fd
    mov %rsi, %r13                      # %r13 = file_fd
    mov %rdx, %r14                      # %r14 = file_size
    mov %rcx, %r15                      # %r15 = mime_type_ptr
    mov %r8, %rbx                       # %rbx = mime_len

    # 1. Send HTTP/1.1 200 OK
    mov $1, %rax
    mov %r12, %rdi
    lea HTTP_200(%rip), %rsi
    mov HTTP_200_LEN(%rip), %rdx
    syscall

    # 2. Send Security Headers
    mov $1, %rax
    mov %r12, %rdi
    lea SEC_HEADERS(%rip), %rsi
    mov SEC_HEADERS_LEN(%rip), %rdx
    syscall

    # 3. Send Content-Type Header
    mov $1, %rax
    mov %r12, %rdi
    lea .L_CONTENT_TYPE_PREFIX(%rip), %rsi
    mov $.L_CONTENT_TYPE_PREFIX_LEN, %rdx
    syscall
    mov $1, %rax
    mov %r12, %rdi
    mov %r15, %rsi
    mov %rbx, %rdx
    syscall

    # 4. Send Content-Length Header
    mov $1, %rax
    mov %r12, %rdi
    lea .L_CONTENT_LENGTH_PREFIX(%rip), %rsi
    mov $.L_CONTENT_LENGTH_PREFIX_LEN, %rdx
    syscall

    mov %r14, %rax
    lea -40(%rbp), %rdi
    add $20, %rdi
    mov $10, %rcx
.L_sfr_itoa_loop_send_file: # Renamed label
    xor %rdx, %rdx
    div %rcx
    add $'0', %dl
    movb %dl, (%rdi)
    dec %rdi
    test %rax, %rax
    jnz .L_sfr_itoa_loop_send_file

    inc %rdi
    lea -40(%rbp), %rax
    add $20, %rax
    sub %rdi, %rax
    inc %rax
    
    push %rax
    push %rdi
    mov $1, %rax
    mov %r12, %rdi
    pop %rsi
    pop %rdx
    syscall

    mov $1, %rax
    mov %r12, %rdi
    lea .L_CRLF(%rip), %rsi
    mov $.L_CRLF_LEN, %rdx
    syscall

    # 5. Send Header Terminator
    mov $1, %rax
    mov %r12, %rdi
    lea .L_CRLF(%rip), %rsi
    mov $.L_CRLF_LEN, %rdx
    syscall

    # 6. Send File Content
    mov $40, %rax
    mov %r12, %rdi
    mov %r13, %rsi
    mov $0, %rdx
    mov %r14, %r10
    syscall
    
    test %rax, %rax
    js .L_sfr_sendfile_error_send_file # Renamed label
    cmp $0, %rax
    jle .L_sfr_sendfile_done_send_file # Renamed label
    lock addq %rax, BYTES_SENT(%rip)
.L_sfr_sendfile_error_send_file: # Renamed label
    nop
.L_sfr_sendfile_done_send_file: # Renamed label

    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    mov %rbp, %rsp
    pop %rbp
    ret

# Function: send_400_response
# Sends a basic HTTP 400 Bad Request response.
# Argument %rdi: client_fd
send_400_response:
    push %rbp
    mov %rsp, %rbp
    # No complex stack operations needed beyond saving rdi if it's not callee-saved by convention for this simple func
    # For simplicity, directly use %rdi if syscalls don't clobber it in a way that matters for subsequent calls here.
    # Or save it:
    push %rdi # Save client_fd

    # Send HTTP/1.1 400 Bad Request
    mov $1, %rax                        # syscall: write
    # %rdi is already client_fd from argument
    lea HTTP_400(%rip), %rsi
    mov HTTP_400_LEN(%rip), %rdx
    syscall

    # Send Security Headers
    mov $1, %rax                        # syscall: write
    # %rdi is still client_fd
    lea SEC_HEADERS(%rip), %rsi
    mov SEC_HEADERS_LEN(%rip), %rdx
    syscall

    # Send Content-Length: 0 and Connection: close, then \r\n\r\n to end headers
    mov $1, %rax                        # syscall: write
    # %rdi is still client_fd
    lea .L_ERROR_BODY_HEADERS(%rip), %rsi
    mov $.L_ERROR_BODY_HEADERS_LEN, %rdx
    syscall
    
    pop %rdi  # Restore client_fd if pushed
    pop %rbp
    ret

# Function: send_404_response
# Sends a basic HTTP 404 Not Found response.
# Argument %rdi: client_fd
send_404_response:
    push %rbp
    mov %rsp, %rbp
    push %rdi # Save client_fd

    # Send HTTP/1.1 404 Not Found
    mov $1, %rax                        # syscall: write
    # %rdi is client_fd
    lea HTTP_404(%rip), %rsi
    mov HTTP_404_LEN(%rip), %rdx
    syscall

    # Send Security Headers
    mov $1, %rax                        # syscall: write
    # %rdi is client_fd
    lea SEC_HEADERS(%rip), %rsi
    mov SEC_HEADERS_LEN(%rip), %rdx
    syscall

    # Send Content-Length: 0 and Connection: close, then \r\n\r\n
    mov $1, %rax                        # syscall: write
    # %rdi is client_fd
    lea .L_ERROR_BODY_HEADERS(%rip), %rsi
    mov $.L_ERROR_BODY_HEADERS_LEN, %rdx
    syscall

    pop %rdi
    pop %rbp
    ret

# Function: send_500_response
# Sends a basic HTTP 500 Internal Server Error response.
# Argument %rdi: client_fd
send_500_response:
    push %rbp
    mov %rsp, %rbp
    push %rdi # Save client_fd

    # Send HTTP/1.1 500 Internal Server Error
    mov $1, %rax                        # syscall: write
    # %rdi is client_fd
    lea HTTP_500(%rip), %rsi
    mov HTTP_500_LEN(%rip), %rdx
    syscall

    # Send Security Headers
    mov $1, %rax                        # syscall: write
    # %rdi is client_fd
    lea SEC_HEADERS(%rip), %rsi
    mov SEC_HEADERS_LEN(%rip), %rdx
    syscall

    # Send Content-Length: 0 and Connection: close, then \r\n\r\n
    mov $1, %rax                        # syscall: write
    # %rdi is client_fd
    lea .L_ERROR_BODY_HEADERS(%rip), %rsi
    mov $.L_ERROR_BODY_HEADERS_LEN, %rdx
    syscall
    
    pop %rdi
    pop %rbp
    ret
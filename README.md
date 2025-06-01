```bash
as --64 -o main.o main.asm
as --64 -o security.o security.asm
as --64 -o mime.o mime.asm
as --64 -o memory.o memory.asm
as --64 -o response.o response.asm
ld -o asmhttpd main.o security.o mime.o memory.o response.o
```

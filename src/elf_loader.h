#ifndef ELF_LOADER_H
#define ELF_LOADER_H

typedef void (*exec_mem_cb_t)(void *, unsigned long);

/* The auxv entry a DIFUSE-patched ld.so reads its syscall stub from (see
 * exec_elf_config()). */
#define AT_DIFUSE_SYSCALL 0x44494655

void init_exec_elf(char *argv[]);
/* For the next exec_elf(): load `interp` (if not NULL) instead of the
 * program's PT_INTERP, and, if `syscall_stub` isn't 0, hand it to the
 * interpreter as AT_DIFUSE_SYSCALL, in the auxv's first AT_IGNORE entry
 * (DIFUSE's kernel module reserves one). */
void exec_elf_config(const char *interp, unsigned long syscall_stub);
void exec_elf(const char *file, int argc, char *argv[],
              exec_mem_cb_t exec_mem_cb);

#endif /* ELF_LOADER_H */

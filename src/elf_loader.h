#ifndef ELF_LOADER_H
#define ELF_LOADER_H

typedef void (*exec_mem_cb_t)(void *, unsigned long);

void init_exec_elf(char *argv[]);
void exec_elf(const char *file, int argc, char *argv[],
              exec_mem_cb_t exec_mem_cb);

#endif /* ELF_LOADER_H */

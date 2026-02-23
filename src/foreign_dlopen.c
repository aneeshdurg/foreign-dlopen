#include "foreign_dlopen.h"
#include "elf_loader.h"
#include "z_utils.h"
#include <setjmp.h>

jmp_buf jmpbuf;
char addrbuf[17];
void *(*z_dlopen)(const char *filename, int flags);
void *(*z_dlmopen)(long int lmid, const char *filename, int flags);
void *(*z_dlsym)(void *handle, const char *symbol);
int (*z_dlclose)(void *handle);
char *(*z_dlerror)(void);
int (*z_dlinfo)(void *handle, int request, void *info);

void do_jump(void **p) {
  z_dlopen = p[0];
  z_dlsym = p[1];
  z_dlclose = p[2];
  z_dlerror = p[3];
  z_dlmopen = p[4];
  z_dlinfo = p[5];
  longjmp(jmpbuf, 1);
}

void init_foreign_dlopen(const char *file, exec_mem_cb_t exec_mem_cb) {
  char *argv[3];
  z_sprintn(addrbuf, (unsigned long)do_jump, 16);
  argv[0] = "fdlhelper";
  argv[1] = addrbuf;
  argv[2] = NULL;

  if (!setjmp(jmpbuf)) {
    exec_elf(file, 2, argv, exec_mem_cb);
  } else {
    return;
  }
}

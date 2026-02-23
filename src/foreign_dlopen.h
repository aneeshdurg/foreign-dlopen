#ifndef FOREIGN_DLOPEN_H
#define FOREIGN_DLOPEN_H

#include "elf_loader.h"

extern void *(*z_dlopen)(const char *filename, int flags);
extern void *(*z_dlmopen)(long int lmid, const char *filename, int flags);
extern void *(*z_dlsym)(void *handle, const char *symbol);
extern int (*z_dlclose)(void *handle);
extern char *(*z_dlerror)(void);
extern int (*z_dlinfo)(void *handle, int request, void *info);

void init_foreign_dlopen(const char *file, exec_mem_cb_t exec_mem_cb);

#endif /* FOREIGN_DLOPEN_H */

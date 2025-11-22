#include "elf_loader.h"
#include "fdlhelper.h"
#include "z_asm.h"
#include "z_elf.h"
#include "z_syscalls.h"
#include "z_utils.h"
#include <sys/mman.h>

#define PAGE_SIZE 4096
#define ALIGN (PAGE_SIZE - 1)
#define ROUND_PG(x) (((x) + (ALIGN)) & ~(ALIGN))
#define TRUNC_PG(x) ((x) & ~(ALIGN))
#define PFLAGS(x)                                                              \
  ((((x) & PF_R) ? PROT_READ : 0) | (((x) & PF_W) ? PROT_WRITE : 0) |          \
   (((x) & PF_X) ? PROT_EXEC : 0))
#define LOAD_ERR ((unsigned long)-1)

/* Original sp (i.e. pointer to executable params) passed to entry, if any. */
unsigned long *entry_sp = NULL;

/* External fini function that the caller can provide us. */
static void (*x_fini)(void);

static void z_fini(void) {
  z_printf("Fini at work: x_fini %p\n", x_fini);
  if (x_fini != NULL)
    x_fini();
}

static int check_ehdr(Elf_Ehdr *ehdr) {
  unsigned char *e_ident = ehdr->e_ident;
  return (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
          e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3 ||
          e_ident[EI_CLASS] != ELFCLASS || e_ident[EI_VERSION] != EV_CURRENT ||
          (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN))
             ? 0
             : 1;
}

static unsigned long loadelf_anon(const void *mem, size_t *offset,
                                  Elf_Ehdr *ehdr, Elf_Phdr *phdr) {
  unsigned long minva, maxva;
  Elf_Phdr *iter;
  ssize_t sz;
  int flags, dyn = ehdr->e_type == ET_DYN;
  unsigned char *p, *base, *hint;

  minva = (unsigned long)-1;
  maxva = 0;

  for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
    if (iter->p_type != PT_LOAD)
      continue;
    if (iter->p_vaddr < minva)
      minva = iter->p_vaddr;
    if (iter->p_vaddr + iter->p_memsz > maxva)
      maxva = iter->p_vaddr + iter->p_memsz;
  }

  minva = TRUNC_PG(minva);
  maxva = ROUND_PG(maxva);

  /* For dynamic ELF let the kernel chose the address. */
  hint = dyn ? NULL : (void *)minva;
  flags = dyn ? 0 : MAP_FIXED;
  flags |= (MAP_PRIVATE | MAP_ANONYMOUS);

  z_printf("hint = %p\n", hint);

  /* Check that we can hold the whole image. */
  base = z_mmap(hint, maxva - minva, PROT_NONE, flags, -1, 0);
  if (base == (void *)-1)
    return -1;
  z_munmap(base, maxva - minva);

  flags = MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE;
  /* Now map each segment separately in precalculated address. */
  for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
    unsigned long off, start;
    if (iter->p_type != PT_LOAD)
      continue;
    off = iter->p_vaddr & ALIGN;
    start = dyn ? (unsigned long)base : 0;
    start += TRUNC_PG(iter->p_vaddr);
    sz = ROUND_PG(iter->p_memsz + off);

    p = z_mmap((void *)start, sz, PROT_WRITE, flags, -1, 0);
    if (p == (void *)-1)
      goto err;
    *offset = iter->p_offset;
    memcpy(p + off, mem + *offset, iter->p_filesz);
    *offset += iter->p_filesz;
    z_mprotect(p, sz, PFLAGS(iter->p_flags));
  }

  return (unsigned long)base;
err:
  z_munmap(base, maxva - minva);
  return LOAD_ERR;
}

#define Z_PROG 0
#define Z_INTERP 1

#if !STDLIB
int main(int argc, char *argv[]);

void z_entry(unsigned long *sp, void (*fini)(void)) {
  int argc;
  char **argv;

  entry_sp = sp;
  x_fini = fini;
  argc = (int)*(sp);
  argv = (char **)(sp + 1);
  main(argc, argv);
}
#endif

void init_exec_elf(char *argv[]) {
  /* We assume that argv comes from the original executable params. */
  // if (entry_sp == NULL) {
  entry_sp = (unsigned long *)argv - 1;
  z_printf("Set entry_sp to %p based on %p\n", argv, entry_sp);
  //}
  z_printf("After init_exec_elf entry_sp=%p &entry_sp=%p\n", entry_sp,
           &entry_sp);
}

void exec_elf(const char *file, int argc, char *argv[]) {
  Elf_Ehdr ehdrs[2], *ehdr = ehdrs;
  Elf_Phdr *phdr, *iter;
  Elf_auxv_t *av;
  char **env, **p, *elf_interp = NULL;
  unsigned long *sp = entry_sp;
  unsigned long base[2], entry[2];
  ssize_t sz;
  int fd, i;

  {
    z_printf("Setting up argc/argv\n");
    unsigned long *p = sp;
    z_printf("sp = %p\n", sp);
    /* argc */
    p++;
    /* argv */
    while (*p++ != 0) {
      z_printf("found arg\n");
    }

    z_printf("envp=%p envp[0]=%p\n", p, (void *)p[0]);
    z_printf("measuring env+auxv\n");
    unsigned long *from = p;
    /* env */
    while (*p++ != 0)
      ;
    /* aux vector */
    while (*p++ != 0) {
      p++;
    }
    p++;

    z_printf("memcpying?\n");
    unsigned long argv_sz = (argc + 1) * sizeof(*p);
    unsigned sz = (char *)p - (char *)from;
    p = alloca(sizeof(*p) + argv_sz + sz);
    *p = argc;
    z_memcpy(p + 1, argv, argv_sz);
    z_memcpy((char *)(p + 1) + argv_sz, from, sz);
    sp = p;
    argv = (char **)sp + 1;
  }

  z_printf("set envp?\n");
  env = p = (char **)&argv[argc + 1];
  while (*p++ != NULL)
    ;
  av = (void *)p;

  (void)env;
  z_printf("envp = %p\n", env[0]);
  z_printf("envp = %s\n", env[0]);
  z_printf("start actual load?\n");
  const void *mem = NULL;
  size_t offset = 0;
  size_t mem_len = 0;

  for (i = 0;; i++, ehdr++) {
    /* Open file, read and than check ELF header.*/
    if (!file) {
      z_printf("use static fdlhelper\n");
      mem = (const void *)fdlhelper;
      offset = 0;
      mem_len = fdlhelper_len;
    } else {
      z_printf("mmaping %s\n", file);
      if ((fd = z_open(file, O_RDONLY)) < 0)
        z_errx(1, "can't open %s", file);
      off_t sz = z_lseek(fd, 0, SEEK_END);
      if (sz == -1) {
        z_errx(1, "can't read file size %s", file);
      }
      if (z_lseek(fd, 0, SEEK_SET) < 0) {
        z_errx(1, "can't read file size %s", file);
      }
      mem_len = sz;
      z_printf("Mapping %lu bytes\n", mem_len);
      mem = mmap(NULL, mem_len, PROT_READ, MAP_PRIVATE, fd, 0);
      if (mem == MAP_FAILED) {
        z_errx(1, "can't mmap file %s", file);
      }
      offset = 0;
      z_printf("mem=%p, offset=%lu\n", mem, offset);
      z_printf("mem[0] = %lx\n", *(unsigned long *)mem);
      z_printf("&offset = %p, offset = %lx\n", &offset, offset);
    }
    z_printf("&offset = %p, offset = %lx\n", &offset, offset);
    z_printf("mem[0] = %lx\n", *(unsigned long *)mem);
    z_printf("&offset = %p, offset = %lx\n", &offset, offset);
    memcpy(ehdr, mem + offset, sizeof(*ehdr));
    offset += sizeof(*ehdr);
    z_printf("ehdr[0] = %lx\n", *(unsigned long *)ehdr);
    if (!check_ehdr(ehdr))
      z_errx(1, "bogus ELF header %s", file);

    z_printf("ehdr->e_phnum = %d\n", ehdr->e_phnum);
    /* Read the program header. */
    sz = ehdr->e_phnum * sizeof(Elf_Phdr);
    phdr = z_alloca(sz);
    memcpy(phdr, mem + ehdr->e_phoff, sz);
    /* Time to load ELF. */
    if ((base[i] = loadelf_anon(mem, &offset, ehdr, phdr)) == LOAD_ERR)
      z_errx(1, "can't load ELF %s", file);

    z_printf("elfloaded %d at addr = %p\n", i, base[i]);
    /* Set the entry point, if the file is dynamic than add bias. */
    entry[i] = ehdr->e_entry + (ehdr->e_type == ET_DYN ? base[i] : 0);
    z_printf("entry[i] = %lx base[i] = %lx\n", entry[i], base[i]);
    /* The second round, we've loaded ELF interp. */
    if (file != NULL && file == elf_interp)
      break;
    z_printf("iter = %lx ehdr->e_phnum = %d &phdr[ehdr->e_phnum]=%lx\n",
             (unsigned long)phdr, ehdr->e_phnum,
             (unsigned long)&phdr[ehdr->e_phnum]);
    for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
      z_printf("iter->p_type = %d\n", iter->p_type);
      if (iter->p_type != PT_INTERP)
        continue;
      elf_interp = z_alloca(iter->p_filesz);
      memcpy(elf_interp, mem + iter->p_offset, iter->p_filesz);
      if (elf_interp[iter->p_filesz - 1] != '\0')
        z_errx(1, "bogus interp path");
      if (file) {
        munmap((void *)mem, mem_len);
      }
      file = elf_interp;
    }
    /* Looks like the ELF is static -- leave the loop. */
    if (elf_interp == NULL) {
      z_printf("elf_interp was null!\n");
      break;
    }
  }

  /* Reassign some vectors that are important for
   * the dynamic linker and for lib C. */
#define AVSET(t, v, expr)                                                      \
  case (t):                                                                    \
    (v)->a_un.a_val = (expr);                                                  \
    break
  while (av->a_type != AT_NULL) {
    switch (av->a_type) {
      AVSET(AT_PHDR, av, base[Z_PROG] + ehdrs[Z_PROG].e_phoff);
      AVSET(AT_PHNUM, av, ehdrs[Z_PROG].e_phnum);
      AVSET(AT_PHENT, av, ehdrs[Z_PROG].e_phentsize);
      AVSET(AT_ENTRY, av, entry[Z_PROG]);
      AVSET(AT_EXECFN, av, (unsigned long)argv[1]);
      AVSET(AT_BASE, av, elf_interp ? base[Z_INTERP] : av->a_un.a_val);
    }
    ++av;
  }
#undef AVSET
  ++av;

  z_printf("trampo elf_iterp = %p, entry[Z_INTERP]=%p entry[Z_PROG]=%p \n",
           elf_interp, entry[Z_INTERP], entry[Z_PROG]);
  z_trampo((void (*)(void))(elf_interp ? entry[Z_INTERP] : entry[Z_PROG]), sp,
           z_fini);
  /* Should not reach. */
  z_exit(0);
}

#ifndef __LOAD_LIBRARY_PRIV_H__
#define  __LOAD_LIBRARY_PRIV_H__

#include <stdlib.h>
#include <stdint.h>
#include <elf.h>

#include "remote.h"

struct elf_section {
    uint64_t type;
    uint64_t vaddr;       /* Virtual address in the remote process. */
    char *local_vaddr;    /* Local mapping of the section. */
    size_t size;
    size_t entrysize;
};

int fix_relocation(struct remote_process *remote, Elf64_Rel *rel, 
                   Elf64_Sym *sym, uint64_t base);
#endif

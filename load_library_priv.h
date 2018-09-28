#ifndef __LOAD_LIBRARY_PRIV_H__
#define  __LOAD_LIBRARY_PRIV_H__

#include <stdlib.h>
#include <stdint.h>

struct elf_section {
    uint64_t type;
    uint64_t vaddr;       /* Virtual address in the remote process. */
    char *local_vaddr;    /* Local mapping of the section. */
    size_t size;
    size_t entrysize;
};

#endif

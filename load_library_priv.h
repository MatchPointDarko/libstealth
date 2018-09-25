#ifndef __LOAD_LIBRARY_PRIV_H__
#define  __LOAD_LIBRARY_PRIV_H__

#include <stdlib.h>
#include <stdint.h>

struct elf_section {
    uint64_t vaddr;       /* Virtual address in the remote process. */
    uint64_t local_vaddr; /* Virtual address in this process. */
    size_t size;
    size_t entrysize;
};

#endif

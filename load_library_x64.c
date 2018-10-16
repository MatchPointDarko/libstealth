#include <elf.h>
#include <errno.h>
#include <stdio.h>

#include "remote.h"
#include "load_library_priv.h"
#include "util.h"


int fix_relocation(struct remote_process *remote, 
                   Elf64_Rel *rel, Elf64_Sym *sym, 
                   uint64_t base)
{
    int ret = 0;
    Elf64_Rela *rela = (Elf64_Rela *) rel;
    uint64_t value64 = 0;
    uint32_t value32 = 0;
    void *buf = NULL;
    size_t size = 0;

    UNUSED(value32);

    /* We are writing uint64_t unless a specific
     * relocation that requires uint32_t tells otherwise. */
    buf = &value64;
    size = sizeof(value64);

    switch (ELF64_R_TYPE(rel->r_info)) {
    case R_X86_64_NONE:
        goto out;
    break;
    case R_X86_64_64:
        value64 = base + sym->st_value + rela->r_addend;
    break;
    break;
    case R_X86_64_JUMP_SLOT:
    case R_X86_64_GLOB_DAT:
        value64 = base + sym->st_value;
    break;
    case R_X86_64_RELATIVE:
        value64 = base + rela->r_addend;
    break;
    break;
    default: 
        ret = -ENOSYS;
        goto out;
    }

    ret = write_process_memory(remote, base + rel->r_offset, buf, size);
    if (ret > 0)
        ret = 0;

out:
    return ret;
}

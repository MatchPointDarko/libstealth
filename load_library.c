/*
 * Copyright (c) Mike Bazov
 */

#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>
#include <stdio.h>
#include <sys/utsname.h>
#include <limits.h>

#include "util.h"
#include "remote.h"
#include "load_library_priv.h"
#include "sym_hashtable.h"

#include "stealth.h"


/* TLS support is very limited for now. We only
 * keep data on the initialization image. */
struct dyn_library_tls {
    uint64_t init_image_vaddr;
    size_t init_image_size;
    size_t file_offset;
    bool is_static;
};

struct dyn_library {
    pid_t pid;
    char path[PATH_MAX+1];                 /* Path of the shared object. */
    struct memory_map local_map;           /* A local mmap of the library's file. */
    struct memory_map remote_map;          /* Remote memory mapping of the library. */
    struct dyn_library **depends;          /* An array of libraries this library depends on. */
    size_t depends_size;                   /* Size of the dependencies array. */ 
    size_t refcnt;                         /* Reference count, who is dependent on this library. */
    struct elf_section fini_section;       /* FINI section. */
    struct elf_section finiarray_section;  /* FINI_ARRAY section. */
    struct elf_section sym_hashtable;      /* symbols hash table. */
    struct elf_section string_table;       /* dynamic string table section. */
    struct elf_section symbol_table;       /* dynamic symbol table section. */
    struct dyn_library_tls tls;            /* Thread local storage info */
};

struct dyn_library_node {
    struct dyn_library *library;
    struct dyn_library_node *next;
};

int __load_library(struct remote_process *info, const char *path, 
                   struct dyn_library_node **loaded_libs,
                   struct dyn_library **out_library);
void __unload_library(struct remote_process *remote, struct dyn_library *library);


/* Loads PT_LOAD program headers into the tracee. 
 *
 * @tracee: the tracee object.
 * @remote_fd: a remote file descriptor that represent the library we're loading.
 * @header: a pointer to a localy memory mapping of the library we're loading.
 *
 * return how many segments were loaded. or <0 on failure. */
static int map_remote_segments64(struct remote_process *tracee, int remote_fd, 
                                 Elf64_Ehdr *header, struct memory_map *remote_map)
{
    int ret = 0;
    int prot = 0;
    Elf64_Phdr *program_header = NULL;    
    size_t num_phdrs = 0;
    size_t size = 0;
    uint64_t offset = 0;
    uint64_t base = 0;
    uint64_t last_end_vaddr = 0, vaddr = 0;
    struct memory_map segment_map;

    program_header = (Elf64_Phdr *) ((char *) header + header->e_phoff);
    num_phdrs = header->e_phnum;

    for (; num_phdrs; ++program_header, --num_phdrs) {
        if (program_header->p_type != PT_LOAD)
            continue;

        if (program_header->p_memsz == 0)
            continue;

        size += program_header->p_memsz;
        size += program_header->p_vaddr - last_end_vaddr;

        last_end_vaddr = program_header->p_vaddr + program_header->p_memsz;
    }

    if (size == 0)
        return -EINVAL;

    /* Do the remote mmap. We allocate a single chunk
     * hoping that the gaps between PT_LOAD segments are small
     * enough that it'll be worth it. instead of bookkeeping a list
     * of segments. */
    ret = remote_mmap(tracee, NULL, size, PROT_NONE,
                      MAP_PRIVATE, remote_fd, offset, remote_map);
    if (ret != 0)
        goto out;

    base = (uint64_t) remote_map->addr;
    program_header = (Elf64_Phdr *) ((char *) header + header->e_phoff);
    num_phdrs = header->e_phnum;
    for (; num_phdrs; ++program_header, --num_phdrs) {
        if (program_header->p_type != PT_LOAD)
            continue;

        size = program_header->p_memsz;
        if (size == 0)
            continue;

        /* Segment protection. */
        prot = 0;
        prot |= program_header->p_flags & PF_W ? PROT_WRITE : 0;
        prot |= program_header->p_flags & PF_R ? PROT_READ : 0;
        prot |= program_header->p_flags & PF_X ? PROT_EXEC : 0;

        /* Offset in the file. */
        offset = program_header->p_offset;

        vaddr = program_header->p_vaddr;
        vaddr += base; 

        /* Let's align to page boundary. */
        size += vaddr - PAGE_ALIGN_DOWN(vaddr);
        offset -= vaddr - PAGE_ALIGN_DOWN(vaddr);
        size = PAGE_ALIGN(size);
        vaddr = PAGE_ALIGN_DOWN(vaddr);

        /* Do the remote mmap. */
        ret = remote_mmap(tracee, (void *) vaddr, size, prot,
                          MAP_PRIVATE | MAP_FIXED, remote_fd, offset, &segment_map);
        if (ret != 0)
            goto out;

        /* Zero out bss locations. */
        if (program_header->p_filesz < program_header->p_memsz) {
            char zero_mem[1024] = { 0 };
            uint64_t start_bss = 0;
            long written = 0;
            long left = program_header->p_memsz - program_header->p_filesz;
           
            start_bss = base + program_header->p_vaddr + program_header->p_filesz;
            while (left) {

                ret = write_process_memory(tracee, start_bss + written, zero_mem, 
                                           min((size_t) left, sizeof(zero_mem)));
                if (ret < 0) {
                    goto out;
                }

                written += ret;
                left -= ret;
            }
        }
    }

    ret = 0;

out:
    if (ret < 0) {
        if (remote_map->addr != NULL) {
            (void) remote_munmap(tracee, (uint64_t) remote_map->addr, 
                                 remote_map->size);

            remote_map->addr = NULL;
            remote_map->size = 0;
        }
    }

    return ret;
}

/* Make sure the locally memory mapped library 
 * answers all the requirements. */
static bool validate_elf(Elf64_Ehdr *header)
{
    int machine_type;

    /* Must be an ELF. */
    if (header->e_ident[EI_MAG0] != 0x7f || 
        strncmp((const char *) &header->e_ident[EI_MAG1], "ELF", 3) != 0)
        return false;

    /* Must be a shared object. */
    if (header->e_type != ET_DYN)
        return false;

    machine_type = get_machine_type();
    if (machine_type < 0)
        return false;

    /* Machine type must be the same as the machine
     * type we're running on. */
    if (header->e_machine != machine_type)
        return false;

    return true;
}

static int load_dependencies(struct remote_process *remote, 
                             struct dyn_library_node **loaded_libs,
                             Elf64_Dyn *dyn_segment, 
                             struct dyn_library **depends,
                             struct elf_section *string_table)
{
    int ret = 0;
    int idx = 0;
    struct dyn_library_node *loaded_lib = NULL;
    char *env_value = NULL;

    env_value = getenv("STEALTH_LIBRARY_PATH");
    for (; dyn_segment->d_tag != DT_NULL; dyn_segment++) {
        char *file = NULL;
        char path[PATH_MAX+1];
        char *start_path = NULL;
        char *end_path = NULL;
        size_t string_offset;

        if (dyn_segment->d_tag != DT_NEEDED)
            continue;

        string_offset = dyn_segment->d_un.d_val;
        file = string_table->local_vaddr + string_offset;

        /* OK, actually load it. First try using the paths provided in
         * STEALTH_LIBRARY_PATH */
        if (env_value) {
            start_path = env_value;
            for (;;) {
                end_path = strchr(start_path, ';');
                if (end_path == NULL)
                    break;

                snprintf(path, sizeof(path), "%.*s/%s", 
                         (int) (end_path - start_path), start_path, file);
                ret = __load_library(remote, path, loaded_libs, &depends[idx]);
                if (ret == 0)
                    goto load_success;

                start_path = end_path + 1;
            }
        }

        /* Now, try /lib */
        snprintf(path, sizeof(path), "/lib/%s", file);
        ret = __load_library(remote, path, loaded_libs, &depends[idx]);
        if (ret == 0)
            goto load_success;

        /* Now, try /usr/lib */
        snprintf(path, sizeof(path), "/usr/lib/%s", file);
        ret = __load_library(remote, path, loaded_libs, &depends[idx]);
        if (ret == 0)
            goto load_success;

        /* If we've reached here, we couldn't load the library
         * using ANY path. fail. */
        goto failed;

load_success:
        /* Add it to the loaded libs list. */
        loaded_lib = malloc(sizeof(*loaded_lib));
        if (loaded_lib == NULL) {
            ret = -ENOMEM;
            goto failed;
        }

        loaded_lib->library = depends[idx++];
        loaded_lib->next = *loaded_libs;
        *loaded_libs = loaded_lib;
    }

    return 0;

failed:
    for (int i = 0; i < idx; i++) {
        __unload_library(remote, depends[i]);
    }

    /* NOTE: Regardless if we fail or not, the loaded_libs list will 
     * be cleaned by load_library(), so no need to clean it here. */

    return ret;
}

/* Iterate over the symbol table, and resolve symbols. */
static int resolve_symbols(struct dyn_library **depends,
                           size_t depends_size, 
                           struct elf_section *string_table, 
                           struct elf_section *symbol_table)
{
    size_t num_syms = 0;
    Elf64_Sym *symbol = 0;

    num_syms = symbol_table->size / symbol_table->entrysize;
    symbol = (Elf64_Sym *) symbol_table->local_vaddr;

    /* Skip the first symbol. */
    for (size_t i = 1; i < num_syms; i++) {
        if (symbol[i].st_shndx == SHN_UNDEF) {
            char *sym = NULL;
            uint64_t sym_val = 0;
            
            sym = (char *) string_table->local_vaddr + symbol[i].st_name;

            /* Search for the symbol address in all the depends. */
            for (size_t j = 0; j < depends_size; j++) {
                struct dyn_library *library = depends[j];

                sym_val = sym_hashtable_find_symbol(
                                              &library->sym_hashtable, 
                                              &library->string_table,
                                              &library->symbol_table,
                                              sym);
                if (sym_val)
                    break;
            }

            if (sym_val) {
                symbol->st_shndx = SHN_ABS;
                symbol->st_value = sym_val;
            } else if (!(ELF64_ST_BIND(symbol[i].st_info) & STB_WEAK)) {
                /* If this isn't a weak symbol and we couldn't resolve it,
                 * fail. */
                return -EINVAL;
            }
        }
    }

    return 0;
}

/*
 * Fill in the missing information in the elf section
 * structure, by iterating the section header table.
 * We're assuming the only known piece of information
 * about the section is its virtual address and the requested
 * type. */
static int fill_elf_section(Elf64_Ehdr *header,
                            struct elf_section *section)
{
    Elf64_Shdr *section_hdr = NULL;
    int num_sections = 0;
    
    section_hdr = (Elf64_Shdr *) ((char *) header + header->e_shoff);
    num_sections = header->e_shnum;

    for (int i = 0; i < num_sections; i++) {
        if (section_hdr[i].sh_addr == section->vaddr &&
            section_hdr[i].sh_type == section->type) {
            section->size = section_hdr[i].sh_size;
            section->local_vaddr = (char *) header + section_hdr[i].sh_offset;
            section->entrysize = section_hdr[i].sh_entsize;
            return 0;
        }
    }

    return -ENOENT;
}

static int fix_relocations(struct remote_process *remote,
                           uint64_t lib_vaddr_base,
                           struct elf_section *reloc_table,
                           struct elf_section *symbol_table)
{
    int ret = 0;
    char *reloc = NULL;
    Elf64_Rel *rel = NULL;
    Elf64_Sym *sym = NULL;

    for (reloc = reloc_table->local_vaddr;
         reloc < reloc_table->local_vaddr + reloc_table->size;
         reloc += reloc_table->entrysize) {
        rel = (Elf64_Rel *) reloc;
        sym = (Elf64_Sym *) symbol_table->local_vaddr + 
                            ELF64_R_SYM(rel->r_info);

        ret = fix_relocation(remote, rel, sym, lib_vaddr_base);
        if (ret < 0)
            return ret;
    }

    return 0;
}

static int call_init(struct remote_process *remote,
                     struct elf_section *init_section, 
                     struct elf_section *initarray_section)
{
    UNUSED(remote);
    UNUSED(init_section);
    UNUSED(initarray_section);

    /* Remotely call the init functions. */

    if (init_section->vaddr) {
        //remote_call_function(init_section->vaddr, 0, 0, 0, 0, 0, 0);
    }

    if (initarray_section->vaddr) {
        /* Loop on the function pointers array and
         * call every init function. */
    }

    return 0;
}

static int do_dynamic_linking(struct remote_process *remote, 
                              struct dyn_library_node **loaded_libs,
                              Elf64_Ehdr *header, uint64_t vaddr_base,
                              struct dyn_library ***depends, size_t *depends_size,
                              uint64_t *fini_vaddr, 
                              struct elf_section *sym_hashtable,
                              struct elf_section *string_table, 
                              struct elf_section *symbol_table)

{
    int ret = 0;
    Elf64_Phdr *program_header = NULL;    
    Elf64_Dyn *dyn_segment = NULL;
    size_t num_phdrs = 0;
    struct elf_section rela_table = { 0 };
    struct elf_section rel_table = { 0 };
    struct elf_section jmp_table = { 0 };
    struct elf_section init_section = { 0 };
    struct elf_section initarray_section = { 0 };

    UNUSED(fini_vaddr);

    *depends_size = 0;
    *depends = NULL;

    program_header = (Elf64_Phdr *) ((char *) header + header->e_phoff);
    num_phdrs = header->e_phnum;

    /* First, find the PT_DYNAMIC segment. Without it this
     * shared object is corrupt. */
    for (; num_phdrs; ++program_header, num_phdrs--)
        if (program_header->p_type == PT_DYNAMIC)
            break;

    if (!num_phdrs)
        return -EINVAL;

    /* Gather all the needed information for the dynamic linking steps. */
    dyn_segment = (Elf64_Dyn *) ((char *) header + program_header->p_offset);
    for (; dyn_segment->d_tag != DT_NULL; dyn_segment++) {
        switch (dyn_segment->d_tag) {
        case DT_NEEDED:
            /* OK, collect this. */
            ++*depends_size;
        break;
        case DT_STRTAB:
            string_table->type = SHT_STRTAB;
            string_table->vaddr = dyn_segment->d_un.d_ptr;
        break;
        case DT_STRSZ:
            string_table->size = dyn_segment->d_un.d_val;
        break;
        case DT_SYMTAB:
            symbol_table->type = SHT_DYNSYM;
            symbol_table->vaddr = dyn_segment->d_un.d_ptr;
        break;
        case DT_SYMENT:
            symbol_table->entrysize = dyn_segment->d_un.d_val;
        break;
        case DT_HASH:
            if (sym_hashtable->type != SHT_GNU_HASH) {
                sym_hashtable->type = SHT_HASH;
                sym_hashtable->vaddr = dyn_segment->d_un.d_val;
            }
        break;
        case DT_GNU_HASH:
            sym_hashtable->type = SHT_GNU_HASH;
            sym_hashtable->vaddr = dyn_segment->d_un.d_val;
        break;
        case DT_RELA:
            rela_table.type = SHT_RELA;
            rela_table.local_vaddr = (char *) header + dyn_segment->d_un.d_val;
        break;
        case DT_RELASZ:
            rela_table.size = dyn_segment->d_un.d_val;
        break;
        case DT_RELAENT:
            rela_table.entrysize = dyn_segment->d_un.d_val;
        break;
        case DT_REL:
            rel_table.type = SHT_RELA;
            rel_table.local_vaddr = (char *) header + dyn_segment->d_un.d_val;
        break;
        case DT_RELSZ:
            rel_table.size = dyn_segment->d_un.d_val;
        break;
        case DT_RELENT:
            rel_table.entrysize = dyn_segment->d_un.d_val;
        break;
        case DT_PLTREL:
            if (dyn_segment->d_un.d_val != DT_RELA &&
                dyn_segment->d_un.d_val != DT_REL)
                return -EINVAL;
        break;
        case DT_JMPREL:
            jmp_table.type = SHT_PROGBITS;
            jmp_table.local_vaddr = (char *) header + dyn_segment->d_un.d_val;
            /* Entrysize is not specified. */
            jmp_table.entrysize = sizeof(Elf64_Rela); 
        break;
        case DT_PLTRELSZ:
            jmp_table.size = dyn_segment->d_un.d_val;
        break;
        case DT_INIT:
            init_section.type = SHT_PROGBITS;
            init_section.vaddr = dyn_segment->d_un.d_val;
        break;
        case DT_INIT_ARRAY:
            init_section.type = SHT_INIT_ARRAY;
            init_section.vaddr = dyn_segment->d_un.d_val;
        break;
        case DT_INIT_ARRAYSZ:
            init_section.size = dyn_segment->d_un.d_val;
        break;
        case DT_TEXTREL:
            /* TODO: We don't support this yet. */
            return -ENOSYS;
        }
    }

    /* Check that all the mandatory sections are available. */
    if (string_table->vaddr == 0 || string_table->size == 0 ||
        symbol_table->vaddr == 0 || symbol_table->entrysize == 0 ||
        sym_hashtable->vaddr == 0) {
        ret = -EINVAL;
        goto fail;
    }

    /* Unfortunetly there is no size information about
     * the hash table and the symbol table in the DT_DYNAMIC
     * segment... not sure why. let's handle this quirk and get the size
     * and all the other info using the section header table.. 
     */
    ret = fill_elf_section(header, sym_hashtable);
    if (ret != 0)
        goto fail;

    ret = fill_elf_section(header, symbol_table);
    if (ret != 0)
        goto fail;

    ret = fill_elf_section(header, string_table);
    if (ret < 0)
        goto fail;

    if (*depends_size) {
        *depends = calloc(1, *depends_size * sizeof(struct dyn_library *));
        if (*depends == NULL) {
            ret = -ENOMEM;
            goto fail;
        }

        /* Load all the needed libraries. */
        dyn_segment = (Elf64_Dyn *) ((char *) header + 
                                     program_header->p_offset);
        ret = load_dependencies(remote, loaded_libs, dyn_segment, 
                                *depends, string_table);
        if (ret < 0)
            goto fail;
    }

    ret = resolve_symbols(*depends, *depends_size, 
                          string_table, symbol_table);
    if (ret < 0)
        goto unload;

    if (rel_table.local_vaddr) {
        if (rel_table.entrysize == 0 || rel_table.size == 0) {
            ret = -EINVAL;
            goto unload;
        }

        ret = fix_relocations(remote, vaddr_base, &rel_table,
                              symbol_table);
        if (ret < 0)
            goto unload;
    }

    if (rela_table.local_vaddr) {
        if (rela_table.entrysize == 0 || rela_table.size == 0) {
            ret = -EINVAL;
            goto unload;
        }

        ret = fix_relocations(remote, vaddr_base, &rela_table,
                              symbol_table);
        if (ret < 0)
            goto unload;
    }

    /* TODO: Load the jmp table lazily. */
    if (jmp_table.local_vaddr) {
        if (jmp_table.entrysize == 0 || jmp_table.size == 0) {
            ret = -EINVAL;
            goto unload;
        }

        ret = fix_relocations(remote, vaddr_base, &jmp_table,
                              symbol_table);
        if (ret < 0)
            goto unload;
    }

    /* TODO */
    /* Call the init function. */
    ret = call_init(remote, &init_section, &initarray_section);
    if (ret < 0)
        goto unload;

    /* DONE. */
    return 0;

unload:
    for (size_t i = 0; i < *depends_size; i++)
        __unload_library(remote, (*depends)[i]);

fail:
    *depends_size = 0;

    if (*depends) {
        free(*depends);
        *depends = NULL;
    }

    string_table->local_vaddr = NULL;
    string_table->vaddr = 0;
    string_table->size = 0;

    symbol_table->local_vaddr = NULL;
    symbol_table->vaddr = 0;
    symbol_table->size = 0;

    return ret;
}

/* TODO */
#if 0
static int collect_tls_info(struct remote_process *remote, 
                            Elf64_Ehdr *header,
                            uint64_t base_vaddr,
                            unsigned long dt_flags,
                            struct dyn_library_tls *tls)
{
    Elf64_Phdr *program_header = NULL;    
    size_t num_phdrs = 0;

    program_header = (Elf64_Phdr *) ((char *) header + header->e_phoff);
    num_phdrs = header->e_phnum;

    for (; num_phdrs; ++program_header, --num_phdrs) {
        if (program_header->p_type != PT_TLS)
            continue;

        if (program_header->p_memsz == 0)
            break;

        tls->init_image_vaddr = base_vaddr + program_header->p_vaddr;
        tls->init_image_size = program_header->p_memsz;
        tls->is_static = !!(dt_flags & DF_STATIC_TLS);

        break;
    }

    if (!num_phdrs)
        /* No TLS. */
        return 0;

    return 0;
}
#endif

/*
 * Load library to the remote target. This function
 * does the actual "loader" job. 
 *
 * @info: a remote process object.a
 * @path: path to the library to load.
 * @loaded_libs: libraries that have been loaded already as part 
 *  of the recursion calls.
 * @out_library: a pointer to a dyn_library pointer that receives the
 *  loaded library object.
 */
int __load_library(struct remote_process *info, const char *path, 
                   struct dyn_library_node **loaded_libs, 
                   struct dyn_library **out_library)
{
    int ret = 0;
    int remote_fd = 0;
    struct memory_map local_map;
    struct memory_map remote_map;
    Elf64_Ehdr *header = NULL;
    struct dyn_library *library = NULL;
    struct dyn_library **depends = NULL;
    size_t depends_size = 0;
    uint64_t fini_vaddr = 0;
    struct elf_section string_table = { 0 };
    struct elf_section symbol_table = { 0 };
    struct elf_section sym_hashtable = { 0 };

    *out_library = NULL;

    /* Check if we've already loaded the requested library. */
    while (*loaded_libs) {
        library = (*loaded_libs)->library;

        if (strncmp(library->path, path, PATH_MAX) == 0) {
            library->refcnt++;
            return 0;
        }

        loaded_libs = &(*loaded_libs)->next;
    }

    ret = local_mmap(&local_map, path, PROT_READ | PROT_WRITE);
    if (ret != 0)
        return ret;

    remote_fd = remote_open(info, path, O_RDONLY);
    if (remote_fd < 0) {
        ret = remote_fd;
        remote_fd = 0;
        goto out;
    }

    header = (Elf64_Ehdr *) local_map.addr;
    if (!validate_elf(header)) {
        ret = -EINVAL;
        goto out;
    }

    /* Load all PT_LOAD segments into the remote process. */
    switch (header->e_ident[EI_CLASS]) {
    case 1: /* TODO: 32 bit */
        ret = -ENOSYS;
        break;
    case 2: /* 64 bit */
        ret = map_remote_segments64(info, remote_fd, header, &remote_map);
        break;
    default:
        ret = -EINVAL;
        break;
    }

    if (ret < 0)
        goto out;

    ret = do_dynamic_linking(info, loaded_libs, header, 
                             (uint64_t) remote_map.addr, &depends, 
                             &depends_size, &fini_vaddr, &sym_hashtable, 
                             &string_table, &symbol_table);
    if (ret != 0)
        goto out;

    /* We're good to go. */
    library = calloc(1, sizeof(*library));
    if (library == NULL) {
        ret = -ENOMEM;
        goto out;
    }

    strncpy(library->path, path, PATH_MAX);
    library->pid = info->pid;
    library->local_map = local_map;
    library->remote_map = remote_map;
    library->depends = depends;
    library->depends_size = depends_size;
    library->sym_hashtable = sym_hashtable;
    library->string_table = string_table;
    library->symbol_table = symbol_table;
    library->refcnt = 1;

    *out_library = library;
out:
    if (remote_fd)
        remote_close(info, remote_fd);

    if (ret < 0) {
        if (local_map.addr)
            munmap(local_map.addr, local_map.size);

        if (remote_map.addr != NULL)
            (void) remote_munmap(info, (uint64_t) remote_map.addr, 
                                 remote_map.size);

        if (library)
            free(library);

        if (depends) {
            for (size_t i = 0; i < depends_size; i++)
                __unload_library(info, depends[i]);

            free(depends);
        }
    }

    return ret;
}

void __unload_library(struct remote_process *remote, 
                      struct dyn_library *library)
{
    for (size_t i = 0; i < library->depends_size; i++) {
        __unload_library(remote, library->depends[i]);
    }

    if (--library->refcnt == 0) {
        /* TODO: Call fini */
        /* call_fini();
         */
        munmap(library->local_map.addr, library->local_map.size);
        remote_munmap(remote, (uint64_t) library->remote_map.addr, 
                      library->remote_map.size);
        free(library->depends);
        free(library);
    }
}

int stealth_unload_library(struct dyn_library *library)
{
    int ret = 0;
    struct remote_process info = { 0 };

    if (library == NULL)
        return -EINVAL;

    /* Create a tracee instance for this PID, to be able
     * to call systemcalls remotely. */
    ret = init_remote_process(&info, library->pid);
    if (ret != 0)
        return ret;

    __unload_library(&info, library);

    fini_remote_process(&info);
    return 0;
}

int stealth_load_library(pid_t pid, const char *path, struct dyn_library **out_library)
{
    int ret = 0;
    struct remote_process info = { 0 };
    struct dyn_library_node *loaded_libs = NULL;

    if (path == NULL || out_library == NULL)
        return -EINVAL;

    /* Create a tracee instance for this PID, to be able
     * to call systemcalls remotely. */
    ret = init_remote_process(&info, pid);
    if (ret != 0)
        return ret;

    ret = __load_library(&info, path, &loaded_libs, out_library);
    if (ret < 0)
        goto out;

out:
    if (ret && *out_library) {
        __unload_library(&info, *out_library);
        *out_library = NULL;
    }

    /* free the loaded libs */
    while (loaded_libs) {
        struct dyn_library_node *safe = loaded_libs->next;

        free(loaded_libs);
        loaded_libs = safe;
    }

    fini_remote_process(&info);

    return ret;
}

/* Testing. We currenty link as an executable. */
int main(int argc, char **argv)
{
    struct dyn_library *library;

    if (argc < 3) {
        printf("stealth <pid> <shared_object>\n");
        return -1;
    }

    stealth_load_library(atoi(argv[1]), argv[2], &library);
    stealth_unload_library(library);

    return 0;
}

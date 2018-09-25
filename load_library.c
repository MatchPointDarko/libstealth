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


struct dyn_library {
    pid_t pid;
    char path[PATH_MAX+1];            /* Path of the shared object. */
    struct memory_map remote_map;     /* Remote memory mapping of the library. */
    struct dyn_library **depends;     /* An array of libraries this library depends on. */
    size_t depends_size;              /* Size of the dependencies array. */ 
    size_t refcnt;                    /* Reference count, who is dependent on this library. */
    uint64_t fini_vaddr;              /* Address of the FINI function pointers table. */
    struct sym_hashtable hash_table;
    struct elf_section string_table;
    struct elf_section symbol_table;
};

struct dyn_library_node {
    struct dyn_library *library;
    struct dyn_library_node *next;
};

int __load_library(struct remote_process *info, const char *path, 
                   struct dyn_library_node **loaded_libs,
                   struct dyn_library **out_library);
void __unload_library(struct remote_process *remote, struct dyn_library *library);


static int map_remote_segments32(struct remote_process *tracee, Elf32_Ehdr *header)
{
    /* TODO */
    return -ENOSYS;
}

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

    for (; num_phdrs--; ++program_header) {
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
    for (; num_phdrs--; ++program_header) {
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
                                           min(left, sizeof(zero_mem)));
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

/* Return the running machine type in Elf format. */
static uint16_t get_machine_type(void)
{
    int ret;
    int length = 0;
    struct utsname utsname;

    ret = uname(&utsname);
    if (ret == -1)
        return -errno;

    length = strlen(utsname.machine);

    if (strncmp("x86_64", utsname.machine, length) == 0) {
        return EM_X86_64;
    } else {
        /* Unsupported.. */
        return -EINVAL;
    }
}

/* Make sure the locally memory mapped library 
 * answers all the requirements. */
static bool validate_elf(Elf64_Ehdr *header)
{
    int machine_type;

    /* Must be an ELF. */
    if (header->e_ident[EI_MAG0] != 0x7f || 
        strncmp(&header->e_ident[EI_MAG1], "ELF", 3) != 0)
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

    env_value = getenv("INJECT_LIBRARY_PATH");
    for (; dyn_segment->d_tag != DT_NULL; dyn_segment++) {
        char file[PATH_MAX+1];
        char path[PATH_MAX+1];
        char *start_path = NULL;
        char *end_path = NULL;
        size_t string_offset;
        size_t read = 0;

        if (dyn_segment->d_tag != DT_NEEDED)
            continue;

        string_offset = dyn_segment->d_un.d_val;
        if (string_table->vaddr + string_offset >= 
            string_table->vaddr + string_table->size) {
            ret = -EINVAL;
            goto failed;
        }

        read = min(sizeof(file), (string_table->vaddr + string_table->size - 
                                  string_table->vaddr + string_offset));
        ret = read_process_memory(remote, string_table->vaddr + string_offset, 
                                  file, read);
        if (ret < 0)
            goto failed;

        /* OK, actually load it. First try using the paths provided in
         * INJECT_LIBRARY_PATH */
        if (env_value) {
            start_path = env_value;
            for (;;) {
                end_path = strchr(start_path, ';');
                if (end_path == NULL)
                    break;

                snprintf(path, sizeof(path), "%.*s/%s", 
                         end_path - start_path, start_path, file);
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
        ret = -ENOENT;
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
static int resolve_symbols(struct remote_process *remote,
                           struct dyn_library **depends,
                           size_t depends_size, 
                           struct elf_section *string_table, 
                           struct elf_section *symbol_table,
                           struct elf_section *hash_table)
{
    int ret = 0;
    size_t num_syms = 0;
    Elf64_Sym *symbol = 0;

    num_syms = symbol_table->size / symbol_table->entrysize;
    symbol = (Elf64_Sym *) symbol_table->local_vaddr;

    /* Skip the first symbol. */
    for (int i = 1; i < num_syms; i++) {
        if (symbol[i].st_shndx == SHN_UNDEF) {
            char *sym = NULL;
            uint64_t sym_val = 0;
            
            sym = (char *) string_table->local_vaddr + symbol[i].st_name;

            /* Search for the symbol address in all the depends. */
            for (int j = 0; j < depends_size; j++) {
                //sym_val = symbol_find(depends[j], sym);
                if (sym_val)
                    break;
            }

            if (sym_val) {
                continue;
            } else if (!symbol[i].st_info & STB_WEAK) {
                /* If this isn't a weak symbol and we couldn't resolve it,
                 * fail. */
                return -EINVAL;
            }
        }
    }
}

static int elf_section_local_map(struct remote_process *remote, 
                                 struct elf_section *section)
{
    int ret = 0;
    struct memory_map map;

    ret = remote_vma_map(remote, section->vaddr, section->size, &map);
    if (ret < 0)
        return ret;

    section->local_vaddr = (uint64_t) map.addr;

    return 0;
}

static int do_dynamic_linking(struct remote_process *remote, 
                              struct dyn_library_node **loaded_libs,
                              Elf64_Ehdr *header, uint64_t vaddr_base,
                              struct dyn_library ***depends, size_t *depends_size,
                              uint64_t *fini_vaddr, struct sym_hashtable *sym_hashtable,
                              struct elf_section *string_table, 
                              struct elf_section *symbol_table)

{
    int ret = 0;
    int needed_libs = 0;
    int hash_type = 0;
    Elf64_Phdr *program_header = NULL;    
    Elf64_Word *symtab_size = 0;
    Elf64_Dyn *dyn_segment = NULL;
    Elf64_Dyn *plt = NULL, *gdt = NULL;
    size_t num_phdrs = 0;
    struct elf_section hash_table = { 0 };

    *depends_size = 0;
    *depends = NULL;

    program_header = (Elf64_Phdr *) ((char *) header + header->e_phoff);
    num_phdrs = header->e_phnum;

    /* First, find the PT_DYNAMIC segment. Without it this
     * shared object is corrupt. */
    for (; num_phdrs--; ++program_header)
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
            string_table->vaddr = vaddr_base + dyn_segment->d_un.d_ptr;
        break;
        case DT_STRSZ:
            string_table->size = dyn_segment->d_un.d_val;
        break;
        case DT_SYMTAB:
            symbol_table->vaddr = vaddr_base + dyn_segment->d_un.d_ptr;
        break;
        case DT_SYMENT:
            symbol_table->entrysize = dyn_segment->d_un.d_val;
        break;
        case DT_HASH:
            if (hash_type != DT_GNU_HASH) {
                hash_type = DT_HASH;
                hash_table.vaddr = dyn_segment->d_un.d_val;
            }
        break;
        case DT_GNU_HASH:
            hash_type = DT_GNU_HASH;
            hash_table.vaddr = dyn_segment->d_un.d_val;
        break;
        }
    }

    /* Check that all the mandatory sections are available. */
    if (string_table->vaddr == 0 || string_table->size == 0 ||
        symbol_table->vaddr == 0 || symbol_table->entrysize == 0 ||
        hash_table.vaddr == 0) {
        ret = -EINVAL;
        goto fail;
    }

    ret = elf_section_local_map(remote, &hash_table);
    if (ret < 0)
        goto fail;

    init_sym_hashtable(sym_hashtable, &hash_table, hash_type);

    /* Map all remote sections localy. */
    ret = elf_section_local_map(remote, string_table);
    if (ret < 0)
        goto fail;

    ret = elf_section_local_map(remote, symbol_table);
    if (ret < 0)
        goto fail;

    /* Get the size of the symbol table using the hash table
     * number of entries. */
    symbol_table->size = sym_hashtable->nchains * symbol_table->entrysize;

    if (*depends_size) {
        *depends = calloc(1, *depends_size * sizeof(struct dyn_library *));
        if (*depends == NULL) {
            ret = -ENOMEM;
            goto fail;
        }

        /* Load all the needed libraries. */
        dyn_segment = (Elf64_Dyn *) ((char *) header + program_header->p_offset);
        ret = load_dependencies(remote, loaded_libs, dyn_segment, 
                                *depends, string_table);
        if (ret < 0)
            goto fail;

        /* Resolve symbols. */
        ret = resolve_symbols(remote, *depends, *depends_size, 
                              string_table, symbol_table, &hash_table);
        if (ret < 0)
            goto unload;

        /* TODO */
        /* Fix relocations. */
        //fix_relocations();
    }

    /* TODO */
    /* Call the init function. */
    //call_init();

    /* DONE. */
    return 0;

unload:
    for (int i = 0; i < *depends_size; i++)
        __unload_library(remote, (*depends)[i]);

fail:
    *depends_size = 0;

    if (*depends) {
        free(*depends);
        *depends = NULL;
    }

    if (string_table->local_vaddr) {
        munmap((void *) string_table->local_vaddr, string_table->size);
        string_table->local_vaddr = string_table->vaddr = 0;
        string_table->size = 0;
    }
    if (symbol_table->local_vaddr) {
        munmap((void *) symbol_table->local_vaddr, symbol_table->size);
        symbol_table->local_vaddr = symbol_table->vaddr = 0;
        symbol_table->size = 0;
    }
    if (hash_table.local_vaddr)
        munmap((void *) hash_table.local_vaddr, hash_table.size);

    return ret;
}

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
    struct memory_map map;
    struct memory_map remote_map;
    Elf64_Ehdr *header = NULL;
    struct dyn_library *library = NULL;
    struct dyn_library **depends = NULL;
    size_t depends_size = 0;
    uint64_t fini_vaddr = 0;
    struct elf_section string_table = { 0 };
    struct elf_section symbol_table = { 0 };
    struct sym_hashtable sym_hashtable = { 0 };

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

    ret = local_mmap(&map, path, PROT_READ);
    if (ret != 0)
        return ret;

    remote_fd = remote_open(info, path, O_RDONLY);
    if (remote_fd < 0) {
        ret = remote_fd;
        remote_fd = 0;
        goto out;
    }

    header = (Elf64_Ehdr *) map.addr;
    if (!validate_elf(header)) {
        ret = -EINVAL;
        goto out;
    }

    /* Load all PT_LOAD segments into the remote process. */
    switch (header->e_ident[EI_CLASS]) {
    case 1: /* 32 bit */
        ret = map_remote_segments32(info, (Elf32_Ehdr *) header);
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

    ret = do_dynamic_linking(info, loaded_libs, header, (uint64_t) remote_map.addr, 
                             &depends, &depends_size, &fini_vaddr,
                             &sym_hashtable, &string_table, &symbol_table);
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
    library->remote_map = remote_map;
    library->depends = depends;
    library->depends_size = depends_size;
    library->fini_vaddr = fini_vaddr;
    library->hash_table = sym_hashtable;
    library->string_table = string_table;
    library->symbol_table = symbol_table;

    *out_library = library;
out:
    if (remote_fd)
        remote_close(info, remote_fd);

    if (map.addr)
        munmap(map.addr, map.size);

    if (ret < 0) {
        if (remote_map.addr != NULL)
            (void) remote_munmap(info, (uint64_t) remote_map.addr, 
                                 remote_map.size);

        if (library)
            free(library);

        if (depends) {
            for (int i = 0; i < depends_size; i++)
                __unload_library(info, depends[i]);

            free(depends);
        }
    }

    return ret;
}

void __unload_library(struct remote_process *remote, 
                      struct dyn_library *library)
{
    for (int i = 0; i < library->depends_size; i++) {
        __unload_library(remote, library->depends[i]);
    }

    if (library->refcnt == 0) {
        /* TODO: Call fini */

        remote_munmap(remote, (uint64_t) library->remote_map.addr, 
                      library->remote_map.size);
        free(library->depends);
        free(library);
    } else
        library->refcnt--;
}

int unload_library(struct dyn_library *library)
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

int load_library(pid_t pid, const char *path, struct dyn_library **out_library)
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

int main(int argc, char **argv)
{
    struct dyn_library *library;

    if (argc < 2) {
        printf("stealth <pid>\n");
        return -1;
    }

    load_library(atoi(argv[1]), "/home/mike/foo.so", &library);
    unload_library(library);

    return 0;
}

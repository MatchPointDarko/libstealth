#include <elf.h>
#include <errno.h>

#include "load_library_priv.h"
#include "sym_hashtable.h"

#define ARRAYSIZE(arr) (sizeof(arr) / sizeof(arr[0]))

struct dt_hash {
};

static int dt_gnuhash_find_symbol(struct sym_hashtable *sym_hashtable,
                                  struct elf_section *string_table, 
                                  struct elf_section *symbol_table,
                                  const char *symbol)
{
}

static int do_dt_hash(const char *symbol)
{
    uint32_t h = 0, g;

    for (; *symbol; symbol++) {
        h = (h << 4) + *symbol;
        if (g = h & 0xf0000000) {
            h ^= g >> 24;
        }
        h &= ~g;
    }
    return h;
}

static int dt_hash_find_symbol(struct sym_hashtable *sym_hashtable,
                               struct elf_section *string_table, 
                               struct elf_section *symbol_table,
                               const char *symbol)
{
    int hash = 0;

    hash = do_dt_hash(symbol);
}

static int (*find_symbol_funcs[]) (struct sym_hashtable *sym_hashtable,
                                   struct elf_section *string_table, 
                                   struct elf_section *symbol_table,
                                   const char *symbol) = { 
    [DT_HASH]     = dt_hash_find_symbol,
    [DT_GNU_HASH] = dt_gnuhash_find_symbol
};

int init_sym_hashtable(struct sym_hashtable *sym_hashtable, 
                       struct elf_section *hash_table, int type)

{
    if (type < 0 || type >= ARRAYSIZE(find_symbol_funcs) ||
        find_symbol_funcs[type] == NULL)
        return -EINVAL;

    sym_hashtable->hash_table = *hash_table;
    sym_hashtable->find_symbol = find_symbol_funcs[type];

    return 0;
}

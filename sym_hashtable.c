#include <elf.h>
#include <errno.h>
#include <string.h>

#include "load_library_priv.h"
#include "sym_hashtable.h"
#include "util.h"


/* XXX: This struct is only valid for 64bit. 32bit is not suppported yet. */
struct dt_gnuhash {
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t bloom_size;
    uint32_t bloom_shift;
    uint64_t bloom[1]; /* uint64 for 64bit */
};

struct dt_hash {
    uint32_t nbuckets;
    uint32_t nchains;
    uint32_t buckets[1];
};

static int do_dt_gnuhash(const char *symbol)
{
    uint32_t h = 5381;

    for (; *symbol; symbol++) {
        h = (h << 5) + h + *symbol;
    }

    return h;
}

static uint64_t dt_gnuhash_find_symbol(struct sym_hashtable *sym_hashtable,
                                       struct elf_section *string_table, 
                                       struct elf_section *symbol_table,
                                       const char *symbol)
{
    int symbol_hash = 0;
    int idx = 0;
    struct dt_gnuhash *hashtable = NULL;    
    uint32_t *buckets = NULL;
    uint32_t *chain = NULL;
    uint64_t word = 0;  /* XXX: Again, highly 64 bit. */
    uint64_t mask = 0;

    symbol_hash = do_dt_gnuhash(symbol);
    hashtable = (struct dt_gnuhash *) sym_hashtable->hash_table.local_vaddr;

    /* XXX: Again, highly 64 bit. */
    word = hashtable->bloom[(symbol_hash / 64) % hashtable->bloom_size];
    mask = 0 | ((uint64_t) 1 << (symbol_hash % 64)) 
             | (((uint64_t) 1 << ((symbol_hash >> hashtable->bloom_shift) % 64)));

    if ((word & mask) != mask)
        return 0;

    buckets = (uint32_t *) hashtable->bloom + hashtable->bloom_size;
    idx = buckets[symbol_hash % hashtable->nbuckets];
    if (idx < hashtable->symoffset)
        return 0;

    chain = buckets + hashtable->nbuckets;
    for (;;) {
        Elf64_Sym *sym = NULL;
        uint32_t this_sym_hash = 0;
        const char *this_sym = NULL;


        sym = (Elf64_Sym *) symbol_table->local_vaddr + idx;
        this_sym = string_table->local_vaddr + sym->st_name;
        this_sym_hash = chain[idx - hashtable->symoffset];

        if (((symbol_hash | 1) == (this_sym_hash | 1)) &&
            strcmp(symbol, this_sym) == 0) {
            return sym->st_value;
        }

        if (this_sym_hash & 1)
            break;

        idx++;
    }

    return 0;
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

static uint64_t dt_hash_find_symbol(struct sym_hashtable *sym_hashtable,
                                    struct elf_section *string_table, 
                                    struct elf_section *symbol_table,
                                    const char *symbol)
{
    int symbol_idx = 0;
    struct dt_hash *hashtable = NULL;
    Elf64_Sym *symbol_entry = NULL; 
    uint32_t *chains = NULL;
    int hash = 0;

    hash = do_dt_hash(symbol);
    hashtable = (struct dt_hash *) sym_hashtable->hash_table.local_vaddr;
    chains = hashtable->buckets + hashtable->nbuckets;
    symbol_entry = (Elf64_Sym *) symbol_table->local_vaddr;

    symbol_idx = hashtable->buckets[hash % hashtable->nbuckets];

    /* Iterate over the nchains, stop at STN_UNDEF(always index 0) */
    while (symbol_idx != 0) {
        char *this_sym = NULL;

        /* If this exceeds the mapping, something is wrong... */
        if (symbol_idx >= hashtable->nchains)
            return -EINVAL;

        /* Fetch the symbol in the index, compare it. */
        this_sym = (char *) string_table->local_vaddr + 
                            symbol_entry[symbol_idx].st_name;
        if (strcmp(this_sym, symbol) == 0) {
            /* Found the symbol. */
            return symbol_entry[symbol_idx].st_value;
        }

        symbol_idx = chains[symbol_idx];
    }

    return 0;
}

int init_sym_hashtable(struct sym_hashtable *sym_hashtable, 
                       struct elf_section *hash_table)

{
    if (sym_hashtable == NULL || hash_table == NULL)
        return -EINVAL;

    sym_hashtable->hash_table = *hash_table;

    switch (hash_table->type) {
    case SHT_HASH:
        sym_hashtable->find_symbol = dt_hash_find_symbol;
    break;
    case SHT_GNU_HASH:
        sym_hashtable->find_symbol = dt_gnuhash_find_symbol;
    break;
    default:
        return -EINVAL;
    }

    return 0;
}

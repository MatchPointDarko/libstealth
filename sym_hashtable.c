#include <elf.h>
#include <errno.h>
#include <string.h>

#include "load_library_priv.h"
#include "sym_hashtable.h"
#include "util.h"


/* XXX: This struct is only valid for 64bit. 32bit is not suppported yet. */
struct gnuhash_table {
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t bloom_size;
    uint32_t bloom_shift;
    uint64_t bloom[1]; /* uint64 for 64bit */
};

struct hashtable {
    uint32_t nbuckets;
    uint32_t nchains;
    uint32_t buckets[1];
};

static int do_gnuhash(const char *symbol)
{
    uint32_t h = 5381;

    for (; *symbol; symbol++) {
        h = (h << 5) + h + *symbol;
    }

    return h;
}

static uint64_t gnuhash_find_symbol(struct elf_section *sym_hashtable,
                                    struct elf_section *string_table, 
                                    struct elf_section *symbol_table,
                                    const char *symbol)
{
    uint32_t symbol_hash = 0;
    size_t idx = 0;
    struct gnuhash_table *hashtable = NULL;    
    uint32_t *buckets = NULL;
    uint32_t *chain = NULL;
    uint64_t word = 0;  /* XXX: Again, only for 64 bit. */
    uint64_t mask = 0;

    symbol_hash = do_gnuhash(symbol);
    hashtable = (struct gnuhash_table *) sym_hashtable->local_vaddr;

    /* XXX: Again, only for 64 bit. */
    word = hashtable->bloom[(symbol_hash / 64) % hashtable->bloom_size];
    mask = 0 | ((uint64_t) 1 << (symbol_hash % 64)) 
             | (((uint64_t) 1 << ((symbol_hash >> hashtable->bloom_shift) % 64)));

    if ((word & mask) != mask)
        return 0;

    buckets = (uint32_t *) (hashtable->bloom + hashtable->bloom_size);
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

static int do_hash(const char *symbol)
{
    uint32_t h = 0, g;

    for (; *symbol; symbol++) {
        h = (h << 4) + *symbol;
        g = h & 0xf0000000;

        if (g)
            h ^= g >> 24;

        h &= ~g;
    }
    return h;
}

static uint64_t hash_find_symbol(struct elf_section *sym_hashtable,
                                 struct elf_section *string_table, 
                                 struct elf_section *symbol_table,
                                 const char *symbol)
{
    size_t symbol_idx = 0;
    struct hashtable *hashtable = NULL;
    Elf64_Sym *symbol_entry = NULL; 
    uint32_t *chains = NULL;
    int hash = 0;

    hash = do_hash(symbol);
    hashtable = (struct hashtable *) sym_hashtable->local_vaddr;
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

int sym_hashtable_find_symbol(struct elf_section *hash_table,
                              struct elf_section *string_table, 
                              struct elf_section *symbol_table,
                              const char *symbol)
{
    switch (hash_table->type) {
    case SHT_HASH:
        return hash_find_symbol(hash_table, string_table, 
                                symbol_table, symbol);
    break;
    case SHT_GNU_HASH:
        return gnuhash_find_symbol(hash_table, string_table, 
                                   symbol_table, symbol);
    break;
    default:
        return -EINVAL;
    }
}

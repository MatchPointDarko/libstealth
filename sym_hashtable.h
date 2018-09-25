#ifndef __SYM_HASHTABLE_H__
#define  __SYM_HASHTABLE_H__

struct sym_hashtable {
    int nchains;
    struct elf_section hash_table;
    int (*find_symbol) (struct sym_hashtable *sym_hashtable,
                        struct elf_section *string_table, 
                        struct elf_section *symbol_table,
                        const char *symbol);
};

int init_sym_hashtable(struct sym_hashtable *sym_hashtable, 
                       struct elf_section *section, int type);

#endif

#ifndef __SYM_HASHTABLE_H__
#define  __SYM_HASHTABLE_H__

int sym_hashtable_find_symbol(struct elf_section *hash_table,
                              struct elf_section *string_table, 
                              struct elf_section *symbol_table,
                              const char *symbol);

#endif

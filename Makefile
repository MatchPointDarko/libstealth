all:
	gcc -g -Wall -Wextra -pedantic -Wmissing-prototypes -Wstrict-prototypes -o stealth load_library.c remote.c util.c load_library_x64.c sym_hashtable.c remote_x64.c

#ifndef _LIBELFMASTER_INTERNAL_H_
#define _LIBELFMASTER_INTERNAL_H_

#ifdef DEBUG
#define DEBUG_LOG(...) do { fprintf(stderr, __VA_ARGS__); } while(0)
#else
#define DEBUG_LOG(...) do {} while(0)
#endif

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif


#define SET_STACK_AND_JMP_x64(stack, addr, rbp)__asm__ __volatile__("mov %0, %%rsp\n" \
                                            "push %1\n" \
                                            "mov $0, %%rax\n" \
                                            "mov $0, %%rbx\n" \
                                            "mov $0, %%rcx\n" \
                                            "mov $0, %%rdx\n" \
                                            "mov $0, %%rsi\n" \
                                            "mov $0, %%rdi\n" \
                                            "mov %2, %%rbp\n" \
                                            "ret" :: "r" (stack), "g" (addr), "g"(rbp))

/*
 * TODO this is just a dummy until I wrote the code for it.
 */

#define PAGE_SIZE 4096
#define PAGE_ALIGN(x) (x & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(x) (PAGE_ALIGN(x) + PAGE_SIZE) 

#define CACHEMAGIC "ld.so-1.7.0"
struct file_entry {
	int flags;
	uint32_t key;
	uint32_t value;
};

struct cache_file {
	char magic[sizeof CACHEMAGIC - 1];
	uint32_t nlibs;
	struct file_entry libs[0];
};

#define CACHEMAGIC_NEW "glibc-ld.so.cache"
#define CACHE_VERSION "1.1"

struct file_entry_new {
	int32_t flags;
	uint32_t key;
	uint32_t value;
	uint32_t osversion;
	uint64_t hwcap;
};

struct cache_file_new {
	char magic[sizeof CACHEMAGIC_NEW - 1];
	char version[sizeof CACHE_VERSION - 1];
	uint32_t nlibs;		/* number of entries */
	uint32_t len_strings;	/* size of string table */
	uint32_t unused[5];	/* space for future extension */
	struct file_entry_new libs[0]; /* Entries describing libraries */
	/* After this the string table of size len_strings is found */
};

/*
 * This struct is used internally only.
 */
struct elf_rel_helper_node {
	union {
		Elf32_Rel *rel32;
		Elf64_Rel *rel64;
	};
	union {
		Elf32_Rela *rela32;
		Elf64_Rela *rela64;
	};
	size_t size;
	bool addend;
	char *section_name;
	LIST_ENTRY(elf_rel_helper_node) _linkage;
};

/*
 * Internal only
 */
struct elf_mapping_node {
	void *mem;
	size_t size;
	uint64_t perms;
	uint64_t flags;
	uint64_t vaddr;
	uint64_t offset;
	SLIST_ENTRY(elf_mapping_node) _linkage;
};

/*
 * This should only be used internally.
 */
struct elf_symbol_node {
	const char *name;
	uint64_t value;
	uint64_t size;
	uint16_t shndx;
	uint8_t bind;
	uint8_t type;
	uint8_t visibility;
	LIST_ENTRY(elf_symbol_node) _linkage;
};

typedef struct elf_shared_object_node {
	const char *basename;
	char *path;
	unsigned int index; // used by elf_shared_object iterator
	LIST_ENTRY(elf_shared_object_node) _linkage;
} elf_shared_object_node_t;

typedef struct elf_plt_node {
	char *symname;
	uint64_t addr;
	LIST_ENTRY(elf_plt_node) _linkage;
} elf_plt_node_t;


typedef struct elf_malloc_node {
	void *ptr;
	LIST_ENTRY(elf_malloc_node) _linkage;
} elf_malloc_node_t;

typedef struct auxv {
	size_t size;
	int count;
	uint8_t *vector;
} auxv_t;

struct argdata {
	int argcount;
	int arglen;
	char *argstr;
	size_t envpcount;
	size_t envplen;
	char *envstr;
	auxv_t *saved_auxv;
};

bool elf_error_set(elf_error_t *, const char *, ...);

int section_name_cmp(const void *, const void *);

bool build_plt_data(struct elfobj *);

bool build_dynsym_data(struct elfobj *);

bool build_symtab_data(struct elfobj *);

const char * ldso_cache_bsearch(struct elf_shared_object_iterator *,
    const char *);

bool ldso_recursive_cache_resolve(struct elf_shared_object_iterator *,
    const char *);

bool ldso_insert_yield_cache(struct elf_shared_object_iterator *,
    const char *);

void ldso_free_malloc_list(struct elf_shared_object_iterator *);

void ldso_cleanup(struct elf_shared_object_iterator *);

bool load_dynamic_segment_data(struct elfobj *);

void free_lists(elfobj_t *);

void free_caches(elfobj_t *);

void free_arrays(elfobj_t *);
/*
 * userland debugging (ul_exec) type functionality
 */
auxv_t *save_auxv(elfobj_t *);
bool save_stack_data(int, char **, char **, struct argdata *);
bool build_auxv_stack(elfobj_t *, struct argdata *, uint64_t *);
void pass_control_to_dl(elfobj_t *, uintptr_t, uintptr_t);
/*
 * util
 */
void 
elfmaster_memcpy(void *dst, void *src, unsigned int len);

#endif // _LIBELFMASTER_INTERNAL_H_

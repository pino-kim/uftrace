#ifndef UFTRACE_DWARF_H
#define UFTRACE_DWARF_H

#include <stdint.h>
#include <stdbool.h>

struct sym;

#ifdef HAVE_LIBDW

#include <elfutils/libdw.h>

struct debug_info {
	Dwarf		*dw;
	uint64_t	offset;
};

extern int setup_debug_info(const char *filename, struct debug_info *dinfo,
			    uint64_t offset);
extern void release_debug_info(struct debug_info *info);
extern char * get_dwarf_argspec(struct debug_info *dinfo, char *name,
				uint64_t addr);
extern char * get_dwarf_retspec(struct debug_info *dinfo, char *name,
				uint64_t addr);

static inline bool debug_info_available(struct debug_info *dinfo)
{
	return dinfo != NULL;
}

#else /* !HAVE_LIBDW */

struct debug_info {
	/* nothing */
};

static inline int setup_debug_info(const char *filename, struct debug_info *dinfo,
				   uint64_t offset)
{
	return -1;
}

static inline void release_debug_info(struct debug_info *dinfo) {}
static inline char * get_dwarf_argspec(struct debug_info *dinfo, char *name,
				       uint64_t addr)
{
	return NULL;
}
static inline char * get_dwarf_retspec(struct debug_info *dinfo, char *name,
				       uint64_t addr)
{
	return NULL;
}

static inline bool debug_info_available(struct debug_info *dinfo)
{
	return false;
}

#endif /* HAVE_LIBDW */

#endif /* UFTRACE_DWARF_H */

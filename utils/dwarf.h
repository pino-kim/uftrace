#ifndef __UFTRACE_DWARF_H__
#define __UFTRACE_DWARF_H__

struct sym;

#ifdef HAVE_LIBDW

#include <libdw.h>

struct debug_info {
	Dwarf		*dw;
	unsigned long	offset;
};

extern int setup_debug_info(const char *filename, struct debug_info *dinfo,
			    unsigned long offset);
extern void release_debug_info(struct debug_info *info);
extern char * get_dwarf_argspec(struct debug_info *dinfo, char *name, unsigned long addr);
extern char * get_dwarf_retspec(struct debug_info *dinfo, char *name, unsigned long addr);

#else /* !HAVE_LIBDW */

struct debug_info {
	/* nothing */
};

static inline int setup_debug_info(const char *filename, struct debug_info *dinfo,
				   unsigned long offset)
{
	return -1;
}

static inline void release_debug_info(struct debug_info *dinfo) {}
static inline char * get_dwarf_argspec(struct debug_info *dinfo, char *name, unsigned long addr)
{
	return NULL;
}
static inline char * get_dwarf_retspec(struct debug_info *dinfo, char *name, unsigned long addr)
{
	return NULL;
}

#endif /* HAVE_LIBDW */

#endif /* __UFTRACE_DWARF_H__ */

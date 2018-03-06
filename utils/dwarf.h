#ifndef UFTRACE_DWARF_H
#define UFTRACE_DWARF_H

#include <stdio.h>
#include <stdbool.h>

#include "utils/rbtree.h"

#ifdef HAVE_LIBDW

#include <elfutils/libdw.h>

struct debug_info {
	Dwarf		*dw;
	struct rb_root	args;
	struct rb_root	rets;
	unsigned long	offset;
};

extern int setup_debug_info(const char *dirname, const char *filename,
			    struct debug_info *dinfo, unsigned long offset);
extern void release_debug_info(struct debug_info *info);
extern char * get_dwarf_argspec(struct debug_info *dinfo, char *name,
				unsigned long addr);
extern char * get_dwarf_retspec(struct debug_info *dinfo, char *name,
				unsigned long addr);

static inline bool debug_info_available(struct debug_info *dinfo)
{
	if (dinfo == NULL)
		return false;

	if (dinfo->dw != NULL)
		return true;

	return !RB_EMPTY_ROOT(&dinfo->args) || !RB_EMPTY_ROOT(&dinfo->args);
}

#else /* !HAVE_LIBDW */

struct debug_info {
	struct rb_root	args;
	struct rb_root	rets;
};

extern int setup_debug_info(const char *dirname, const char *filename,
			    struct debug_info *dinfo, unsigned long offset);
extern void release_debug_info(struct debug_info *dinfo);
extern char * get_dwarf_argspec(struct debug_info *dinfo, char *name,
				       unsigned long addr);
extern char * get_dwarf_retspec(struct debug_info *dinfo, char *name,
				       unsigned long addr);

static inline bool debug_info_available(struct debug_info *dinfo)
{
	return !RB_EMPTY_ROOT(&dinfo->args) || !RB_EMPTY_ROOT(&dinfo->rets);
}

#endif /* HAVE_LIBDW */

FILE * create_debug_file(char *dirname, char *filename);
void close_debug_file(FILE *fp, char *dirname, char *filename);
void save_debug_file(FILE *fp, char *name, char *spec, bool retval);

#endif /* UFTRACE_DWARF_H */

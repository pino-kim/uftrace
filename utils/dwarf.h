#ifndef UFTRACE_DWARF_H
#define UFTRACE_DWARF_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef HAVE_LIBDW
# include <elfutils/libdw.h>
#else
# define Dwarf  void
#endif

#include "utils/rbtree.h"

struct debug_info {
	Dwarf		*dw;
	uint64_t	offset;
	uint64_t	last_addr;
	struct rb_root	args;
	struct rb_root	rets;
};

extern int setup_debug_info(const char *dirname, const char *filename,
			    struct debug_info *dinfo, uint64_t offset);
extern void release_debug_info(struct debug_info *info);
extern char * get_dwarf_argspec(struct debug_info *dinfo, char *name,
				uint64_t addr);
extern char * get_dwarf_retspec(struct debug_info *dinfo, char *name,
				uint64_t addr);

static inline bool debug_info_available(struct debug_info *dinfo)
{
	if (dinfo == NULL)
		return false;

	if (dinfo->dw != NULL)
		return true;

	return !RB_EMPTY_ROOT(&dinfo->args) || !RB_EMPTY_ROOT(&dinfo->rets);
}

FILE * create_debug_file(const char *dirname, const char *filename);
void close_debug_file(FILE *fp, const char *dirname, const char *filename);
void save_debug_file(FILE *fp, char code, char *str, unsigned long val);

#endif /* UFTRACE_DWARF_H */

#ifdef HAVE_LIBDW

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <dwarf.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dwarf"
#define PR_DOMAIN  DBG_DWARF

#include "utils/utils.h"
#include "utils/dwarf.h"
#include "utils/symbol.h"

FILE * create_debug_file(const char *dirname, const char *filename)
{
	FILE *fp;
	char *tmp;

	xasprintf(&tmp, "%s/%s.dbg", dirname, filename);

	fp = fopen(tmp, "ax");

	free(tmp);
	return fp;
}

void close_debug_file(FILE *fp, const char *dirname, const char *filename)
{
	bool delete = !ftell(fp);
	char *tmp;

	fclose(fp);

	if (!delete)
		return;

	pr_dbg2("delete empty debug file for %s\n", filename);

	xasprintf(&tmp, "%s/%s.dbg", dirname, filename);
	unlink(tmp);
	free(tmp);
}

void save_debug_file(FILE *fp, char code, char *str, unsigned long val)
{
	fprintf(fp, "%c: ", code);

	switch (code) {
	case 'F':
		fprintf(fp, "%#lx %s\n", val, str);
		break;
	case 'A':
	case 'R':
		fprintf(fp, "%s\n", str);
		break;
	default:
		fprintf(fp, "unknown debug info\n");
		break;
	}
}

/* setup debug info from filename, return 0 for success */
int setup_debug_info(const char *filename, struct debug_info *dinfo,
		     unsigned long offset)
{
	int fd;
	GElf_Ehdr ehdr;

	if (!check_trace_functions(filename))
		return 0;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pr_dbg2("cannot open debug info for %s: %m\n", filename);
		return -1;
	}

	dinfo->dw = dwarf_begin(fd, DWARF_C_READ);
	close(fd);

	if (dinfo->dw == NULL) {
		pr_dbg2("failed to setup debug info: %s\n",
			dwarf_errmsg(dwarf_errno()));
		return -1;
	}

	/*
	 * symbol address was adjusted to add offset already
	 * but it needs to use address in file (for shared libraries).
	 */
	if (gelf_getehdr(dwarf_getelf(dinfo->dw), &ehdr) && ehdr.e_type == ET_DYN)
		dinfo->offset = offset;
	else
		dinfo->offset = 0;

	return 0;
}

void release_debug_info(struct debug_info *dinfo)
{
	if (dinfo->dw == NULL)
		return;

	dwarf_end(dinfo->dw);
	dinfo->dw = NULL;
}

struct arg_data {
	const char	*name;
	uint32_t	addr;
	char		*argspec;
};

/* return true only if die matches to the arg_data */
static bool check_func_die(Dwarf_Die *die, struct arg_data *ad)
{
	return dwarf_haspc(die, ad->addr) == 1;
}

static int get_argspec_cb(Dwarf_Die *die, void *data)
{
	struct arg_data *ad = data;
	Dwarf_Die arg;
	int idx = 0;

	if (!check_func_die(die, ad))
		return DWARF_CB_OK;

	pr_dbg2("found '%s' function for argspec\n", ad->name);

	if (dwarf_child(die, &arg) != 0) {
		pr_dbg2("has no argument (children)\n");
		return DWARF_CB_ABORT;
	}

	while (dwarf_tag(&arg) == DW_TAG_formal_parameter) {
		char buf[256];

		snprintf(buf, sizeof(buf), "arg%d", ++idx);

		if (ad->argspec == NULL)
			xasprintf(&ad->argspec, "@%s", buf);
		else
			ad->argspec = strjoin(ad->argspec, buf, ",");

		if (dwarf_siblingof(&arg, &arg) != 0)
			break;
	}

	return DWARF_CB_ABORT;
}

static int get_retspec_cb(Dwarf_Die *die, void *data)
{
	struct arg_data *ad = data;
	char buf[256];

	if (!check_func_die(die, ad))
		return DWARF_CB_OK;

	pr_dbg2("found '%s' function for retspec\n", ad->name);

	if (dwarf_hasattr(die, DW_AT_type)) {
		snprintf(buf, sizeof(buf), "@retval");
		ad->argspec = xstrdup(buf);
	}

	return DWARF_CB_ABORT;
}

char * get_dwarf_argspec(struct debug_info *dinfo, char *name, uint64_t addr)
{
	Dwarf_Die cudie;
	struct arg_data ad = {
		.name = name,
		.addr = addr - dinfo->offset,
	};

	if (dinfo->dw == NULL)
		return NULL;

	if (dwarf_addrdie(dinfo->dw, ad.addr, &cudie) == NULL) {
		pr_dbg2("no DWARF info found for %s (%lx)\n", name, ad.addr);
		return NULL;
	}

	dwarf_getfuncs(&cudie, get_argspec_cb, &ad, 0);
	return ad.argspec;
}

char * get_dwarf_retspec(struct debug_info *dinfo, char *name, uint64_t addr)
{
	Dwarf_Die cudie;
	struct arg_data ad = {
		.name = name,
		.addr = addr - dinfo->offset,
	};

	if (dinfo->dw == NULL)
		return NULL;

	if (dwarf_addrdie(dinfo->dw, ad.addr, &cudie) == NULL) {
		pr_dbg2("no DWARF info found for %s (%lx)\n", name, ad.addr);
		return NULL;
	}

	dwarf_getfuncs(&cudie, get_retspec_cb, &ad, 0);
	return ad.argspec;
}

#endif /* HAVE_LIBDW */

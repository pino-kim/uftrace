#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dwarf"
#define PR_DOMAIN  DBG_DWARF

#include "utils/utils.h"
#include "utils/dwarf.h"
#include "utils/symbol.h"

struct debug_entry {
	struct rb_node		node;
	uint32_t		offset;
	char			*name;
	char			*spec;
};

static int add_debug_entry(struct rb_root *root, char *func, uint32_t offset, char *argspec)
{
	struct debug_entry *entry, *iter;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;

	entry = xmalloc(sizeof(*entry));
	entry->name = xstrdup(func);

	entry->spec = xstrdup(argspec);
	entry->offset = offset;

	pr_dbg3("debug entry: %x %s%s\n",
		entry->offset, entry->name, entry->spec);

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct debug_entry, node);

		if (iter->offset < entry->offset)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	rb_link_node(&entry->node, parent, p);
	rb_insert_color(&entry->node, root);

	return 0;
}

static struct debug_entry * find_debug_entry(struct rb_root *root, uint32_t offset)
{
	struct debug_entry *iter;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	int ret;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct debug_entry, node);

		ret = iter->offset - offset;
		if (ret == 0) {
			pr_dbg3("found debug entry at %x (%s%s)\n",
				offset, iter->name, iter->spec);
			return iter;
		}

		if (ret < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	return NULL;
}

static void free_debug_entry(struct rb_root *root)
{
	struct debug_entry *entry;
	struct rb_node *node;

	while (!RB_EMPTY_ROOT(root)) {
		node = rb_first(root);
		entry = rb_entry(node, typeof(*entry), node);

		rb_erase(node, root);
		free(entry->name);
		free(entry->spec);
		free(entry);
	}
}

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

static int load_debug_file(const char *dirname, const char *filename,
			   struct debug_info *dinfo)
{
	char *pathname;
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	int ret = -1;
	char *func = NULL;
	uint32_t offset = 0;

	xasprintf(&pathname, "%s/%s.dbg", dirname, basename(filename));

	fp = fopen(pathname, "r");
	if (fp == NULL) {
		if (errno == ENOENT) {
			free(pathname);
			return -1;
		}

		pr_err("failed to open: %s", pathname);
	}

	pr_dbg2("load debug info from %s\n", pathname);

	while (getline(&line, &len, fp) >= 0) {
		char *pos;
		struct rb_root *root = &dinfo->args;

		if (line[1] != ':' || line[2] != ' ')
			goto out;

		/* remove trailing newline */
		line[strlen(line) - 1] = '\0';

		switch (line[0]) {
		case 'F':
			offset = strtoul(&line[3], &pos, 16);
			if (*pos == ' ')
				pos++;

			free(func);
			func = xstrdup(pos);
			break;
		case 'A':
		case 'R':
			if (line[0] == 'R')
				root = &dinfo->rets;

			if (add_debug_entry(root, func, offset, &line[3]) < 0)
				goto out;
			break;
		default:
			goto out;
		}
	}
	ret = 0;

out:
	if (ret < 0) {
		pr_dbg("invalid dbg file: %s: %s\n", pathname, line);

		free_debug_entry(&dinfo->args);
		free_debug_entry(&dinfo->rets);
	}

	fclose(fp);
	free(pathname);
	free(func);
	return ret;
}

#ifdef HAVE_LIBDW

#include <libelf.h>
#include <gelf.h>
#include <dwarf.h>

/* setup debug info from filename, return 0 for success */
int setup_debug_info(const char *dirname, const char *filename,
		     struct debug_info *dinfo, uint64_t offset)
{
	int fd;
	GElf_Ehdr ehdr;

	if (debug_info_available(dinfo))
		return 0;

	if (dirname != NULL) {
		dinfo->offset = offset;
		return load_debug_file(dirname, filename, dinfo);
	}

	if (!check_trace_functions(filename))
		return 0;

	pr_dbg2("setup debug info for %s\n", filename);

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
	free_debug_entry(&dinfo->args);
	free_debug_entry(&dinfo->rets);

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
	struct debug_entry *entry;

	entry = find_debug_entry(&dinfo->args, ad.addr);
	if (entry)
		return entry->spec;

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
	struct debug_entry *entry;

	entry = find_debug_entry(&dinfo->rets, ad.addr);
	if (entry)
		return entry->spec;

	if (dinfo->dw == NULL)
		return NULL;

	if (dwarf_addrdie(dinfo->dw, ad.addr, &cudie) == NULL) {
		pr_dbg2("no DWARF info found for %s (%lx)\n", name, ad.addr);
		return NULL;
	}

	dwarf_getfuncs(&cudie, get_retspec_cb, &ad, 0);
	return ad.argspec;
}

#else  /* !HAVE_LIBDW */

int setup_debug_info(const char *dirname, const char *filename,
		     struct debug_info *dinfo, unsigned long offset)
{
	dinfo->dw     = NULL;
	dinfo->args   = RB_ROOT;
	dinfo->rets   = RB_ROOT;
	dinfo->offset = offset;

	if (dirname != NULL)
		return load_debug_file(dirname, filename, dinfo);

	return -1;
}

void release_debug_info(struct debug_info *dinfo)
{
	free_debug_entry(&dinfo->args);
	free_debug_entry(&dinfo->rets);
}

char * get_dwarf_argspec(struct debug_info *dinfo, char *name, unsigned long addr)
{
	struct debug_entry *entry = find_debug_entry(&dinfo->args, addr);

	return entry ? entry->spec : NULL;
}

char * get_dwarf_retspec(struct debug_info *dinfo, char *name, unsigned long addr)
{
	struct debug_entry *entry = find_debug_entry(&dinfo->rets, addr);

	return entry ? entry->spec : NULL;
}

#endif /* HAVE_LIBDW */

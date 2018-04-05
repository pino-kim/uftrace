#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "utils/utils.h"
#include "utils/dwarf.h"
#include "utils/symbol.h"
#include "utils/filter.h"

struct debug_entry {
	struct rb_node		node;
	uint32_t		offset;
	char			*name;
	char			*spec;
};

static int add_debug_entry(struct rb_root *root, uint32_t offset, char *argspec)
{
	struct debug_entry *entry, *iter;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	char *pos = strchr(argspec, '@');

	if (pos == NULL)
		return -1;

	*pos = '\0';

	entry = xmalloc(sizeof(*entry));
	entry->name = xstrdup(argspec);

	*pos = '@';
	/* remove trailing newline and copy */
	entry->spec = xstrndup(pos, strlen(pos) - 1);
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

FILE * create_debug_file(char *dirname, char *filename)
{
	FILE *fp;
	char *tmp;

	xasprintf(&tmp, "%s/%s.dbg", dirname, filename);

	fp = fopen(tmp, "a");

	free(tmp);
	return fp;
}

void close_debug_file(FILE *fp, char *dirname, char *filename)
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

void save_debug_file(FILE *fp, uint32_t offset, char *name, char *spec,
		     bool retval)
{
	char prefix = retval ? 'R' : 'A';

	fprintf(fp, "%c: %x %s%s\n", prefix, offset, name, spec);
}

static int load_debug_file(const char *dirname, const char *filename,
			   struct debug_info *dinfo)
{
	char *pathname;
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	int ret = -1;

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
		uint32_t offset;

		if (line[1] != ':' || line[2] != ' ')
			goto out;

		offset = strtoul(&line[3], &pos, 16);
		if (*pos == ' ')
			pos++;

		switch (line[0]) {
		case 'A':
			if (add_debug_entry(&dinfo->args, offset, pos) < 0)
				goto out;
			break;
		case 'R':
			if (add_debug_entry(&dinfo->rets, offset, pos) < 0)
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

struct type_data {
	enum uftrace_arg_format		fmt;
	int				size;
	int				pointer;
	char 				*enum_name;
	char 				*enum_str;
};

static char * fill_enum_str(Dwarf_Die *die)
{
	char *str = NULL;
	Dwarf_Die e_val;

	if (dwarf_child(die, &e_val) != 0) {
		pr_dbg2("no enum values\n");
		return NULL;
	}

	while (dwarf_tag(&e_val) == DW_TAG_enumerator) {
		char buf[256];
		Dwarf_Attribute attr_val;
		Dwarf_Sword val;

		dwarf_attr(&e_val, DW_AT_const_value, &attr_val);
		dwarf_formsdata(&attr_val, &val);
		snprintf(buf, sizeof(buf), "%s=%ld", dwarf_diename(&e_val), (long)val);

		str = strjoin(str, buf, ",");

		if (dwarf_siblingof(&e_val, &e_val) != 0)
			break;
	}

	return str;
}

static char * make_enum_name(Dwarf_Die *die)
{
	Dwarf_Die cudie;
	const char *cu_name = NULL;
	unsigned long off;
	char *enum_name;
	char *tmp;

	if (dwarf_diecu (die, &cudie, NULL, NULL))
		cu_name = dwarf_diename(&cudie);

	if (cu_name == NULL)
		cu_name = "unnamed";

	off = dwarf_cuoffset(die);

	xasprintf(&enum_name, "%s_%lx", basename(cu_name), off);

	/* replace forbidden characters */
	tmp = enum_name;
	while ((tmp = strpbrk(tmp, "+-.() ")) != NULL)
		*tmp++ = '_';

	return enum_name;
}

static int arg_type_cb(Dwarf_Attribute *attr, void *arg)
{
	unsigned aname = dwarf_whatattr(attr);
	unsigned aform = dwarf_whatform(attr);
	struct type_data *td = arg;
	Dwarf_Die die;
	Dwarf_Attribute type;
	bool done = false;
	const char *tname;
	char *enum_def;

	if (aname != DW_AT_type)
		return DWARF_CB_OK;

	while (!done) {
		switch (aform) {
		case DW_FORM_ref1:
		case DW_FORM_ref2:
		case DW_FORM_ref4:
		case DW_FORM_ref8:
		case DW_FORM_ref_udata:
		case DW_FORM_ref_addr:
		case DW_FORM_ref_sig8:
		case DW_FORM_GNU_ref_alt:
			dwarf_formref_die(attr, &die);
			break;
		default:
			done = true;
			continue;
		}

		switch (dwarf_tag(&die)) {
		case DW_TAG_base_type:
			tname = dwarf_diename(&die);
			if (!strcmp(tname, "char") ||
			    !strcmp(tname, "signed char")) {
				if (td->pointer == 0)
					td->fmt = ARG_FMT_CHAR;
				else if (td->pointer == 1)
					td->fmt = ARG_FMT_STR;
			}
			else if (!strcmp(tname, "float")) {
				td->fmt = ARG_FMT_FLOAT;
				td->size = 32;
			}
			else if (!strcmp(tname, "double")) {
				td->fmt = ARG_FMT_FLOAT;
				td->size = 64;
			}
			done = true;
			continue;
		case DW_TAG_enumeration_type:
			done = true;
			td->enum_str = fill_enum_str(&die);
			if (td->enum_str == NULL)
				continue;  /* use default format */

			td->fmt = ARG_FMT_ENUM;
			tname = dwarf_diename(&die);
			if (tname)
				td->enum_name = xstrdup(tname);
			else
				td->enum_name = make_enum_name(&die);

			xasprintf(&enum_def, "enum %s { %s }",
				  td->enum_name, td->enum_str);
			pr_dbg3("dwarf: %s\n", td->enum_str);

			parse_enum_string(enum_def, &dwarf_enum);
			free(enum_def);
			free(td->enum_str);
			continue;
		case DW_TAG_pointer_type:
		case DW_TAG_ptr_to_member_type:
			td->pointer++;
			/* fall through */
		case DW_TAG_reference_type:
		case DW_TAG_rvalue_reference_type:
		case DW_TAG_array_type:
		default:
			if (!dwarf_hasattr(&die, DW_AT_type)) {
				done = true;
				continue;
			}
			break;
		}

		pr_dbg3("dwarf: %s (tag %d)\n", dwarf_diename(&die), dwarf_tag(&die));
		dwarf_attr(&die, DW_AT_type, &type);
		aform = dwarf_whatform(&type);
		attr = &type;
	}

	return DWARF_CB_ABORT;
}

struct arg_data {
	const char	*name;
	uint32_t	addr;
	char		*argspec;
	int		idx;
	int		fpidx;
};

static void add_type_info(char *spec, size_t len, Dwarf_Die *die, void *arg)
{
	struct arg_data *ad = arg;
	struct type_data data = {
		.fmt = ARG_FMT_AUTO,
	};

	dwarf_getattrs(die, arg_type_cb, &data, 0);

	switch (data.fmt) {
	case ARG_FMT_CHAR:
		strcat(spec, "/c");
		break;
	case ARG_FMT_STR:
		strcat(spec, "/s");
		break;
	case ARG_FMT_FLOAT:
		snprintf(spec, len, "fparg%d/%d", ++ad->fpidx, data.size);
		--ad->idx;  /* do not increase index of integer arguments */
		break;
	case ARG_FMT_ENUM:
		strcat(spec, "/e:");
		strcat(spec, data.enum_name);
		break;
	default:
		break;
	}
}

struct location_data {
	int		type;
	int		reg;    // DWARF register number
	int		offset; // stack offset
};

static int location_cb(Dwarf_Attribute *attr, void *arg)
{
	unsigned aname = dwarf_whatattr(attr);
	struct location_data *ld = arg;
	Dwarf_Op *ops = NULL;
	size_t len = 0;

	if (aname != DW_AT_location)
		return DWARF_CB_OK;

	if (dwarf_getlocation(attr, &ops, &len) == -1) {
		Dwarf_Addr base, start, end;

		/* try to get the first entry in the location list */
		if (dwarf_getlocations(attr, 0, &base, &start, &end,
				       &ops, &len) == -1)
			return DWARF_CB_ABORT;
	}

	while (len--) {
		switch (ops->atom) {
		case DW_OP_fbreg:
			/*
			 * ignore minus offsets since it doesn't set the
			 * frame-pointer yet (we're before the prologue).
			 */
			if ((int)ops->number >= 0) {
				ld->type = ARG_TYPE_STACK;
				ld->offset = DIV_ROUND_UP(ops->number,
							  sizeof(long)) + 1;
			}
			break;

		case DW_OP_reg0...DW_OP_reg31:
			ld->type = ARG_TYPE_REG;
			ld->reg = ops->atom;
			break;
		}
	}

	return DWARF_CB_ABORT;
}

__weak const char * arch_register_dwarf_name(int dwarf_reg)
{
	return "invalid register";
}

static void add_location(char *spec, size_t len, Dwarf_Die *die, void *arg)
{
	struct location_data data = {
		.type = ARG_TYPE_INDEX,
	};
	char buf[32];
	const char *reg;

	dwarf_getattrs(die, location_cb, &data, 0);

	switch (data.type) {
	case ARG_TYPE_REG:
		reg = arch_register_dwarf_name(data.reg);

		if (strcmp(reg, "invalid register")) {
			snprintf(buf, sizeof(buf), "%%%s", reg);
			strcat(spec, buf);
		}
		break;
	case ARG_TYPE_STACK:
		snprintf(buf, sizeof(buf), "%%stack+%d", data.offset);
		strcat(spec, buf);
		break;
	default:
		break;
	}
}

/* return true only if die matches to the arg_data */
static bool check_func_die(Dwarf_Die *die, struct arg_data *ad)
{
	return dwarf_haspc(die, ad->addr) == 1;
}

static int get_argspec_cb(Dwarf_Die *die, void *data)
{
	struct arg_data *ad = data;
	Dwarf_Die arg;

	if (!check_func_die(die, ad))
		return DWARF_CB_OK;

	pr_dbg2("found '%s' function for argspec\n", ad->name);

	if (dwarf_child(die, &arg) != 0) {
		pr_dbg2("has no argument (children)\n");
		return DWARF_CB_ABORT;
	}

	while (dwarf_tag(&arg) == DW_TAG_formal_parameter) {
		char buf[256];

		snprintf(buf, sizeof(buf), "arg%d", ++ad->idx);
		add_type_info(buf, sizeof(buf), &arg, ad);
		add_location(buf, sizeof(buf), &arg, ad);

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
		add_type_info(buf, sizeof(buf), die, ad);
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

#ifdef HAVE_LIBDW

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <dwarf.h>

#include "utils/utils.h"
#include "utils/dwarf.h"
#include "utils/symbol.h"
#include "utils/filter.h"

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
	case 'E':
		/* this format is compatible with parse_enum_string() */
		fprintf(fp, "enum %s {%s}\n", str, (char *)val);
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

struct type_data {
	enum uftrace_arg_format		fmt;
	int				size;
	int				pointer;
	char 				*enum_name;
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
	char *enum_str;

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
			enum_str = fill_enum_str(&die);
			if (enum_str == NULL)
				continue;  /* use default format */

			td->fmt = ARG_FMT_ENUM;
			tname = dwarf_diename(&die);
			if (tname)
				td->enum_name = xstrdup(tname);
			else
				td->enum_name = make_enum_name(&die);

			xasprintf(&enum_def, "enum %s { %s }",
				  td->enum_name, enum_str);
			pr_dbg3("dwarf: %s\n", enum_str);

			parse_enum_string(enum_def, &dwarf_enum);
			free(enum_def);
			free(enum_str);
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
	Dwarf_Die origin;

	if (!dwarf_hasattr(die, DW_AT_type)) {
		Dwarf_Attribute attr;

		if (!dwarf_hasattr(die, DW_AT_abstract_origin))
			return;

		dwarf_attr(die, DW_AT_abstract_origin, &attr);
		dwarf_formref_die(&attr, &origin);
		die = &origin;
	}

	dwarf_getattrs(die, arg_type_cb, &data, 0);

	switch (data.fmt) {
	case ARG_FMT_CHAR:
		strcat(spec, "/c");
		break;
	case ARG_FMT_STR:
		strcat(spec, "/s");
		break;
	case ARG_FMT_FLOAT:
		if (ad->idx) {  /* for arguments */
			snprintf(spec, len, "fparg%d/%d",
				 ++ad->fpidx, data.size);
			/* do not increase index of integer arguments */
			--ad->idx;
		}
		else {  /* for return values */
			char sz[4];

			snprintf(sz, sizeof(sz), "%d", data.size);
			strcat(spec, "/f");
			strcat(spec, sz);
		}
		break;
	case ARG_FMT_ENUM:
		strcat(spec, "/e:");
		strcat(spec, data.enum_name);
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
	Dwarf_Die spec;

	if (!check_func_die(die, ad))
		return DWARF_CB_OK;

	pr_dbg2("found '%s' function for retspec\n", ad->name);

retry:
	if (dwarf_hasattr(die, DW_AT_type)) {
		snprintf(buf, sizeof(buf), "@retval");
		add_type_info(buf, sizeof(buf), die, ad);
		ad->argspec = xstrdup(buf);
	} else if (dwarf_hasattr(die, DW_AT_specification)) {
		Dwarf_Attribute attr;

		dwarf_attr(die, DW_AT_specification, &attr);
		dwarf_formref_die(&attr, &spec);
		die = &spec;
		goto retry;
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

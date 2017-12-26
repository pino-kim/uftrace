#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <gelf.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "symbol"
#define PR_DOMAIN  DBG_SYMBOL

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/symbol.h"

const char * const x86_skip_syms_bindnow[] = {
	"mcount", "__fentry__",
	"__cyg_profile_func_enter", "__cyg_profile_func_exit",
	"__cxa_finalize",  /* XXX: it caused segfault */
	"__gmon_start__",  /* XXX: it makes process stuck */
	"_mcleanup",
	"__libc_start_main",
	NULL,
};

int arch_load_dynsymtab_bindnow(Elf *elf, struct symtab *dsymtab,
				unsigned long offset, unsigned long flags)
{
	unsigned grow = SYMTAB_GROW;
	Elf_Scn *dynsym_sec, *relplt_sec, *sec;
	Elf_Data *dynsym_data, *relplt_data;
	int rel_type = SHT_NULL;
	size_t shstr_idx, dynstr_idx = 0;
	int i, ret = -1;
	size_t idx, nr_rels = 0;
	unsigned long rel_addr = 0;
	size_t rel_size = 0;

	pr_dbg2("load dynamic symbols for bind-now (no-plt)\n");

	if (elf_getshdrstrndx(elf, &shstr_idx) < 0)
		goto elf_error;

	sec = dynsym_sec = relplt_sec = NULL;
	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		char *shstr;
		GElf_Shdr shdr;

		if (gelf_getshdr(sec, &shdr) == NULL)
			goto elf_error;

		shstr = elf_strptr(elf, shstr_idx, shdr.sh_name);

		if (strcmp(shstr, ".dynsym") == 0) {
			dynsym_sec = sec;
			dynstr_idx = shdr.sh_link;
		}
		else if (strcmp(shstr, ".rela.dyn") == 0) {
			if (rel_type != SHT_NULL)
				continue;
			relplt_sec = sec;
			rel_addr = shdr.sh_addr + offset;

			nr_rels = shdr.sh_size / shdr.sh_entsize;
			rel_size = shdr.sh_entsize;
			rel_type = SHT_RELA;
		}
	}

	if (dynsym_sec == NULL) {
		pr_dbg("cannot find dynamic symbols.. skipping\n");
		goto out;
	}

	if (rel_type != SHT_RELA) {
		pr_dbg("cannot find relocation info for PLT\n");
		goto out;
	}

	dynsym_data = elf_getdata(dynsym_sec, NULL);
	if (dynsym_data == NULL)
		goto elf_error;

	relplt_data = elf_getdata(relplt_sec, NULL);
	if (relplt_data == NULL)
		goto elf_error;

	for (idx = 0; idx < nr_rels; idx++) {
		GElf_Sym esym;
		struct sym *sym;
		int symidx;
		char *name;
		GElf_Rela rela;

		if (gelf_getrela(relplt_data, idx, &rela) == NULL)
			goto elf_error;

		if (GELF_R_TYPE(rela.r_info) != R_X86_64_GLOB_DAT)
			continue;

		symidx = GELF_R_SYM(rela.r_info);

		gelf_getsym(dynsym_data, symidx, &esym);
		name = elf_strptr(elf, dynstr_idx, esym.st_name);

		/* load function calls only */
		if (GELF_ST_TYPE(esym.st_info) != STT_FUNC &&
		    GELF_ST_TYPE(esym.st_info) != STT_GNU_IFUNC)
			continue;

		for (i = 0; x86_skip_syms_bindnow[i]; i++) {
			if (!strcmp(name, x86_skip_syms_bindnow[i]))
				break;
		}
		if (x86_skip_syms_bindnow[i])
			continue;

		if (dsymtab->nr_sym >= dsymtab->nr_alloc) {
			if (dsymtab->nr_alloc >= grow * 4)
				grow *= 2;
			dsymtab->nr_alloc += grow;
			dsymtab->sym = xrealloc(dsymtab->sym,
						dsymtab->nr_alloc * sizeof(*sym));
		}

		sym = &dsymtab->sym[dsymtab->nr_sym++];

		/*
		 * the .rela.dyn section is in the text segment as well,
		 * use it for symbol address
		 */
		sym->addr = rel_addr + ((dsymtab->nr_sym  - 1)* rel_size);
		sym->size = rel_size;
		sym->type = ST_PLT;

		if (flags & SYMTAB_FL_DEMANGLE)
			sym->name = demangle(name);
		else
			sym->name = xstrdup(name);

		pr_dbg3("[%zd] %c %lx + %-5u %s\n", dsymtab->nr_sym,
			sym->type, sym->addr, sym->size, sym->name);
	}
	pr_dbg2("loaded %u symbols from .rela.dyn section\n", dsymtab->nr_sym);
	ret = 0;

out:
	return ret;

elf_error:
	pr_dbg("ELF error during load dynsymtab: %s\n",
	       elf_errmsg(elf_errno()));
	return -1;
}

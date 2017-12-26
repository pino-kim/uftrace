#include <assert.h>
#include <string.h>
#include <gelf.h>
#include <sys/mman.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "mcount"
#define PR_DOMAIN  DBG_MCOUNT

#include "libmcount/internal.h"
#include "utils/filter.h"

int mcount_get_register_arg(struct mcount_arg_context *ctx,
			    struct uftrace_arg_spec *spec)
{
	struct mcount_regs *regs = ctx->regs;
	int reg_idx;

	switch (spec->type) {
	case ARG_TYPE_REG:
		reg_idx = spec->reg_idx;
		break;
	case ARG_TYPE_INDEX:
		reg_idx = spec->idx; /* for integer arguments */
		break;
	case ARG_TYPE_FLOAT:
		reg_idx = spec->idx + X86_REG_FLOAT_BASE;
		break;
	case ARG_TYPE_STACK:
	default:
		return -1;
	}

	switch (reg_idx) {
	case X86_REG_RDI:
		ctx->val.i = ARG1(regs);
		break;
	case X86_REG_RSI:
		ctx->val.i = ARG2(regs);
		break;
	case X86_REG_RDX:
		ctx->val.i = ARG3(regs);
		break;
	case X86_REG_RCX:
		ctx->val.i = ARG4(regs);
		break;
	case X86_REG_R8:
		ctx->val.i = ARG5(regs);
		break;
	case X86_REG_R9:
		ctx->val.i = ARG6(regs);
		break;
	case X86_REG_XMM0:
		asm volatile ("movsd %%xmm0, %0\n" : "=m" (ctx->val.v));
		break;
	case X86_REG_XMM1:
		asm volatile ("movsd %%xmm1, %0\n" : "=m" (ctx->val.v));
		break;
	case X86_REG_XMM2:
		asm volatile ("movsd %%xmm2, %0\n" : "=m" (ctx->val.v));
		break;
	case X86_REG_XMM3:
		asm volatile ("movsd %%xmm3, %0\n" : "=m" (ctx->val.v));
		break;
	case X86_REG_XMM4:
		asm volatile ("movsd %%xmm4, %0\n" : "=m" (ctx->val.v));
		break;
	case X86_REG_XMM5:
		asm volatile ("movsd %%xmm5, %0\n" : "=m" (ctx->val.v));
		break;
	case X86_REG_XMM6:
		asm volatile ("movsd %%xmm6, %0\n" : "=m" (ctx->val.v));
		break;
	case X86_REG_XMM7:
		asm volatile ("movsd %%xmm7, %0\n" : "=m" (ctx->val.v));
		break;
	default:
		return -1;
	}

	return 0;
}

void mcount_get_stack_arg(struct mcount_arg_context *ctx,
			  struct uftrace_arg_spec *spec)
{
	int offset;

	switch (spec->type) {
	case ARG_TYPE_STACK:
		offset = spec->stack_ofs;
		break;
	case ARG_TYPE_INDEX:
		offset = spec->idx - ARCH_MAX_REG_ARGS;
		break;
	case ARG_TYPE_FLOAT:
		offset = (spec->idx - ARCH_MAX_FLOAT_REGS) * 2 - 1;
		break;
	case ARG_TYPE_REG:
	default:
		/* should not reach here */
		pr_err_ns("invalid stack access for arguments\n");
		break;
	}

	if (offset < 1 || offset > 100)
		pr_dbg("invalid stack offset: %d\n", offset);

	memcpy(ctx->val.v, ctx->stack_base + offset, spec->size);
}

void mcount_arch_get_arg(struct mcount_arg_context *ctx,
			 struct uftrace_arg_spec *spec)
{
	if (mcount_get_register_arg(ctx, spec) < 0)
		mcount_get_stack_arg(ctx, spec);
}

void mcount_arch_get_retval(struct mcount_arg_context *ctx,
			    struct uftrace_arg_spec *spec)
{
	/* type of return value cannot be FLOAT, so check format instead */
	if (spec->fmt != ARG_FMT_FLOAT)
		memcpy(ctx->val.v, ctx->retval, spec->size);
	else if (spec->size == 10) /* for long double type */
		asm volatile ("fstpt %0\n\tfldt %0" : "=m" (ctx->val.v));
	else
		asm volatile ("movsd %%xmm0, %0\n" : "=m" (ctx->val.v));
}

void mcount_save_arch_context(struct mcount_arch_context *ctx)
{
	asm volatile ("movsd %%xmm0, %0\n" : "=m" (ctx->xmm[0]));
	asm volatile ("movsd %%xmm1, %0\n" : "=m" (ctx->xmm[1]));
	asm volatile ("movsd %%xmm2, %0\n" : "=m" (ctx->xmm[2]));
	asm volatile ("movsd %%xmm3, %0\n" : "=m" (ctx->xmm[3]));
	asm volatile ("movsd %%xmm4, %0\n" : "=m" (ctx->xmm[4]));
	asm volatile ("movsd %%xmm5, %0\n" : "=m" (ctx->xmm[5]));
	asm volatile ("movsd %%xmm6, %0\n" : "=m" (ctx->xmm[6]));
	asm volatile ("movsd %%xmm7, %0\n" : "=m" (ctx->xmm[7]));
}

void mcount_restore_arch_context(struct mcount_arch_context *ctx)
{
	asm volatile ("movsd %0, %%xmm0\n" :: "m" (ctx->xmm[0]));
	asm volatile ("movsd %0, %%xmm1\n" :: "m" (ctx->xmm[1]));
	asm volatile ("movsd %0, %%xmm2\n" :: "m" (ctx->xmm[2]));
	asm volatile ("movsd %0, %%xmm3\n" :: "m" (ctx->xmm[3]));
	asm volatile ("movsd %0, %%xmm4\n" :: "m" (ctx->xmm[4]));
	asm volatile ("movsd %0, %%xmm5\n" :: "m" (ctx->xmm[5]));
	asm volatile ("movsd %0, %%xmm6\n" :: "m" (ctx->xmm[6]));
	asm volatile ("movsd %0, %%xmm7\n" :: "m" (ctx->xmm[7]));
}

extern const char * const x86_skip_syms_bindnow[];

#define PUSH_IDX_POS  1
#define JMP_OFS_POS   7
#define PAD_SIZE      5

int mcount_arch_undo_bindnow(Elf *elf, struct plthook_data *pd)
{
	unsigned idx, s;
	struct sym *sym;
	struct symtab *dsymtab;
	unsigned long plt_addr = 0;
	bool has_rela_plt = false;
	void *target_addr;
	unsigned jump_offset;
	void *trampoline_buf;
	size_t i, trampoline_size;
	unsigned char trampoline[] = {
		0x68, 0x00, 0x00, 0x00, 0x00,        /* push $idx */
		0xff, 0x25, 0x00, 0x00, 0x00, 0x00,  /* jmp *(offset) */
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc,        /* padding */
	};
	Elf_Scn *sec, *dyn_sec, *rel_sec;
	Elf_Data *dyn_data, *rel_data;
	size_t shstr_idx, dynstr_idx = 0;
	size_t nr_rel = 0;

	dsymtab = &pd->dsymtab;

	if (elf_getshdrstrndx(elf, &shstr_idx) < 0)
		return -1;

	sec = dyn_sec = rel_sec = NULL;
	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		GElf_Shdr shdr;
		char *shname;

		if (gelf_getshdr(sec, &shdr) == NULL)
			return -1;

		shname = elf_strptr(elf, shstr_idx, shdr.sh_name);
		if (!strcmp(shname, ".plt"))
			plt_addr = shdr.sh_addr + pd->base_addr;
		if (!strcmp(shname, ".rela.plt"))
			has_rela_plt = true;

		else if (strcmp(shname, ".dynsym") == 0) {
			dyn_sec = sec;
			dynstr_idx = shdr.sh_link;
		}
		else if (strcmp(shname, ".rela.dyn") == 0) {
			rel_sec = sec;
			nr_rel = shdr.sh_size / shdr.sh_entsize;
		}
	}

	if (has_rela_plt || dyn_sec == NULL) {
		/* it's already handled by restore_plt_functions() in find_got() */
		return 0;
	}

	dyn_data = elf_getdata(dyn_sec, NULL);
	rel_data = elf_getdata(rel_sec, NULL);

	trampoline_size = (dsymtab->nr_sym + 1) * sizeof(trampoline);

	if (plt_addr == 0) {
		/* append pseudo PLT0 at the end */
		trampoline_size += sizeof(trampoline) * 2;
	}

	trampoline_buf = mmap(0, trampoline_size, PROT_READ | PROT_WRITE,
			      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (trampoline_buf == MAP_FAILED)
		pr_err("failed to mmap trampoline for bind now");

	pr_dbg2("setup bind-now PLT trampoline at %#lx\n", trampoline_buf);

	for (idx = s = 0; idx < nr_rel; idx++) {
		GElf_Sym esym;
		int symidx;
		char *name;
		GElf_Rela rela;
		unsigned long *GOT;

		if (gelf_getrela(rel_data, idx, &rela) == NULL)
			return -1;

		if (GELF_R_TYPE(rela.r_info) != R_X86_64_GLOB_DAT)
			continue;

		symidx = GELF_R_SYM(rela.r_info);

		gelf_getsym(dyn_data, symidx, &esym);
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

		sym = &dsymtab->sym[s];
		assert(!strcmp(sym->name, name));

		target_addr = trampoline_buf + (s * sizeof(trampoline));

		GOT = (unsigned long *)(rela.r_offset + pd->base_addr);
		pd->resolved_addr[s] = *GOT;
		*GOT = (unsigned long)target_addr;

		jump_offset = (dsymtab->nr_sym - s - 1) * sizeof(trampoline) + PAD_SIZE;

		pr_dbg3("[%d] %s, GOT = %p, target addr = %p, jump offset = %#lx\n",
			s, sym->name, GOT, target_addr, jump_offset);

		/* make up the instruction and copy to the trampoline buffer */
		memcpy(&trampoline[PUSH_IDX_POS], &s, sizeof(s));
		memcpy(&trampoline[JMP_OFS_POS], &jump_offset, sizeof(jump_offset));
		memcpy(target_addr, trampoline, sizeof(trampoline));

		s++;
	}

	if (plt_addr == 0) {
		unsigned char plt0[] = {
			0xff, 0x35, 0x0a, 0x00, 0x00, 0x00,  /* PUSH GOT[1] (copy) */
			0xff, 0x25, 0x0c, 0x00, 0x00, 0x00,  /* JMP *GOT[2] (copy) */
			0xcc, 0xcc, 0xcc, 0xcc,
			/* copy of GOT[1] here */
			/* copy of GOT[2] here */
		};
		unsigned long *pltgot_addr = pd->pltgot_ptr;

		plt_addr  = (unsigned long)trampoline_buf + sizeof(plt_addr);
		plt_addr += s * sizeof(trampoline);

		memcpy((void *)plt_addr, plt0, sizeof(plt0));

		pltgot_addr++;  /* copy GOT[1] */

		if (*pltgot_addr == 0) {
			/* update module-id - must sync with find_got() */
			*pltgot_addr = (unsigned long)pd;
		}

		memcpy((void *)plt_addr + sizeof(plt0), pltgot_addr, sizeof(long));

		pltgot_addr++;  /* copy GOT[2] */
		memcpy((void *)plt_addr + sizeof(plt0) + 8, pltgot_addr, sizeof(long));
	}

	pr_dbg2("real address to jump: %#lx\n", plt_addr);
	memcpy(trampoline_buf + (s * sizeof(trampoline)),
	       &plt_addr, sizeof(plt_addr));

	mprotect(trampoline_buf, trampoline_size, PROT_READ | PROT_EXEC);
	return 0;
}

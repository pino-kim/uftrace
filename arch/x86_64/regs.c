#include <dwarf.h>

#include "mcount-arch.h"
#include "utils/utils.h"

struct x86_reg_table {
	const char		*name;
	int			idx;
} reg_table[] = {

#define X86_REG(_r)  { #_r, X86_REG_##_r }

	/* integer registers */
	X86_REG(RDI), X86_REG(RSI), X86_REG(RDX),
	X86_REG(RCX), X86_REG(R8),  X86_REG(R9),
	/* floating-point registers */
	X86_REG(XMM0), X86_REG(XMM1), X86_REG(XMM2), X86_REG(XMM3),
	X86_REG(XMM4), X86_REG(XMM5), X86_REG(XMM6), X86_REG(XMM7),

#undef X86_REG
};

int arch_register_index(char *reg_name)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(reg_table); i++) {
		if (!strcasecmp(reg_name, reg_table[i].name))
			return reg_table[i].idx;
	}
	return -1;
}

struct x86_reg_table dwarf_table[] = {
	{ "rax", DW_OP_reg0, },
	{ "rdx", DW_OP_reg1, },
	{ "rcx", DW_OP_reg2, },
	{ "rbx", DW_OP_reg3, },
	{ "rsi", DW_OP_reg4, },
	{ "rdi", DW_OP_reg5, },
	{ "rbp", DW_OP_reg6, },
	{ "rsp", DW_OP_reg7, },
	{ "r8",  DW_OP_reg8, },
	{ "r9",  DW_OP_reg9, },
	{ "r10", DW_OP_reg10, },
	{ "r11", DW_OP_reg11, },
	{ "r12", DW_OP_reg12, },
	{ "r13", DW_OP_reg13, },
	{ "r14", DW_OP_reg14, },
	{ "r15", DW_OP_reg15, },
};

const char * arch_register_dwarf_name(int dwarf_reg)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(dwarf_table); i++) {
		if (dwarf_reg == dwarf_table[i].idx)
			return dwarf_table[i].name;
	}
	return "invalid register";
}

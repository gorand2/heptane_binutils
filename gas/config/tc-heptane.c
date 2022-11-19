/* tc-i386.c -- Assemble code for the Intel 80386
   Copyright (C) 1989-2015 Free Software Foundation, Inc.

   This file is part of GAS, the GNU Assembler.

   GAS is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GAS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GAS; see the file COPYING.  If not, write to the Free
   Software Foundation, 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */

/* Heptane CPU machine specific gas. Written by Goran Dakov. 
   Based on Intel 80386 machine specific gas.
   Bugs & suggestions are completely welcome.  This is free software.
   Please help us make it better. haha. */

#include "as.h"
#include "safe-ctype.h"
#include "subsegs.h"
#include "dwarf2dbg.h"
#include "dw2gencfi.h"
#include "elf/heptane.h"
#include "opcodes/heptane-init.h"

#ifndef DEFAULT_ARCH
#define DEFAULT_ARCH "heptane"
#endif

#ifndef INLINE
#if __GNUC__ >= 2
#define INLINE __inline__
#else
#define INLINE
#endif
#endif


/* we define the syntax here (modulo base,index,scale syntax) */
#define REGISTER_PREFIX '%'
#define IMMEDIATE_PREFIX '$'
#define ABSOLUTE_PREFIX '*'

/* these are the instruction mnemonic suffixes in AT&T syntax or
   memory operand size in Intel syntax.  */
#define WORD_MNEM_SUFFIX  'w'
#define BYTE_MNEM_SUFFIX  'b'
#define SHORT_MNEM_SUFFIX 's'
#define LONG_MNEM_SUFFIX  'l'
#define QWORD_MNEM_SUFFIX  'q'
#define XMMWORD_MNEM_SUFFIX  'x'
#define YMMWORD_MNEM_SUFFIX 'y'
#define ZMMWORD_MNEM_SUFFIX 'z'
/* Intel Syntax.  Use a non-ascii letter since since it never appears
   in instructions.  */
#define LONG_DOUBLE_MNEM_SUFFIX '\1'

#define END_OF_INSN '\0'

/*
  'templates' is for grouping together 'template' structures for opcodes
  of the same name.  This is only used for storing the insns in the grand
  ole hash table of insns.
  The templates themselves start at START and range up to (but not including)
  END.
  */
typedef struct
{
  const insn_template *start;
  const insn_template *end;
}
templates;

/* 386 operand encoding bytes:  see 386 book for details of this.  */
typedef struct
{
  unsigned int regmem;	/* codes register or memory operand */
  unsigned int reg;	/* codes register operand (or extended opcode) */
  unsigned int mode;	/* how to interpret regmem & reg */
}
modrm_byte;


/* 386 opcode byte to code indirect addressing.  */
typedef struct
{
  unsigned base;
  unsigned index;
  unsigned scale;
}
sib_byte;

/* x86 arch names, types and features */
typedef struct
{
  const char *name;		/* arch name */
  unsigned int len;		/* arch string length */
  enum processor_type type;	/* arch type */
  i386_cpu_flags flags;		/* cpu feature flags */
  unsigned int skip;		/* show_arch should skip this. */
  unsigned int negated;		/* turn off indicated flags.  */
}
arch_entry;

//static void update_code_flag (int, int);
//static void set_code_flag (int);
//static void set_intel_syntax (int);
//static void set_intel_mnemonic (int);
//static void set_allow_index_reg (int);
static void set_check (int);
static void set_cpu_arch (int);
#ifdef TE_PE
static void pe_directive_secrel (int);
#endif
static void signed_cons (int);
static char *output_invalid (int c);
static int i386_att_operand (char *);
//static int i386_intel_operand (char *, int);
//static int i386_intel_simplify (expressionS *);
//static int i386_intel_parse_name (const char *, expressionS *);
static const reg_entry *parse_register (char *, char **);
static char *parse_insn (char *, char *);
static char *parse_operands (char *);
//static void swap_operands (void);
static void swap_2_operands (int, int);
static const insn_template *match_template (void);
//static int check_string (void);
//static int process_suffix (void);
//static int check_byte_reg (void);
//static int check_long_reg (void);
//static int check_qword_reg (void);
//static int check_word_reg (void);
static int finalize_imm (void);
//static int process_operands (void);
//static const seg_entry *build_modrm_byte (void);
static void output_insn (void);
static void output_imm (fragS *, offsetT);
static void output_disp (fragS *, offsetT);
#ifndef I386COFF
static void s_bss (int);
#endif
#if defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF)
static void handle_large_common (int small ATTRIBUTE_UNUSED);
#endif

static const char *default_arch = DEFAULT_ARCH;



/* 'md_assemble ()' gathers together information and puts it into a
   i386_insn.  */

union i386_op
  {
    expressionS *disps;
    expressionS *imms;
    const reg_entry *regs;
  };

enum i386_error
  {
    operand_size_mismatch,
    operand_type_mismatch,
    register_type_mismatch,
    number_of_operands_mismatch,
    invalid_instruction_suffix,
    bad_imm4,
    old_gcc_only,
    unsupported_with_intel_mnemonic,
    unsupported_syntax,
    unsupported,
    invalid_vsib_address,
    invalid_vector_register_set,
    unsupported_vector_index_register,
    unsupported_broadcast,
    broadcast_not_on_src_operand,
    broadcast_needed,
    unsupported_masking,
    mask_not_on_destination,
    no_default_mask,
    unsupported_rc_sae,
    rc_sae_operand_not_last_imm,
    invalid_register_operand,
    try_vector_disp8
  };

struct _i386_insn
  {
    /* TM holds the template for the insn were currently assembling.  */
    insn_template tm;

    /* SUFFIX holds the instruction size suffix for byte, word, dword
       or qword, if given.  */
    char suffix;

    /* OPERANDS gives the number of given operands.  */
    unsigned int operands;

    /* REG_OPERANDS, DISP_OPERANDS, MEM_OPERANDS, IMM_OPERANDS give the number
       of given register, displacement, memory operands and immediate
       operands.  */
    unsigned int reg_operands, disp_operands, mem_operands, imm_operands;

    /* TYPES [i] is the type (see above #defines) which tells us how to
       use OP[i] for the corresponding operand.  */
    i386_operand_type types[MAX_OPERANDS];

    /* Displacement expression, immediate expression, or register for each
       operand.  */
    union i386_op op[MAX_OPERANDS];

    /* Flags for operands.  */
    unsigned int flags[MAX_OPERANDS];
#define Operand_PCrel 1

    /* Relocation type for operand */
    enum bfd_reloc_code_real reloc[MAX_OPERANDS];


    /* BASE_REG, INDEX_REG, and LOG2_SCALE_FACTOR are used to encode
       the base index byte below.  */
    const reg_entry *base_reg;
    const reg_entry *index_reg;
    unsigned int log2_scale_factor;


    /* Swap operand in encoding.  */
    unsigned int swap_operand;


    /* Error message.  */
    enum i386_error error;
  };

typedef struct _i386_insn i386_insn;

#define REGXTRA0 24
#define REGXTRA1 25


/* List of chars besides those in app.c:symbol_chars that can start an
   operand.  Used to prevent the scrubber eating vital white-space.  */
const char extra_symbol_chars[] = "*%-([{"
#ifdef LEX_AT
	"@"
#endif
#ifdef LEX_QM
	"?"
#endif
	;

#if (defined (TE_I386AIX)				\
     || ((defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF))	\
	 && !defined (TE_GNU)				\
	 && !defined (TE_LINUX)				\
	 && !defined (TE_NACL)				\
	 && !defined (TE_NETWARE)			\
	 && !defined (TE_FreeBSD)			\
	 && !defined (TE_DragonFly)			\
	 && !defined (TE_NetBSD)))
/* This array holds the chars that always start a comment.  If the
   pre-processor is disabled, these aren't very useful.  The option
   --divide will remove '/' from this list.  */
const char *i386_comment_chars = "#/";
#define SVR4_COMMENT_CHARS 1
#define PREFIX_SEPARATOR '\\'

#else
const char *i386_comment_chars = "#";
#define PREFIX_SEPARATOR '/'
#endif

/* This array holds the chars that only start a comment at the beginning of
   a line.  If the line seems to have the form '# 123 filename'
   .line and .file directives will appear in the pre-processed output.
   Note that input_file.c hand checks for '#' at the beginning of the
   first line of the input file.  This is because the compiler outputs
   #NO_APP at the beginning of its output.
   Also note that comments started like this one will always work if
   '/' isn't otherwise defined.  */
const char line_comment_chars[] = "#/";

const char line_separator_chars[] = ";";

/* Chars that can be used to separate mant from exp in floating point
   nums.  */
const char EXP_CHARS[] = "eE";

/* Chars that mean this number is a floating point constant
   As in 0f12.456
   or    0d1.2345e12.  */
const char FLT_CHARS[] = "fFdDxX";

/* Tables for lexical analysis.  */
static char mnemonic_chars[256];
static char register_chars[256];
static char operand_chars[256];
static char identifier_chars[256];
static char digit_chars[256];

/* Lexical macros.  */
#define is_mnemonic_char(x) (mnemonic_chars[(unsigned char) x])
#define is_operand_char(x) (operand_chars[(unsigned char) x])
#define is_register_char(x) (register_chars[(unsigned char) x])
#define is_space_char(x) ((x) == ' ')
#define is_identifier_char(x) (identifier_chars[(unsigned char) x])
#define is_digit_char(x) (digit_chars[(unsigned char) x])

/* All non-digit non-letter characters that may occur in an operand.  */
static char operand_special_chars[] = "%$-+(,)*._~/<>|&^!:[@]";

/* md_assemble() always leaves the strings it's passed unaltered.  To
   effect this we maintain a stack of saved characters that we've smashed
   with '\0's (indicating end of strings for various sub-fields of the
   assembler instruction).  */
static char save_stack[32];
static char *save_stack_p;
#define END_STRING_AND_SAVE(s) \
	do { *save_stack_p++ = *(s); *(s) = '\0'; } while (0)
#define RESTORE_END_STRING(s) \
	do { *(s) = *--save_stack_p; } while (0)

/* The instruction we're assembling.  */
static i386_insn i;
static int insn_count=0;
static int insn_stop=-1;
static int insn_bits=0;
static int insn_jumps=0;
static int insn_count_s=0;
static int insn_stop_s=-1;
static int insn_bits_s=0;
static int insn_jumps_s=0;
fragS *XXFR=NULL;
fragS *NNFR=NULL;

/* Possible templates for current insn.  */
static const templates *current_templates;

/* Per instruction expressionS buffers: max displacements & immediates.  */
static expressionS disp_expressions[MAX_MEMORY_OPERANDS];
static expressionS im_expressions[MAX_IMMEDIATE_OPERANDS];

/* Current operand we are working on.  */
static int this_operand = -1;

/* We support four different modes.  FLAG_CODE variable is used to distinguish
   these.  */

enum flag_code {
	CODE_64BIT };

static enum flag_code flag_code;
static unsigned int object_64bit;
static unsigned int disallow_64bit_reloc;
static int use_rela_relocations = 0;


#if defined (TE_PE) || defined (TE_PEP)
/* Use big object file format.  */
static int use_big_obj = 0;
#endif

#if defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF)
/* 1 if generating code for a shared library.  */
static int shared = 0;
#endif



/* 1 if the assembler should ignore LOCK prefix, even if it was
   specified explicitly.  */
static int omit_lock_prefix = 0;

static enum check_kind
  {
    check_none = 0,
    check_warning,
    check_error
  }
sse_check, operand_check = check_warning;

/* Register prefix used for error message.  */
//static const char *register_prefix = "%";


/* Non-zero to optimize code alignment.  */
int optimize_align_code = 1;

/* Non-zero to quieten some warnings.  */
static int quiet_warnings = 0;

/* CPU name.  */
//static const char *cpu_arch_name = NULL;
//static char *cpu_sub_arch_name = NULL;

/* CPU feature flags.  */
static i386_cpu_flags cpu_arch_flags = CPU_UNKNOWN_FLAGS;

/* If we have selected a cpu we are generating instructions for.  */
//static int cpu_arch_tune_set = 0;

/* Cpu we are generating instructions for.  */
enum processor_type cpu_arch_tune = PROCESSOR_UNKNOWN;

/* CPU feature flags of cpu we are generating instructions for.  */
//static i386_cpu_flags cpu_arch_tune_flags;

/* CPU instruction set architecture used.  */
enum processor_type cpu_arch_isa = PROCESSOR_UNKNOWN;

/* CPU feature flags of instruction set architecture used.  */
i386_cpu_flags cpu_arch_isa_flags;

/* If set, conditional jumps are not automatically promoted to handle
   larger than a byte offset.  */
//static unsigned int no_cond_jump_promotion = 0;

/* Encode SSE instructions with VEX prefix.  */
//static unsigned int sse2avx;

/* Encode scalar AVX instructions with specific vector length.  */
static enum
  {
    vex128 = 0,
    vex256
  } avxscalar;




/* Pre-defined "_GLOBAL_OFFSET_TABLE_".  */
static symbolS *GOT_symbol;

/* The dwarf2 return column, adjusted for 32 or 64 bit.  */
unsigned int x86_dwarf2_return_column;

/* The dwarf2 data alignment, adjusted for 32 or 64 bit.  */
int x86_cie_data_alignment;

/* Interface to relax_segment.
   There are 3 major relax states for 386 jump insns because the
   different types of jumps add different sizes to frags when we're
   figuring out what sort of jump to choose to reach a given label.  */

/* Types.  */
#define UNCOND_JUMP 0
#define COND_JUMP 1
#define COMPARE_JUMP 2
#define NON_JUMP 3
#define UNREL_JUMP 4

/* Sizes.  */
#define SMALL	0
#define MED	1
#define BIG	2
#define BIGGER  3
#define BIGGEST 4


#ifndef INLINE
#ifdef __GNUC__
#define INLINE __inline__
#else
#define INLINE
#endif
#endif

#define ENCODE_RELAX_STATE(type, size) \
  ((relax_substateT) (((type) << 3) | (size)))
#define TYPE_FROM_RELAX_STATE(s) \
  ((s) >> 3)
#define DISP_SIZE_FROM_RELAX_STATE(s) \
    (((s)&7)==BIGGEST ? 8 : (((s) & 7) == BIG || ((s) & 7)==BIGGER ? 4 : (((s) & 7) == MED ? 2 : 0)))

/* This table is used by relax_frag to promote short jumps to long
   ones where necessary.  SMALL (short) jumps may be promoted to BIG
   (32 bit long) ones, and SMALL16 jumps to BIG16 (16 bit long).  We
   don't allow a short jump in a 32 bit code segment to be promoted to
   a 16 bit offset jump because it's slower (requires data size
   prefix), and doesn't work, unless the destination is in the bottom
   64k of the code segment (The top 16 bits of eip are zeroed).  */

const relax_typeS md_relax_table[] =
{
  /* The fields are:
     1) most positive reach of this state,
     2) most negative reach of this state,
     3) how many bytes this mode will have in the variable part of the frag
     4) which index into the table to try if we can't fit into this one.  */

  /* UNCOND_JUMP states.  */
  {254+2-24 , -256 + 2, 0, ENCODE_RELAX_STATE (UNCOND_JUMP, MED)},
  {16777214 + 2-24, -16777216 + 2, 2, ENCODE_RELAX_STATE (UNCOND_JUMP, BIG)},
  /* dword jmp adds 4 bytes to frag:
     0 extra opcode bytes, 4 displacement bytes.  */
  {0, 0, 4, 0},
  /* word jmp adds 2 byte2 to frag:
     0 extra opcode bytes, 2 displacement bytes.  */
  {0, 0, 4, 0},
  {0, 0, 4, 0},
  {0, 0, 4, 0},
  {0, 0, 4, 0},
  {0, 0, 4, 0},

  /* COND_JUMP states.  */
  {254 + 0-24, -256 + 0, 0, ENCODE_RELAX_STATE (COND_JUMP, MED)},
  {1048574 + 2-24, -1048576 + 2, 2, ENCODE_RELAX_STATE (COND_JUMP, BIG)},
  /* dword conditionals adds 5 bytes to frag:
     1 extra opcode byte, 4 displacement bytes.  */
  {0, 0, 4, 0},
  /* word conditionals add 3 bytes to frag:
     1 extra opcode byte, 2 displacement bytes.  */
  {0, 0, 4, 0},
  {0, 0, 4, 0},
  {0, 0, 4, 0},
  {0, 0, 4, 0},
  {0, 0, 4, 0},

  /* CJUMP states.  */
  {254 + 0-24, -256 + 0, 0, ENCODE_RELAX_STATE (COMPARE_JUMP, MED)},
  {16382 + 2-24, -16384 + 2, 2, ENCODE_RELAX_STATE (COMPARE_JUMP, BIG)},
  {65534+4-24, -65536+4, 4, ENCODE_RELAX_STATE(COMPARE_JUMP,BIGGER)},
  {0, 0, 6, 0},
  {0, 0, 4, 0},
  {0, 0, 4, 0},
  {0, 0, 4, 0},
  {0, 0, 4, 0}
};
/*
static const arch_entry cpu_arch[] =
{
  /x* Do not replace the first two entries - i386_target_format()
     relies on them being there in this order.  *x/
  { STRING_COMMA_LEN ("generic32"), PROCESSOR_GENERIC32,
    CPU_GENERIC32_FLAGS, 0, 0 },
  { STRING_COMMA_LEN ("generic64"), PROCESSOR_GENERIC64,
    CPU_GENERIC64_FLAGS, 0, 0 },
  { STRING_COMMA_LEN ("heptane"), PROCESSOR_UNKNOWN,
    CPU_SSSE3_FLAGS, 0, 0 }
};
*/

const pseudo_typeS md_pseudo_table[] =
{
#if !defined(OBJ_AOUT) && !defined(USE_ALIGN_PTWO)
  {"align", s_align_bytes, 0},
#else
  {"align", s_align_ptwo, 0},
#endif
  {"arch", set_cpu_arch, 0},
#ifndef I386COFF
  {"bss", s_bss, 0},
#else
  {"lcomm", pe_lcomm, 1},
#endif
  {"ffloat", float_cons, 'f'},
  {"dfloat", float_cons, 'd'},
  {"tfloat", float_cons, 'x'},
  {"value", cons, 2},
  {"slong", signed_cons, 4},
  {"noopt", s_ignore, 0},
  {"optim", s_ignore, 0},
 // {"intel_syntax", set_intel_syntax, 1},
 // {"att_syntax", set_intel_syntax, 0},
 // {"intel_mnemonic", set_intel_mnemonic, 1},
 // {"att_mnemonic", set_intel_mnemonic, 0},
 // {"allow_index_reg", set_allow_index_reg, 1},
 // {"disallow_index_reg", set_allow_index_reg, 0},
  {"sse_check", set_check, 0},
  {"operand_check", set_check, 1},
#if defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF)
  {"largecomm", handle_large_common, 0},
#else
  {"file", (void (*) (int)) dwarf2_directive_file, 0},
  {"loc", dwarf2_directive_loc, 0},
  {"loc_mark_labels", dwarf2_directive_loc_mark_labels, 0},
#endif
#ifdef TE_PE
  {"secrel32", pe_directive_secrel, 0},
#endif
  {0, 0, 0}
};

/* For interface with expression ().  */
extern char *input_line_pointer;

/* Hash table for instruction mnemonic lookup.  */
static struct hash_control *op_hash;

/* Hash table for register lookup.  */
static struct hash_control *reg_hash;

void
heptane_align_code (fragS *fragP, int count)
{
  offsetT start_addr=fragP->fr_address+fragP->fr_fix;
  //int bits_pos=(((start_addr+31)>>5)<<5)-start_addr-2;  
  /* Only align for at least a positive non-zero boundary. */
  if (count <= 0 || count > MAX_MEM_FOR_RS_ALIGN_CODE)
     count=32-(start_addr&0x1f);    
  if (count==32) return;
  if (start_addr>>5==(start_addr+count)>>5) return; 
//  if (bits_pos<0) bits_pos=28;
  
  memset(fragP->fr_literal+fragP->fr_fix,0,count);
  fragP->fr_literal[fragP->fr_fix+count-2]=insn_bits&0xff;
  fragP->fr_literal[fragP->fr_fix+count-1]=(insn_bits&0xff00)>>8;
 
  insn_bits=0;
  insn_count=0;
  insn_stop=-1;
  insn_jumps=0;
  
  fragP->fr_var = count;
}
static offsetT
offset_in_range (offsetT val, int size)
{
  addressT mask;

  switch (size)
    {
    case 1: mask = ((addressT) 1 <<  8) - 1; break;
    case 2: mask = ((addressT) 1 << 16) - 1; break;
    case 4: mask = ((addressT) 2 << 31) - 1; break;
#ifdef BFD64
    case 8: mask = ((addressT) 2 << 63) - 1; break;
#endif
    default: abort ();
    }


  if ((val & ~mask) != 0 && (val & ~mask) != ~mask)
    {
      char buf1[40], buf2[40];

      sprint_value (buf1, val);
      sprint_value (buf2, val & mask);
      as_warn (_("%s shortened to %s"), buf1, buf2);
    }
  return val & mask;
}


static INLINE int
operand_type_all_zero (const union i386_operand_type *x)
{
  switch (ARRAY_SIZE(x->array))
    {
    case 3:
      if (x->array[2])
	return 0;
      /* fall through */
    case 2:
      if (x->array[1])
	return 0;
      /* fall through */
    case 1:
      return !x->array[0];
      /* fall through */
    default:
      abort ();
    }
}

static INLINE void
operand_type_set (union i386_operand_type *x, unsigned int v)
{
  switch (ARRAY_SIZE(x->array))
    {
    case 3:
      x->array[2] = v;
      /* fall through */
    case 2:
      x->array[1] = v;
      /* fall through */
    case 1:
      x->array[0] = v;
      break;
    default:
      abort ();
    }
}

static INLINE int
operand_type_equal (const union i386_operand_type *x,
		    const union i386_operand_type *y)
{
  switch (ARRAY_SIZE(x->array))
    {
    case 3:
      if (x->array[2] != y->array[2])
	return 0;
    case 2:
      if (x->array[1] != y->array[1])
	return 0;
    case 1:
      return x->array[0] == y->array[0];
      break;
    default:
      abort ();
    }
}





static INLINE i386_operand_type
operand_type_and (i386_operand_type x, i386_operand_type y)
{
  switch (ARRAY_SIZE (x.array))
    {
    case 3:
      x.array [2] &= y.array [2];
      /* fall through */
    case 2:
      x.array [1] &= y.array [1];
      /* fall through */
    case 1:
      x.array [0] &= y.array [0];
      break;
    default:
      abort ();
    }
  return x;
}

static INLINE i386_operand_type
operand_type_or (i386_operand_type x, i386_operand_type y)
{
  switch (ARRAY_SIZE (x.array))
    {
    case 3:
      x.array [2] |= y.array [2];
      /* fall through */
    case 2:
      x.array [1] |= y.array [1];
      /* fall through */
    case 1:
      x.array [0] |= y.array [0];
      break;
    default:
      abort ();
    }
  return x;
}

static INLINE i386_operand_type
operand_type_xor (i386_operand_type x, i386_operand_type y)
{
  switch (ARRAY_SIZE (x.array))
    {
    case 3:
      x.array [2] ^= y.array [2];
      /* fall through */
    case 2:
      x.array [1] ^= y.array [1];
      /* fall through */
    case 1:
      x.array [0] ^= y.array [0];
      break;
    default:
      abort ();
    }
  return x;
}
/*
static const i386_operand_type control = OPERAND_TYPE_CONTROL;
static const i386_operand_type inoutportreg
  = OPERAND_TYPE_INOUTPORTREG;
static const i386_operand_type reg16_inoutportreg
  = OPERAND_TYPE_REG16_INOUTPORTREG;
static const i386_operand_type disp14 = OPERAND_TYPE_DISP14S;
static const i386_operand_type disp32 = OPERAND_TYPE_DISP32;
static const i386_operand_type disp32s = OPERAND_TYPE_DISP32S;*/
static const i386_operand_type anydisp
  = OPERAND_TYPE_ANYDISP;/*
static const i386_operand_type regxmm = OPERAND_TYPE_REGXMM;
static const i386_operand_type regymm = OPERAND_TYPE_REGYMM;
static const i386_operand_type regzmm = OPERAND_TYPE_REGZMM;
static const i386_operand_type regmask = OPERAND_TYPE_REGMASK;
static const i386_operand_type imm8 = OPERAND_TYPE_IMM8;
static const i386_operand_type imm13s = OPERAND_TYPE_IMM13S;
static const i386_operand_type imm32 = OPERAND_TYPE_IMM32;
static const i386_operand_type imm32s = OPERAND_TYPE_IMM32S;
static const i386_operand_type imm64 = OPERAND_TYPE_IMM64;
static const i386_operand_type vec_imm4 = OPERAND_TYPE_VEC_IMM4;
*/
enum operand_type
{
  reg,
  imm,
  disp,
  anymem
};

static INLINE int
operand_type_check (i386_operand_type t, enum operand_type c)
{
  switch (c)
    {
    case reg:
      return (t.bitfield.reg8
	      || t.bitfield.reg16
	      || t.bitfield.reg32
	      || t.bitfield.reg64);

    case imm:
      return (t.bitfield.imm8
	      || t.bitfield.imm13s
	      || t.bitfield.imm32
	      || t.bitfield.imm32s
	      || t.bitfield.imm64);

    case disp:
      return (
	      t.bitfield.disp14s
	      || t.bitfield.disp32
	      || t.bitfield.disp32s
	      || t.bitfield.disp64);

    case anymem:
      return (
	      t.bitfield.disp14s
	      || t.bitfield.disp32
	      || t.bitfield.disp32s
	      || t.bitfield.disp64
	      || t.bitfield.baseindex);

    default:
      abort ();
    }

  return 0;
}

/* Return 1 if there is no conflict in 8bit/16bit/32bit/64bit on
   operand J for instruction template T.  */

static INLINE int
match_reg_size (const insn_template *t, unsigned int j)
{
  if (t->group!=instrg_isFPU23Op && t->group!=instrg_isFPU2Op && t->group!=instrg_isExt) {
  return !((i.types[j].bitfield.reg8
	    && ((t->size_offsets&0xff000000)==0xff000000))
	   || (i.types[j].bitfield.reg16
	       && (t->size_offsets&0xff0000)==0xff0000)
	   || (i.types[j].bitfield.reg32
	       && (t->size_offsets&0xff00)==0xff00)
	   || (i.types[j].bitfield.reg64
	       && (t->size_offsets&0xff)==0xff));
  }
  else if (t->group==instrg_isExt) {
      if (j==0) {
	  switch (t->name[4]) {
	  case 'b': return i.types[j].bitfield.reg8;
	  case 'w': return i.types[j].bitfield.reg16;
	  case 'l': return i.types[j].bitfield.reg32;
	  default: return 0;
	  }
      } else {
         return !((i.types[j].bitfield.reg8
	    && ((t->size_offsets&0xff000000)==0xff000000))
	   || (i.types[j].bitfield.reg16
	       && (t->size_offsets&0xff0000)==0xff0000)
	   || (i.types[j].bitfield.reg32
	       && (t->size_offsets&0xff00)==0xff00)
	   || (i.types[j].bitfield.reg64
	       && (t->size_offsets&0xff)==0xff));
	  
      }
  }  else return 0;
}

/* Return 1 if there is no conflict in any size on operand J for
   instruction template T.  */

static INLINE int
match_mem_size (const insn_template *t, unsigned int j)
{
  return (match_reg_size (t, j)
	  && !((i.types[j].bitfield.unspecified
		)
	       ));
}

/* Return 1 if there is no size conflict on any operands for
   instruction template T.  */

static INLINE int
operand_size_match (const insn_template *t)
{
  unsigned int j;
  int match = 1;

  /* Don't check jump instructions.  */
  if (t->group==instrg_isCondJump
      || t->group==instrg_isUncondJump)
    return match;

  for (j = 0; j < i.operands; j++)
    {
       switch(t->group) {
       case instrg_isCondJump:
       case instrg_isUncondJump:
       case instrg_isCall:
       case instrg_isRet:
       break;
       default:
	   if (!match_reg_size(t,j) && operand_type_check(i.types[j],reg)) match=0;
	   break;
       }

    }

  return match;
}

static INLINE int
operand_type_match (i386_operand_type overlap,
		    i386_operand_type given)
{
  i386_operand_type temp = overlap;

  temp.bitfield.jumpabsolute = 0;
  temp.bitfield.unspecified = 0;
  temp.bitfield.byte = 0;
  temp.bitfield.word = 0;
  temp.bitfield.dword = 0;
  temp.bitfield.fword = 0;
  temp.bitfield.qword = 0;
  temp.bitfield.tbyte = 0;
  temp.bitfield.xmmword = 0;
  temp.bitfield.ymmword = 0;
  temp.bitfield.zmmword = 0;
  if (operand_type_all_zero (&temp))
    goto mismatch;

  if (given.bitfield.baseindex == overlap.bitfield.baseindex
      && given.bitfield.jumpabsolute == overlap.bitfield.jumpabsolute)
    return 1;

mismatch:
  i.error = operand_type_mismatch;
  return 0;
}


static INLINE unsigned int
register_number (const reg_entry *r)
{
  unsigned int nr = r->reg_num;

  return nr;
}

static INLINE unsigned int
mode_from_disp_size (i386_operand_type t)
{
  if (t.bitfield.disp14s)
    return 1;
  else if (
	   t.bitfield.disp32
	   || t.bitfield.disp32s)
    return 2;
  else
    return 0;
}

static INLINE int
fits_in_signed_byte (addressT num)
{
  return num + 0x80 <= 0xff;
}

static INLINE int
fits_in_unsigned_byte (addressT num)
{
  return num <= 0xff;
}

static INLINE int
fits_in_unsigned_word (addressT num)
{
  return num <= 0xffff;
}

static INLINE int
fits_in_signed_word (addressT num)
{
  return num + 0x8000 <= 0xffff;
}

static INLINE int
fits_in_signed_word13 (addressT num)
{
  return num + 0x1000 <= 0x1fff;
}

static INLINE int
fits_in_signed_word14 (addressT num)
{
  return num + 0x2000 <= 0x3fff;
}


static INLINE int
fits_in_signed_long (addressT num ATTRIBUTE_UNUSED)
{
#ifndef BFD64
  return 1;
#else
  return num + 0x80000000 <= 0xffffffff;
#endif
}				/* fits_in_signed_long() */

static INLINE int
fits_in_unsigned_long (addressT num ATTRIBUTE_UNUSED)
{
#ifndef BFD64
  return 1;
#else
  return num <= 0xffffffff;
#endif
}				/* fits_in_unsigned_long() */

static INLINE int
fits_in_imm5 (offsetT num)
{
  return (num & 0x1f) == num;
}

static INLINE int
fits_in_imm4 (offsetT num)
{
  return (num & 0xf) == num;
}
/*
static i386_operand_type
smallest_imm_type (offsetT num)
{
  i386_operand_type t;

  operand_type_set (&t, 0);
  t.bitfield.imm64 = 1;

  if (fits_in_signed_word13 (num))
    {
      t.bitfield.imm13s = 1;
    }
  else if (fits_in_signed_long (num))
    {
      t.bitfield.imm32 = 1;
      t.bitfield.imm32s = 1;
    }
  else if (fits_in_unsigned_long (num))
    t.bitfield.imm32 = 1;

  return t;
}
*/





static void
set_check (int what)
{
  enum check_kind *kind;
  const char *str;

  if (what)
    {
      kind = &operand_check;
      str = "operand";
    }
  else
    {
      kind = &sse_check;
      str = "sse";
    }

  SKIP_WHITESPACE ();

  if (!is_end_of_line[(unsigned char) *input_line_pointer])
    {
      char *string;
      int e = get_symbol_name (&string);

      if (strcmp (string, "none") == 0)
	*kind = check_none;
      else if (strcmp (string, "warning") == 0)
	*kind = check_warning;
      else if (strcmp (string, "error") == 0)
	*kind = check_error;
      else
	as_bad (_("bad argument to %s_check directive."), str);
      (void) restore_line_pointer (e);
    }
  else
    as_bad (_("missing argument for %s_check directive"), str);

  demand_empty_rest_of_line ();
}


static void
set_cpu_arch (int dummy ATTRIBUTE_UNUSED)
{
}

enum bfd_architecture
heptane_arch (void)
{
    return bfd_arch_heptane;
}

unsigned long
heptane_mach (void)
{
	return bfd_mach_heptane;
}

void
md_begin (void)
{
  const char *hash_err;

  /* Initialize op_hash hash table.  */
  op_hash = hash_new ();

  {
    const insn_template *optab;
    templates *core_optab;

    /* Setup for loop.  */
    optab = heptane_optab;
    core_optab = (templates *) xmalloc (sizeof (templates));
    core_optab->start = optab;

    while (1)
      {
	++optab;
	if (optab->name == NULL
	    || strcmp (optab->name, (optab - 1)->name) != 0)
	  {
	    /* different name --> ship out current template list;
	       add to hash table; & begin anew.  */
	    core_optab->end = optab;
	    hash_err = hash_insert (op_hash,
				    (optab - 1)->name,
				    (void *) core_optab);
	    if (hash_err)
	      {
		as_fatal (_("can't hash %s: %s"),
			  (optab - 1)->name,
			  hash_err);
	      }
	    if (optab->name == NULL)
	      break;
	    core_optab = (templates *) xmalloc (sizeof (templates));
	    core_optab->start = optab;
	  }
      }
  }

  /* Initialize reg_hash hash table.  */
  reg_hash = hash_new ();
  {
    const reg_entry *regtab;
    unsigned int regtab_size = heptane_regtab_size;

    for (regtab = heptane_regtab; regtab_size--; regtab++)
      {
	hash_err = hash_insert (reg_hash, regtab->reg_name, (void *) regtab);
	if (hash_err)
	  as_fatal (_("can't hash %s: %s"),
		    regtab->reg_name,
		    hash_err);
      }
  }

  /* Fill in lexical tables:  mnemonic_chars, operand_chars.  */
  {
    int c;
    char *p;

    for (c = 0; c < 256; c++)
      {
	if (ISDIGIT (c))
	  {
	    digit_chars[c] = c;
	    mnemonic_chars[c] = c;
	    register_chars[c] = c;
	    operand_chars[c] = c;
	  }
	else if (ISLOWER (c))
	  {
	    mnemonic_chars[c] = c;
	    register_chars[c] = c;
	    operand_chars[c] = c;
	  }
	else if (ISUPPER (c))
	  {
	    mnemonic_chars[c] = TOLOWER (c);
	    register_chars[c] = mnemonic_chars[c];
	    operand_chars[c] = c;
	  }
	else if (c == '{' || c == '}')
	  operand_chars[c] = c;

	if (ISALPHA (c) || ISDIGIT (c))
	  identifier_chars[c] = c;
	else if (c >= 128)
	  {
	    identifier_chars[c] = c;
	    operand_chars[c] = c;
	  }
      }

#ifdef LEX_AT
    identifier_chars['@'] = '@';
#endif
#ifdef LEX_QM
    identifier_chars['?'] = '?';
    operand_chars['?'] = '?';
#endif
    digit_chars['-'] = '-';
    mnemonic_chars['_'] = '_';
    mnemonic_chars['-'] = '-';
    mnemonic_chars['.'] = '.';
    identifier_chars['_'] = '_';
    identifier_chars['.'] = '.';

    for (p = operand_special_chars; *p != '\0'; p++)
      operand_chars[(unsigned char) *p] = *p;
  }

  if (flag_code == CODE_64BIT)
    {
#if defined (OBJ_COFF) && defined (TE_PE)
      x86_dwarf2_return_column = (OUTPUT_FLAVOR == bfd_target_coff_flavour
				  ? 32 : 16);
#else
      x86_dwarf2_return_column = 16;
#endif
      x86_cie_data_alignment = -8;
    }
  else
    {
      x86_dwarf2_return_column = 8;
      x86_cie_data_alignment = -4;
    }
}

void
i386_print_statistics (FILE *file)
{
  hash_print_statistics (file, "i386 opcode", op_hash);
  hash_print_statistics (file, "i386 register", reg_hash);
}

#ifdef DEBUG386

/* Debugging routines for md_assemble.  */
static void pte (insn_template *);
static void pt (i386_operand_type);
static void pe (expressionS *);
static void ps (symbolS *);


static void
pi (char *line, i386_insn *x)
{
  //print instr
}

static void
pte (insn_template *t)
{
}

static void
pe (expressionS *e)
{
  fprintf (stdout, "    operation     %d\n", e->X_op);
  fprintf (stdout, "    add_number    %ld (%lx)\n",
	   (long) e->X_add_number, (long) e->X_add_number);
  if (e->X_add_symbol)
    {
      fprintf (stdout, "    add_symbol    ");
      ps (e->X_add_symbol);
      fprintf (stdout, "\n");
    }
  if (e->X_op_symbol)
    {
      fprintf (stdout, "    op_symbol    ");
      ps (e->X_op_symbol);
      fprintf (stdout, "\n");
    }
}

static void
ps (symbolS *s)
{
  fprintf (stdout, "%s type %s%s",
	   S_GET_NAME (s),
	   S_IS_EXTERNAL (s) ? "EXTERNAL " : "",
	   segment_name (S_GET_SEGMENT (s)));
}

static struct type_name
  {
    i386_operand_type mask;
    const char *name;
  }
const type_names[] =
{
  { OPERAND_TYPE_REG8, "r8" },
  { OPERAND_TYPE_REG16, "r16" },
  { OPERAND_TYPE_REG32, "r32" },
  { OPERAND_TYPE_REG64, "r64" },
  { OPERAND_TYPE_IMM13, "i13" },
  { OPERAND_TYPE_IMM32, "i32" },
  { OPERAND_TYPE_IMM32S, "i32s" },
  { OPERAND_TYPE_IMM64, "i64" },
  { OPERAND_TYPE_IMM1, "i1" },
  { OPERAND_TYPE_BASEINDEX, "BaseIndex" },
  { OPERAND_TYPE_DISP7, "d7" },
  { OPERAND_TYPE_DISP14, "d14" },
  { OPERAND_TYPE_DISP32, "d32" },
  { OPERAND_TYPE_DISP32S, "d32s" },
  { OPERAND_TYPE_DISP64, "d64" },
  { OPERAND_TYPE_INOUTPORTREG, "InOutPortReg" },
  { OPERAND_TYPE_SHIFTCOUNT, "ShiftCount" },
  { OPERAND_TYPE_CONTROL, "control reg" },
  { OPERAND_TYPE_TEST, "test reg" },
  { OPERAND_TYPE_DEBUG, "debug reg" },
  { OPERAND_TYPE_SREG2, "SReg2" },
  { OPERAND_TYPE_SREG3, "SReg3" },
  { OPERAND_TYPE_JUMPABSOLUTE, "Jump Absolute" },
  { OPERAND_TYPE_REGMMX, "rMMX" },
  { OPERAND_TYPE_REGXMM, "rXMM" },
  { OPERAND_TYPE_REGYMM, "rYMM" }
};

static void
pt (i386_operand_type t)
{
  unsigned int j;
  i386_operand_type a;

  for (j = 0; j < ARRAY_SIZE (type_names); j++)
    {
      a = operand_type_and (t, type_names[j].mask);
      if (!operand_type_all_zero (&a))
	fprintf (stdout, "%s, ",  type_names[j].name);
    }
  fflush (stdout);
}

#endif /* DEBUG386 */

operatorT heptane_operator (const char *name, unsigned int operands, char *pc)
{  
   (void)(name);
   (void) operands;
   (void)(pc);

    return O_absent;

}

int heptane_need_index_operator (void)
{
  return  0;
}
static bfd_reloc_code_real_type
reloc (unsigned int size,
       int pcrel,
       int sign,
       bfd_reloc_code_real_type other)
{
  if (other != NO_RELOC)
    {
      reloc_howto_type *rel;

      if (size == 8)
	switch (other)
	  {
	  case BFD_RELOC_HEPTANE_GOT32:
	    return BFD_RELOC_HEPTANE_GOT64;
	    break;
	  case BFD_RELOC_HEPTANE_GOTPLT64:
	    return BFD_RELOC_HEPTANE_GOTPLT64;
	    break;
	  case BFD_RELOC_HEPTANE_PLTOFF64:
	    return BFD_RELOC_HEPTANE_PLTOFF64;
	    break;
	  case BFD_RELOC_HEPTANE_GOTPC32:
	    other = BFD_RELOC_HEPTANE_GOTPC64;
	    break;
	  case BFD_RELOC_HEPTANE_GOTPCREL:
	    other = BFD_RELOC_HEPTANE_GOTPCREL64;
	    break;
	  case BFD_RELOC_HEPTANE_TPOFF32:
	    other = BFD_RELOC_HEPTANE_TPOFF64;
	    break;
	  case BFD_RELOC_HEPTANE_DTPOFF32:
	    other = BFD_RELOC_HEPTANE_DTPOFF64;
	    break;
	  default:
	    break;
	  }

#if defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF)
      if (other == BFD_RELOC_SIZE32)
	{
	  if (size == 8)
	    other = BFD_RELOC_SIZE64;
	  if (pcrel)
	    {
	      as_bad (_("there are no pc-relative size relocations"));
	      return NO_RELOC;
	    }
	}
#endif

      /* Sign-checking 4-byte relocations in 16-/32-bit code is pointless.  */
      if (size == 4 && (flag_code != CODE_64BIT || disallow_64bit_reloc))
	sign = -1;

      rel = bfd_reloc_type_lookup (stdoutput, other);
      if (!rel)
	as_bad (_("unknown relocation (%u)"), other);
      else if (size != bfd_get_reloc_size (rel))
	as_bad (_("%u-byte relocation cannot be applied to %u-byte field"),
		bfd_get_reloc_size (rel),
		size);
      else if (pcrel && !rel->pc_relative)
	as_bad (_("non-pc-relative relocation for pc-relative field"));
      else if ((rel->complain_on_overflow == complain_overflow_signed
		&& !sign)
	       || (rel->complain_on_overflow == complain_overflow_unsigned
		   && sign > 0))
	as_bad (_("relocated field and relocation type differ in signedness"));
      else
	return other;
      return NO_RELOC;
    }

  if (pcrel)
    {
      if (!sign)
	as_bad (_("there are no unsigned pc-relative relocations"));
      switch (size)
	{
	case 1: return BFD_RELOC_8_PCREL;
	case 2: return BFD_RELOC_16_PCREL;
	case 4: return BFD_RELOC_32_PCREL;
	case 8: return BFD_RELOC_64_PCREL;
	}
      as_bad (_("cannot do %u byte pc-relative relocation"), size);
    }
  else
    {
      if (sign > 0)
	switch (size)
	  {
	  case 4: return BFD_RELOC_X86_64_32S;
	  }
      else
	switch (size)
	  {
	  case 1: return BFD_RELOC_8;
	  case 2: return BFD_RELOC_16;
	  case 4: return BFD_RELOC_32;
	  case 8: return BFD_RELOC_64;
	  }
      as_bad (_("cannot do %s %u byte relocation"),
	      sign > 0 ? "signed" : "unsigned", size);
    }

  return NO_RELOC;
}




/* This is the guts of the machine-dependent assembler.  LINE points to a
   machine dependent instruction.  This function is supposed to emit
   the frags/bytes it assembles to.  */

void
md_assemble (char *line)
{
  unsigned int j;
  char mnemonic[MAX_MNEM_SIZE];
  const insn_template *t;

  /* Initialize globals.  */
  memset (&i, '\0', sizeof (i));
  for (j = 0; j < MAX_OPERANDS; j++)
    i.reloc[j] = NO_RELOC;
  memset (disp_expressions, '\0', sizeof (disp_expressions));
  memset (im_expressions, '\0', sizeof (im_expressions));
  save_stack_p = save_stack;

  /* First parse an instruction mnemonic & call i386_operand for the operands.
     We assume that the scrubber has arranged it so that line[0] is the valid
     start of a (possibly prefixed) mnemonic.  */

  line = parse_insn (line, mnemonic);
  if (line == NULL)
    return;

  line = parse_operands (line);
  this_operand = -1;
  if (line == NULL)
    return;

  /* Now we've parsed the mnemonic into a set of templates, and have the
     operands at hand.  */


  /* The order of the immediates should be reversed
     for 2 immediates extrq and insertq instructions */
  if (i.imm_operands == 2
      && (strcmp (mnemonic, "extrq") == 0
	  || strcmp (mnemonic, "insertq") == 0))
      swap_2_operands (0, 1);

//  if (i.imm_operands)
//    optimize_imm ();

  /* Don't optimize displacement for movabs since it only takes 64bit
     displacement.  */
/*  if (i.disp_operands
      && strcmp (mnemonic, "movabs") != 0))
    optimize_disp ();
*/
  /* Next, we find a template that matches the given insn,
     making sure the overlap of the given operands types is consistent
     with the template operand types.  */

  if (!(t = match_template ()))
    return;





  /* Make still unresolved immediate matches conform to size of immediate
     given in i.suffix.  */
  if (!finalize_imm ())
    return;




  /* We are ready to output the insn.  */
  output_insn ();
}

static char *
parse_insn (char *line, char *mnemonic)
{
  char *l = line;
  char *token_start = l;
  char *mnem_p;
 // int supported;
 // const insn_template *t;
  //char *dot_p = NULL;

  while (1)
    {
      mnem_p = mnemonic;
      while ((*mnem_p = mnemonic_chars[(unsigned char) *l]) != 0)
	{
//	  if (*mnem_p == '.')
//	    dot_p = mnem_p;
	  mnem_p++;
	  if (mnem_p >= mnemonic + MAX_MNEM_SIZE)
	    {
	      as_bad (_("no such instruction: `%s'"), token_start);
	      return NULL;
	    }
	  l++;
	}
      if (!is_space_char (*l)
	  && *l != END_OF_INSN
	  && ( (*l != PREFIX_SEPARATOR
		  && *l != ',')))
	{
	  as_bad (_("invalid character %s in mnemonic"),
		  output_invalid (*l));
	  return NULL;
	}
      if (token_start == l)
	{
	  if (*l == PREFIX_SEPARATOR)
	    as_bad (_("expecting prefix; got nothing"));
	  else
	    as_bad (_("expecting mnemonic; got nothing"));
	  return NULL;
	}

      /* Look up instruction (or prefix) via hash table.  */
      current_templates = (const templates *) hash_find (op_hash, mnemonic);
      break;
    }

 /* if (!current_templates)
    {
      /x* Check if we should swap operand or force 32bit displacement in
	 encoding.  *x/
      if (mnem_p - 2 == dot_p && dot_p[1] == 's')
	i.swap_operand = 1;
      else if (mnem_p - 3 == dot_p
	       && dot_p[1] == 'd'
	       && dot_p[2] == '8')
	i.disp_encoding = disp_encoding_8bit;
      else if (mnem_p - 4 == dot_p
	       && dot_p[1] == 'd'
	       && dot_p[2] == '3'
	       && dot_p[3] == '2')
	i.disp_encoding = disp_encoding_32bit;
      else
	goto check_suffix;
      mnem_p = dot_p;
      *dot_p = '\0';
      current_templates = (const templates *) hash_find (op_hash, mnemonic);
    }
*/
  if (!current_templates)
    {
//check_suffix:
      /* See if we can get a match by trimming off a suffix.  */
      switch (mnem_p[-1])
	{
	case WORD_MNEM_SUFFIX:
	case BYTE_MNEM_SUFFIX:
	case QWORD_MNEM_SUFFIX:
	  i.suffix = mnem_p[-1];
	  mnem_p[-1] = '\0';
	  current_templates = (const templates *) hash_find (op_hash,
                                                             mnemonic);
	  break;
	case SHORT_MNEM_SUFFIX:
	case LONG_MNEM_SUFFIX:
	      i.suffix = mnem_p[-1];
	      mnem_p[-1] = '\0';
	      current_templates = (const templates *) hash_find (op_hash,
                                                                 mnemonic);
	  break;

	}
      if (!current_templates)
	{
	  as_bad (_("no such instruction: `%s'"), token_start);
	  return NULL;
	}
    }

  /* Any other comma loses.  */
  if (*l == ',')
    {
      as_bad (_("invalid character %s in mnemonic"),
	      output_invalid (*l));
      return NULL;
    }

  /* Check if instruction is supported on specified architecture.  */
 // supported = CPU_FLAGS_PERFECT_MATCH;
/*  for (t = current_templates->start; t < current_templates->end; ++t)
    {
      supported |= cpu_flags_match (t);
      if (supported == CPU_FLAGS_PERFECT_MATCH)
	goto skip;
    }
*/
/*  if (!(supported & CPU_FLAGS_64BIT_MATCH))
    {
      as_bad (flag_code == CODE_64BIT
	      ? _("`%s' is not supported in 64-bit mode")
	      : _("`%s' is only supported in 64-bit mode"),
	      current_templates->start->name);
      return NULL;
    }*/
/*  if (supported != CPU_FLAGS_PERFECT_MATCH)
    {
      as_bad (_("`%s' is not supported on `%s%s'"),
	      current_templates->start->name,
	      cpu_arch_name ? cpu_arch_name : default_arch,
	      cpu_sub_arch_name ? cpu_sub_arch_name : "");
      return NULL;
    }*/

//skip:

  return l;
}

static char *
parse_operands (char *l)
{
  char *token_start;

  /* 1 if operand is pending after ','.  */
  unsigned int expecting_operand = 0;

  /* Non-zero if operand parens not balanced.  */
  unsigned int paren_not_balanced;

  while (*l != END_OF_INSN)
    {
      /* Skip optional white space before operand.  */
      if (is_space_char (*l))
	++l;
      if (!is_operand_char (*l) && *l != END_OF_INSN && *l != '"')
	{
	  as_bad (_("invalid character %s before operand %d"),
		  output_invalid (*l),
		  i.operands + 1);
	  return NULL;
	}
      token_start = l;	/* After white space.  */
      paren_not_balanced = 0;
      while (paren_not_balanced || *l != ',')
	{
	  if (*l == END_OF_INSN)
	    {
	      if (paren_not_balanced)
		{
		    as_bad (_("unbalanced parenthesis in operand %d."),
			    i.operands + 1);
		  return NULL;
		}
	      else
		break;	/* we are done */
	    }
	  else if (!is_operand_char (*l) && !is_space_char (*l) && *l != '"')
	    {
	      as_bad (_("invalid character %s in operand %d"),
		      output_invalid (*l),
		      i.operands + 1);
	      return NULL;
	    }
	    if (*l == '(')
		++paren_not_balanced;
            if (*l == ')')
		--paren_not_balanced;
	  l++;
	}
      if (l != token_start)
	{			/* Yes, we've read in another operand.  */
	  unsigned int operand_ok;
	  this_operand = i.operands++;
	  i.types[this_operand].bitfield.unspecified = 1;
	  if (i.operands > MAX_OPERANDS)
	    {
	      as_bad (_("spurious operands; (%d operands/instruction max)"),
		      MAX_OPERANDS);
	      return NULL;
	    }
	  /* Now parse operand adding info to 'i' as we go along.  */
	  END_STRING_AND_SAVE (l);

	  operand_ok = i386_att_operand (token_start);

	  RESTORE_END_STRING (l);
	  if (!operand_ok)
	    return NULL;
	}
      else
	{
	  if (expecting_operand)
	    {
	    expecting_operand_after_comma:
	      as_bad (_("expecting operand after ','; got nothing"));
	      return NULL;
	    }
	  if (*l == ',')
	    {
	      as_bad (_("expecting operand before ','; got nothing"));
	      return NULL;
	    }
	}

      /* Now *l must be either ',' or END_OF_INSN.  */
      if (*l == ',')
	{
	  if (*++l == END_OF_INSN)
	    {
	      /* Just skip it, if it's \n complain.  */
	      goto expecting_operand_after_comma;
	    }
	  expecting_operand = 1;
	}
    }
  return l;
}

static void
swap_2_operands (int xchg1, int xchg2)
{
  union i386_op temp_op;
  i386_operand_type temp_type;
  enum bfd_reloc_code_real temp_reloc;

  temp_type = i.types[xchg2];
  i.types[xchg2] = i.types[xchg1];
  i.types[xchg1] = temp_type;
  temp_op = i.op[xchg2];
  i.op[xchg2] = i.op[xchg1];
  i.op[xchg1] = temp_op;
  temp_reloc = i.reloc[xchg2];
  i.reloc[xchg2] = i.reloc[xchg1];
  i.reloc[xchg1] = temp_reloc;

}
/*
static void
swap_operands (void)
{
  switch (i.operands)
    {
    case 5:
    case 4:
      swap_2_operands (1, i.operands - 2);
    case 3:
    case 2:
      swap_2_operands (0, i.operands - 1);
      break;
    default:
      abort ();
    }

}
*/
/* Try to ensure constant immediates are represented in the smallest
   opcode possible.  */
/*static void
optimize_imm (void)
{
}*/

/* Try to use the smallest displacement type too.  */
/*static void
optimize_disp (void)
{

}*/


static int heptane_type_imm(i386_operand_type opt)
{
  return operand_type_check(opt,imm);
}

static int heptane_type_reg(i386_operand_type opt)
{
  return opt.bitfield.reg8 || opt.bitfield.reg16 ||
    opt.bitfield.reg32 || opt.bitfield.reg64;  
}

static int heptane_type_regImm(i386_operand_type opt)
{
  return heptane_type_imm(opt) || heptane_type_reg(opt);
}

/*static int heptane_type_regf(i386_operand_type opt)
{
  return opt.bitfield.regxmm || opt.bitfield.regymm;
}
*/
static const insn_template *
match_template (void)
{
  /* Points to template once we've found it.  */
  const insn_template *t;
  i386_operand_type overlap0, overlap1, overlap2, overlap3;
 // i386_operand_type overlap4;
 // unsigned int found_reverse_match;
 // i386_opcode_modifier suffix_check;//,t_suffix;
 // i386_operand_type operand_types [MAX_OPERANDS];
  //int addr_prefix_disp;
  //unsigned int j;
  //unsigned int found_cpu_match;
  //unsigned int check_register;
  enum i386_error specific_error = 0;

#if MAX_OPERANDS != 5
# error "MAX_OPERANDS must be 5."
#endif

  //found_reverse_match = 0;
  //addr_prefix_disp = -1;

  memset (&overlap0, 0, sizeof (overlap0));
  memset (&overlap1, 0, sizeof (overlap1));
  memset (&overlap2, 0, sizeof (overlap2));
  memset (&overlap3, 0, sizeof (overlap3));

  /* Must have right number of operands.  */
  i.error = number_of_operands_mismatch;

  for (t = current_templates->start; t < current_templates->end; t++)
    {
      //addr_prefix_disp = -1;

      i.error = number_of_operands_mismatch;

      switch (t->group) {
      case instrg_isBasicALU: case instrg_isBasicShift: case instrg_isIMulShort: 
      case instrg_isBigIMul: case  instrg_isBasicAddNoFl: case  instrg_isShiftNoFl: 
      case instrg_isFPU23Op: case instrg_isCmov:
	if (i.operands!=2 && i.operands!=3) continue;
	break;
      case instrg_isAddNoFlExtra:
	if (i.operands!=3) continue;
	break;
      case instrg_isBasicCmpTest: case instrg_isCmpTestExtra: case  instrg_isBaseLoadStore: 
        case instrg_isMov: case instrg_isExt: case instrg_isImmLoadStore: 
        case  instrg_isFPU2Op: case instrg_isBaseLoadStoreF: 
        case instrg_isBaseIndexLoadStoreF: case instrg_isImmLoadStoreF: 
        case instrg_mov_abs: case instrg_mov_xmm_i:
	if (i.operands!=2) continue;
	break;
      case instrg_isCSet: case  instrg_isImmSpecLoad: case  instrg_isBaseSpecLoad: 
      case  instrg_isBaseIndexSpecLoad:  
      case instrg_isCondJump: case instrg_isUncondJump: case  instrg_isIndirJump: 
      case  instrg_isCall: case instrg_push_pop:
	if (i.operands!=1) continue;
	break;
      case instrg_isRet:
        if (i.operands>1) continue;
        break;
      default:
	if (i.operands!=0) continue;
	break;
      }

      i.error = invalid_instruction_suffix;
      switch (t->group) {
      case   instrg_isFPU23Op: case  instrg_isFPU2Op:
	  //to do: handle suffix
	  break;
      default:
	if (i.suffix==BYTE_MNEM_SUFFIX && (t->size_offsets&0xff000000)==0xff000000) continue;
	else if (i.suffix==WORD_MNEM_SUFFIX && (t->size_offsets&0xff0000)==0xff0000) continue;
	else if (i.suffix==SHORT_MNEM_SUFFIX && (t->size_offsets&0xff0000)==0xff0000) continue;
	else if (i.suffix==LONG_MNEM_SUFFIX && (t->size_offsets&0xff00)==0xff00) continue;
	else if (i.suffix==QWORD_MNEM_SUFFIX && (t->size_offsets&0xff)==0xff) continue;
	else if (i.suffix==LONG_DOUBLE_MNEM_SUFFIX) continue;
	break;
        //default:
        break;
      }

      if (!operand_size_match (t))
	continue;

      if (!i.operands)
	    /* We've found a match; break out of loop.  */
	break;
      i.error=operand_type_mismatch;
      switch (t->group) {
      case instrg_isBasicALU: case instrg_isBasicShift: case instrg_isShiftNoFl:
	  if (i.operands==2) {
	      if (!heptane_type_regImm(i.types[0]) && !operand_type_check(i.types[0],anymem)) continue;  
	      if (!heptane_type_reg(i.types[1]) && !operand_type_check
	      (i.types[1],anymem)) continue;
	      if (operand_type_check(i.types[1],anymem) && operand_type_check(i.types[0],anymem)) continue;
	  } else {
	      if (!heptane_type_regImm(i.types[0]) && !operand_type_check(i.types[0],anymem)) continue;  
	      if (!heptane_type_reg(i.types[1])) continue;  
	      if (!heptane_type_reg(i.types[2])) continue;  
	  }
	  break;
      case instrg_isBasicAddNoFl:
	  if (i.operands==2) {
	      if (!heptane_type_regImm(i.types[0])) continue;  
	      if (!heptane_type_reg(i.types[1])) continue;  
	  } else {
	      if (!heptane_type_imm(i.types[0])) continue;  
	      if (!heptane_type_reg(i.types[1])) continue;  
	      if (!heptane_type_reg(i.types[2])) continue;  
	  }
	  break;
      case instrg_isAddNoFlExtra:
          if (!heptane_type_reg(i.types[0])) continue;  
	  if (!heptane_type_reg(i.types[1])) continue;  
	  if (!heptane_type_reg(i.types[2])) continue;  
	  break;
/*      case instrg_isBaseLoadStore:
	  if (i.types[0].bitfield.mem) {//load
	      if (!heptane_type_reg(i.types[1])) continue;
	      if (i.index_reg) continue;
	      if (!i.base_reg) continue;
	  } else {//store
	      if (~i.types[1].bitfield.mem)
		  continue;
	      if (!heptane_type_reg(i.types[0])) continue;  
	      if (i.index_reg) continue;
	      if (!i.base_reg) continue;
	  }
	  break;*/
/*      case instrg_isBaseIndexLoadStore:
	  if (i.types[0].bitfield.mem) {//load
	      if (!heptane_type_reg(i.types[1])) continue;  
	      if (!i.index_reg) continue;
	  } else {//store
	      if (~i.types[1].bitfield.mem)
		  continue;
	      if (!heptane_type_reg(i.types[0])) continue;  
	      if (!i.index_reg) continue;
	  }
	  break;*/
/*      case instrg_isImmLoadStore:
	  if (i.types[0].bitfield.mem) {//load
	      if (i.types[0].bitfield.baseindex)
	          continue;
	      if (!heptane_type_reg(i.types[1])) continue;
	  } else {
	      if (!i.types[1].bitfield.mem || i.types[1].bitfield.baseindex)
		  continue;
	      if (!heptane_type_reg(i.types[0])) continue;
	  }
	  break;*/
/*      case instrg_isBaseLoadStoreF:
	  if (i.types[0].bitfield.mem) {//load
	      if (!heptane_type_regf(i.types[1])) continue;  
	      if (i.index_reg) continue;
	      if (!i.base_reg) continue;
	  } else {//store
	      if (~i.types[1].bitfield.mem)
		  continue;
	      if (!heptane_type_regf(i.types[0])) continue;  
	      if (i.index_reg) continue;
	      if (!i.base_reg) continue;
	  }
	  break;*/
/*      case instrg_isBaseIndexLoadStoreF:
	  if (i.types[0].bitfield.mem) {//load
	      if (!heptane_type_regf(i.types[1])) continue;  
	      if (!i.index_reg) continue;
	  } else {//store
	      if (~i.types[1].bitfield.mem)
		  continue;
	      if (!heptane_type_regf(i.types[0])) continue;  
	      if (!i.index_reg) continue;
	  }
	  break;*/
/*      case instrg_isImmLoadStoreF:
	  if (i.types[0].bitfield.mem) {//load
	      if (i.types[0].bitfield.baseindex)
	          continue;
	      if (!heptane_type_regf(i.types[1])) continue;
	  } else {
	      if (!i.types[1].bitfield.mem || i.types[1].bitfield.baseindex)
		  continue;
	      if (!heptane_type_regf(i.types[0])) continue;
	  }
	  break;*/
      case instrg_isBasicCmpTest:
	  if (operand_type_check(i.types[0],anymem) && operand_type_check(
            i.types[1],anymem)) continue;
          if (operand_type_check(i.types[1],imm)) continue;
          break;
      case instrg_mov_abs:
          if (!heptane_type_reg(i.types[1])||!operand_type_check(i.types[0],imm))
            continue;
          break;
      case instrg_mov_xmm_i:
	  if (!i.types[0].bitfield.regxmm && !i.types[1].bitfield.regxmm) 
            continue;  
	  if (i.imm_operands) continue;
          break;
      case instrg_isMov:
	  if (!heptane_type_reg(i.types[0]) && !heptane_type_reg(i.types[1]) &&
            !operand_type_check(i.types[0],imm)) continue;
          if (operand_type_check(i.types[0],imm) && t->base_opcode!=183)
            continue;  
	  if (operand_type_check(i.types[1],imm)) continue;
          break;
      case instrg_isExt:
	  if (!(heptane_type_reg(i.types[0]) || heptane_type_reg(i.types[1]))) continue;  
          if (i.imm_operands) continue;
	  break;
      case instrg_push_pop:
          break;
      case  instrg_isRegImul: case instrg_isCmov:
	  if (!heptane_type_reg(i.types[0])) continue;  
	  if (!heptane_type_reg(i.types[1])) continue;  
	  if (i.operands==3 && !heptane_type_reg(i.types[2])) continue;  
	  break;
      case instrg_isIndirJump: case instrg_isCSet:
	  if (!heptane_type_reg(i.types[0])) continue;  
	  break;
      case instrg_isCondJump: case instrg_isCall: case instrg_isUncondJump:
	  if (!operand_type_check(i.types[0],disp))
	    continue;
          if (i.types[0].bitfield.baseindex) continue;
	  break;
      case instrg_isRet:
          if (i.operands && !operand_type_check(i.types[0],imm)) continue;
          break;
      case instrg_isBaseSpecLoad: case instrg_isBaseSpecLoadF:
	  if (~i.types[0].bitfield.mem || !i.base_reg || i.index_reg) continue;
	  break;
      case instrg_isBaseIndexSpecLoad: case instrg_isBaseIndexSpecLoadF:
	  if (~i.types[0].bitfield.mem || !i.base_reg || !i.index_reg) continue;
	  break;
      case instrg_isImmSpecLoad: case instrg_isImmSpecLoadF:
	  if (~i.types[0].bitfield.mem || i.types[0].bitfield.baseindex) 
              continue;
	  break;
      case instrg_isIMulShort: case instrg_isBigIMul:
	  if (!heptane_type_imm(i.types[0])) continue;
	  if (!heptane_type_reg(i.types[1])) continue;
	  if (i.operands==3 && !heptane_type_reg(i.types[2])) continue;
	  if (t->group==instrg_isBigIMul) break;
	  if (i.reloc[0]!=BFD_RELOC_NONE) continue;
	  if (i.op[0].imms->X_op!=O_constant) continue;
	  if (i.op[0].imms->X_add_number>2047 || 
            i.op[0].imms->X_add_number<-2048) continue;
	  break;
      default: continue;
      }




      /* Check if vector and VEX operands are valid.*/
//      if (check_VecOperands (t) || VEX_check_operan/ds (t))
//	{
//	  specific_error = i.error;
//	  continue;
//	}

      /* We've found a match; break out of loop.  */
      break;
    }

  if (t == current_templates->end)
    {
      /* We found no match.  */
      const char *err_msg;
      switch (specific_error ? specific_error : i.error)
	{
	default:
	  abort ();
	case operand_size_mismatch:
	  err_msg = _("operand size mismatch");
	  break;
	case operand_type_mismatch:
	  err_msg = _("operand type mismatch");
	  break;
	case register_type_mismatch:
	  err_msg = _("register type mismatch");
	  break;
	case number_of_operands_mismatch:
	  err_msg = _("number of operands mismatch");
	  break;
	case invalid_instruction_suffix:
	  err_msg = _("invalid instruction suffix");
	  break;
	case bad_imm4:
	  err_msg = _("constant doesn't fit in 4 bits");
	  break;
	case old_gcc_only:
	  err_msg = _("only supported with old gcc");
	  break;
	case unsupported_syntax:
	  err_msg = _("unsupported syntax");
	  break;
	case unsupported:
	  as_bad (_("unsupported instruction `%s'"),
		  current_templates->start->name);
	  return NULL;
	case invalid_register_operand:
	  err_msg = _("invalid register operand");
	  break;
	}
      as_bad (_("%s for `%s'"), err_msg,
	      current_templates->start->name);
      return NULL;
    }


  /* Copy the template we found.  */
  i.tm = *t;


  return t;
}



static int
finalize_imm (void)
{
  return 1;
}


/*
static void
output_branch (void)
{
  char *p;
  int size;
  int code16;
  int prefix;
  relax_substateT subtype;
  symbolS *sym;
  offsetT off;

  code16 = flag_code == CODE_16BIT ? CODE16 : 0;
  size = i.disp_encoding == disp_encoding_32bit ? BIG : SMALL;

  prefix = 0;
  if (i.prefix[DATA_PREFIX] != 0)
    {
      prefix = 1;
      i.prefixes -= 1;
      code16 ^= CODE16;
    }
  /,* Pentium4 branch hints.  *,/
  if (i.prefix[SEG_PREFIX] == CS_PREFIX_OPCODE /,* not taken *,/
      || i.prefix[SEG_PREFIX] == DS_PREFIX_OPCODE /,* taken *,/)
    {
      prefix++;
      i.prefixes--;
    }
  if (i.prefix[REX_PREFIX] != 0)
    {
      prefix++;
      i.prefixes--;
    }

  /,* BND prefixed jump.  *./
  if (i.prefix[BND_PREFIX] != 0)
    {
      FRAG_APPEND_1_CHAR (i.prefix[BND_PREFIX]);
      i.prefixes -= 1;
    }

  if (i.prefixes != 0 && !intel_syntax)
    as_warn (_("skipping prefixes on this instruction"));

  /,* It's always a symbol;  End frag & setup for relax.
     Make sure there is enough room in this frag for the largest
     instruction we may generate in md_convert_frag.  This is 2
     bytes for the opcode and room for the prefix and largest
     displacement.  *./
  frag_grow (prefix + 2 + 4);
  /,* Prefix and 1 opcode byte go in fr_fix.  *./
  p = frag_more (prefix + 1);
  if (i.prefix[DATA_PREFIX] != 0)
    *p++ = DATA_PREFIX_OPCODE;
  if (i.prefix[SEG_PREFIX] == CS_PREFIX_OPCODE
      || i.prefix[SEG_PREFIX] == DS_PREFIX_OPCODE)
    *p++ = i.prefix[SEG_PREFIX];
  if (i.prefix[REX_PREFIX] != 0)
    *p++ = i.prefix[REX_PREFIX];
  *p = i.tm.base_opcode;

  if ((unsigned char) *p == JUMP_PC_RELATIVE)
    subtype = ENCODE_RELAX_STATE (UNCOND_JUMP, size);
  else if (cpu_arch_flags.bitfield.cpui386)
    subtype = ENCODE_RELAX_STATE (COND_JUMP, size);
  else
    subtype = ENCODE_RELAX_STATE (COND_JUMP86, size);
  subtype |= code16;

  sym = i.op[0].disps->X_add_symbol;
  off = i.op[0].disps->X_add_number;

  if (i.op[0].disps->X_op != O_constant
      && i.op[0].disps->X_op != O_symbol)
    {
      /,* Handle complex expressions.  *./
      sym = make_expr_symbol (i.op[0].disps);
      off = 0;
    }

  /,* 1 possible extra opcode + 4 byte displacement go in var part.
     Pass reloc in fr_var.  *./
  frag_var (rs_machine_dependent, 5, i.reloc[0], subtype, sym, off, p);
}
*/

/*
static void
output_jump (void)
{
  char *p;
  int size;
  fixS *fixP;

  if (i.tm.opcode_modifier.jumpbyte)
    {
      /,* This is a loop or jecxz type instruction.  *./
      size = 1;
      if (i.prefix[ADDR_PREFIX] != 0)
	{
	  FRAG_APPEND_1_CHAR (ADDR_PREFIX_OPCODE);
	  i.prefixes -= 1;
	}
      /,* Pentium4 branch hints.  *./
      if (i.prefix[SEG_PREFIX] == CS_PREFIX_OPCODE /,* not taken *./
	  || i.prefix[SEG_PREFIX] == DS_PREFIX_OPCODE /,* taken *./)
	{
	  FRAG_APPEND_1_CHAR (i.prefix[SEG_PREFIX]);
	  i.prefixes--;
	}
    }
  else
    {
      int code16;

      code16 = 0;
      if (flag_code == CODE_16BIT)
	code16 = CODE16;

      if (i.prefix[DATA_PREFIX] != 0)
	{
	  FRAG_APPEND_1_CHAR (DATA_PREFIX_OPCODE);
	  i.prefixes -= 1;
	  code16 ^= CODE16;
	}

      size = 4;
      if (code16)
	size = 2;
    }

  if (i.prefix[REX_PREFIX] != 0)
    {
      FRAG_APPEND_1_CHAR (i.prefix[REX_PREFIX]);
      i.prefixes -= 1;
    }

  /,* BND prefixed jump.  *./
  if (i.prefix[BND_PREFIX] != 0)
    {
      FRAG_APPEND_1_CHAR (i.prefix[BND_PREFIX]);
      i.prefixes -= 1;
    }

  if (i.prefixes != 0 && !intel_syntax)
    as_warn (_("skipping prefixes on this instruction"));

  p = frag_more (i.tm.opcode_length + size);
  switch (i.tm.opcode_length)
    {
    case 2:
      *p++ = i.tm.base_opcode >> 8;
    case 1:
      *p++ = i.tm.base_opcode;
      break;
    default:
      abort ();
    }

  fixP = fix_new_exp (frag_now, p - frag_now->fr_literal, size,
		      i.op[0].disps, 1, reloc (size, 1, 1, i.reloc[0]));

  /,* All jumps handled here are signed, but don't use a signed limit
     check for 32 and 16 bit jumps as we want to allow wrap around at
     4G and 64k respectively.  *./
  if (size == 1)
    fixP->fx_signed = 1;
}

*/

void heptane_label(void) {
  return;
}

static void output_load_store_32(int rA,int rB,int off,char suffix,int st) {
  unsigned char code[10];
  int code_s;
  if (suffix=='b') code_s=3; //byte zx
  if (suffix=='w') code_s=2; //word zx
  if (suffix=='l') code_s=1; //32 bit
  if (suffix=='q') code_s=0; //64 bit
  code[0]=0x60+(code_s<<1)+st;
  code[1]=(rB&0xf)|((rA&0xf)<<4);
  code[2]=((rA&0x10)>>4)|((rB&0x10)>>3);
  code[2]|=(off&0x3f)<<2;
  code[3]=(off&0x3fc0)>>6;
  FRAG_APPEND_1_CHAR(code[0]);
  FRAG_APPEND_1_CHAR(code[1]);
  FRAG_APPEND_1_CHAR(code[2]);
  FRAG_APPEND_1_CHAR(code[3]);
  frag_var (rs_machine_dependent, 30, NO_RELOC, 
     ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
  return;
}

static void output_spec_load_fpu(int codeF) {

	//not yet done; copied from int
  unsigned char code[10]={0,0,0,0,0,0,0,0,0,0};
  int subcode=0,store,memop,disp_var;
  switch(i.suffix) {
  case 'q':subcode=3; break;
  case 'l':subcode=2; break;
  case 'w':subcode=1; break;
  case 'b':subcode=0; break;
  }
  if (i.index_reg) goto do_index;
  if (i.base_reg && i.base_reg->reg_num!=255) goto do_base;
  store=operand_type_check(i.types[1],anymem);
  memop=store;
  code[0]=0xb0;
  code[1]=subcode | ((i.base_reg!=0)<<3) |0x60;//no imm load to rsp
  FRAG_APPEND_1_CHAR(code[0]);
  FRAG_APPEND_1_CHAR(code[1]);
  output_disp(frag_now,2);
  frag_var (rs_machine_dependent, 30, i.reloc[memop], 
    ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
  return;
  do_base:
    store=operand_type_check(i.types[1],anymem);
    memop=store;
    disp_var=operand_type_check(i.types[memop],disp); 
    code[0]=176;
    code[1]=subcode;
    if (!disp_var || (i.op[memop].disps->X_op==O_constant && i.op[memop].disps->X_add_number>=-8192
        && i.op[memop].disps->X_add_number<=8191)) {
        if (disp_var) disp_var=i.op[memop].disps->X_add_number;
	code[1]|=(i.base_reg->reg_num&0xf)<<4;
	code[2]=((i.base_reg->reg_num&0x10)>>4);
	code[3]=(disp_var&0x3f)<<2;
	code[4]=(disp_var&0x3fc0)>>6;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        FRAG_APPEND_1_CHAR(code[2]);
        FRAG_APPEND_1_CHAR(code[3]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
    } else if (!(i.base_reg->reg_num&0x10)) {
        if (disp_var) disp_var=i.op[memop].disps->X_add_number;
	code[1]|=(i.base_reg->reg_num&0xf)<<4;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        output_disp(frag_now,2);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
    } else {
        code[1]|=i.base_reg->reg_num<<4;
	code[6]=(i.base_reg->reg_num &0x1)<<6;
	code[7]=0x2;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        output_disp(frag_now,2);
        FRAG_APPEND_1_CHAR(code[6]);
        FRAG_APPEND_1_CHAR(code[7]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIGGER), NULL, 0, NULL);
    }
    return;
  do_index:
    store=operand_type_check(i.types[1],anymem);
    memop=store;
    disp_var=operand_type_check(i.types[memop],disp); 
    code[0]=177;
    code[1]=subcode;
    if (!disp_var || (i.op[memop].disps->X_op==O_constant  && 
      i.op[memop].disps->X_add_number>=-64 && 
      i.op[memop].disps->X_add_number<=63 && !(i.index_reg->reg_num&0x10)
      && (!i.base_reg || !(i.base_reg->reg_num&0x10)))) { 
        if (disp_var) disp_var=i.op[memop].disps->X_add_number;
	if (i.base_reg) {
	  code[1]|=i.base_reg->reg_num<<4;
	} else {
	  code[1]|=0x50;
	}
	code[2]=i.index_reg->reg_num | ((i.log2_scale_factor&0x3)<<5);
        code[2]|=((disp_var&0x1)<<7);
	code[3]=(disp_var&0xfe)>>1;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        FRAG_APPEND_1_CHAR(code[2]);
        FRAG_APPEND_1_CHAR(code[3]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
      } else if (i.op[memop].disps->X_op==O_constant && i.op[memop].disps->X_add_number>=-4096*1024
        && i.op[memop].disps->X_add_number<4096*1024) {
        disp_var=i.op[memop].disps->X_add_number;
	if (i.base_reg) {
	  code[1]|=i.base_reg->reg_num<<4;
	  code[2]=i.base_reg->reg_num &0x1;
	} else {
	  code[1]|=0x50;
	}
	code[2]|=((i.index_reg->reg_num&0x1f)<<1) | ((i.log2_scale_factor&0x1)<<7);
	code[3]=((i.log2_scale_factor&0x2)>>1) | ((disp_var&0x7f)<<1);
	code[4]=(disp_var&0x7f80)>>7;
	code[5]=(disp_var&0x7f8000)>>15;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        FRAG_APPEND_1_CHAR(code[2]);
        FRAG_APPEND_1_CHAR(code[3]);
        FRAG_APPEND_1_CHAR(code[4]);
        FRAG_APPEND_1_CHAR(code[5]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
    } else {
	if (i.base_reg) {
	  code[1]|=i.base_reg->reg_num<<4;
	  code[6]=(i.base_reg->reg_num &0x1)<<6;
	} else {
	  code[1]|=0x50;
	}
	code[6]|=(i.index_reg->reg_num&0xf) |((i.index_reg->reg_num&0x10)<<3);
	code[6]|=i.log2_scale_factor<<4;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        output_disp(frag_now,2);
        FRAG_APPEND_1_CHAR(code[6]);
        FRAG_APPEND_1_CHAR(code[7]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIGGER), NULL, 0, NULL);
    }
    return;
}


static void output_spec_load(void) {
  unsigned char code[10]={0,0,0,0,0,0,0,0,0,0};
  int subcode=0,store,memop,disp_var;
  switch(i.suffix) {
  case 'q':subcode=3; break;
  case 'l':subcode=2; break;
  case 'w':subcode=1; break;
  case 'b':subcode=0; break;
  }
  if (i.index_reg) goto do_index;
  if (i.base_reg && i.base_reg->reg_num!=255) goto do_base;
  store=operand_type_check(i.types[1],anymem);
  memop=store;
  code[0]=0xb0;
  code[1]=subcode | 0x8;//no imm load to rsp
  FRAG_APPEND_1_CHAR(code[0]);
  FRAG_APPEND_1_CHAR(code[1]);
  output_disp(frag_now,2);
  frag_var (rs_machine_dependent, 30, i.reloc[memop], 
    ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
  return;
  do_base:
    store=operand_type_check(i.types[1],anymem);
    memop=store;
    disp_var=operand_type_check(i.types[memop],disp); 
    code[0]=176;
    code[1]=subcode;
    if (!disp_var || (i.op[memop].disps->X_op==O_constant && i.op[memop].disps->X_add_number>=-8192
        && i.op[memop].disps->X_add_number<=8191)) {
        if (disp_var) disp_var=i.op[memop].disps->X_add_number;
	code[1]|=(i.base_reg->reg_num&0xf)<<4;
	code[2]=((i.base_reg->reg_num&0x10)>>4);
	code[3]=(disp_var&0x3f)<<2;
	code[4]=(disp_var&0x3fc0)>>6;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        FRAG_APPEND_1_CHAR(code[2]);
        FRAG_APPEND_1_CHAR(code[3]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
    } else if (!(i.base_reg->reg_num&0x10)) {
        if (disp_var) disp_var=i.op[memop].disps->X_add_number;
	code[1]|=(i.base_reg->reg_num&0xf)<<4;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        output_disp(frag_now,2);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
    } else {
        code[1]|=i.base_reg->reg_num<<4;
	code[6]=(i.base_reg->reg_num &0x1)<<6;
	code[7]=0x2;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        output_disp(frag_now,2);
        FRAG_APPEND_1_CHAR(code[6]);
        FRAG_APPEND_1_CHAR(code[7]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIGGER), NULL, 0, NULL);
    }
    return;
  do_index:
    store=operand_type_check(i.types[1],anymem);
    memop=store;
    disp_var=operand_type_check(i.types[memop],disp); 
    code[0]=177;
    code[1]=subcode;
    if (!disp_var || (i.op[memop].disps->X_op==O_constant  && 
      i.op[memop].disps->X_add_number>=-64 && 
      i.op[memop].disps->X_add_number<=63 && !(i.index_reg->reg_num&0x10)
      && (!i.base_reg || !(i.base_reg->reg_num&0x10)))) { 
        if (disp_var) disp_var=i.op[memop].disps->X_add_number;
	if (i.base_reg) {
	  code[1]|=i.base_reg->reg_num<<4;
	} else {
	  code[1]|=0x50;
	}
	code[2]=i.index_reg->reg_num | ((i.log2_scale_factor&0x3)<<5);
        code[2]|=((disp_var&0x1)<<7);
	code[3]=(disp_var&0xfe)>>1;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        FRAG_APPEND_1_CHAR(code[2]);
        FRAG_APPEND_1_CHAR(code[3]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
      } else if (i.op[memop].disps->X_op==O_constant && i.op[memop].disps->X_add_number>=-4096*1024
        && i.op[memop].disps->X_add_number<4096*1024) {
        disp_var=i.op[memop].disps->X_add_number;
	if (i.base_reg) {
	  code[1]|=i.base_reg->reg_num<<4;
	  code[2]=i.base_reg->reg_num &0x1;
	} else {
	  code[1]|=0x50;
	}
	code[2]|=((i.index_reg->reg_num&0x1f)<<1) | ((i.log2_scale_factor&0x1)<<7);
	code[3]=((i.log2_scale_factor&0x2)>>1) | ((disp_var&0x7f)<<1);
	code[4]=(disp_var&0x7f80)>>7;
	code[5]=(disp_var&0x7f8000)>>15;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        FRAG_APPEND_1_CHAR(code[2]);
        FRAG_APPEND_1_CHAR(code[3]);
        FRAG_APPEND_1_CHAR(code[4]);
        FRAG_APPEND_1_CHAR(code[5]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
    } else {
	if (i.base_reg) {
	  code[1]|=i.base_reg->reg_num<<4;
	  code[6]=(i.base_reg->reg_num &0x1)<<6;
	} else {
	  code[1]|=0x50;
	}
	code[6]|=(i.index_reg->reg_num&0xf) |((i.index_reg->reg_num&0x10)<<3);
	code[6]|=i.log2_scale_factor<<4;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        output_disp(frag_now,2);
        FRAG_APPEND_1_CHAR(code[6]);
        FRAG_APPEND_1_CHAR(code[7]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIGGER), NULL, 0, NULL);
    }
    return;
}

static void output_link(int regno,int skip) {
  unsigned char code[10];
  code[0]=0xd8;
  code[1]=(regno &0xf) | ((skip & 0xf)<<4);
  FRAG_APPEND_1_CHAR(code[0]);      
  FRAG_APPEND_1_CHAR(code[1]);      
  frag_var (rs_machine_dependent, 30, NO_RELOC, 
     ENCODE_RELAX_STATE(NON_JUMP,SMALL), NULL, 0, NULL);
  return;
}

static void output_stack_add(int c) {
  unsigned char code[10];
  code[0]=1;
  code[1]=0x44;
  code[2]=(c&0x3f)<<2;
  code[3]=((c&0x1fc0)>>6) | 0x80;
  FRAG_APPEND_1_CHAR(code[0]);      
  FRAG_APPEND_1_CHAR(code[1]);      
  FRAG_APPEND_1_CHAR(code[2]);      
  FRAG_APPEND_1_CHAR(code[3]);      
  frag_var (rs_machine_dependent, 30, NO_RELOC, 
     ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
}

static void output_double3(void) {
  unsigned char code[10];
  int rA,rB,rT;
  if (!i.mem_operands) {
    if (i.operands==2) {
      rA=1;
      rT=1;
      rB=0;
    } else {
      rT=2;
      rA=1;
      rB=0;
    }
    if (i.op[rT].regs->reg_num==i.op[rA].regs->reg_num && 
      (i.op[rT].regs->reg_num&0x10) && i.tm.base_opcode) { //16 bit enc
      if (i.tm.base_opcode<=57) {
	code[0]=i.tm.base_opcode+(i.tm.size_offsets!=0)+((i.op[rB].regs->
	reg_num&0x10)<<3);
	code[1]=i.op[rA].regs->reg_num | ((i.op[rB].regs->reg_num&0xf)<<4);
      } else {
	//packed
	if (i.tm.size_offsets==3 && i.tm.name[0]!='m') goto bits_32;
	code[0]=i.tm.base_opcode + i.tm.size_offsets&0x1 + ((i.tm.size_offsets
	&0x2)<<5) + ((i.op[rB].regs->reg_num&0x10)<<3);
	code[1]=i.op[rA].regs->reg_num | ((i.op[rB].regs->reg_num&0xf)<<4);
      }
      FRAG_APPEND_1_CHAR(code[0]);      
      FRAG_APPEND_1_CHAR(code[1]);      
      frag_var (rs_machine_dependent, 30, NO_RELOC, 
         ENCODE_RELAX_STATE(NON_JUMP,SMALL), NULL, 0, NULL);
      return;
    } else {
      bits_32:
      code[0]=0xef;
      code[1]=i.tm.extension_opcode|((i.tm.size_offsets&0x3)<<14);
      code[2]=((i.tm.size_offsets&0x04)>>2) | (i.op[rA].regs->reg_num<<1) |
	      ( (i.op[rB].regs->reg_num&0x3)<<14);
      code[3]=((i.op[rB].regs->reg_num&0x1c)>>2) | (i.op[rT].regs->reg_num<<3);
      FRAG_APPEND_1_CHAR(code[0]);      
      FRAG_APPEND_1_CHAR(code[1]);      
      FRAG_APPEND_1_CHAR(code[2]);      
      FRAG_APPEND_1_CHAR(code[3]);      
      frag_var (rs_machine_dependent, 30, NO_RELOC, 
         ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
      return;
    }
  } else {
  }
}
static void output_xmm_mov(int is_fp) {
  unsigned char code[10];
  int memop=operand_type_check(i.types[1],anymem);
  valueT displ=0;
  int basel;
  if (i.mem_operands) {
    if (memop && !i.tm.extension_opcode) as_bad(_("Illegal Instruction."));
    if ((!memop) && !i.tm.base_opcode) as_bad(_("Illegal Instruction."));
    if (i.index_reg) goto mem_index;
    if (!i.base_reg) goto mem_disponly;
    if (i.base_reg->reg_num==255) goto mem_disponly;
    if ((i.op[memop].disps->X_op==O_constant && i.op[memop].disps->X_add_number
      >=-8192 && i.op[memop].disps->X_add_number<=8191)||
      !operand_type_check(i.types[memop],disp)) {
      if (operand_type_check(i.types[memop],disp)) displ=i.op[memop].disps->
        X_add_number; 
      code[0]=memop ? i.tm.extension_opcode|memop : i.tm.base_opcode;
      code[1]=(i.base_reg->reg_num&0xf) | ((i.op[!memop].regs->reg_num&0xf)<<4);
      code[2]=((i.base_reg->reg_num&0x10)>>3) | 
        ((i.op[!memop].regs->reg_num&0x10)>>4);
      code[2]|=(displ&0x3f)<<2;
      code[3]=(displ&0x3fc0)>>6;
      FRAG_APPEND_1_CHAR(code[0]);      
      FRAG_APPEND_1_CHAR(code[1]);      
      FRAG_APPEND_1_CHAR(code[2]);      
      FRAG_APPEND_1_CHAR(code[3]);      
      frag_var (rs_machine_dependent, 30, i.reloc[memop], 
         ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
      return;

    } else if (!(i.base_reg->reg_num&0x10) && !(i.op[!memop].regs->reg_num&0x10)
      ) {
      code[0]=memop ? i.tm.extension_opcode|memop : i.tm.base_opcode;
      code[1]=(i.op[!memop].regs->reg_num&0xf) | ((i.base_reg->reg_num&0xf)<<4);
      FRAG_APPEND_1_CHAR(code[0]);      
      FRAG_APPEND_1_CHAR(code[1]);      
      output_disp(frag_now,2); 
      frag_var (rs_machine_dependent, 30, i.reloc[memop], 
         ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
      return;
    } else {
      code[0]=memop ? i.tm.extension_opcode|memop : i.tm.base_opcode;
      code[0]=code[0]+0x40;
      code[1]=(i.op[!memop].regs->reg_num&0xf)|((i.base_reg->reg_num&0xf)<<4);
      code[6]=((i.op[!memop].regs->reg_num&0x10)<<2)|
        ((i.base_reg->reg_num&0x10)<<3);
      code[7]=0x02;
      FRAG_APPEND_1_CHAR(code[0]);      
      FRAG_APPEND_1_CHAR(code[1]);      
      output_disp(frag_now,2); 
      FRAG_APPEND_1_CHAR(code[6]);      
      FRAG_APPEND_1_CHAR(code[7]);      
      frag_var (rs_machine_dependent, 30, i.reloc[memop], 
         ENCODE_RELAX_STATE(NON_JUMP,BIGGER), NULL, 0, NULL);
      return;

    }
    mem_disponly:
    if (i.op[memop].disps->X_op==O_constant && i.op[memop].disps->X_add_number
      >=-8192 && i.op[memop].disps->X_add_number<=8191 && i.base_reg) {
      if (operand_type_check(i.types[memop],disp)) displ=i.op[memop].disps->
        X_add_number; 
      code[0]=60 | memop | ((i.base_reg!=NULL)<<1);
      code[1]=(((memop ? i.tm.extension_opcode : i.tm.base_opcode)&0x1e)>>1) | 
        ((i.op[!memop].regs->reg_num&0xf)<<4);
      code[2]=((i.op[!memop].regs->reg_num&0x10)>>4) | ((displ & 0x3f)<<2);
      code[3]=(displ & 0x3fc0)>>6; 
      FRAG_APPEND_1_CHAR(code[0]);      
      FRAG_APPEND_1_CHAR(code[1]);      
      FRAG_APPEND_1_CHAR(code[2]);      
      FRAG_APPEND_1_CHAR(code[3]);      
      frag_var (rs_machine_dependent, 30, i.reloc[memop], 
         ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
      return;
    } else if (!(i.op[!memop].regs->reg_num & 0x10)) {
      if (operand_type_check(i.types[memop],disp)) displ=i.op[memop].disps->
        X_add_number; 
      code[0]=60 | memop | ((i.base_reg!=NULL)<<1);
      code[1]=(((memop ? i.tm.extension_opcode : i.tm.base_opcode)&0x1e)>>1) | 
        ((i.op[!memop].regs->reg_num&0xf)<<4);
      FRAG_APPEND_1_CHAR(code[0]);      
      FRAG_APPEND_1_CHAR(code[1]);      
      output_disp(frag_now,2); 
      frag_var (rs_machine_dependent, 30, i.reloc[memop], 
         ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
      return;
    } else {
      code[0]=memop ? i.tm.extension_opcode|memop : i.tm.base_opcode;
      code[0]=code[0]+0x40;
      code[1]=(i.op[!memop].regs->reg_num&0xf);
      code[6]=((i.op[!memop].regs->reg_num&0x10)<<2);
      code[7]=0x04 | ((i.base_reg!=NULL)<<3);
      FRAG_APPEND_1_CHAR(code[0]);      
      FRAG_APPEND_1_CHAR(code[1]);      
      output_disp(frag_now,2); 
      FRAG_APPEND_1_CHAR(code[6]);      
      FRAG_APPEND_1_CHAR(code[7]);      
      frag_var (rs_machine_dependent, 30, i.reloc[memop], 
         ENCODE_RELAX_STATE(NON_JUMP,BIGGER), NULL, 0, NULL);
      return;
    }
    mem_index:
    if ((i.op[memop].disps->X_op==O_constant && i.op[memop].disps->X_add_number
      >=-64 && i.op[memop].disps->X_add_number<=63 && !(i.index_reg->reg_num
      &0x10) && (!i.base_reg||!(i.base_reg->reg_num&0x10)))||
      !operand_type_check(i.types[memop],disp)) {
      if (operand_type_check(i.types[memop],disp)) displ=i.op[memop].disps->
        X_add_number; 
      code[0]=memop ? i.tm.extension_opcode|memop : i.tm.base_opcode;
      code[0]=code[0]+0x40;
      
      if (i.base_reg) basel=i.base_reg->reg_num;
      else basel=5;
      code[1]=(i.op[!memop].regs->reg_num&0xf) | ((basel&0xf)<<4);
      code[2]=(i.index_reg->reg_num&0xf)|(i.op[!memop].regs->reg_num&0x10);
      code[2]|=((i.log2_scale_factor&0x3)<<5)|((displ&0x1)<<7);
      code[3]=((displ&0xfe)>>1);
      FRAG_APPEND_1_CHAR(code[0]);      
      FRAG_APPEND_1_CHAR(code[1]);      
      FRAG_APPEND_1_CHAR(code[2]);      
      FRAG_APPEND_1_CHAR(code[3]);      
      frag_var (rs_machine_dependent, 30, i.reloc[memop], 
         ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
      return;

    } else if (i.op[memop].disps->X_op==O_constant && i.op[memop].disps->
      X_add_number>=-8*1024*1024 && i.op[memop].disps->X_add_number<
      8*1024*1024) {
      if (operand_type_check(i.types[memop],disp)) displ=i.op[memop].disps->
        X_add_number; 
      code[0]=memop ? i.tm.extension_opcode|memop : i.tm.base_opcode;
      code[0]=code[0]+0x40;
      
      if (i.base_reg) basel=i.base_reg->reg_num;
      else basel=5;
      code[1]=(i.op[!memop].regs->reg_num&0xf) | ((basel&0xf)<<4);
      code[2]=(i.index_reg->reg_num&0xf)|(i.op[!memop].regs->reg_num&0x10)|
        ((basel&0x10)<<1)|((i.index_reg->reg_num&0x10)<<2);
      code[2]|=((i.log2_scale_factor&0x1)<<7);
      code[3]=((i.log2_scale_factor&0x2)>>1) | ((displ&0x7f)<<1);
      code[4]=(displ&0x7f80)>>7;      
      code[5]=(displ&0x7f8000)>>15;      
      FRAG_APPEND_1_CHAR(code[0]);      
      FRAG_APPEND_1_CHAR(code[1]);      
      FRAG_APPEND_1_CHAR(code[2]);      
      FRAG_APPEND_1_CHAR(code[3]);      
      FRAG_APPEND_1_CHAR(code[4]);      
      FRAG_APPEND_1_CHAR(code[5]);      
      frag_var (rs_machine_dependent, 30, i.reloc[memop], 
         ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
      return;
    } else {
      if (operand_type_check(i.types[memop],disp)) displ=i.op[memop].disps->
        X_add_number; 
      code[0]=memop ? i.tm.extension_opcode|memop : i.tm.base_opcode;
      code[0]=code[0]+0x40;
      
      if (i.base_reg) basel=i.base_reg->reg_num;
      else basel=5;
      code[1]=(i.op[!memop].regs->reg_num&0xf) | ((basel&0xf)<<4);
      code[6]=(i.index_reg->reg_num&0xf)|((i.op[!memop].regs->reg_num&0x10)<<2)|
        ((basel&0x10)<<3) | ((i.log2_scale_factor&0x3)<<4);
      code[7]=(i.index_reg->reg_num&0x10)>>4;
      FRAG_APPEND_1_CHAR(code[0]);      
      FRAG_APPEND_1_CHAR(code[1]);      
      output_disp(frag_now,2); 
      FRAG_APPEND_1_CHAR(code[6]);      
      FRAG_APPEND_1_CHAR(code[7]);      
      frag_var (rs_machine_dependent, 30, i.reloc[memop], 
         ENCODE_RELAX_STATE(NON_JUMP,BIGGER), NULL, 0, NULL);
      return;
    }
      
  } else { //non-mem
    if (is_fp) goto do_fpu;
    code[0]=200;
    code[1]=3;
    code[2]=0x1|((i.op[0].regs->reg_num&0x3)<<6);
    code[3]=((i.op[0].regs->reg_num&0x1c)>>2)|((i.op[1].regs->reg_num&0x1f)<<3);
    FRAG_APPEND_1_CHAR(code[0]);      
    FRAG_APPEND_1_CHAR(code[1]);      
    FRAG_APPEND_1_CHAR(code[2]);      
    FRAG_APPEND_1_CHAR(code[3]);      
    frag_var (rs_machine_dependent, 30, i.reloc[memop], 
       ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
    return;
 

    do_fpu:
    as_bad(_("fpu mov not implemented yet."));
    return;
  }
}
static void output_push_pop(void) {
  unsigned char code[10];
  int store=i.tm.extension_opcode;
  int rA=16;
  int sz;
  switch(i.suffix) {
  case 'q': sz=8; break;
  case 'l': sz=4; break;
  case 'w': sz=2; break;
  case 'b': sz=1; break;
  default: sz=8; break;
  }
  if (store) output_stack_add(-sz);
  if ((i.mem_operands||i.imm_operands) && !store) 
    as_bad(_("Illegal pop operand\n"));
  if (i.mem_operands) output_spec_load();
  if (i.imm_operands) {
    valueT disp_var;
    if (i.op[0].imms->X_op==O_constant && i.op[0].imms->X_add_number>=1 && 
      i.op[0].imms->X_add_number<=32 && (i.suffix=='l' || i.suffix=='q')) {
      code[0]=0x29;
      code[0]|=(0x10)<<3;
      code[0]|=(i.op[0].imms->X_add_number&0x10)<<2;
      code[1]=(i.op[0].imms->X_add_number&0xf);  
      FRAG_APPEND_1_CHAR(code[0]);      
      FRAG_APPEND_1_CHAR(code[1]);      
      frag_var (rs_machine_dependent, 30, i.reloc[0], 
         ENCODE_RELAX_STATE(NON_JUMP,SMALL), NULL, 0, NULL);
   //   return;

    } else if (i.op[0].imms->X_op==O_constant && 
      i.op[0].imms->X_add_number>=-4096 && i.op[0].imms->X_add_number<=4095) {
        switch(i.suffix) {
    case 'q' : code[0]=183; break;
    case 'l' : code[0]=184; break;
    case 'w' : code[0]=188; break;
    case 'b' : code[0]=187; break;
    default: code[0]=0; break;
        }
        code[1]=0;
        code[2]=(0x10)>>3;
        disp_var=i.op[0].imms->X_add_number;
        code[2]|=(disp_var &0x3f)<<2;
        code[3]=(disp_var &0x1fc0)>>6;
        code[3]|=0x80;     
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        FRAG_APPEND_1_CHAR(code[2]);
        FRAG_APPEND_1_CHAR(code[3]);
        
        frag_var (rs_machine_dependent, 30, i.reloc[0], 
          ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
      //  return;
    } else {
        switch(i.suffix) {
    case 'q' : code[0]=183; break;
    case 'l' : code[0]=184; break;
    case 'w' : code[0]=188; break;
    case 'b' : code[0]=187; break;
    default: code[0]=0; break;
        }
        code[1]=0x10>>3;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        output_imm(frag_now,2);
        frag_var (rs_machine_dependent, 30, i.reloc[0], 
          ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
      //  return;
    }
    
  }
  if (operand_type_check(i.types[0],reg)) rA=i.op[0].regs->reg_num;
  if (store) output_load_store_32(rA,4,0,i.suffix,1);
  else output_load_store_32(rA,4,0,i.suffix,0);
  if (!store) output_stack_add(sz);
  return;
}
static void output_call(void) {
  unsigned char code[10];
  output_stack_add(-8);
  output_link(REGXTRA0,1);
  code[0]=182;
  code[1]=(REGXTRA0 & 0x1f) | 0x40;
  FRAG_APPEND_1_CHAR(code[0]);      
  FRAG_APPEND_1_CHAR(code[1]);      
  output_disp(frag_now,2);
  frag_var (rs_machine_dependent, 30, i.reloc[0], 
     ENCODE_RELAX_STATE(UNREL_JUMP,BIG), i.op[0].disps->X_add_symbol, 0, NULL);
  return;
}

static void output_ret(void) {
  unsigned char code[10];
  int cnt=0;
  if (i.imm_operands) cnt=i.op[0].imms->X_add_number;
  output_load_store_32(REGXTRA0,4,0,'q',0);
  output_stack_add(8+8*cnt);
  code[0]=182;
  code[1]=0xe | (REGXTRA0&0x1f);
  code[2]=0;
  code[3]=0;
  FRAG_APPEND_1_CHAR(code[0]);      
  FRAG_APPEND_1_CHAR(code[1]);      
  FRAG_APPEND_1_CHAR(code[2]);      
  FRAG_APPEND_1_CHAR(code[3]);      
  frag_var (rs_machine_dependent, 30, NO_RELOC, 
     ENCODE_RELAX_STATE(UNREL_JUMP,MED), NULL , 0, NULL);
  return;
}

static void output_uc_jump(void) {
  unsigned char code[10];
  code[0]=181;
  code[1]=code[2]=code[3]=0;
  FRAG_APPEND_1_CHAR(code[0]);
  FRAG_APPEND_1_CHAR(code[1]);
//  FRAG_APPEND_1_CHAR(code[2]);
//  FRAG_APPEND_1_CHAR(code[3]);
        
  frag_var (rs_machine_dependent, 30, i.reloc[0], 
      ENCODE_RELAX_STATE(UNCOND_JUMP,SMALL),i.op[0].disps->X_add_symbol,0,NULL);
  return;
}

static void output_cond_jump(void) {
  unsigned char code[10];
  code[0]=180;
  code[1]=i.tm.extension_opcode&0xf;
  code[2]=0;
  code[3]=0;
  if ((i.tm.extension_opcode&0xf)!=0xf) {
    FRAG_APPEND_1_CHAR(code[0]);      
    FRAG_APPEND_1_CHAR(code[1]);      
    frag_var (rs_machine_dependent, 30, i.reloc[0], 
       ENCODE_RELAX_STATE(COND_JUMP,SMALL), i.op[0].disps->X_add_symbol, 0, NULL);
    return;
  } else {
    FRAG_APPEND_1_CHAR(code[0]);      
    FRAG_APPEND_1_CHAR(code[1]);      
    FRAG_APPEND_1_CHAR(code[2]);      
    FRAG_APPEND_1_CHAR(code[3]);      
    frag_var (rs_machine_dependent, 30, i.reloc[0], 
       ENCODE_RELAX_STATE(COND_JUMP,MED), i.op[0].disps->X_add_symbol, 0, NULL);
  }
}

static void output_cmp_test(void) {
  unsigned char code[10];
  int /*memop=0,*/rA,rB,hasmem=0;
  if ((i.suffix=='l' || i.suffix=='q') && (i.tm.name[0]=='c' || 
    !i.imm_operands)) {
    switch(i.tm.base_opcode) {
  case 46:
      code[0]=42+i.imm_operands!=0;
      break;
  case 47:
      code[0]=44+i.imm_operands!=0;
      break;
  case 50:
      code[0]=46+i.suffix=='q';
      break;
  case 51:  
      code[0]=46+i.suffix=='l';
      break;
  default:
      as_bad(_("unreachable code dlfjb"));
      return;
    }
    if (i.imm_operands && (i.op[0].imms->X_op!=O_constant || i.op[0].imms->
      X_add_number>32 || i.op[0].imms->X_add_number<1)) goto do_4_byte;
    if (i.imm_operands) {
      if (operand_type_check(i.types[1],anymem)) output_spec_load();
      code[0]|=((i.op[0].imms->X_add_number&0x10)<<2) | (operand_type_check(
        i.types[1],anymem) ? 0x80 :((i.op[1].regs->reg_num
        &0x10)<<3));
      code[1]=(i.op[0].imms->X_add_number&0xf) | (operand_type_check(i.types[1]
        ,anymem) ? 0 : ((i.op[1].regs->reg_num&0xf)<<4));
      FRAG_APPEND_1_CHAR(code[0]);      
      FRAG_APPEND_1_CHAR(code[1]);      
      frag_var (rs_machine_dependent, 30, i.reloc[0], 
         ENCODE_RELAX_STATE(NON_JUMP,SMALL), NULL, 0, NULL);
      return;
    } else {
      if (operand_type_check(i.types[0],anymem)) { 
        rB=16; 
      //  memop=0; 
        hasmem=1; 
        rA=i.op[1].regs->reg_num;
      } else if (operand_type_check(i.types[1],anymem)) { 
        rA=16; 
      //  memop=1; 
        hasmem=1;
        rB=i.op[0].regs->reg_num;
      } else {
        rA=i.op[1].regs->reg_num;
        rB=i.op[0].regs->reg_num;
      }
   
    if (hasmem) output_spec_load();
    code[0]|=((rB&0x10)<<2) | ((rA&0x10)<<3);
    code[1]=(rB&0xf) | ((rA&0xf)<<4);
    FRAG_APPEND_1_CHAR(code[0]);      
    FRAG_APPEND_1_CHAR(code[1]);      
    frag_var (rs_machine_dependent, 30, i.reloc[0], 
       ENCODE_RELAX_STATE(NON_JUMP,SMALL), NULL, 0, NULL);
    }
  }
  do_4_byte:
  code[0]=i.tm.base_opcode;
  switch(i.suffix) {
case 'q' : code[0]+=(i.tm.size_offsets&0xff); break;
case 'l' : code[0]+=(i.tm.size_offsets&0xff00)>>8; break;
case 'w' : code[0]+=(i.tm.size_offsets&0xff0000)>>16; break;
case 'b' : code[0]+=(i.tm.size_offsets&0xff000000)>>24; break;
  }
  if (!i.imm_operands) {
    if (operand_type_check(i.types[0],anymem)) { 
      rB=16; 
   //   memop=0; 
      hasmem=1; 
      rA=i.op[1].regs->reg_num;
    } else if (operand_type_check(i.types[1],anymem)) { 
      rA=16; 
   //   memop=1; 
      hasmem=1;
      rB=i.op[0].regs->reg_num;
    } else {
      rA=i.op[1].regs->reg_num;
      rB=i.op[0].regs->reg_num;
    }
   
    if (hasmem) output_spec_load();
    code[1]=(abs(rB)&0xf)|((abs(rA)&0xf)<<4);
    code[2]=((abs(rB)&0x10)>>3)|((abs(rA)&0x10)>>4);
    code[3]=0;
   // if (rA<0) code[3]|=0x40;
   // if (rB<0) code[3]|=0x20;
    FRAG_APPEND_1_CHAR(code[0]);
    FRAG_APPEND_1_CHAR(code[1]);
    FRAG_APPEND_1_CHAR(code[2]);
    FRAG_APPEND_1_CHAR(code[3]);
        
    frag_var (rs_machine_dependent, 30, i.reloc[0], 
        ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
    return;
  } else {
    if (i.op[0].imms->X_op==O_constant && i.op[0].imms->X_add_number>=-8192 &&
      i.op[0].imms->X_add_number<=8191) {
      if (operand_type_check(i.types[1],anymem)) { rA=16; output_spec_load();}
      else { rA=i.op[1].regs->reg_num; }
      code[1]=(abs(rA)&0xf)<<4;
      code[2]=((abs(rA)&0x10)>>4)|((i.op[0].imms->X_add_number&0x3f)<<2);
      code[3]=(i.op[0].imms->X_add_number&0x3fc0)>>6;
      if (rA<0) code[3]=(code[3] & 0x0f) | 0x20;
      FRAG_APPEND_1_CHAR(code[0]);
      FRAG_APPEND_1_CHAR(code[1]);
      FRAG_APPEND_1_CHAR(code[2]);
      FRAG_APPEND_1_CHAR(code[3]);
        
      frag_var (rs_machine_dependent, 30, i.reloc[0], 
        ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
      return;
    } else { 
      if (operand_type_check(i.types[1],anymem)) { rA=16; output_spec_load();}
      else { rA=i.op[1].regs->reg_num; }
      code[1]=rA;
      if (i.suffix=='b') as_bad(_("Byte cmp with large imm."));
      FRAG_APPEND_1_CHAR(code[0]);
      FRAG_APPEND_1_CHAR(code[1]);
      output_imm(frag_now,2);
      frag_var (rs_machine_dependent, 30, i.reloc[1], 
        ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
      return; 
    } 
  }
  return;
}

static void output_spec_store(int no);

static void output_shift(void)
{
  unsigned char code[10];
  int rT,rA,memop=0,immop;
 // int disp_var;
  if (i.operands==2) memop=operand_type_check(i.types[1],anymem);
  if (i.operands==3 && operand_type_check(i.types[2],anymem)) memop=2;
  immop=i.operands==2 ? 0 : 1;
  rA=1;
  rT=i.operands==2 ? 1 : 2;
  //if (memop) as_bad(_("memory shifts not implemented yet."));
  if (memop) output_spec_load();
  if (i.imm_operands && !memop) goto do_imm_reg;
  code[0]=i.tm.base_opcode;
  switch(i.suffix) {
case 'q' : code[0]+=(i.tm.size_offsets&0xff); break;
case 'l' : code[0]+=(i.tm.size_offsets&0xff00)>>8; break;
case 'w' : code[0]+=(i.tm.size_offsets&0xff0000)>>16; break;
case 'b' : code[0]+=(i.tm.size_offsets&0xff000000)>>24; break;
  }      
  if (!memop) {
      code[1]=(i.op[rA].regs->reg_num&0xf)|((i.op[rT].regs->reg_num&0xf)<<4);
      code[2]=((i.op[rA].regs->reg_num&0x10)>>3)|((i.op[rT].regs->reg_num&0x10)>>4) |((i.op[0].regs->reg_num&0x1f)<<2);
  } else {
      code[1]=0;
      code[2]=((0x10)>>3)|((0x10)>>4) |((i.op[0].regs->reg_num&0x1f)<<2);
  }
  code[3]=(i.tm.name[strlen(i.tm.name)-1]=='x') | (i.tm.extension_opcode<<7);
  FRAG_APPEND_1_CHAR(code[0]);
  FRAG_APPEND_1_CHAR(code[1]);
  FRAG_APPEND_1_CHAR(code[2]);
  FRAG_APPEND_1_CHAR(code[3]);
        
  frag_var (rs_machine_dependent, 30, i.reloc[0], 
       ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
  if (memop) output_spec_store(i.suffix=='q' ? 16 : 17);
  return;

   
  do_imm_reg:
  if (!memop) rA=i.op[rA].regs->reg_num;
  else rA=16;
  if (!memop || i.operands==3) rT=i.op[rT].regs->reg_num;
  else rT=16;
  if ((i.suffix=='q' || i.suffix=='l') && i.op[immop].imms->X_add_number>0
    && i.op[immop].imms->X_add_number<=32 && i.operands==2) {
    switch(i.tm.base_opcode) {
  case 40: code[0]=20; break;
  case 41: code[0]=22; break;
  case 42: code[0]=21; break;
  case 43: code[0]=23; break;
  case 44: code[0]=25; break;
  case 45:
  default:  code[0]=24; break;
    }
    code[1]=rA&0xf;
    code[0]|=(rA&0x10)<<2;
    FRAG_APPEND_1_CHAR(code[0]);      
    FRAG_APPEND_1_CHAR(code[1]);      
    frag_var (rs_machine_dependent, 30, i.reloc[0], 
       ENCODE_RELAX_STATE(NON_JUMP,SMALL), NULL, 0, NULL);
    if (memop) output_spec_store(i.suffix=='q' ? 16 : 17);
    return;
  } 
      code[0]=i.tm.base_opcode;
      switch(i.suffix) {
  case 'q' : code[0]+=(i.tm.size_offsets&0xff); break;
  case 'l' : code[0]+=(i.tm.size_offsets&0xff00)>>8; break;
  case 'w' : code[0]+=(i.tm.size_offsets&0xff0000)>>16; break;
  case 'b' : code[0]+=(i.tm.size_offsets&0xff000000)>>24; break;
      }      
    code[1]=(rA&0xf) | ((rT&0xf)<<4);
    code[2]=((rT&0x10)>>4) |((rA&0x10)>>3)|((i.op[immop].imms->
      X_add_number&0x3f)<<2);
    code[3]=(i.tm.name[strlen(i.tm.name)-1]=='x') | (i.tm.extension_opcode<<7);
    FRAG_APPEND_1_CHAR(code[0]);
    FRAG_APPEND_1_CHAR(code[1]);
    FRAG_APPEND_1_CHAR(code[2]);
    FRAG_APPEND_1_CHAR(code[3]);
        
    frag_var (rs_machine_dependent, 30, i.reloc[0], 
       ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
    if (memop) output_spec_store(i.suffix=='q' ? 16 : 17);
    return;

}
static void output_cset(void) {
  unsigned char code[10];
  if (i.tm.base_opcode>=200) {
      unsigned char code_s;
      int rT,rB,rA,memop;
      int disp_var;
      rA=rB=rT=i.op[0].regs->reg_num;
      code[0]=198;
      code[1]=(rA&0xf) | ((rT&0xf)<<4);
      code[2]=((rA&0x10)>>3) | ((rT&0x10)>>4) | ((rB&0x1f)<<2);
      code_s=i.tm.base_opcode==200 ? (i.tm.extension_opcode&1) : 0;
      code[3]=((((i.tm.base_opcode-200)&1)+code_s)<<2);
      if (i.tm.base_opcode==200) {
          code[3]|=((i.tm.extension_opcode&6)>>2);
          code[2]|=((i.tm.extension_opcode&8)<<4);
      } else {
          code[3]|=((i.tm.base_opcode&6)<<2);
         // code[2]|=((i.tm.extension_opcode&8)<<4);
      }
      FRAG_APPEND_1_CHAR(code[0]);
      FRAG_APPEND_1_CHAR(code[1]);
      FRAG_APPEND_1_CHAR(code[2]);
      FRAG_APPEND_1_CHAR(code[3]);
      frag_var (rs_machine_dependent, 30, i.reloc[0], 
        ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
      return;
  }
  code[0]=194;
  code[1]=((i.tm.extension_opcode&0xf)<<4) | ((i.op[0].regs->reg_num&0xf));
  code[2]=((i.op[0].regs->reg_num&0x10)>>3);
  code[3]=0;
  FRAG_APPEND_1_CHAR(code[0]);
  FRAG_APPEND_1_CHAR(code[1]);
  FRAG_APPEND_1_CHAR(code[2]);
  FRAG_APPEND_1_CHAR(code[3]);
        
  frag_var (rs_machine_dependent, 30, i.reloc[0], 
     ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
}
static void output_mov_abs(void) {
  unsigned char code[10];
  code[0]=183;
  code[1]=(i.op[1].regs->reg_num&0x1f)|
    ((i.tm.extension_opcode&1)<<7);
  FRAG_APPEND_1_CHAR(code[0]);      
  FRAG_APPEND_1_CHAR(code[1]);      
  output_imm(frag_now,2);
  frag_var (rs_machine_dependent, 30, i.reloc[0], 
    ENCODE_RELAX_STATE(NON_JUMP,BIGGEST), NULL, 0, NULL);
  return;
}

static void output_mov_ext(void) 
{
  unsigned char code[10],code_s;
  int rT,rB,rA,store,memop;
  int disp_var;
  store=operand_type_check(i.types[1],anymem);
  memop=store;
  if (i.imm_operands) goto imm_reg;
  if (i.mem_operands) {
    if (i.suffix=='b' && i.tm.base_opcode==187 && !memop) 
      goto do_memonly; //byte zx
    if (i.suffix=='b' && i.tm.base_opcode==183 && memop) 
      goto do_memonly; //byte zx
    if (i.suffix=='w' && i.tm.base_opcode==188 && !memop) 
      goto do_memonly; //word zx
    if (i.suffix=='w' && i.tm.base_opcode==183 && memop) 
      goto do_memonly; //word zx
    if (i.suffix=='l' && i.tm.base_opcode==183) goto do_memonly; //32 bit
    if (i.suffix=='q' && i.tm.base_opcode==183) goto do_memonly; //64 bit
//    if (operand_type_check(i.types[1],anymem)) goto do_store_ext;
    output_spec_load();
    if (i.suffix=='l' || i.suffix=='q') {
      switch(i.tm.base_opcode) {
    case 183: //mov
        code[0]=i.suffix=='l' ? 0x21 : 0x20;
    case 189: //movsb*
        code[0]=i.suffix=='l' ? 0x24 : 0x26; 
        if (i.suffix=='l') break;
        code[0]=i.suffix=='l' ? 189 : 191;
        goto mem_4byte;
    case 190: //movsw*
        code[0]=i.suffix=='l' ? 0x25 : 0x27;
        if (i.suffix=='l') break;
        code[0]=i.suffix=='l' ? 190 : 192;
        goto mem_4byte;
    case 193: //movslq
        code[0]=0x28;
        break;
    default: 
        code[0]=i.tm.base_opcode;
        goto mem_4byte;
        //return;
      } 
      //rA=i.op[1].regs->reg_num;
      rT=i.op[1].regs->reg_num;
      code[1]=rT<<4&0xf0;
      code[0]|=((rT&0x10)<<3)|0x40;
      FRAG_APPEND_1_CHAR(code[0]);      
      FRAG_APPEND_1_CHAR(code[1]);      
      frag_var (rs_machine_dependent, 30, i.reloc[0], 
         ENCODE_RELAX_STATE(NON_JUMP,SMALL), NULL, 0, NULL);
      return;
    } else {
    //movb/movw
       
      mem_4byte:
      code[0]=i.tm.base_opcode;
      switch(i.suffix) {
  case 'q' : code[0]+=(i.tm.size_offsets&0xff); break;
  case 'l' : code[0]+=(i.tm.size_offsets&0xff00)>>8; break;
  case 'w' : code[0]+=(i.tm.size_offsets&0xff0000)>>16; break;
  case 'b' : code[0]+=(i.tm.size_offsets&0xff000000)>>24; break;
      }      
      code[1]=abs(i.op[!memop].regs->reg_num)&0xf;
      code[2]=(abs(i.op[!memop].regs->reg_num)&0x10)>>3;
      code[3]=(i.suffix=='b' && i.op[!memop].regs->reg_num<0) ? 0xc0 : 0x0;
      FRAG_APPEND_1_CHAR(code[0]);
      FRAG_APPEND_1_CHAR(code[1]);
      FRAG_APPEND_1_CHAR(code[2]);
      FRAG_APPEND_1_CHAR(code[3]);
        
      frag_var (rs_machine_dependent, 30, i.reloc[0], 
          ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
        return;
    }
  } else {
    if (i.imm_operands) goto imm_reg;
    //regonly 
    if (i.suffix=='l' || i.suffix=='q') {
      switch(i.tm.base_opcode) {
    case 183: //mov
        code[0]=i.suffix=='l' ? 0x21 : 0x20;
    case 189: //movsb*
        code[0]=i.suffix=='l' ? 0x24 : 0x26; 
        if (i.suffix=='l') break;
        code[0]=i.suffix=='l' ? 189 : 191;
        goto mem_4byte;
    case 190: //movsw*
        code[0]=i.suffix=='l' ? 0x25 : 0x27;
        if (i.suffix=='l') break;
        code[0]=i.suffix=='l' ? 190 : 192;
        goto mem_4byte;
    case 193: //movslq
        code[0]=28;
        break;
    case 187: //movzb*
        code[0]=187;
        goto reg_4byte;
    case 188: //movzw*
        code[0]=188;
        goto reg_4byte;
  //need more
    default: as_bad(_("Unreachable code\n"));
        return;
      } 
      rB=i.op[0].regs->reg_num;
      rT=i.op[1].regs->reg_num;
      code[1]=(rT<<4&0xf0)|(rB&0xf);
      code[0]|=((rT&0x10)<<3)|((rB&0x10)<<2);
      FRAG_APPEND_1_CHAR(code[0]);      
      FRAG_APPEND_1_CHAR(code[1]);      
      frag_var (rs_machine_dependent, 30, i.reloc[0], 
         ENCODE_RELAX_STATE(NON_JUMP,SMALL), NULL, 0, NULL);
      return;
    } else {
    //movb/movw reg
       
      reg_4byte:
      code[0]=i.tm.base_opcode;
      switch(i.suffix) {
  case 'q' : code[0]+=(i.tm.size_offsets&0xff); break;
  case 'l' : code[0]+=(i.tm.size_offsets&0xff00)>>8; break;
  case 'w' : code[0]+=(i.tm.size_offsets&0xff0000)>>16; break;
  case 'b' : code[0]+=(i.tm.size_offsets&0xff000000)>>24; break;
      }      
      code[1]=(abs(i.op[1].regs->reg_num)&0xf)|
        ((abs(i.op[0].regs->reg_num)&0xf)<<4);
      code[2]=(abs(i.op[1].regs->reg_num)&0x10)>>3;
      code[2]|=(abs(i.op[0].regs->reg_num)&0x10)>>4;
      code[3]=(i.suffix=='b' && i.op[1].regs->reg_num<0) ? 0x40 : 0x0;
      code[3]|=(i.op[0].regs->reg_num<0) ? 0x20 : 0x0;
      if (i.tm.extension_opcode) code[3]|=0x80;
      FRAG_APPEND_1_CHAR(code[0]);
      FRAG_APPEND_1_CHAR(code[1]);
      FRAG_APPEND_1_CHAR(code[2]);
      FRAG_APPEND_1_CHAR(code[3]);
        
      frag_var (rs_machine_dependent, 30, i.reloc[0], 
	 ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
      return;
    }
  }
  imm_reg://to do
  if (operand_type_check(i.types[1],anymem)) rA=16; 
  else rA=i.op[1].regs->reg_num;
  
  if (i.op[0].imms->X_op==O_constant && i.op[0].imms->X_add_number>=1 && 
    i.op[0].imms->X_add_number<=32 && (i.suffix=='l' || i.suffix=='q') && 
    code[0]==183) {
    code[0]=0x29;
    code[0]|=(rA&0x10)<<3;
    code[0]|=(i.op[0].imms->X_add_number&0x10)<<2;
    code[1]=(i.op[0].imms->X_add_number&0xf) | 
      ((rA&0xf)<<4);
    FRAG_APPEND_1_CHAR(code[0]);      
    FRAG_APPEND_1_CHAR(code[1]);      
    frag_var (rs_machine_dependent, 30, i.reloc[0], 
       ENCODE_RELAX_STATE(NON_JUMP,SMALL), NULL, 0, NULL);

  } else if (i.op[0].imms->X_op==O_constant && 
    ((i.op[0].imms->X_add_number>=-4096 && i.op[0].imms->X_add_number<=4095)
     || i.suffix=='b')) {
      code[0]=i.tm.base_opcode;
      switch(i.suffix) {
  case 'q' : code[0]+=(i.tm.size_offsets&0xff); break;
  case 'l' : code[0]+=(i.tm.size_offsets&0xff00)>>8; break;
  case 'w' : code[0]+=(i.tm.size_offsets&0xff0000)>>16; break;
  case 'b' : code[0]+=(i.tm.size_offsets&0xff000000)>>24; break;
      }
      code[1]=abs(rA)&0xf;
      code[2]=(abs(rA)&0x10)>>3;
      disp_var=i.op[0].imms->X_add_number;
      code[2]|=(disp_var &0x3f)<<2;
      code[3]=(disp_var &0x1fc0)>>6;
      code[3]|=0x80;  
      if (code[0]==186) code[3]&=0xbf;   
      if (code[0]==186 && rA<0) 
        code[3]|=0x40; 
      FRAG_APPEND_1_CHAR(code[0]);
      FRAG_APPEND_1_CHAR(code[1]);
      FRAG_APPEND_1_CHAR(code[2]);
      FRAG_APPEND_1_CHAR(code[3]);
        
      frag_var (rs_machine_dependent, 30, i.reloc[0], 
        ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
  } else {
      code[0]=i.tm.base_opcode;
      switch(i.suffix) {
  case 'q' : code[0]+=(i.tm.size_offsets&0xff); break;
  case 'l' : code[0]+=(i.tm.size_offsets&0xff00)>>8; break;
  case 'w' : code[0]+=(i.tm.size_offsets&0xff0000)>>16; break;
  case 'b' : as_bad(_("unreachable code in output_mov_ext")); return;
      }
      code[1]=((rA&0xf)<<4)|
        ((rA&0x10)>>3);
      FRAG_APPEND_1_CHAR(code[0]);
      FRAG_APPEND_1_CHAR(code[1]);
      output_imm(frag_now,2);
      frag_var (rs_machine_dependent, 30, i.reloc[0], 
         ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
  }
  if (operand_type_check(i.types[1],anymem)) {rB=16; goto do_memonly_2;}
  else {return;}
  do_memonly:
    rB=i.op[!memop].regs->reg_num;
  do_memonly_2:
    if (i.suffix=='b') code_s=3; //byte zx
    if (i.suffix=='w') code_s=2; //word zx
    if (i.suffix=='l') code_s=1; //32 bit
    if (i.suffix=='q') code_s=0; //64 bit
    disp_var=operand_type_check(i.types[memop],disp); 
    if (i.index_reg) {
      code[0]=0x70+(code_s<<1)+store;
      if (!disp_var || (i.op[memop].disps->X_op==O_constant && 
        i.op[memop].disps->X_add_number>=-64
        && i.op[memop].disps->X_add_number<=63 && (!i.base_reg||!(i.base_reg->
        reg_num&0x10)) && !(i.index_reg->reg_num&0x10))) {//9 bit disp
        if (disp_var) disp_var=i.op[memop].disps->X_add_number;
        else disp_var=0;
        code[1]=(rB&0xf);
        if (i.base_reg) code[1]|=((i.base_reg->reg_num&0xf)<<4);
        else code[1]|=5<<4;
        code[2]=(i.index_reg->reg_num&0xf);
        code[2]|=((i.log2_scale_factor&0x3)<<5)|((disp&0x1)<<7);
        code[3]=(disp&0xfe)>>1;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        FRAG_APPEND_1_CHAR(code[2]);
        FRAG_APPEND_1_CHAR(code[3]);
       // p=code; 
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
        return;
      } else if (i.op[memop].disps->X_op==O_constant && i.op[memop].disps->X_add_number>=-4096*1024
        && i.op[memop].disps->X_add_number<4096*1024) {//23 bit disp
        disp_var=i.op[memop].disps->X_add_number;
        code[1]=(rB&0xf);
        if (i.base_reg) code[1]|=((i.base_reg->reg_num&0xf)<<4);
        else code[1]|=5<<4;
        code[2]=(i.index_reg->reg_num&0xf)|(rB&0x10)|
             ((i.index_reg->reg_num&0x10)<<2);
        if (i.base_reg) code[2]|=(i.base_reg->reg_num&0x10)<<1;     
        code[2]|=i.log2_scale_factor&0x1;
        code[3]=i.log2_scale_factor>>1;
        code[3]|=(disp_var&0x7f)<<1;
        code[4]=(disp_var&0x7f8)>>7;
        code[5]=(disp_var&0x7f800)>>15;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        FRAG_APPEND_1_CHAR(code[2]);
        FRAG_APPEND_1_CHAR(code[3]);
        FRAG_APPEND_1_CHAR(code[4]);
        FRAG_APPEND_1_CHAR(code[5]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
        return;
      } else { //32 bit disp
        code[1]=(rB&0xf);
        if (i.base_reg) code[1]|=((i.base_reg->reg_num&0xf)<<4);
        else code[1]|=5<<4;
        code[6]=(i.index_reg->reg_num&0xf)|((rB&0x10)<<2);
        if (i.base_reg) code[6]|=((i.base_reg->reg_num&0x10)<<3);
        code[7]=((i.index_reg->reg_num&0x10)>>4);
        code[6]|=i.log2_scale_factor<<4;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        output_disp(frag_now,2);
        FRAG_APPEND_1_CHAR(code[6]);
        FRAG_APPEND_1_CHAR(code[7]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIGGER), NULL, 0, NULL);
        return;
      }
    } else if (i.base_reg && i.base_reg->reg_num!=255) {
      code[0]=0x60+(code_s<<1)+store;
      if (!disp_var || (i.op[memop].disps->X_op==O_constant && i.op[memop].disps->X_add_number>=-8192
        && i.op[memop].disps->X_add_number<=8191)) {//14 bit disp
        code[1]=(i.base_reg->reg_num&0xf)|((rB&0xf)<<4);
        if (disp_var) disp_var=i.op[memop].disps->X_add_number;
        else disp_var=0;
        code[2]=((rB&0x10)>>4)|((i.base_reg->reg_num&0x10)>>3);
        code[2]|=(disp_var&0x3f)<<2;
        code[3]=(disp_var&0x3fc0)>>6;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        FRAG_APPEND_1_CHAR(code[2]);
        FRAG_APPEND_1_CHAR(code[3]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
        return;
      } else if ((!(rB&0x10))&&(!(i.base_reg->reg_num&0x10))){//32 bit disp, 16 reg
        code[1]=((i.base_reg->reg_num&0xf)<<4)|(rB&0xf);
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        output_disp(frag_now,2);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
        return;
      } else { //32 bit disp, 32 reg
        code[1]=(rB&0xf);
        code[1]|=((i.base_reg->reg_num&0xf)<<4);
        code[0]=0x70+(code_s<<1)+store;
        
        code[6]=((rB&0x10)<<2);
        code[6]|=((i.base_reg->reg_num&0x10)<<3);
        code[7]=0x2;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        output_disp(frag_now,2);
        FRAG_APPEND_1_CHAR(code[6]);
        FRAG_APPEND_1_CHAR(code[7]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIGGER), NULL, 0, NULL);
        return;
      }
    } else { //imm only load store
      if (i.op[memop].disps->X_op==O_constant && i.op[memop].disps->X_add_number
        >=-8192 && i.op[memop].disps->X_add_number<=8191 && i.base_reg) {
        if (operand_type_check(i.types[memop],disp)) disp_var=i.op[memop].disps->
          X_add_number; 
        code[0]=0xb0|memop;
        code[1]=(code_s) | ((rB&0xf)<<4) | ((i.base_reg!=NULL)<<4);
        code[2]=((rB&0x10)>>4) | ((disp_var & 0x3f)<<2);
        code[3]=(disp_var & 0x3fc0)>>6; 
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        FRAG_APPEND_1_CHAR(code[2]);
        FRAG_APPEND_1_CHAR(code[3]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
        return;
      } else if (!(rB&0x10)) {
        code[0]=0xb0|memop;
        code[1]=(code_s) | ((rB&0xf)<<4) | ((i.base_reg!=NULL)<<4);
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        output_disp(frag_now,2);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
        return;
      } else {
        code[1]=(rB&0xf);
        code[0]=0x70+(code_s<<1)+store;
        
        code[6]=((rB&0x10)<<2);
        code[7]=0x4 | ((i.base_reg!=NULL)<<3);
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        output_disp(frag_now,2);
        FRAG_APPEND_1_CHAR(code[6]);
        FRAG_APPEND_1_CHAR(code[7]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIGGER), NULL, 0, NULL);
        return;
      }
    }
    as_bad(_("unreachable code in output_mov_ext"));
}

static void output_spec_store(int no) {
    unsigned char code[10],code_s;
    int rT,rB,rA,store,memop;
    int disp_var;
    store=operand_type_check(i.types[1],anymem);
    memop=store;
    rB=16;
    if (i.suffix=='b') code_s=3; //byte zx
    if (i.suffix=='w') code_s=2; //word zx
    if (i.suffix=='l') code_s=1; //32 bit
    if (i.suffix=='q') code_s=0; //64 bit
    disp_var=operand_type_check(i.types[memop],disp); 
    if (i.index_reg) {
      code[0]=0x70+(code_s<<1)+store;
      if (!disp_var || (i.op[memop].disps->X_op==O_constant && 
        i.op[memop].disps->X_add_number>=-64
        && i.op[memop].disps->X_add_number<=63 && (!i.base_reg||!(i.base_reg->
        reg_num&0x10)) && !(i.index_reg->reg_num&0x10))) {//9 bit disp
        if (disp_var) disp_var=i.op[memop].disps->X_add_number;
        else disp_var=0;
        code[1]=(rB&0xf);
        if (i.base_reg) code[1]|=((i.base_reg->reg_num&0xf)<<4);
        else code[1]|=5<<4;
        code[2]=(i.index_reg->reg_num&0xf);
        code[2]|=((i.log2_scale_factor&0x3)<<5)|((disp&0x1)<<7);
        code[3]=(disp&0xfe)>>1;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        FRAG_APPEND_1_CHAR(code[2]);
        FRAG_APPEND_1_CHAR(code[3]);
       // p=code; 
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
        return;
      } else if (i.op[memop].disps->X_op==O_constant && i.op[memop].disps->X_add_number>=-4096*1024
        && i.op[memop].disps->X_add_number<4096*1024) {//23 bit disp
        disp_var=i.op[memop].disps->X_add_number;
        code[1]=(rB&0xf);
        if (i.base_reg) code[1]|=((i.base_reg->reg_num&0xf)<<4);
        else code[1]|=5<<4;
        code[2]=(i.index_reg->reg_num&0xf)|(rB&0x10)|
             ((i.index_reg->reg_num&0x10)<<2);
        if (i.base_reg) code[2]|=(i.base_reg->reg_num&0x10)<<1;     
        code[2]|=i.log2_scale_factor&0x1;
        code[3]=i.log2_scale_factor>>1;
        code[3]|=(disp_var&0x7f)<<1;
        code[4]=(disp_var&0x7f8)>>7;
        code[5]=(disp_var&0x7f800)>>15;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        FRAG_APPEND_1_CHAR(code[2]);
        FRAG_APPEND_1_CHAR(code[3]);
        FRAG_APPEND_1_CHAR(code[4]);
        FRAG_APPEND_1_CHAR(code[5]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
        return;
      } else { //32 bit disp
        code[1]=(rB&0xf);
        if (i.base_reg) code[1]|=((i.base_reg->reg_num&0xf)<<4);
        else code[1]|=5<<4;
        code[6]=(i.index_reg->reg_num&0xf)|((rB&0x10)<<2);
        if (i.base_reg) code[6]|=((i.base_reg->reg_num&0x10)<<3);
        code[7]=((i.index_reg->reg_num&0x10)>>4);
        code[6]|=i.log2_scale_factor<<4;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        output_disp(frag_now,2);
        FRAG_APPEND_1_CHAR(code[6]);
        FRAG_APPEND_1_CHAR(code[7]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIGGER), NULL, 0, NULL);
        return;
      }
    } else if (i.base_reg && i.base_reg->reg_num!=255) {
      code[0]=0x60+(code_s<<1)+store;
      if (!disp_var || (i.op[memop].disps->X_op==O_constant && i.op[memop].disps->X_add_number>=-8192
        && i.op[memop].disps->X_add_number<=8191)) {//14 bit disp
        code[1]=(i.base_reg->reg_num&0xf)|((rB&0xf)<<4);
        if (disp_var) disp_var=i.op[memop].disps->X_add_number;
        else disp_var=0;
        code[2]=((rB&0x10)>>4)|((i.base_reg->reg_num&0x10)>>3);
        code[2]|=(disp_var&0x3f)<<2;
        code[3]=(disp_var&0x3fc0)>>6;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        FRAG_APPEND_1_CHAR(code[2]);
        FRAG_APPEND_1_CHAR(code[3]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
        return;
      } else if ((!(rB&0x10))&&(!(i.base_reg->reg_num&0x10))){//32 bit disp, 16 reg
        code[1]=((i.base_reg->reg_num&0xf)<<4)|(rB&0xf);
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        output_disp(frag_now,2);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
        return;
      } else { //32 bit disp, 32 reg
        code[1]=(rB&0xf);
        code[1]|=((i.base_reg->reg_num&0xf)<<4);
        code[0]=0x70+(code_s<<1)+store;
        
        code[6]=((rB&0x10)<<2);
        code[6]|=((i.base_reg->reg_num&0x10)<<3);
        code[7]=0x2;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        output_disp(frag_now,2);
        FRAG_APPEND_1_CHAR(code[6]);
        FRAG_APPEND_1_CHAR(code[7]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIGGER), NULL, 0, NULL);
        return;
      }
    } else { //imm only load store
      if (i.op[memop].disps->X_op==O_constant && i.op[memop].disps->X_add_number
        >=-8192 && i.op[memop].disps->X_add_number<=8191 && i.base_reg) {
        if (operand_type_check(i.types[memop],disp)) disp_var=i.op[memop].disps->
          X_add_number; 
        code[0]=0xb0|memop;
        code[1]=(code_s) | ((rB&0xf)<<4) | ((i.base_reg!=NULL)<<4);
        code[2]=((rB&0x10)>>4) | ((disp_var & 0x3f)<<2);
        code[3]=(disp_var & 0x3fc0)>>6; 
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        FRAG_APPEND_1_CHAR(code[2]);
        FRAG_APPEND_1_CHAR(code[3]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
        return;
      } else if (!(rB&0x10)) {
        code[0]=0xb0|memop;
        code[1]=(code_s) | ((rB&0xf)<<4) | ((i.base_reg!=NULL)<<4);
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        output_disp(frag_now,2);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
        return;
      } else {
        code[1]=(rB&0xf);
        code[0]=0x70+(code_s<<1)+store;
        
        code[6]=((rB&0x10)<<2);
        code[7]=0x4 | ((i.base_reg!=NULL)<<3);
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        output_disp(frag_now,2);
        FRAG_APPEND_1_CHAR(code[6]);
        FRAG_APPEND_1_CHAR(code[7]);
        frag_var (rs_machine_dependent, 30, i.reloc[memop], 
	   ENCODE_RELAX_STATE(NON_JUMP,BIGGER), NULL, 0, NULL);
        return;
      }
    }
    as_bad(_("unreachable code in output_spec_store"));
}

static void output_cmov(void) {
  unsigned char code[10],code_s;
  int rT,rB,rA,memop;
  int disp_var;
  memop=operand_type_check(i.types[0],anymem);
  if (memop) {
      output_spec_load();
      rA=i.op[1].regs->reg_num;
      rT=i.operands==2 ? rA : i.op[2].regs->reg_num;
      rB=16;
  } else {
      rA=i.op[1].regs->reg_num;
      rT=i.operands==2 ? rA : i.op[2].regs->reg_num;
      rB=i.op[0].regs->reg_num;
  }
  code[0]=198;
  code[1]=(rA&0xf) | ((rT&0xf)<<4);
  code[2]=((rA&0x10)>>3) | ((rT&0x10)>>4) | ((rB&0x1f)<<2);
  code_s=i.suffix=='l' ? 2 :0;
  code[3]=((i.tm.extension_opcode&1)+code_s)<<2;
  code[3]|=((i.tm.extension_opcode&6)>>2);
  code[2]|=((i.tm.extension_opcode&8)<<4);
  FRAG_APPEND_1_CHAR(code[0]);
  FRAG_APPEND_1_CHAR(code[1]);
  FRAG_APPEND_1_CHAR(code[2]);
  FRAG_APPEND_1_CHAR(code[3]);
  frag_var (rs_machine_dependent, 30, i.reloc[0], 
    ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
  return;
}

static void output_calu(void) {
}

static void output_alu(void)
{
  //fragS *insn_start_frag;
  //offsetT insn_start_off;
  int immop=0;
  int rB=0,rA=1,rT=2;
 // int noFlag=0;
  unsigned char code[10];
//  char *p=NULL;
  int xB,xA,xT;
  
 // insn_start_frag = frag_now;
 // insn_start_off = frag_now_fix ();

  if (i.operands==2) {immop=0; rA=1; rB=0; rT=1;}
  if (i.imm_operands==1 && i.mem_operands==0) {
     if (i.op[immop].imms->X_op==O_constant && 
       (i.op[immop].imms->X_add_number<=32) &&
       (i.op[immop].imms->X_add_number>0) && !i.tm.extension_opcode &&
       i.suffix!='b' && i.suffix!='w') goto do_smallest_const;
     else if (i.op[immop].imms->X_op==O_constant && 
       (i.op[immop].imms->X_add_number<=4095) &&
       (i.op[immop].imms->X_add_number>=-4096)) goto do_small_const;
    else goto do_big_const;
  } else if (i.imm_operands==0) {
      if (i.mem_operands==0) goto do_register;
      else goto do_memory;
  } else goto do_memory;
	
do_register:
 // frag_grow(2);
  code[0]=i.tm.base_opcode;
  switch (i.suffix) {
  case 'q' : code[0]+=(i.tm.size_offsets&0xff); break;
  case 'l' : code[0]+=(i.tm.size_offsets&0xff00)>>8; break;
  case 'w' : code[0]+=(i.tm.size_offsets&0xff0000)>>16; break;
  case 'b' : code[0]+=(i.tm.size_offsets&0xff000000)>>24; break;
  }
//  FRAG_APPEND_1_CHAR(code);
    if (i.op[rT].regs->reg_num==i.op[rA].regs->reg_num && 
      (i.suffix=='l' || i.suffix=='q') && !i.tm.extension_opcode)
    {
	xA=i.op[rA].regs->reg_num;
	xB=i.op[rB].regs->reg_num;
	code[0]=((code[0]&0x1)<<1)|(code[0]&0x1c)|((xA&0x10)<<2)|
          (xB&0x10<<3);
        code[1]=(xA&0xf)|((xB&0xf)<<4);
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
//	frag_grow(11);
//	p=frag_more(1);
//	p=code;
        frag_var (rs_machine_dependent, 30, i.reloc[0], 
	   ENCODE_RELAX_STATE(NON_JUMP,SMALL), NULL, 0, NULL);
	
    } else
    {
	//3 op form
	code[1]=((i.op[rT].regs->reg_num<<4) & 0xf0) | 
	  (i.op[rA].regs->reg_num & 0xf);
	code[2]=((i.op[rT].regs->reg_num>>5)&0x1) | 
	  ((i.op[rA].regs->reg_num>>4)&0x2) |
	  ((i.op[rB].regs->reg_num>>3)&0x7C);
	code[3]=i.tm.extension_opcode ? 0x80 : 0x00;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        FRAG_APPEND_1_CHAR(code[2]);
        FRAG_APPEND_1_CHAR(code[3]);
       // p=code; 
        frag_var (rs_machine_dependent, 30, i.reloc[0], 
	   ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
    }
  return;
do_smallest_const:
        code[0]=i.tm.base_opcode;
	xA=i.op[rA].regs->reg_num;
	xB=i.op[immop].imms->X_add_number&0x1f;
	code[0]=((code[0]&0x1)<<1)|(code[0]&0x1c)|((xA&0x10)<<2)|
          (xB&0x10<<3);
        code[1]=(xA&0xf)|((xB&0xf)<<4);
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
//	frag_grow(11);
//	p=frag_more(1);
//	p=code;
        frag_var (rs_machine_dependent, 30, i.reloc[immop], 
	   ENCODE_RELAX_STATE(NON_JUMP,SMALL), NULL, 0, NULL);
        return;
do_small_const:
  code[0]=i.tm.base_opcode;
  switch (i.suffix) {
  case 'q' : code[0]+=(i.tm.size_offsets&0xff); break;
  case 'l' : code[0]+=(i.tm.size_offsets&0xff00)>>8; break;
  case 'w' : code[0]+=(i.tm.size_offsets&0xff0000)>>16; break;
  case 'b' : code[0]+=(i.tm.size_offsets&0xff000000)>>24; break;
  }
  FRAG_APPEND_1_CHAR(code[0]);
  code[1]=(i.op[rA].regs->reg_num&0xf)|((i.op[rT].regs->reg_num &0xf)<<4);
  FRAG_APPEND_1_CHAR(code[1]);
  code[2]=((i.op[rA].regs->reg_num&0x10)>>3)|((i.op[rT].regs->reg_num &0x10)>>4)
    | ((i.op[immop].imms->X_add_number&0x3f)<<2);
  FRAG_APPEND_1_CHAR(code[2]);
  code[3]=(i.op[immop].imms->X_add_number&0x1fc)>>6;
  code[3]|=i.tm.extension_opcode ? 0x80 : 0;
  FRAG_APPEND_1_CHAR(code[3]);
  frag_var (rs_machine_dependent, 30, i.reloc[immop], 
    ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
  return;
do_big_const:
  code[0]=i.tm.base_opcode;
  switch (i.suffix) {
  case 'q' : code[0]+=(i.tm.size_offsets&0xff); break;
  case 'l' : code[0]+=(i.tm.size_offsets&0xff00)>>8; break;
  case 'w' : code[0]+=(i.tm.size_offsets&0xff0000)>>16; break;
  case 'b' : code[0]+=(i.tm.size_offsets&0xff000000)>>24; break;
  }
  xA=i.op[rA].regs->reg_num;
  xT=i.op[rT].regs->reg_num;
  code[1]=(xA&0xf ) | ((xT&0xf)<<4);
  FRAG_APPEND_1_CHAR(code[0]);
  FRAG_APPEND_1_CHAR(code[1]);
  output_imm(frag_now,2);
  if ((xA&0x10) || (xT&0x10)){
    code[6]=((xA&0x10)>>4)|((xT&0x10)>>3);
    code[7]=0;
    FRAG_APPEND_1_CHAR(code[6]);
    FRAG_APPEND_1_CHAR(code[7]);
    frag_var (rs_machine_dependent, 30, i.reloc[immop], 
      ENCODE_RELAX_STATE(NON_JUMP,BIGGER), NULL, 0, NULL);
    return;
  }
      
  frag_var (rs_machine_dependent, 30, i.reloc[immop], 
    ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
  return;
do_memory:
  code[0]=i.tm.base_opcode;
  output_spec_load();
  if (!operand_type_check(i.types[0],anymem)) goto do_memory_store;
  if (i.suffix=='l' || i.suffix=='q') {
    xA=i.op[rA].regs->reg_num;
    xT=i.op[rT].regs->reg_num;
    code[0]=((code[0]&0x1)<<1)|(code[0]&0x1c)|((xA&0x10)<<2)|
      (xT&0x10<<3);
    code[1]=(xA&0xf)|((xT&0xf)<<4);
    FRAG_APPEND_1_CHAR(code[0]);
    FRAG_APPEND_1_CHAR(code[1]);
//	frag_grow(11);
//	p=frag_more(1);

    frag_var (rs_machine_dependent, 30, i.reloc[0], 
      ENCODE_RELAX_STATE(NON_JUMP,SMALL), NULL, 0, NULL);
  } else {
	code[1]=((i.op[rT].regs->reg_num<<4) & 0xf0) | 
	  (i.op[rA].regs->reg_num & 0xf);
	code[2]=((i.op[rT].regs->reg_num>>5)&0x1) | 
	  ((i.op[rA].regs->reg_num>>4)&0x2) |
	  ((i.op[rB].regs->reg_num>>3)&0x7C);
	code[3]=i.tm.extension_opcode ? 0x80 : 0x00;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        FRAG_APPEND_1_CHAR(code[2]);
        FRAG_APPEND_1_CHAR(code[3]);
       // p=code; 
        frag_var (rs_machine_dependent, 30, i.reloc[0], 
	   ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
  }
  return;    
  do_memory_store:
  code[0]=i.tm.base_opcode;
        rB=1;
        if (i.imm_operands) {
          if (i.op[immop].imms->X_op==O_constant && 
            (i.op[immop].imms->X_add_number<4095) &&
            (i.op[immop].imms->X_add_number>-4096)) goto store_small_const;
          else goto store_big_const;
        }
	code[1]=((16<<4) & 0xf0) | 
	  (16 & 0xf);
	code[2]=((16>>5)&0x1) | 
	  ((16>>4)&0x2) |
	  ((i.op[rB].regs->reg_num>>3)&0x7C);
	code[3]=i.tm.extension_opcode ? 0x80 : 0x00;
        FRAG_APPEND_1_CHAR(code[0]);
        FRAG_APPEND_1_CHAR(code[1]);
        FRAG_APPEND_1_CHAR(code[2]);
        FRAG_APPEND_1_CHAR(code[3]);
       // p=code; 
        frag_var (rs_machine_dependent, 30, i.reloc[0], 
	   ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
	output_spec_store(i.suffix=='l' ? 17 : 16);
  return;
  store_small_const:
  code[0]=i.tm.base_opcode;
  switch (i.suffix) {
  case 'q' : code[0]+=(i.tm.size_offsets&0xff); break;
  case 'l' : code[0]+=(i.tm.size_offsets&0xff00)>>8; break;
  case 'w' : code[0]+=(i.tm.size_offsets&0xff0000)>>16; break;
  case 'b' : code[0]+=(i.tm.size_offsets&0xff000000)>>24; break;
  }
  FRAG_APPEND_1_CHAR(code[0]);
  code[1]=0;
  FRAG_APPEND_1_CHAR(code[1]);
  code[2]=((0x10)>>3)|((0x10)>>4)
    | ((i.op[immop].imms->X_add_number&0x3f)<<2);
  FRAG_APPEND_1_CHAR(code[2]);
  code[3]=(i.op[immop].imms->X_add_number&0x1fc)>>6;
  code[3]|=i.tm.extension_opcode ? 0x80 : 0;
  FRAG_APPEND_1_CHAR(code[3]);
  frag_var (rs_machine_dependent, 30, i.reloc[immop], 
    ENCODE_RELAX_STATE(NON_JUMP,MED), NULL, 0, NULL);
  output_spec_store(i.suffix=='l' ? 17 : 16);
  return;
  store_big_const:
  code[0]=i.tm.base_opcode;
  switch (i.suffix) {
  case 'q' : code[0]+=(i.tm.size_offsets&0xff); break;
  case 'l' : code[0]+=(i.tm.size_offsets&0xff00)>>8; break;
  case 'w' : code[0]+=(i.tm.size_offsets&0xff0000)>>16; break;
  case 'b' : code[0]+=(i.tm.size_offsets&0xff000000)>>24; break;
  }
  xA=16;
  xT=16;
  code[1]=(xA&0xf ) | ((xT&0xf)<<4);
  FRAG_APPEND_1_CHAR(code[0]);
  FRAG_APPEND_1_CHAR(code[1]);
  output_imm(frag_now,2);
  if ((xA&0x10) || (xT&0x10)){
    code[6]=((xA&0x10)>>4)|((xT&0x10)>>3);
    code[7]=0;
    FRAG_APPEND_1_CHAR(code[6]);
    FRAG_APPEND_1_CHAR(code[7]);
    frag_var (rs_machine_dependent, 30, i.reloc[immop], 
      ENCODE_RELAX_STATE(NON_JUMP,BIGGER), NULL, 0, NULL);
    output_spec_store(i.suffix=='l' ? 17 :16);
    return;
  }
      
  frag_var (rs_machine_dependent, 30, i.reloc[immop], 
    ENCODE_RELAX_STATE(NON_JUMP,BIG), NULL, 0, NULL);
  output_spec_store(i.suffix=='l' ? 17 :16);
  return;
}

static void
output_insn (void)
{
  //fragS *insn_start_frag;
  //offsetT insn_start_off;

  /* Tie dwarf2 debug info to the address at the start of the insn.
     We can't do this after the insn has been output as the current
     frag may have been closed off.  eg. by frag_var.  */
  dwarf2_emit_insn (0);

 // insn_start_frag = frag_now;
 // insn_start_off = frag_now_fix ();
  if (i.base_reg && i.base_reg->reg_num==REGNAM_RIP) {
      int op=0;
      if (operand_type_check(i.types[0],anymem)) op=0;
      else if (operand_type_check(i.types[1],anymem)) op=1;
      else if (operand_type_check(i.types[2],anymem)) op=2;
      else as_bad(_("Unreachable code\n"));
      i.types[op].bitfield.disp14s = 0;
      i.types[op].bitfield.disp32 = 0;
      i.types[op].bitfield.disp32s = 1;
      i.types[op].bitfield.disp64 = 0;
   //   i.types[op].bitfield.disp7 = 0;
      i.flags[op] |= Operand_PCrel;
  }

  switch (i.tm.group)
    {
  case instrg_isCondJump:
    output_cond_jump();
    break;
  case instrg_isUncondJump:
    output_uc_jump();
    break;
  case instrg_isCSet:
    output_cset();
    break;
  case instrg_isCmov:
    output_cmov();
    break;
  case instrg_calu:
    output_calu();
    break;
  case instrg_isIndirJump:
    break;
  case instrg_isCall:
    output_call();
    break;
  case instrg_isRet:
    output_ret();
    break;
  case instrg_isBasicALU:
    output_alu();  
    break;
  case instrg_isMov:
  case instrg_isExt:
    output_mov_ext();
    break;
  case instrg_isBasicShift:
    output_shift();
    break;
  case instrg_isBasicCmpTest:
    output_cmp_test();
    break;
  case instrg_push_pop:
    output_push_pop();
    break;
  case instrg_mov_abs:
    output_mov_abs();
    break;
  case instrg_mov_xmm_i:
    output_xmm_mov(0);
    break;
  case instrg_isFPU23Op:
    output_double3();
    break;
  default:
    as_bad(_("unhandled instruction type\n"));
    break;
    }
    return;
}

static int disp_size(int n) {
  (void)(n);
  int size=4;
 // if (i.types[n].bitfield.disp64) size=8;
  return size; 
}

static int imm_size(int n) {
  int size=4;
  if (i.tm.group==instrg_mov_abs) size=8;
  (void) n;
  return size; 
}

static void
output_disp (fragS *insn_start_frag, offsetT insn_start_off)
{
  char *p;
  unsigned int n;

  for (n = 0; n < i.operands; n++)
    {
      if (operand_type_check (i.types[n], disp))
	{
	  if (i.op[n].disps->X_op == O_constant)
	    {
	      int size = disp_size (n);
	      offsetT val = i.op[n].disps->X_add_number;

	      val = offset_in_range (val, size);
	      p = frag_more (size);
	      md_number_to_chars (p, val, size);
	    }
	  else
	    {
	      enum bfd_reloc_code_real reloc_type;
	      int size = disp_size (n);
	      int sign = i.types[n].bitfield.disp32s;
	      int pcrel = (i.flags[n] & Operand_PCrel) != 0;
	      //fixS *fixP;

              //gas_assert(i.imm_operands==0);

	      p = frag_more (size);
	      reloc_type = reloc (size, pcrel, sign, i.reloc[n]);
	      if (GOT_symbol
		  && GOT_symbol == i.op[n].disps->X_add_symbol
		  && (((reloc_type == BFD_RELOC_32
			|| reloc_type == BFD_RELOC_HEPTANE_32S
			|| (reloc_type == BFD_RELOC_64
			    && object_64bit))
		       && (i.op[n].disps->X_op == O_symbol
			   || (i.op[n].disps->X_op == O_add
			       && ((symbol_get_value_expression
				    (i.op[n].disps->X_op_symbol)->X_op)
				   == O_subtract))))
		      || reloc_type == BFD_RELOC_32_PCREL))
		{
		  offsetT add;

		  if (insn_start_frag == frag_now)
		    add = (p - frag_now->fr_literal) - insn_start_off;
		  else
		    {
		      fragS *fr;

		      add = insn_start_frag->fr_fix - insn_start_off;
		      for (fr = insn_start_frag->fr_next;
			   fr && fr != frag_now; fr = fr->fr_next)
			add += fr->fr_fix;
		      add += p - frag_now->fr_literal;
		    }

		  if (reloc_type == BFD_RELOC_64)
		    reloc_type = BFD_RELOC_HEPTANE_GOTPC64;
		  else
		    /* Don't do the adjustment for x86-64, as there
		       the pcrel addressing is relative to the _next_
		       insn, and that is taken care of in other code.  */
		    reloc_type = BFD_RELOC_HEPTANE_GOTPC32;
		}
	      //fixP = 
              fix_new_exp (frag_now, p - frag_now->fr_literal,
				  size, i.op[n].disps, pcrel,
				  reloc_type);
	    }
	}
    }
}


static void
output_imm (fragS *insn_start_frag, offsetT insn_start_off)
{
  char *p;
  unsigned int n;

  for (n = 0; n < i.operands; n++)
    {

      if (operand_type_check (i.types[n], imm))
	{
	  if (i.op[n].imms->X_op == O_constant)
	    {
	      int size = imm_size (n);
	      offsetT val;

	      val = offset_in_range (i.op[n].imms->X_add_number,
				     size);
	      p = frag_more (size);
	      md_number_to_chars (p, val, size);
	    }
	  else
	    {
	      /* Not absolute_section.
		 Need a 32-bit fixup (don't support 8bit
		 non-absolute imms).  Try to support other
		 sizes ...  */
	      enum bfd_reloc_code_real reloc_type;
	      int size = imm_size (n);
	      int sign;

	      if (i.types[n].bitfield.imm32s
		  && (i.suffix == QWORD_MNEM_SUFFIX))
		    //  || (!i.suffix && i.tm.opcode_modifier.no_lsuf)))
		sign = 1;
	      else
		sign = 0;

	      p = frag_more (size);
	      reloc_type = reloc (size, 0, sign, i.reloc[n]);

	      /*   This is tough to explain.  We end up with this one if we
	       * have operands that look like
	       * "_GLOBAL_OFFSET_TABLE_+[.-.L284]".  The goal here is to
	       * obtain the absolute address of the GOT, and it is strongly
	       * preferable from a performance point of view to avoid using
	       * a runtime relocation for this.  The actual sequence of
	       * instructions often look something like:
	       *
	       *	call	.L66
	       * .L66:
	       *	popl	%ebx
	       *	addl	$_GLOBAL_OFFSET_TABLE_+[.-.L66],%ebx
	       *
	       *   The call and pop essentially return the absolute address
	       * of the label .L66 and store it in %ebx.  The linker itself
	       * will ultimately change the first operand of the addl so
	       * that %ebx points to the GOT, but to keep things simple, the
	       * .o file must have this operand set so that it generates not
	       * the absolute address of .L66, but the absolute address of
	       * itself.  This allows the linker itself simply treat a GOTPC
	       * relocation as asking for a pcrel offset to the GOT to be
	       * added in, and the addend of the relocation is stored in the
	       * operand field for the instruction itself.
	       *
	       *   Our job here is to fix the operand so that it would add
	       * the correct offset so that %ebx would point to itself.  The
	       * thing that is tricky is that .-.L66 will point to the
	       * beginning of the instruction, so we need to further modify
	       * the operand so that it will point to itself.  There are
	       * other cases where you have something like:
	       *
	       *	.long	$_GLOBAL_OFFSET_TABLE_+[.-.L66]
	       *
	       * and here no correction would be required.  Internally in
	       * the assembler we treat operands of this form as not being
	       * pcrel since the '.' is explicitly mentioned, and I wonder
	       * whether it would simplify matters to do it this way.  Who
	       * knows.  In earlier versions of the PIC patches, the
	       * pcrel_adjust field was used to store the correction, but
	       * since the expression is not pcrel, I felt it would be
	       * confusing to do it this way.  */

	      if ((reloc_type == BFD_RELOC_32
		   || reloc_type == BFD_RELOC_HEPTANE_32S
		   || reloc_type == BFD_RELOC_64)
		  && GOT_symbol
		  && GOT_symbol == i.op[n].imms->X_add_symbol
		  && (i.op[n].imms->X_op == O_symbol
		      || (i.op[n].imms->X_op == O_add
			  && ((symbol_get_value_expression
			       (i.op[n].imms->X_op_symbol)->X_op)
			      == O_subtract))))
		{
		  offsetT add;

		  if (insn_start_frag == frag_now)
		    add = (p - frag_now->fr_literal) - insn_start_off;
		  else
		    {
		      fragS *fr;

		      add = insn_start_frag->fr_fix - insn_start_off;
		      for (fr = insn_start_frag->fr_next;
			   fr && fr != frag_now; fr = fr->fr_next)
			add += fr->fr_fix;
		      add += p - frag_now->fr_literal;
		    }

		  if (size == 4)
		    reloc_type = BFD_RELOC_HEPTANE_GOTPC32;
		  else if (size == 8)
		    reloc_type = BFD_RELOC_HEPTANE_GOTPC64;
		  i.op[n].imms->X_add_number += add;
		}
	      fix_new_exp (frag_now, p - frag_now->fr_literal, size,
			   i.op[n].imms, 0, reloc_type);
	    }
	}
    }
}


/* x86_cons_fix_new is called via the expression parsing code when a
   reloc is needed.  We use this hook to get the correct .got reloc.  */
static int cons_sign = -1;

void
x86_cons_fix_new (fragS *frag, unsigned int off, unsigned int len,
		  expressionS *exp, bfd_reloc_code_real_type r)
{
  r = reloc (len, 0, cons_sign, r);

#ifdef TE_PE
  if (exp->X_op == O_secrel)
    {
      exp->X_op = O_symbol;
      r = BFD_RELOC_32_SECREL;
    }
#endif

  fix_new_exp (frag, off, len, exp, 0, r);
}

/* Export the ABI address size for use by TC_ADDRESS_BYTES for the
   purpose of the `.dc.a' internal pseudo-op.  */

int
x86_address_bytes (void)
{
  if ((stdoutput->arch_info->mach & bfd_mach_x64_32))
    return 4;
  return stdoutput->arch_info->bits_per_address / 8;
}

#if !(defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF) || defined (OBJ_MACH_O)) \
    || defined (LEX_AT)
# define lex_got(reloc, adjust, types) NULL
#else
/* Parse operands of the form
   <symbol>@GOTOFF+<nnn>
   and similar .plt or .got references.

   If we find one, set up the correct relocation in RELOC and copy the
   input string, minus the `@GOTOFF' into a malloc'd buffer for
   parsing by the calling routine.  Return this buffer, and if ADJUST
   is non-null set it to the length of the string we removed from the
   input line.  Otherwise return NULL.  */
static char *
lex_got (enum bfd_reloc_code_real *rel,
	 int *adjust,
	 i386_operand_type *types)
{
  /* Some of the relocations depend on the size of what field is to
     be relocated.  But in our callers i386_immediate and i386_displacement
     we don't yet know the operand size (this will be set by insn
     matching).  Hence we record the word32 relocation here,
     and adjust the reloc according to the real size in reloc().  */
  static const struct {
    const char *str;
    int len;
    const enum bfd_reloc_code_real rel[2];
    const i386_operand_type types64;
  } gotrel[] = {
#if defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF)
    { STRING_COMMA_LEN ("SIZE"),      { BFD_RELOC_SIZE32,
					BFD_RELOC_SIZE32 },
      OPERAND_TYPE_IMM32_64 },
#endif
    { STRING_COMMA_LEN ("PLTOFF"),   { _dummy_first_bfd_reloc_code_real,
				       BFD_RELOC_HEPTANE_PLTOFF64 },
      OPERAND_TYPE_IMM64 },
    { STRING_COMMA_LEN ("PLT"),      { BFD_RELOC_386_PLT32,
				       BFD_RELOC_HEPTANE_PLT32    },
      OPERAND_TYPE_IMM32_32S_DISP32 },
    { STRING_COMMA_LEN ("GOTPLT"),   { _dummy_first_bfd_reloc_code_real,
				       BFD_RELOC_HEPTANE_GOTPLT64 },
      OPERAND_TYPE_IMM64_DISP64 },
    { STRING_COMMA_LEN ("GOTOFF"),   { BFD_RELOC_386_GOTOFF,
				       BFD_RELOC_HEPTANE_GOTOFF64 },
      OPERAND_TYPE_IMM64_DISP64 },
    { STRING_COMMA_LEN ("GOTPCREL"), { _dummy_first_bfd_reloc_code_real,
				       BFD_RELOC_HEPTANE_GOTPCREL },
      OPERAND_TYPE_IMM32_32S_DISP32 },
    { STRING_COMMA_LEN ("TLSGD"),    { BFD_RELOC_386_TLS_GD,
				       BFD_RELOC_HEPTANE_TLSGD    },
      OPERAND_TYPE_IMM32_32S_DISP32 },
    { STRING_COMMA_LEN ("TLSLDM"),   { BFD_RELOC_386_TLS_LDM,
				       _dummy_first_bfd_reloc_code_real },
      OPERAND_TYPE_NONE },
    { STRING_COMMA_LEN ("TLSLD"),    { _dummy_first_bfd_reloc_code_real,
				       BFD_RELOC_HEPTANE_TLSLD    },
      OPERAND_TYPE_IMM32_32S_DISP32 },
    { STRING_COMMA_LEN ("GOTTPOFF"), { BFD_RELOC_386_TLS_IE_32,
				       BFD_RELOC_HEPTANE_GOTTPOFF },
      OPERAND_TYPE_IMM32_32S_DISP32 },
    { STRING_COMMA_LEN ("TPOFF"),    { BFD_RELOC_386_TLS_LE_32,
				       BFD_RELOC_HEPTANE_TPOFF32  },
      OPERAND_TYPE_IMM32_32S_64_DISP32_64 },
    { STRING_COMMA_LEN ("NTPOFF"),   { BFD_RELOC_386_TLS_LE,
				       _dummy_first_bfd_reloc_code_real },
      OPERAND_TYPE_NONE },
    { STRING_COMMA_LEN ("DTPOFF"),   { BFD_RELOC_386_TLS_LDO_32,
				       BFD_RELOC_HEPTANE_DTPOFF32 },
      OPERAND_TYPE_IMM32_32S_64_DISP32_64 },
    { STRING_COMMA_LEN ("GOTNTPOFF"),{ BFD_RELOC_386_TLS_GOTIE,
				       _dummy_first_bfd_reloc_code_real },
      OPERAND_TYPE_NONE },
    { STRING_COMMA_LEN ("INDNTPOFF"),{ BFD_RELOC_386_TLS_IE,
				       _dummy_first_bfd_reloc_code_real },
      OPERAND_TYPE_NONE },
    { STRING_COMMA_LEN ("GOT"),      { BFD_RELOC_386_GOT32,
				       BFD_RELOC_HEPTANE_GOT32    },
      OPERAND_TYPE_IMM32_32S_64_DISP32 },
    { STRING_COMMA_LEN ("TLSDESC"),  { BFD_RELOC_386_TLS_GOTDESC,
				       BFD_RELOC_HEPTANE_GOTPC32_TLSDESC },
      OPERAND_TYPE_IMM32_32S_DISP32 },
    { STRING_COMMA_LEN ("TLSCALL"),  { BFD_RELOC_386_TLS_DESC_CALL,
				       BFD_RELOC_HEPTANE_TLSDESC_CALL },
      OPERAND_TYPE_IMM32_32S_DISP32 },
  };
  char *cp;
  unsigned int j;

#if defined (OBJ_MAYBE_ELF)
  if (!IS_ELF)
    return NULL;
#endif

  for (cp = input_line_pointer; *cp != '@'; cp++)
    if (is_end_of_line[(unsigned char) *cp] || *cp == ',')
      return NULL;

  for (j = 0; j < ARRAY_SIZE (gotrel); j++)
    {
      int len = gotrel[j].len;
      if (strncasecmp (cp + 1, gotrel[j].str, len) == 0)
	{
	  if (gotrel[j].rel[object_64bit] != 0)
	    {
	      int first, second;
	      char *tmpbuf, *past_reloc;

	      *rel = gotrel[j].rel[object_64bit];

	      if (types)
		{
		  if (flag_code != CODE_64BIT)
		    {
		      types->bitfield.imm32 = 1;
		      types->bitfield.disp32 = 1;
		    }
		  else
		    *types = gotrel[j].types64;
		}

	      if (j != 0 && GOT_symbol == NULL)
		GOT_symbol = symbol_find_or_make (GLOBAL_OFFSET_TABLE_NAME);

	      /* The length of the first part of our input line.  */
	      first = cp - input_line_pointer;

	      /* The second part goes from after the reloc token until
		 (and including) an end_of_line char or comma.  */
	      past_reloc = cp + 1 + len;
	      cp = past_reloc;
	      while (!is_end_of_line[(unsigned char) *cp] && *cp != ',')
		++cp;
	      second = cp + 1 - past_reloc;

	      /* Allocate and copy string.  The trailing NUL shouldn't
		 be necessary, but be safe.  */
	      tmpbuf = (char *) xmalloc (first + second + 2);
	      memcpy (tmpbuf, input_line_pointer, first);
	      if (second != 0 && *past_reloc != ' ')
		/* Replace the relocation token with ' ', so that
		   errors like foo@GOTOFF1 will be detected.  */
		tmpbuf[first++] = ' ';
	      else
		/* Increment length by 1 if the relocation token is
		   removed.  */
		len++;
	      if (adjust)
		*adjust = len;
	      memcpy (tmpbuf + first, past_reloc, second);
	      tmpbuf[first + second] = '\0';
	      return tmpbuf;
	    }

	  as_bad (_("@%s reloc is not supported with %d-bit output format"),
		  gotrel[j].str, 1 << (5 + object_64bit));
	  return NULL;
	}
    }

  /* Might be a symbol version string.  Don't as_bad here.  */
  return NULL;
}
#endif

#ifdef TE_PE
#ifdef lex_got
#undef lex_got
#endif
/* Parse operands of the form
   <symbol>@SECREL32+<nnn>

   If we find one, set up the correct relocation in RELOC and copy the
   input string, minus the `@SECREL32' into a malloc'd buffer for
   parsing by the calling routine.  Return this buffer, and if ADJUST
   is non-null set it to the length of the string we removed from the
   input line.  Otherwise return NULL.

   This function is copied from the ELF version above adjusted for PE targets.  */

static char *
lex_got (enum bfd_reloc_code_real *rel ATTRIBUTE_UNUSED,
	 int *adjust ATTRIBUTE_UNUSED,
	 i386_operand_type *types)
{
  static const struct
  {
    const char *str;
    int len;
    const enum bfd_reloc_code_real rel[2];
    const i386_operand_type types64;
  }
  gotrel[] =
  {
    { STRING_COMMA_LEN ("SECREL32"),    { BFD_RELOC_32_SECREL,
					  BFD_RELOC_32_SECREL },
      OPERAND_TYPE_IMM32_32S_64_DISP32_64 },
  };

  char *cp;
  unsigned j;

  for (cp = input_line_pointer; *cp != '@'; cp++)
    if (is_end_of_line[(unsigned char) *cp] || *cp == ',')
      return NULL;

  for (j = 0; j < ARRAY_SIZE (gotrel); j++)
    {
      int len = gotrel[j].len;

      if (strncasecmp (cp + 1, gotrel[j].str, len) == 0)
	{
	  if (gotrel[j].rel[object_64bit] != 0)
	    {
	      int first, second;
	      char *tmpbuf, *past_reloc;

	      *rel = gotrel[j].rel[object_64bit];
	      if (adjust)
		*adjust = len;

	      if (types)
		{
		  if (flag_code != CODE_64BIT)
		    {
		      types->bitfield.imm32 = 1;
		      types->bitfield.disp32 = 1;
		    }
		  else
		    *types = gotrel[j].types64;
		}

	      /* The length of the first part of our input line.  */
	      first = cp - input_line_pointer;

	      /* The second part goes from after the reloc token until
		 (and including) an end_of_line char or comma.  */
	      past_reloc = cp + 1 + len;
	      cp = past_reloc;
	      while (!is_end_of_line[(unsigned char) *cp] && *cp != ',')
		++cp;
	      second = cp + 1 - past_reloc;

	      /* Allocate and copy string.  The trailing NUL shouldn't
		 be necessary, but be safe.  */
	      tmpbuf = (char *) xmalloc (first + second + 2);
	      memcpy (tmpbuf, input_line_pointer, first);
	      if (second != 0 && *past_reloc != ' ')
		/* Replace the relocation token with ' ', so that
		   errors like foo@SECLREL321 will be detected.  */
		tmpbuf[first++] = ' ';
	      memcpy (tmpbuf + first, past_reloc, second);
	      tmpbuf[first + second] = '\0';
	      return tmpbuf;
	    }

	  as_bad (_("@%s reloc is not supported with %d-bit output format"),
		  gotrel[j].str, 1 << (5 + object_64bit));
	  return NULL;
	}
    }

  /* Might be a symbol version string.  Don't as_bad here.  */
  return NULL;
}

#endif /* TE_PE */

bfd_reloc_code_real_type
x86_cons (expressionS *exp, int size)
{
  bfd_reloc_code_real_type got_reloc = NO_RELOC;

//  intel_syntax = -intel_syntax;

  exp->X_md = 0;
  if (size == 4 || (object_64bit && size == 8))
    {
      /* Handle @GOTOFF and the like in an expression.  */
      char *save;
      char *gotfree_input_line;
      int adjust = 0;

      save = input_line_pointer;
      gotfree_input_line = lex_got (&got_reloc, &adjust, NULL);
      if (gotfree_input_line)
	input_line_pointer = gotfree_input_line;

      expression (exp);

      if (gotfree_input_line)
	{
	  /* expression () has merrily parsed up to the end of line,
	     or a comma - in the wrong buffer.  Transfer how far
	     input_line_pointer has moved to the right buffer.  */
	  input_line_pointer = (save
				+ (input_line_pointer - gotfree_input_line)
				+ adjust);
	  free (gotfree_input_line);
	  if (exp->X_op == O_constant
	      || exp->X_op == O_absent
	      || exp->X_op == O_illegal
	      || exp->X_op == O_register
	      || exp->X_op == O_big)
	    {
	      char c = *input_line_pointer;
	      *input_line_pointer = 0;
	      as_bad (_("missing or invalid expression `%s'"), save);
	      *input_line_pointer = c;
	    }
	}
    }
  else
    expression (exp);

//  intel_syntax = -intel_syntax;

//  if (intel_syntax)
//    i386_intel_simplify (exp);

  return got_reloc;
}

static void
signed_cons (int size)
{
  if (flag_code == CODE_64BIT)
    cons_sign = 1;
  cons (size);
  cons_sign = -1;
}

#ifdef TE_PE
static void
pe_directive_secrel (int dummy ATTRIBUTE_UNUSED)
{
  expressionS exp;

  do
    {
      expression (&exp);
      if (exp.X_op == O_symbol)
	exp.X_op = O_secrel;

      emit_expr (&exp, 4);
    }
  while (*input_line_pointer++ == ',');

  input_line_pointer--;
  demand_empty_rest_of_line ();
}
#endif

static int
i386_finalize_immediate (segT exp_seg ATTRIBUTE_UNUSED, expressionS *exp,
			 i386_operand_type types, const char *imm_start);


static int
i386_immediate (char *imm_start)
{
  char *save_input_line_pointer;
  char *gotfree_input_line;
  segT exp_seg = 0;
  expressionS *exp;
  i386_operand_type types;

  operand_type_set (&types, ~0);

  if (i.imm_operands == MAX_IMMEDIATE_OPERANDS)
    {
      as_bad (_("at most %d immediate operands are allowed"),
	      MAX_IMMEDIATE_OPERANDS);
      return 0;
    }

  exp = &im_expressions[i.imm_operands++];
  i.op[this_operand].imms = exp;

  if (is_space_char (*imm_start))
    ++imm_start;

  save_input_line_pointer = input_line_pointer;
  input_line_pointer = imm_start;

  gotfree_input_line = lex_got (&i.reloc[this_operand], NULL, &types);
  if (gotfree_input_line)
    input_line_pointer = gotfree_input_line;

  exp_seg = expression (exp);

  SKIP_WHITESPACE ();


  if (*input_line_pointer)
    as_bad (_("junk `%s' after expression"), input_line_pointer);

  input_line_pointer = save_input_line_pointer;
  if (gotfree_input_line)
    {
      free (gotfree_input_line);

      if (exp->X_op == O_constant || exp->X_op == O_register)
	exp->X_op = O_illegal;
    }

  return i386_finalize_immediate (exp_seg, exp, types, imm_start);
}

static int
i386_finalize_immediate (segT exp_seg ATTRIBUTE_UNUSED, expressionS *exp,
			 i386_operand_type types, const char *imm_start)
{
  if (exp->X_op == O_absent || exp->X_op == O_illegal || exp->X_op == O_big)
    {
      if (imm_start)
	as_bad (_("missing or invalid immediate expression `%s'"),
		imm_start);
      return 0;
    }
  else if (exp->X_op == O_constant)
    {
      /* Size it properly later.  */
      i.types[this_operand].bitfield.imm64 =1;
      i.types[this_operand].bitfield.imm8 = 1;
      i.types[this_operand].bitfield.imm13s = 1;
      i.types[this_operand].bitfield.imm32 = 1;
      i.types[this_operand].bitfield.imm32s = 1;
    }
  
  else if (exp_seg == reg_section)
    {
      if (imm_start)
	as_bad (_("illegal immediate register operand %s"), imm_start);
      return 0;
    }
  else
    {
      /* This is an address.  The size of the address will be
	 determined later, depending on destination register,
	 suffix, or the default for the section.  */
      i.types[this_operand].bitfield.imm8 = 1;
      i.types[this_operand].bitfield.imm13s = 1;
      i.types[this_operand].bitfield.imm32 = 1;
      i.types[this_operand].bitfield.imm32s = 1;
      i.types[this_operand].bitfield.imm64 = 1;
      i.types[this_operand] = operand_type_and (i.types[this_operand],
						types);
    }

  return 1;
}

static char *
i386_scale (char *scale)
{
  offsetT val;
  char *save = input_line_pointer;

  input_line_pointer = scale;
  val = get_absolute_expression ();

  switch (val)
    {
    case 1:
      i.log2_scale_factor = 0;
      break;
    case 2:
      i.log2_scale_factor = 1;
      break;
    case 4:
      i.log2_scale_factor = 2;
      break;
    case 8:
      i.log2_scale_factor = 3;
      break;
    default:
      {
	char sep = *input_line_pointer;

	*input_line_pointer = '\0';
	as_bad (_("expecting scale factor of 1, 2, 4, or 8: got `%s'"),
		scale);
	*input_line_pointer = sep;
	input_line_pointer = save;
	return NULL;
      }
    }
  if (i.log2_scale_factor != 0 && i.index_reg == 0)
    {
      as_warn (_("scale factor of %d without an index register"),
	       1 << i.log2_scale_factor);
      i.log2_scale_factor = 0;
    }
  scale = input_line_pointer;
  input_line_pointer = save;
  return scale;
}

static int
i386_finalize_displacement (segT exp_seg ATTRIBUTE_UNUSED, expressionS *exp,
			    i386_operand_type types, const char *disp_start);

static int
i386_displacement (char *disp_start, char *disp_end)
{
  expressionS *exp;
  segT exp_seg = 0;
  char *save_input_line_pointer;
  char *gotfree_input_line;
  //int override;
  i386_operand_type bigdisp, types = anydisp;
  int ret;

  if (i.disp_operands == MAX_MEMORY_OPERANDS)
    {
      as_bad (_("at most %d displacement operands are allowed"),
	      MAX_MEMORY_OPERANDS);
      return 0;
    }

  operand_type_set (&bigdisp, 0);
  if ((i.types[this_operand].bitfield.jumpabsolute)
      || (!(current_templates->start->group==instrg_isIndirJump) 
        && !(current_templates->start->group==instrg_isCondJump)
	&& !(current_templates->start->group==instrg_isUncondJump)
	&& !(current_templates->start->group==instrg_isCall)
	&& !(current_templates->start->group==instrg_isRet)))
    {
      bigdisp.bitfield.disp32 = 1;
      bigdisp.bitfield.disp32s = 1;
      bigdisp.bitfield.disp64 = 1;
    }
  else
    {
      /* For PC-relative branches, the width of the displacement
	 is dependent upon data size, not address size.  */
      bigdisp.bitfield.disp32 = 1;
      bigdisp.bitfield.disp32s = 1;
    }
  i.types[this_operand] = operand_type_or (i.types[this_operand],
					   bigdisp);

  exp = &disp_expressions[i.disp_operands];
  i.op[this_operand].disps = exp;
  i.disp_operands++;
  save_input_line_pointer = input_line_pointer;
  input_line_pointer = disp_start;
  END_STRING_AND_SAVE (disp_end);

#ifndef GCC_ASM_O_HACK
#define GCC_ASM_O_HACK 0
#endif
#if GCC_ASM_O_HACK
  END_STRING_AND_SAVE (disp_end + 1);
  if (i.types[this_operand].bitfield.baseIndex
      && displacement_string_end[-1] == '+')
    {
      /* This hack is to avoid a warning when using the "o"
	 constraint within gcc asm statements.
	 For instance:

	 #define _set_tssldt_desc(n,addr,limit,type) \
	 __asm__ __volatile__ ( \
	 "movw %w2,%0\n\t" \
	 "movw %w1,2+%0\n\t" \
	 "rorl $16,%1\n\t" \
	 "movb %b1,4+%0\n\t" \
	 "movb %4,5+%0\n\t" \
	 "movb $0,6+%0\n\t" \
	 "movb %h1,7+%0\n\t" \
	 "rorl $16,%1" \
	 : "=o"(*(n)) : "q" (addr), "ri"(limit), "i"(type))

	 This works great except that the output assembler ends
	 up looking a bit weird if it turns out that there is
	 no offset.  You end up producing code that looks like:

	 #APP
	 movw $235,(%eax)
	 movw %dx,2+(%eax)
	 rorl $16,%edx
	 movb %dl,4+(%eax)
	 movb $137,5+(%eax)
	 movb $0,6+(%eax)
	 movb %dh,7+(%eax)
	 rorl $16,%edx
	 #NO_APP

	 So here we provide the missing zero.  */

      *displacement_string_end = '0';
    }
#endif
  gotfree_input_line = lex_got (&i.reloc[this_operand], NULL, &types);
  if (gotfree_input_line)
    input_line_pointer = gotfree_input_line;

  exp_seg = expression (exp);

  SKIP_WHITESPACE ();
  if (*input_line_pointer)
    as_bad (_("junk `%s' after expression"), input_line_pointer);
#if GCC_ASM_O_HACK
  RESTORE_END_STRING (disp_end + 1);
#endif
  input_line_pointer = save_input_line_pointer;
  if (gotfree_input_line)
    {
      free (gotfree_input_line);

      if (exp->X_op == O_constant || exp->X_op == O_register)
	exp->X_op = O_illegal;
    }

  ret = i386_finalize_displacement (exp_seg, exp, types, disp_start);

  RESTORE_END_STRING (disp_end);

  return ret;
}

static int
i386_finalize_displacement (segT exp_seg ATTRIBUTE_UNUSED, expressionS *exp,
			    i386_operand_type types, const char *disp_start)
{
  i386_operand_type bigdisp;
  int ret = 1;

  /* We do this to make sure that the section symbol is in
     the symbol table.  We will ultimately change the relocation
     to be relative to the beginning of the section.  */
  if (   i.reloc[this_operand] == BFD_RELOC_HEPTANE_GOTPCREL
      || i.reloc[this_operand] == BFD_RELOC_HEPTANE_GOTOFF64)
    {
      if (exp->X_op != O_symbol)
	goto inv_disp;

      if (S_IS_LOCAL (exp->X_add_symbol)
	  && S_GET_SEGMENT (exp->X_add_symbol) != undefined_section
	  && S_GET_SEGMENT (exp->X_add_symbol) != expr_section)
	section_symbol (S_GET_SEGMENT (exp->X_add_symbol));
      exp->X_op = O_subtract;
      exp->X_op_symbol = GOT_symbol;
      if (i.reloc[this_operand] == BFD_RELOC_HEPTANE_GOTPCREL)
	i.reloc[this_operand] = BFD_RELOC_32_PCREL;
      else if (i.reloc[this_operand] == BFD_RELOC_HEPTANE_GOTOFF64)
	i.reloc[this_operand] = BFD_RELOC_64;
      else
	i.reloc[this_operand] = BFD_RELOC_32;
    }

  else if (exp->X_op == O_absent
	   || exp->X_op == O_illegal
	   || exp->X_op == O_big)
    {
    inv_disp:
      as_bad (_("missing or invalid displacement expression `%s'"),
	      disp_start);
      ret = 0;
    }

  else if (exp->X_op == O_constant)
    {
      /* Since displacement is signed extended to 64bit, don't allow
	 disp32 and turn off disp32s if they are out of range.  */
      i.types[this_operand].bitfield.disp32 = 0;
      if (!fits_in_signed_long (exp->X_add_number))
	{
	  i.types[this_operand].bitfield.disp32s = 0;
	  if (i.types[this_operand].bitfield.baseindex)
	    {
	      as_bad (_("0x%lx out range of signed 32bit displacement"),
		      (long) exp->X_add_number);
	      ret = 0;
	    }
	}
    }

#if (defined (OBJ_AOUT) || defined (OBJ_MAYBE_AOUT))
  else if (exp->X_op != O_constant
	   && OUTPUT_FLAVOR == bfd_target_aout_flavour
	   && exp_seg != absolute_section
	   && exp_seg != text_section
	   && exp_seg != data_section
	   && exp_seg != bss_section
	   && exp_seg != undefined_section
	   && !bfd_is_com_section (exp_seg))
    {
      as_bad (_("unimplemented segment %s in operand"), exp_seg->name);
      ret = 0;
    }
#endif

  /* Check if this is a displacement only operand.  */
  bigdisp = i.types[this_operand];
  bigdisp.bitfield.disp14s = 0;
  bigdisp.bitfield.disp32 = 0;
  bigdisp.bitfield.disp32s = 0;
  bigdisp.bitfield.disp64 = 0;
  if (operand_type_all_zero (&bigdisp))
    i.types[this_operand] = operand_type_and (i.types[this_operand],
					      types);

  return ret;
}

/* Make sure the memory operand we've been dealt is valid.
   Return 1 on success, 0 on a failure.  */

static int
i386_index_check (void)
{
  //const char *kind = "base/index";
  if (i.base_reg && i.index_reg) 
     return i.base_reg->reg_num!=7; 
  return 1;
}



/* Parse OPERAND_STRING into the i386_insn structure I.  Returns zero
   on error.  */

static int
i386_att_operand (char *operand_string)
{
  const reg_entry *r;
  char *end_op;
  char *op_string = operand_string;

  if (is_space_char (*op_string))
    ++op_string;

  /* We check for an absolute prefix (differentiating,
     for example, 'jmp pc_relative_label' from 'jmp *absolute_label'.  */
  if (*op_string == ABSOLUTE_PREFIX)
    {
      ++op_string;
      if (is_space_char (*op_string))
	++op_string;
      i.types[this_operand].bitfield.jumpabsolute = 1;
    }

  /* Check if operand is a register.  */
  if ((r = parse_register (op_string, &end_op)) != NULL)
    {
      i386_operand_type temp;

      /* Check for a segment override by searching for ':' after a
	 segment register.  */
      op_string = end_op;
      if (is_space_char (*op_string))
	++op_string;


      if (*op_string)
	{
	  as_bad (_("junk `%s' after register"), op_string);
	  return 0;
	}
      temp = r->reg_type;
      temp.bitfield.baseindex = 0;
      i.types[this_operand] = operand_type_or (i.types[this_operand],
					       temp);
      i.types[this_operand].bitfield.unspecified = 0;
      i.op[this_operand].regs = r;
      i.reg_operands++;
    }
  else if (*op_string == REGISTER_PREFIX)
    {
      as_bad (_("bad register name `%s'"), op_string);
      return 0;
    }
  else if (*op_string == IMMEDIATE_PREFIX)
    {
      ++op_string;
      if (i.types[this_operand].bitfield.jumpabsolute)
	{
	  as_bad (_("immediate operand illegal with absolute jump"));
	  return 0;
	}
      if (!i386_immediate (op_string))
	return 0;
    }
  else if (is_digit_char (*op_string)
	   || is_identifier_char (*op_string)
	   || *op_string == '"'
	   || *op_string == '(')
    {
      /* This is a memory reference of some sort.  */
      char *base_string;

      /* Start and end of displacement string expression (if found).  */
      char *displacement_string_start;
      char *displacement_string_end;
      //ichar *vop_start;

//    do_memory_reference:
      if ( i.mem_operands == 2)
	{
	  as_bad (_("too many memory references for `%s'"),
		  current_templates->start->name);
	  return 0;
	}

      /* Check for base index form.  We detect the base index form by
	 looking for an ')' at the end of the operand, searching
	 for the '(' matching it, and finding a REGISTER_PREFIX or ','
	 after the '('.  */
      base_string = op_string + strlen (op_string);

      /* Handle vector operations.  */
     // vop_start = strchr (op_string, '{');

      --base_string;
      if (is_space_char (*base_string))
	--base_string;

      /* If we only have a displacement, set-up for it to be parsed later.  */
      displacement_string_start = op_string;
      displacement_string_end = base_string + 1;

      if (*base_string == ')')
	{
	  char *temp_string;
	  unsigned int parens_balanced = 1;
	  /* We've already checked that the number of left & right ()'s are
	     equal, so this loop will not be infinite.  */
	  do
	    {
	      base_string--;
	      if (*base_string == ')')
		parens_balanced++;
	      if (*base_string == '(')
		parens_balanced--;
	    }
	  while (parens_balanced);

	  temp_string = base_string;

	  /* Skip past '(' and whitespace.  */
	  ++base_string;
	  if (is_space_char (*base_string))
	    ++base_string;

	  if (*base_string == ','
	      || ((i.base_reg = parse_register (base_string, &end_op))
		  != NULL))
	    {
	      displacement_string_end = temp_string;

	      i.types[this_operand].bitfield.baseindex = 1;

	      if (i.base_reg)
		{
		  base_string = end_op;
		  if (is_space_char (*base_string))
		    ++base_string;
		}

	      /* There may be an index reg or scale factor here.  */
	      if (*base_string == ',')
		{
		  ++base_string;
		  if (is_space_char (*base_string))
		    ++base_string;

		  if ((i.index_reg = parse_register (base_string, &end_op))
		      != NULL)
		    {
		      base_string = end_op;
		      if (is_space_char (*base_string))
			++base_string;
		      if (*base_string == ',')
			{
			  ++base_string;
			  if (is_space_char (*base_string))
			    ++base_string;
			}
		      else if (*base_string != ')')
			{
			  as_bad (_("expecting `,' or `)' "
				    "after index register in `%s'"),
				  operand_string);
			  return 0;
			}
		    }
		  else if (*base_string == REGISTER_PREFIX)
		    {
		      end_op = strchr (base_string, ',');
		      if (end_op)
			*end_op = '\0';
		      as_bad (_("bad register name `%s'"), base_string);
		      return 0;
		    }

		  /* Check for scale factor.  */
		  if (*base_string != ')')
		    {
		      char *end_scale = i386_scale (base_string);

		      if (!end_scale)
			return 0;

		      base_string = end_scale;
		      if (is_space_char (*base_string))
			++base_string;
		      if (*base_string != ')')
			{
			  as_bad (_("expecting `)' "
				    "after scale factor in `%s'"),
				  operand_string);
			  return 0;
			}
		    }
		  else if (!i.index_reg)
		    {
		      as_bad (_("expecting index register or scale factor "
				"after `,'; got '%c'"),
			      *base_string);
		      return 0;
		    }
		}
	      else if (*base_string != ')')
		{
		  as_bad (_("expecting `,' or `)' "
			    "after base register in `%s'"),
			  operand_string);
		  return 0;
		}
	    }
	  else if (*base_string == REGISTER_PREFIX)
	    {
	      end_op = strchr (base_string, ',');
	      if (end_op)
		*end_op = '\0';
	      as_bad (_("bad register name `%s'"), base_string);
	      return 0;
	    }
	}

      /* If there's an expression beginning the operand, parse it,
	 assuming displacement_string_start and
	 displacement_string_end are meaningful.  */
      if (displacement_string_start != displacement_string_end)
	{
	  if (!i386_displacement (displacement_string_start,
				  displacement_string_end))
	    return 0;
	}


      if (i386_index_check () == 0)
	return 0;
      i.types[this_operand].bitfield.mem = 1;
      i.mem_operands++;
    }
  else
    {
      /* It's not a memory operand; argh!  */
      as_bad (_("invalid char %s beginning operand %d `%s'"),
	      output_invalid (*op_string),
	      this_operand + 1,
	      op_string);
      return 0;
    }
  return 1;			/* Normal return.  */
}

/* Calculate the maximum variable size (i.e., excluding fr_fix)
   that an rs_machine_dependent frag may reach.  */

unsigned int
i386_frag_max_var (fragS *frag)
{
  /* The only relaxable frags are for jumps.
     Unconditional jumps can grow by 4 bytes and others by 5 bytes.  */
  gas_assert (frag->fr_type == rs_machine_dependent);
  return 28;
}

#if defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF)
/*static int
elf_symbol_resolved_in_segment_p (symbolS *fr_symbol, offsetT fr_var)
{
  /,* STT_GNU_IFUNC symbol must go through PLT.  *,/
  if ((symbol_get_bfdsym (fr_symbol)->flags
       & BSF_GNU_INDIRECT_FUNCTION) != 0)
    return 0;

  if (!S_IS_EXTERNAL (fr_symbol))
    /,* Symbol may be weak or local.  *,/
    return !S_IS_WEAK (fr_symbol);

  /,* Global symbols with non-default visibility can't be preempted. *,/
  if (ELF_ST_VISIBILITY (S_GET_OTHER (fr_symbol)) != STV_DEFAULT)
    return 1;

  if (fr_var != NO_RELOC)
    switch ((enum bfd_reloc_code_real) fr_var)
      {
      case BFD_RELOC_HEPTANE_PLT32:
	/,* Symbol with PLT relocatin may be preempted. *,/
	return 0;
      default:
	abort ();
      }

  /,* Global symbols with default visibility in a shared library may be
     preempted by another definition.  *,/
  return !shared;
}*/
#endif

/* get the size before and including magic bits; */
static offsetT relax_get_bottom_size(fragS *fragP)
{
  int type=TYPE_FROM_RELAX_STATE(fragP->fr_subtype);
  int sz;
  if (fragP->fr_type!=rs_machine_dependent) return (15-insn_stop)*2;
  sz=DISP_SIZE_FROM_RELAX_STATE(fragP->fr_subtype);
  if (fragP->fr_subtype==ENCODE_RELAX_STATE(NON_JUMP,BIGGER)) sz+=2;;
  if (fragP->fr_subtype==ENCODE_RELAX_STATE(COMPARE_JUMP,BIGGER)) sz+=2;;
 // if ((fragP->fr_address&0x1f)==0) return 0;
  if (insn_count==12) return (15-insn_stop)*2;
  if ((insn_stop*2+sz)>28) return (15-insn_stop)*2;
  if (type!=NON_JUMP && insn_jumps>=4) return (15-insn_stop)*2;
  return 0;
}
static offsetT relax_get_bottom_size2(fragS *fragP)
{
  int type=TYPE_FROM_RELAX_STATE(fragP->fr_subtype);
  int sz;
  if (fragP->fr_type!=rs_machine_dependent) return (15-insn_stop)*2;
  sz=DISP_SIZE_FROM_RELAX_STATE(fragP->fr_subtype);
  if (fragP->fr_subtype==ENCODE_RELAX_STATE(NON_JUMP,BIGGER)) sz+=2;;
  if (fragP->fr_subtype==ENCODE_RELAX_STATE(COMPARE_JUMP,BIGGER)) sz+=2;;
  //sz=fragP->last_fr_size-2;
//  if (fragP->fr_subtype==ENCODE_RELAX_STATE(NON_JUMP,BIGGER)) sz+=2;;
//  if ((fragP->fr_address&0x1f)==0) return 0;
  if (insn_count==12) return (15-insn_stop)*2;
  if ((insn_stop*2+sz)>28) return (15-insn_stop)*2;
  if (type!=NON_JUMP && insn_jumps>=4) return (15-insn_stop)*2;
  return 0;
}

static void relax_proceed_instr(fragS *fragP)
{
  offsetT ofs=relax_get_bottom_size(fragP);
  int type=TYPE_FROM_RELAX_STATE(fragP->fr_subtype);
  int sz;
  if (fragP->fr_type!=rs_machine_dependent) {
    insn_bits=0;
    insn_count=0;
    insn_stop=-1;
    insn_jumps=0;
    return;
  }
  sz=DISP_SIZE_FROM_RELAX_STATE(fragP->fr_subtype);
//  int ptr;
  if (fragP->fr_subtype==ENCODE_RELAX_STATE(NON_JUMP,BIGGER)) sz+=2;
  if (fragP->fr_subtype==ENCODE_RELAX_STATE(COMPARE_JUMP,BIGGER)) sz+=2;
 /* 
  if ((addr&0x1f)==0) 
    {
      insn_bits=0;
      insn_count=0;
      insn_stop=-1;
      insn_jumps=0;
    }
*/
  if (ofs) 
    {
      insn_bits=1<<(sz/2);
      insn_count=1;
      insn_stop=sz/2;
      insn_jumps=type!=NON_JUMP;
    }
  else 
    {
      insn_bits=insn_bits | (1<<(sz/2+insn_stop+1));
      insn_count++;
      insn_stop+=sz/2+1;
      insn_jumps+=type!=NON_JUMP;
    }
}

static void relax_proceed_instr2(fragS *fragP)
{
  offsetT ofs=relax_get_bottom_size2(fragP);
  int type=TYPE_FROM_RELAX_STATE(fragP->fr_subtype);
  int sz;
  insn_bits_s=insn_bits;
  insn_count_s=insn_count;
  insn_stop_s=insn_stop;
  insn_jumps_s=insn_jumps;
  if (fragP->fr_type!=rs_machine_dependent) {
    insn_bits=0;
    insn_count=0;
    insn_stop=-1;
    insn_jumps=0;
    return;
  }
  sz=DISP_SIZE_FROM_RELAX_STATE(fragP->fr_subtype);
  if (fragP->fr_subtype==ENCODE_RELAX_STATE(NON_JUMP,BIGGER)) sz+=2;;
  if (fragP->fr_subtype==ENCODE_RELAX_STATE(COMPARE_JUMP,BIGGER)) sz+=2;;
//  int ptr;
//  if (fragP->fr_subtype==ENCODE_RELAX_STATE(NON_JUMP,BIGGER)) sz+=2;
//  if (fragP->fr_subtype==ENCODE_RELAX_STATE(COMPARE_JUMP,BIGGER)) sz+=2;
 /* 
  if ((fragP->fr_address&0x1f)==0) 
    {
      insn_bits=0;
      insn_count=0;
      insn_stop=-1;
      insn_jumps=0;
    }
*/
  if (ofs) 
    {
      insn_bits=1<<(sz/2);
      insn_count=1;
      insn_stop=sz/2;
      insn_jumps=type!=NON_JUMP;
    }
  else 
    {
      insn_bits=insn_bits | (1<<(sz/2+insn_stop+1));
      insn_count++;
      insn_stop+=sz/2+1;
      insn_jumps+=type!=NON_JUMP;
    }
}

static void relax_unproceed_instr(void) {
  insn_bits=insn_bits_s;
  insn_count=insn_count_s;
  insn_stop=insn_stop_s;
  insn_jumps=insn_jumps_s;
  
}

/*
  calculate relaxed frag size, including "back-size" kludge
 at first instruction of bundle.
*/
int
heptane_relax_frag (segT segment, fragS *fragP, long stretch)
{
  const relax_typeS *this_type;
//  const relax_typeS *start_type;
  relax_substateT next_state;
  relax_substateT this_state;
  relax_substateT start_state;
  offsetT growth;
  offsetT aim;
  addressT target;
  addressT address;
  symbolS *symbolP;
  const relax_typeS *table;
  offsetT backSize;
  int sz;
  sz=DISP_SIZE_FROM_RELAX_STATE(fragP->fr_subtype);
  if (fragP->fr_subtype==ENCODE_RELAX_STATE(NON_JUMP,BIGGER)) sz+=2;;
  if (fragP->fr_subtype==ENCODE_RELAX_STATE(COMPARE_JUMP,BIGGER)) sz+=2;;

  target = fragP->fr_offset;
  address = fragP->fr_address;
  table = md_relax_table;
  this_state = fragP->fr_subtype;
 /* start_type =*/ this_type = table + this_state;
  symbolP = fragP->fr_symbol;
//  if (!XXFR) XXFR=fragP;
  if ((fragP->fr_address&0x1fll)==0ll) {
    insn_stop=-1;
    insn_bits=0x0;
    insn_count=0;
    insn_jumps=0;
    relax_proceed_instr2(fragP);
  }
  if (fragP->fr_next) {
    backSize=relax_get_bottom_size2(fragP->fr_next);
  } else {
    backSize=((address+31)&0xffffffffffffffe0)-address;
  }
 
  if (TYPE_FROM_RELAX_STATE(fragP->fr_subtype)==NON_JUMP ||
     TYPE_FROM_RELAX_STATE(fragP->fr_subtype)==UNREL_JUMP  )
    {
      growth=backSize+sz+2-fragP->last_fr_size-
        (valueT) fragP->fr_opcode;
      //fragP->last_fr_size+=;
      fragP->fr_opcode=(char *) backSize;
      if (fragP->fr_next) {
        if (!backSize) relax_proceed_instr2(fragP->fr_next);
        if (fragP->fr_next->fr_type!=rs_machine_dependent) {
          insn_stop=-1;
          insn_count=0;
          insn_bits=0;
          insn_jumps=0;
        }
      }
      return growth;
    }

    if (symbolP)
    {
      fragS *sym_frag;

      sym_frag = symbol_get_frag (symbolP);

#ifndef DIFF_EXPR_OK
      know (sym_frag != NULL);
#endif
      know (S_GET_SEGMENT (symbolP) != absolute_section
	    || sym_frag == &zero_address_frag);
      target += S_GET_VALUE (symbolP);

      /* If SYM_FRAG has yet to be reached on this pass, assume it
	 will move by STRETCH just as we did, unless there is an
	 alignment frag between here and SYM_FRAG.  An alignment may
	 well absorb any STRETCH, and we don't want to choose a larger
	 branch insn by overestimating the needed reach of this
	 branch.  It isn't critical to calculate TARGET exactly;  We
	 know we'll be doing another pass if STRETCH is non-zero.  */

      if (stretch != 0
	  && sym_frag->relax_marker != fragP->relax_marker
	  && S_GET_SEGMENT (symbolP) == segment)
	{
	  if (stretch < 0
	      || sym_frag->region == fragP->region)
	    target += stretch;
	  /* If we get here we know we have a forward branch.  This
	     relax pass may have stretched previous instructions so
	     far that omitting STRETCH would make the branch
	     negative.  Don't allow this in case the negative reach is
	     large enough to require a larger branch instruction.  */
	  else if (target < address)
	    target = fragP->fr_next->fr_address + stretch;
	}
    }

  aim = target - address - fragP->fr_fix;

  start_state=fragP->fr_subtype;
  if (aim < 0)
    {
      /* Look backwards.  */
      for (next_state = this_type->rlx_more; next_state;)
	if (aim >= this_type->rlx_backward)
	  next_state = 0;
	else
	  {
	    /* Grow to next state.  */
	    this_state = next_state;
	    this_type = table + this_state;
	    next_state = this_type->rlx_more;
	  }
    }
  else
    {
      /* Look forwards.  */
      for (next_state = this_type->rlx_more; next_state;)
	if (aim <= this_type->rlx_forward)
	  next_state = 0;
	else
	  {
	    /* Grow to next state.  */
	    this_state = next_state;
	    this_type = table + this_state;
	    next_state = this_type->rlx_more;
	  }
    }

  relax_unproceed_instr();
  if (this_state != start_state)
    fragP->fr_subtype = this_state;
  relax_proceed_instr(fragP);
  backSize=relax_get_bottom_size2(fragP->fr_next);
  growth=backSize+fragP->fr_fix+this_type->rlx_length-fragP->last_fr_size-
    (valueT) fragP->fr_opcode;
  fragP->last_fr_size+=fragP->fr_fix+this_type->rlx_length-fragP->last_fr_size;
  fragP->fr_opcode=(char *) backSize;
//  if ((fragP->fr_address&0x1fll)==0ll) relax_proceed_instr2(fragP);
  if (fragP->fr_next) {
    if (fragP->fr_next->fr_type!=rs_machine_dependent) {
      insn_stop=-1;
      insn_count=0;
      insn_bits=0;
      insn_jumps=0;
    }
    if (!backSize) relax_proceed_instr2(fragP->fr_next);
  }
  if (this_state != start_state)
    fragP->fr_subtype = this_state;
  //printf("growth: %ld\n",growth);
  return growth;
}



/* md_estimate_size_before_relax()

   Called just before relax() for rs_machine_dependent frags.  The x86
   assembler uses these frags to handle variable size jump
   instructions.

   Any symbol that is now undefined will not become defined.
   Return the correct fr_subtype in the frag.
   Return the initial "guess for variable size of frag" to caller.
   The guess is actually the growth beyond the fixed part.  Whatever
   we do to grow the fixed or variable part contributes to our
   returned value.  */

int
md_estimate_size_before_relax (fragS *fragP, segT segment)
{
  offsetT sizeBefore; 
//  if (!XXFR) XXFR=fragP;
  if ((fragP->fr_address&0x1fll)==0ll) {
    insn_stop=-1;
    insn_bits=0x0;
    insn_count=0;
    insn_jumps=0;
    relax_proceed_instr(fragP);
  }
  if (fragP->fr_next) {
    sizeBefore=relax_get_bottom_size(fragP->fr_next);
  } else {
    sizeBefore=((fragP->fr_address+31)&0xffffffffffffffe0)-fragP->fr_address;
  }
      
 //  int old_fr_fix;

    /*  if (fragP->fr_var != NO_RELOC)
	reloc_type = (enum bfd_reloc_code_real) fragP->fr_var;
      else
	reloc_type = BFD_RELOC_32_PCREL;
*/
 //     old_fr_fix = fragP->fr_fix;
     // opcode = (unsigned char *) fragP->fr_opcode;

 //     relax_proceed_instr(fragP);
 //     fragP->last_fr_size=sizeBefore+fragP->fr_fix;
 //     fragP->fr_subtype=ENCODE_RELAX_STATE(
  //      TYPE_FROM_RELAX_STATE(fragP->fr_subtype),
  //      BIG);
  //    return fragP->fr_fix - old_fr_fix+sizeBefore;

      if (fragP->fr_next && !sizeBefore) relax_proceed_instr(fragP->fr_next);
      fragP->last_fr_size=fragP->fr_fix;
      fragP->fr_opcode=(char *)sizeBefore;
      if (segment) return sizeBefore;
      else return sizeBefore;
}

/* Called after relax() is finished.

   In:	Address of frag.
	fr_type == rs_machine_dependent.
	fr_subtype is what the address relaxed to.

   Out:	Any fixSs and constants are set up.
	Caller will turn frag into a ".space 0".  */

void
md_convert_frag (bfd *abfd ATTRIBUTE_UNUSED, segT sec ATTRIBUTE_UNUSED,
                 fragS *fragP)
{
  unsigned char *opcode;
  unsigned char *where_to_put_displacement = NULL;
  offsetT target_address;
  offsetT opcode_address;
  unsigned int extension = 0;
  offsetT displacement_from_opcode_start;
  int backSize;
  int old_fr_fix=fragP->fr_fix;
  int old_nn_fix;
  valueT val;
  enum bfd_reloc_code_real reloc_type;
  int sz;
  sz=DISP_SIZE_FROM_RELAX_STATE(fragP->fr_subtype);
  if (fragP->fr_subtype==ENCODE_RELAX_STATE(NON_JUMP,BIGGER)) sz+=2;;
  if (fragP->fr_subtype==ENCODE_RELAX_STATE(COMPARE_JUMP,BIGGER)) sz+=2;;
//  if (!XXFR) XXFR=fragP;
  if ((fragP->fr_address&0x1fll)==0ll) {
    insn_stop=-1;
    insn_bits=0x0;
    insn_count=0;
    insn_jumps=0;
  }
  if (insn_stop==-1) relax_proceed_instr2(fragP);
  if (fragP->fr_next) {
    backSize=relax_get_bottom_size2(fragP->fr_next);
  } else {
    backSize=((fragP->fr_address+31)&0xffffffffffffffe0)-fragP->fr_address;
  }

  if (backSize)
    { 
      old_nn_fix=fragP->fr_fix;
      fragP->fr_fix=backSize+sz+2;
     // memmove(NNFR->fr_literal+old_nn_fix,fragP->fr_literal,old_fr_fix);
      memset(fragP->fr_literal+old_nn_fix,0,backSize);
      fragP->fr_literal[old_nn_fix+backSize-2]=insn_bits&0xff;
      fragP->fr_literal[old_nn_fix+backSize-1]=insn_bits>>8;
      //fragP->fr_address+=backSize;
    }
    
  if (TYPE_FROM_RELAX_STATE(fragP->fr_subtype)==NON_JUMP ||
      TYPE_FROM_RELAX_STATE(fragP->fr_subtype)==UNREL_JUMP)
    {
      reloc_type=(enum bfd_reloc_code_real) fragP->fr_var;
      if (reloc_type!=NO_RELOC)
        {
          int pcrel=fragP->fr_offset>>8;
          int sz2=fragP->fr_offset&0xff;
          fix_new_exp (fragP, old_fr_fix+backSize-sz2, sz2,
		       &(fragP->expr), pcrel, reloc_type);      
        }
      if (fragP->fr_next) {
        if (!backSize) relax_proceed_instr2(fragP->fr_next);
      }
      //relax_proceed_instr(fragP);
      //NNFR=fragP;
      return;
    }

  opcode = (unsigned char *) fragP->fr_literal;

  /* Address we want to reach in file space.  */
  target_address = S_GET_VALUE (fragP->fr_symbol) + fragP->fr_offset;

  /* Address opcode resides at in file space.  */
  opcode_address = fragP->fr_address;// + fragP->fr_fix;

  /* Displacement from opcode start to fill into instruction.  */
  displacement_from_opcode_start = target_address - opcode_address;

  if ((fragP->fr_subtype & (BIG|MED|BIGGEST|BIGGER)) == 0)
    {
      /* Don't have to change opcode.  */
      extension = 2;
      if (fragP->fr_subtype==ENCODE_RELAX_STATE(COND_JUMP,SMALL))		
        opcode[0]=0x30 | (opcode[1]&0x3) |((opcode[1]&0xc)<<4);
      if (fragP->fr_subtype==ENCODE_RELAX_STATE(UNCOND_JUMP,SMALL) &&
        opcode[0]==181)		
        opcode[0]=0xf3;
      where_to_put_displacement=&opcode[1];
    }
  else
    {
      extension=DISP_SIZE_FROM_RELAX_STATE(fragP->fr_subtype)+2;
      if ((fragP->fr_subtype&0x7)==BIGGER) extension+=2;
      //extension-=fragP->fr_fix;
      where_to_put_displacement=&opcode[2];
      if (fragP->fr_subtype==ENCODE_RELAX_STATE(COND_JUMP,MED) ||
        fragP->fr_subtype==ENCODE_RELAX_STATE(UNCOND_JUMP,MED))
        where_to_put_displacement=&opcode[1];
    }

  /* If size if less then four we are sure that the operand fits,
     but if it's 4, then it could be that the displacement is larger
     then -/+ 2GB.  */
  if (DISP_SIZE_FROM_RELAX_STATE (fragP->fr_subtype) == 4
      && fragP->fr_subtype!=ENCODE_RELAX_STATE(COMPARE_JUMP,BIG) && object_64bit
      && ((addressT) (displacement_from_opcode_start - extension
		      + ((addressT) 1 << 31))
	  > (((addressT) 2 << 31) - 1)))
    {
      as_bad_where (fragP->fr_file, fragP->fr_line,
		    _("jump target out of range"));
      /* Make us emit 0.  */
      displacement_from_opcode_start = extension;
    }
  /* Now put displacement after opcode.  */
  if (fragP->fr_subtype==ENCODE_RELAX_STATE(COND_JUMP,BIG) ||   
  fragP->fr_subtype==ENCODE_RELAX_STATE(UNCOND_JUMP,BIG) ||   
  fragP->fr_subtype==ENCODE_RELAX_STATE(COMPARE_JUMP,BIGGER)) {   
      val=(displacement_from_opcode_start - extension) & 0xfffffffell;
      if (fragP->fr_subtype==ENCODE_RELAX_STATE(COMPARE_JUMP,BIGGER))
        val|=opcode[2]&0x1ll;
      md_number_to_chars ((char *) where_to_put_displacement,
		      val,
		      4);
      reloc_type=(enum bfd_reloc_code_real) fragP->fr_var;
      if (TYPE_FROM_RELAX_STATE(fragP->fr_subtype)==COMPARE_JUMP)
      {
        if (reloc_type==BFD_RELOC_32_PCREL)
          reloc_type=BFD_RELOC_HEPTANE_PC32_S1;
      } 
	  if (reloc_type!=NO_RELOC)
	    fix_new (fragP,/*where*/ 2, 4,
		   fragP->fr_symbol,
		   fragP->fr_offset, 1,
		   reloc_type);      
  }
  if (fragP->fr_subtype==ENCODE_RELAX_STATE(COMPARE_JUMP,MED)) {
      val=((displacement_from_opcode_start - extension)&0x3ffe)<<2;
      val=val|(opcode[2]&0x7);
      md_number_to_chars ((char *) where_to_put_displacement,
		      val,
		      2);
  }
  if (fragP->fr_subtype==ENCODE_RELAX_STATE(COMPARE_JUMP,BIG)) {
      val=(displacement_from_opcode_start - extension)&0xfffe;
      val=val|(opcode[2]&0x1);
      md_number_to_chars ((char *) where_to_put_displacement,
		      val,
		      2);
  }
  if (fragP->fr_subtype==ENCODE_RELAX_STATE(UNCOND_JUMP,MED)) {
      val=(displacement_from_opcode_start - extension)&0x1ffffffll;
      val=val>>1;
      md_number_to_chars ((char *) where_to_put_displacement,
		      val,
		      3);
  }
  if (fragP->fr_subtype==ENCODE_RELAX_STATE(COND_JUMP,MED)) {
      val=(displacement_from_opcode_start - extension)&0x1ffffll;
      val=((val>>1)<<4)|(opcode[1]&0xf);
      md_number_to_chars ((char *) where_to_put_displacement,
		      val,
		      3);
  }
  if (fragP->fr_subtype==ENCODE_RELAX_STATE(COND_JUMP,SMALL) ||
    fragP->fr_subtype==ENCODE_RELAX_STATE(UNCOND_JUMP,SMALL)) {
      val=(displacement_from_opcode_start - extension)&0x1ffll;
      val=val>>1;
      md_number_to_chars ((char *) where_to_put_displacement,
		      val,
		      1);
     
  }
  if (!backSize) fragP->fr_fix = extension;
  if (fragP->fr_next) {
    if (!backSize) relax_proceed_instr2(fragP->fr_next);
  } 
  //NNFR=fragP;
}

/* Apply a fixup (fixP) to segment data, once it has been determined
   by our caller that we have all the info we need to fix it up.

   Parameter valP is the pointer to the value of the bits.

   On the 386, immediates, displacements, and data pointers are all in
   the same (little-endian) format, so we don't need to care about which
   we are handling.  */

void
md_apply_fix (fixS *fixP, valueT *valP, segT seg ATTRIBUTE_UNUSED)
{
  char *p = fixP->fx_where + fixP->fx_frag->fr_literal;
  valueT value = *valP;

#if !defined (TE_Mach)
  if (fixP->fx_pcrel)
    {
      switch (fixP->fx_r_type)
	{
	default:
	  break;

	case BFD_RELOC_64:
	  fixP->fx_r_type = BFD_RELOC_64_PCREL;
	  break;
	case BFD_RELOC_32:
	case BFD_RELOC_HEPTANE_32S:
	  fixP->fx_r_type = BFD_RELOC_32_PCREL;
	  break;
	case BFD_RELOC_16:
	  fixP->fx_r_type = BFD_RELOC_16_PCREL;
	  break;
	case BFD_RELOC_8:
	  fixP->fx_r_type = BFD_RELOC_8_PCREL;
	  break;
	}
    }

  if (fixP->fx_addsy != NULL
      && (fixP->fx_r_type == BFD_RELOC_32_PCREL
	  || fixP->fx_r_type == BFD_RELOC_64_PCREL
	  || fixP->fx_r_type == BFD_RELOC_16_PCREL
	  || fixP->fx_r_type == BFD_RELOC_8_PCREL
	  || fixP->fx_r_type == BFD_RELOC_HEPTANE_PC32_S1)
      && !use_rela_relocations)
    {
      /* This is a hack.  There should be a better way to handle this.
	 This covers for the fact that bfd_install_relocation will
	 subtract the current location (for partial_inplace, PC relative
	 relocations); see more below.  */
#ifndef OBJ_AOUT
      if (IS_ELF
#ifdef TE_PE
	  || OUTPUT_FLAVOR == bfd_target_coff_flavour
#endif
	  )
	value += fixP->fx_where + fixP->fx_frag->fr_address;
#endif
#if defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF)
      if (IS_ELF)
	{
	  segT sym_seg = S_GET_SEGMENT (fixP->fx_addsy);

	  if ((sym_seg == seg
	       || (symbol_section_p (fixP->fx_addsy)
		   && sym_seg != absolute_section))
	      && !generic_force_reloc (fixP))
	    {
	      /* Yes, we add the values in twice.  This is because
		 bfd_install_relocation subtracts them out again.  I think
		 bfd_install_relocation is broken, but I don't dare change
		 it.  FIXME.  */
	      value += fixP->fx_where + fixP->fx_frag->fr_address;
	    }
	}
#endif
#if defined (OBJ_COFF) && defined (TE_PE)
      /* For some reason, the PE format does not store a
	 section address offset for a PC relative symbol.  */
      if (S_GET_SEGMENT (fixP->fx_addsy) != seg
	  || S_IS_WEAK (fixP->fx_addsy))
	value += md_pcrel_from (fixP);
#endif
    }
#if defined (OBJ_COFF) && defined (TE_PE)
  if (fixP->fx_addsy != NULL
      && S_IS_WEAK (fixP->fx_addsy)
      /* PR 16858: Do not modify weak function references.  */
      && ! fixP->fx_pcrel)
    {
#if !defined (TE_PEP)
      /* For x86 PE weak function symbols are neither PC-relative
	 nor do they set S_IS_FUNCTION.  So the only reliable way
	 to detect them is to check the flags of their containing
	 section.  */
      if (S_GET_SEGMENT (fixP->fx_addsy) != NULL
	  && S_GET_SEGMENT (fixP->fx_addsy)->flags & SEC_CODE)
	;
      else
#endif
      value -= S_GET_VALUE (fixP->fx_addsy);
    }
#endif

  /* Fix a few things - the dynamic linker expects certain values here,
     and we must not disappoint it.  */
#if defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF)
  if (IS_ELF && fixP->fx_addsy)
    switch (fixP->fx_r_type)
      {
      case BFD_RELOC_HEPTANE_PLT32:
      case BFD_RELOC_HEPTANE_PLT32_S1:
	/* Make the jump instruction point to the address of the operand.  At
	   runtime we merely add the offset to the actual PLT entry.  */
	value = -4;
	break;

      case BFD_RELOC_HEPTANE_TLSGD:
      case BFD_RELOC_HEPTANE_TLSLD:
      case BFD_RELOC_HEPTANE_GOTTPOFF:
      case BFD_RELOC_HEPTANE_GOTPC32_TLSDESC:
	value = 0; /* Fully resolved at runtime.  No addend.  */
	/* Fallthrough */
      case BFD_RELOC_HEPTANE_DTPOFF32:
      case BFD_RELOC_HEPTANE_DTPOFF64:
      case BFD_RELOC_HEPTANE_TPOFF32:
      case BFD_RELOC_HEPTANE_TPOFF64:
	S_SET_THREAD_LOCAL (fixP->fx_addsy);
	break;

      case BFD_RELOC_HEPTANE_TLSDESC_CALL:
	value = 0; /* Fully resolved at runtime.  No addend.  */
	S_SET_THREAD_LOCAL (fixP->fx_addsy);
	fixP->fx_done = 0;
	return;

      case BFD_RELOC_HEPTANE_GOT32:
	value = 0; /* Fully resolved at runtime.  No addend.  */
	break;

      case BFD_RELOC_VTABLE_INHERIT:
      case BFD_RELOC_VTABLE_ENTRY:
	fixP->fx_done = 0;
	return;

      default:
	break;
      }
#endif /* defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF)  */
  *valP = value;
#endif /* !defined (TE_Mach)  */

  /* Are we finished with this relocation now?  */
  if (fixP->fx_addsy == NULL)
    fixP->fx_done = 1;
#if defined (OBJ_COFF) && defined (TE_PE)
  else if (fixP->fx_addsy != NULL && S_IS_WEAK (fixP->fx_addsy))
    {
      fixP->fx_done = 0;
      /* Remember value for tc_gen_reloc.  */
      fixP->fx_addnumber = value;
      /* Clear out the frag for now.  */
      value = 0;
    }
#endif
  else if (use_rela_relocations)
    {
      fixP->fx_no_overflow = 1;
      /* Remember value for tc_gen_reloc.  */
      fixP->fx_addnumber = value;
      value = 0;
    }

  md_number_to_chars (p, value, fixP->fx_size);
}

char *
md_atof (int type, char *litP, int *sizeP)
{
  /* This outputs the LITTLENUMs in REVERSE order;
     in accord with the bigendian 386.  */
  return ieee_md_atof (type, litP, sizeP, FALSE);
}

static char output_invalid_buf[sizeof (unsigned char) * 2 + 6];

static char *
output_invalid (int c)
{
  if (ISPRINT (c))
    snprintf (output_invalid_buf, sizeof (output_invalid_buf),
	      "'%c'", c);
  else
    snprintf (output_invalid_buf, sizeof (output_invalid_buf),
	      "(0x%x)", (unsigned char) c);
  return output_invalid_buf;
}

/* REG_STRING starts *before* REGISTER_PREFIX.  */

static const reg_entry *
parse_real_register (char *reg_string, char **end_op)
{
  char *s = reg_string;
  char *p;
  char reg_name_given[MAX_REG_NAME_SIZE + 1];
  const reg_entry *r;

  /* Skip possible REGISTER_PREFIX and possible whitespace.  */
  if (*s == REGISTER_PREFIX)
    ++s;

  if (is_space_char (*s))
    ++s;

  p = reg_name_given;
  while ((*p++ = register_chars[(unsigned char) *s]) != '\0')
    {
      if (p >= reg_name_given + MAX_REG_NAME_SIZE)
	return (const reg_entry *) NULL;
      s++;
    }


  *end_op = s;

  r = (const reg_entry *) hash_find (reg_hash, reg_name_given);

  /* Handle floating point regs, allowing spaces in the (i) part.  */
  if (r == heptane_regtab /* %st is first entry of table  */)
    {
      if (is_space_char (*s))
	++s;
      if (*s == '(')
	{
	  ++s;
	  if (is_space_char (*s))
	    ++s;
	  if (*s >= '0' && *s <= '7')
	    {
	      int fpr = *s - '0';
	      ++s;
	      if (is_space_char (*s))
		++s;
	      if (*s == ')')
		{
		  *end_op = s + 1;
		  r = (const reg_entry *) hash_find (reg_hash, "st(0)");
		  know (r);
		  return r + fpr;
		}
	    }
	  /* We have "%st(" then garbage.  */
	  return (const reg_entry *) NULL;
	}
    }

  if (r == NULL)
    return r;

  if (operand_type_all_zero (&r->reg_type))
    return (const reg_entry *) NULL;

  if ((r->reg_type.bitfield.reg32
       || r->reg_type.bitfield.sreg3
       || r->reg_type.bitfield.control
       || r->reg_type.bitfield.debug
       || r->reg_type.bitfield.test)
      && !cpu_arch_flags.bitfield.cpui386)
    return (const reg_entry *) NULL;

  if (r->reg_type.bitfield.floatreg
      && !cpu_arch_flags.bitfield.cpu8087
      && !cpu_arch_flags.bitfield.cpu287
      && !cpu_arch_flags.bitfield.cpu387)
    return (const reg_entry *) NULL;

  return r;
}

/* REG_STRING starts *before* REGISTER_PREFIX.  */

static const reg_entry *
parse_register (char *reg_string, char **end_op)
{
  const reg_entry *r;

  if (*reg_string == REGISTER_PREFIX)
    r = parse_real_register (reg_string, end_op);
  else
    r = NULL;
  if (!r)
    {
      char *save = input_line_pointer;
      char c;
      symbolS *symbolP;

      input_line_pointer = reg_string;
      c = get_symbol_name (&reg_string);
      symbolP = symbol_find (reg_string);
      if (symbolP && S_GET_SEGMENT (symbolP) == reg_section)
	{
	  const expressionS *e = symbol_get_value_expression (symbolP);

	  know (e->X_op == O_register);
	  know (e->X_add_number >= 0
		&& (valueT) e->X_add_number < heptane_regtab_size);
	  r = heptane_regtab + e->X_add_number;
	  *end_op = input_line_pointer;
	}
      *input_line_pointer = c;
      input_line_pointer = save;
    }
  return r;
}

int
i386_parse_name (char *name, expressionS *e, char *nextcharP)
{
  const reg_entry *r;
  char *end = input_line_pointer;

  *end = *nextcharP;
  r = parse_register (name, &input_line_pointer);
  if (r && end <= input_line_pointer)
    {
      *nextcharP = *input_line_pointer;
      *input_line_pointer = 0;
      e->X_op = O_register;
      e->X_add_number = r - heptane_regtab;
      return 1;
    }
  input_line_pointer = end;
  *end = 0;
  return 0;
}

void
md_operand (expressionS *e)
{
  char *end;
  const reg_entry *r;

  switch (*input_line_pointer)
    {
    case REGISTER_PREFIX:
      r = parse_real_register (input_line_pointer, &end);
      if (r)
	{
	  e->X_op = O_register;
	  e->X_add_number = r - heptane_regtab;
	  input_line_pointer = end;
	}
      break;

    }
}


#if defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF)
const char *md_shortopts = "kVQ:sqn";
#else
const char *md_shortopts = "qn";
#endif

#define OPTION_32 (OPTION_MD_BASE + 0)
#define OPTION_64 (OPTION_MD_BASE + 1)
#define OPTION_DIVIDE (OPTION_MD_BASE + 2)
#define OPTION_MARCH (OPTION_MD_BASE + 3)
#define OPTION_MTUNE (OPTION_MD_BASE + 4)
#define OPTION_MMNEMONIC (OPTION_MD_BASE + 5)
#define OPTION_MSYNTAX (OPTION_MD_BASE + 6)
#define OPTION_MINDEX_REG (OPTION_MD_BASE + 7)
#define OPTION_MNAKED_REG (OPTION_MD_BASE + 8)
#define OPTION_MOLD_GCC (OPTION_MD_BASE + 9)
#define OPTION_MSSE2AVX (OPTION_MD_BASE + 10)
#define OPTION_MSSE_CHECK (OPTION_MD_BASE + 11)
#define OPTION_MOPERAND_CHECK (OPTION_MD_BASE + 12)
#define OPTION_MAVXSCALAR (OPTION_MD_BASE + 13)
#define OPTION_X32 (OPTION_MD_BASE + 14)
#define OPTION_MADD_BND_PREFIX (OPTION_MD_BASE + 15)
#define OPTION_MEVEXLIG (OPTION_MD_BASE + 16)
#define OPTION_MEVEXWIG (OPTION_MD_BASE + 17)
#define OPTION_MBIG_OBJ (OPTION_MD_BASE + 18)
#define OPTION_OMIT_LOCK_PREFIX (OPTION_MD_BASE + 19)
#define OPTION_MEVEXRCIG (OPTION_MD_BASE + 20)
#define OPTION_MSHARED (OPTION_MD_BASE + 21)
#define OPTION_MAMD64 (OPTION_MD_BASE + 22)
#define OPTION_MINTEL64 (OPTION_MD_BASE + 23)

struct option md_longopts[] =
{
  {"32", no_argument, NULL, OPTION_32},
#if (defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF) \
     || defined (TE_PE) || defined (TE_PEP) || defined (OBJ_MACH_O))
  {"64", no_argument, NULL, OPTION_64},
#endif
#if defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF)
  {"x32", no_argument, NULL, OPTION_X32},
  {"mshared", no_argument, NULL, OPTION_MSHARED},
#endif
  {"divide", no_argument, NULL, OPTION_DIVIDE},
  {"march", required_argument, NULL, OPTION_MARCH},
  {"mtune", required_argument, NULL, OPTION_MTUNE},
  {"mmnemonic", required_argument, NULL, OPTION_MMNEMONIC},
  {"msyntax", required_argument, NULL, OPTION_MSYNTAX},
  {"mindex-reg", no_argument, NULL, OPTION_MINDEX_REG},
  {"mnaked-reg", no_argument, NULL, OPTION_MNAKED_REG},
  {"mold-gcc", no_argument, NULL, OPTION_MOLD_GCC},
  {"msse2avx", no_argument, NULL, OPTION_MSSE2AVX},
  {"msse-check", required_argument, NULL, OPTION_MSSE_CHECK},
  {"moperand-check", required_argument, NULL, OPTION_MOPERAND_CHECK},
  {"mavxscalar", required_argument, NULL, OPTION_MAVXSCALAR},
  {"madd-bnd-prefix", no_argument, NULL, OPTION_MADD_BND_PREFIX},
  {"mevexlig", required_argument, NULL, OPTION_MEVEXLIG},
  {"mevexwig", required_argument, NULL, OPTION_MEVEXWIG},
# if defined (TE_PE) || defined (TE_PEP)
  {"mbig-obj", no_argument, NULL, OPTION_MBIG_OBJ},
#endif
  {"momit-lock-prefix", required_argument, NULL, OPTION_OMIT_LOCK_PREFIX},
  {"mevexrcig", required_argument, NULL, OPTION_MEVEXRCIG},
  {"mamd64", no_argument, NULL, OPTION_MAMD64},
  {"mintel64", no_argument, NULL, OPTION_MINTEL64},
  {NULL, no_argument, NULL, 0}
};
size_t md_longopts_size = sizeof (md_longopts);

int
md_parse_option (int c, char *arg)
{
  //unsigned int j;
  //char *arch,*next;

  switch (c)
    {
    case 'n':
      optimize_align_code = 0;
      break;

    case 'q':
      quiet_warnings = 1;
      break;

#if defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF)
      /* -Qy, -Qn: SVR4 arguments controlling whether a .comment section
	 should be emitted or not.  FIXME: Not implemented.  */
    case 'Q':
      break;

      /* -V: SVR4 argument to print version ID.  */
    case 'V':
      print_version_id ();
      break;

      /* -k: Ignore for FreeBSD compatibility.  */
    case 'k':
      break;

    case 's':
      /* -s: On i386 Solaris, this tells the native assembler to use
	 .stab instead of .stab.excl.  We always use .stab anyhow.  */
      break;

    case OPTION_MSHARED:
      shared = 1;
      break;
#endif
#if (defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF) \
     || defined (TE_PE) || defined (TE_PEP) || defined (OBJ_MACH_O))
    case OPTION_64:
      {
/*	const char **list, **l;

	list = bfd_target_list ();
	for (l = list; *l != NULL; l++)
	  if (CONST_STRNEQ (*l, "elf64-x86-64")
	      || strcmp (*l, "coff-x86-64") == 0
	      || strcmp (*l, "pe-x86-64") == 0
	      || strcmp (*l, "pei-x86-64") == 0
	      || strcmp (*l, "mach-o-x86-64") == 0)
	    {
	      default_arch = "x86_64";
	      break;
	    }
	if (*l == NULL)
	  as_fatal (_("no compiled in support for x86_64"));
	free (list);*/
      }
      break;
#endif

#if defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF)
    case OPTION_X32:
  /*    if (IS_ELF)
	{
	  const char **list, **l;

	  list = bfd_target_list ();
	  for (l = list; *l != NULL; l++)
	    if (CONST_STRNEQ (*l, "elf32-x86-64"))
	      {
		default_arch = "x86_64:32";
		break;
	      }
	  if (*l == NULL)
	    as_fatal (_("no compiled in support for 32bit x86_64"));
	  free (list);
	}
      else*/
	as_fatal (_("32 in 64 bit heptane is not yet supported"));
      break;
#endif

    case OPTION_32:
	as_fatal (_("no 32 bit mode"));
      break;

    case OPTION_DIVIDE:
#ifdef SVR4_COMMENT_CHARS
      {
	char *n, *t;
	const char *s;

	n = (char *) xmalloc (strlen (i386_comment_chars) + 1);
	t = n;
	for (s = i386_comment_chars; *s != '\0'; s++)
	  if (*s != '/')
	    *t++ = *s;
	*t = '\0';
	i386_comment_chars = n;
      }
#endif
      break;

    case OPTION_MARCH:
     
     /* arch = xstrdup (arg);
      do
	{
	  if (*arch == '.')
	    as_fatal (_("invalid -march= option: `%s'"), arg);
	  next = strchr (arch, '+');
	  if (next)
	    *next++ = '\0';
	  for (j = 0; j < ARRAY_SIZE (cpu_arch); j++)
	    {
	      if (strcmp (arch, cpu_arch [j].name) == 0)
		{
		  /,* Processor.  *,/
		  if (! cpu_arch[j].flags.bitfield.cpui386)
		    continue;

		  cpu_arch_name = cpu_arch[j].name;
		  cpu_sub_arch_name = NULL;
		  cpu_arch_flags = cpu_arch[j].flags;
		  cpu_arch_isa = cpu_arch[j].type;
		  cpu_arch_isa_flags = cpu_arch[j].flags;
		  if (!cpu_arch_tune_set)
		    {
		      cpu_arch_tune = cpu_arch_isa;
		      cpu_arch_tune_flags = cpu_arch_isa_flags;
		    }
		  break;
		}
	      else if (*cpu_arch [j].name == '.'
		       && strcmp (arch, cpu_arch [j].name + 1) == 0)
		{
		  /,* ISA entension.  *,/
		  i386_cpu_flags flags;

		  if (!cpu_arch[j].negated)
		    flags = cpu_flags_or (cpu_arch_flags,
					  cpu_arch[j].flags);
		  else
		    flags = cpu_flags_and_not (cpu_arch_flags,
					       cpu_arch[j].flags);

		  if (!valid_iamcu_cpu_flags (&flags))
		    as_fatal (_("`%s' isn't valid for Intel MCU"), arch);
		  else if (!cpu_flags_equal (&flags, &cpu_arch_flags))
		    {
		      if (cpu_sub_arch_name)
			{
			  char *name = cpu_sub_arch_name;
			  cpu_sub_arch_name = concat (name,
						      cpu_arch[j].name,
						      (const char *) NULL);
			  free (name);
			}
		      else
			cpu_sub_arch_name = xstrdup (cpu_arch[j].name);
		      cpu_arch_flags = flags;
		      cpu_arch_isa_flags = flags;
		    }
		  break;
		}
	    }

	  if (j >= ARRAY_SIZE (cpu_arch))
	    as_fatal (_("invalid -march= option: `%s'"), arg);

	  arch = next;
	}
      while (next != NULL );*/
      break;

    case OPTION_MTUNE:
    /*  if (*arg == '.')
	as_fatal (_("invalid -mtune= option: `%s'"), arg);
      for (j = 0; j < ARRAY_SIZE (cpu_arch); j++)
	{
	  if (strcmp (arg, cpu_arch [j].name) == 0)
	    {
	      cpu_arch_tune_set = 1;
	      cpu_arch_tune = cpu_arch [j].type;
	      cpu_arch_tune_flags = cpu_arch[j].flags;
	      break;
	    }
	}
      if (j >= ARRAY_SIZE (cpu_arch))
	as_fatal (_("invalid -mtune= option: `%s'"), arg);*/
      break;

    case OPTION_MMNEMONIC:
   /*   if (strcasecmp (arg, "att") == 0)
	intel_mnemonic = 0;
      else if (strcasecmp (arg, "intel") == 0)
	intel_mnemonic = 1;
      else*/
	as_fatal (_("invalid -mmnemonic= option: `%s'"), arg);
      break;



    case OPTION_MOPERAND_CHECK:
      if (strcasecmp (arg, "error") == 0)
	operand_check = check_error;
      else if (strcasecmp (arg, "warning") == 0)
	operand_check = check_warning;
      else if (strcasecmp (arg, "none") == 0)
	operand_check = check_none;
      else
	as_fatal (_("invalid -moperand-check= option: `%s'"), arg);
      break;

    case OPTION_MAVXSCALAR:
      if (strcasecmp (arg, "128") == 0)
	avxscalar = vex128;
      else if (strcasecmp (arg, "256") == 0)
	avxscalar = vex256;
      else
	as_fatal (_("invalid -mavxscalar= option: `%s'"), arg);
      break;




# if defined (TE_PE) || defined (TE_PEP)
    case OPTION_MBIG_OBJ:
      use_big_obj = 1;
      break;
#endif

    case OPTION_OMIT_LOCK_PREFIX:
      if (strcasecmp (arg, "yes") == 0)
        omit_lock_prefix = 1;
      else if (strcasecmp (arg, "no") == 0)
        omit_lock_prefix = 0;
      else
        as_fatal (_("invalid -momit-lock-prefix= option: `%s'"), arg);
      break;

    default:
      return 0;
    }
  return 1;
}

#define MESSAGE_TEMPLATE \
"                                                                                "
/*
static void
show_arch (FILE *stream, int ext, int check)
{
}
*/
void
md_show_usage (FILE *stream)
{
#if defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF)
  fprintf (stream, _("\
  -Q                      ignored\n\
  -V                      print assembler version number\n\
  -k                      ignored\n"));
#endif
  fprintf (stream, _("\
  -n                      Do not optimize code alignment\n\
  -q                      quieten some warnings\n"));
#if defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF)
  fprintf (stream, _("\
  -s                      ignored\n"));
#endif
#if (defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF) \
     || defined (TE_PE) || defined (TE_PEP))
  fprintf (stream, _("\
  --32/--64/--x32         generate 32bit/64bit/x32 code\n"));
#endif
#ifdef SVR4_COMMENT_CHARS
  fprintf (stream, _("\
  --divide                do not treat `/' as a comment character\n"));
#else
  fprintf (stream, _("\
  --divide                ignored\n"));
#endif
  fprintf (stream, _("\
  -march=CPU[,+EXTENSION...]\n\
                          generate code for CPU and EXTENSION, CPU is one of:\n"));
//  show_arch (stream, 0, 1);
  fprintf (stream, _("\
                          EXTENSION is combination of:\n"));
 // show_arch (stream, 1, 0);
  fprintf (stream, _("\
  -mtune=CPU              optimize for CPU, CPU is one of:\n"));
 // show_arch (stream, 0, 0);
  fprintf (stream, _("\
  -msse2avx               encode SSE instructions with VEX prefix\n"));
  fprintf (stream, _("\
  -msse-check=[none|error|warning]\n\
                          check SSE instructions\n"));
  fprintf (stream, _("\
  -moperand-check=[none|error|warning]\n\
                          check operand combinations for validity\n"));
  fprintf (stream, _("\
  -mavxscalar=[128|256]   encode scalar AVX instructions with specific vector\n\
                           length\n"));
  fprintf (stream, _("\
  -mevexlig=[128|256|512] encode scalar EVEX instructions with specific vector\n\
                           length\n"));
  fprintf (stream, _("\
  -mevexwig=[0|1]         encode EVEX instructions with specific EVEX.W value\n\
                           for EVEX.W bit ignored instructions\n"));
  fprintf (stream, _("\
  -mevexrcig=[rne|rd|ru|rz]\n\
                          encode EVEX instructions with specific EVEX.RC value\n\
                           for SAE-only ignored instructions\n"));
  fprintf (stream, _("\
  -mmnemonic=[att|intel]  use AT&T/Intel mnemonic\n"));
  fprintf (stream, _("\
  -msyntax=[att|intel]    use AT&T/Intel syntax\n"));
  fprintf (stream, _("\
  -mindex-reg             support pseudo index registers\n"));
  fprintf (stream, _("\
  -mnaked-reg             don't require `%%' prefix for registers\n"));
  fprintf (stream, _("\
  -mold-gcc               support old (<= 2.8.1) versions of gcc\n"));
  fprintf (stream, _("\
  -madd-bnd-prefix        add BND prefix for all valid branches\n"));
  fprintf (stream, _("\
  -mshared                disable branch optimization for shared code\n"));
# if defined (TE_PE) || defined (TE_PEP)
  fprintf (stream, _("\
  -mbig-obj               generate big object files\n"));
#endif
  fprintf (stream, _("\
  -momit-lock-prefix=[no|yes]\n\
                          strip all lock prefixes\n"));
  fprintf (stream, _("\
  -mamd64                 accept only AMD64 ISA\n"));
  fprintf (stream, _("\
  -mintel64               accept only Intel64 ISA\n"));
}

#if ((defined (OBJ_MAYBE_COFF) && defined (OBJ_MAYBE_AOUT)) \
     || defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF) \
     || defined (TE_PE) || defined (TE_PEP) || defined (OBJ_MACH_O))

/* Pick the target format to use.  */

const char *
heptane_target_format (void)
{
  if (!strncmp (default_arch, "heptane", 7))
    {
    //  update_code_flag (CODE_64BIT, 1);
      //x86_elf_abi = X86_64_ABI;
//      format=ELF_TARGET_FORMAT64;
      return "elf64-heptane";
    }
  else
    as_fatal (_("unknown architecture"));

/*  if (cpu_flags_all_zero (&cpu_arch_isa_flags))
    cpu_arch_isa_flags = cpu_arch[flag_code == CODE_64BIT].flags;
  if (cpu_flags_all_zero (&cpu_arch_tune_flags))
    cpu_arch_tune_flags = cpu_arch[flag_code == CODE_64BIT].flags;
*/
}

#endif /* OBJ_MAYBE_ more than one  */

symbolS *
md_undefined_symbol (char *name)
{
  if (name[0] == GLOBAL_OFFSET_TABLE_NAME[0]
      && name[1] == GLOBAL_OFFSET_TABLE_NAME[1]
      && name[2] == GLOBAL_OFFSET_TABLE_NAME[2]
      && strcmp (name, GLOBAL_OFFSET_TABLE_NAME) == 0)
    {
      if (!GOT_symbol)
	{
	  if (symbol_find (name))
	    as_bad (_("GOT already in symbol table"));
	  GOT_symbol = symbol_new (name, undefined_section,
				   (valueT) 0, &zero_address_frag);
	};
      return GOT_symbol;
    }
  return 0;
}

/* Round up a section size to the appropriate boundary.  */

valueT
md_section_align (segT segment ATTRIBUTE_UNUSED, valueT size)
{
//  valueT size2;
#if (defined (OBJ_AOUT) || defined (OBJ_MAYBE_AOUT))
  if (OUTPUT_FLAVOR == bfd_target_aout_flavour)
    {
      /* For a.out, force the section size to be aligned.  If we don't do
	 this, BFD will align it for us, but it will not write out the
	 final bytes of the section.  This may be a bug in BFD, but it is
	 easier to fix it here since that is how the other a.out targets
	 work.  */
      int align;

      align = bfd_get_section_alignment (stdoutput, segment);
      size = ((size + (1 << align) - 1) & (-((valueT) 1 << align)));
    }
#endif

  size=(size+31)&0xffffffffffffffe0ll;
 /* if (size2-size>=2) {
  memset(NNFR->fr_literal+NNFR->fr_fix,0x0,size2-size);
  NNFR->fr_literal[NNFR->fr_fix+size2-size-2]=insn_bits&0xff;
  NNFR->fr_literal[NNFR->fr_fix+size2-size-1]=(insn_bits&0xff00)>>8;
  NNFR->fr_fix+=size2-size;
  }*/
  XXFR=NULL;
  return size;
}

/* On the i386, PC-relative offsets are relative to the start of the
   next instruction.  That is, the address of the offset, plus its
   size, since the offset is always the last part of the insn.  */

long
md_pcrel_from (fixS *fixP)
{
  return fixP->fx_size + fixP->fx_where + fixP->fx_frag->fr_address;
}

#ifndef I386COFF

static void
s_bss (int ignore ATTRIBUTE_UNUSED)
{
  int temp;

#if defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF)
  if (IS_ELF)
    obj_elf_section_change_hook ();
#endif
  temp = get_absolute_expression ();
  subseg_set (bss_section, (subsegT) temp);
  demand_empty_rest_of_line ();
}

#endif


arelent *
tc_gen_reloc (asection *section ATTRIBUTE_UNUSED, fixS *fixp)
{
  arelent *rel;
  bfd_reloc_code_real_type code;

  switch (fixp->fx_r_type)
    {
#if defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF)
    case BFD_RELOC_SIZE32:
    case BFD_RELOC_SIZE64:
      if (S_IS_DEFINED (fixp->fx_addsy)
	  && !S_IS_EXTERNAL (fixp->fx_addsy))
	{
	  /* Resolve size relocation against local symbol to size of
	     the symbol plus addend.  */
	  valueT value = S_GET_SIZE (fixp->fx_addsy) + fixp->fx_offset;
	  if (fixp->fx_r_type == BFD_RELOC_SIZE32
	      && !fits_in_unsigned_long (value))
	    as_bad_where (fixp->fx_file, fixp->fx_line,
			  _("symbol size computation overflow"));
	  fixp->fx_addsy = NULL;
	  fixp->fx_subsy = NULL;
	  md_apply_fix (fixp, (valueT *) &value, NULL);
	  return NULL;
	}
#endif
    /* fall through */
    case BFD_RELOC_HEPTANE_PLT32:
    case BFD_RELOC_HEPTANE_GOT32:
    case BFD_RELOC_HEPTANE_GOTPCREL:
    case BFD_RELOC_HEPTANE_GOTPCRELX:
    case BFD_RELOC_HEPTANE_REX_GOTPCRELX:
    case BFD_RELOC_HEPTANE_TLSGD:
    case BFD_RELOC_HEPTANE_TLSLD:
    case BFD_RELOC_HEPTANE_DTPOFF32:
    case BFD_RELOC_HEPTANE_DTPOFF64:
    case BFD_RELOC_HEPTANE_GOTTPOFF:
    case BFD_RELOC_HEPTANE_TPOFF32:
    case BFD_RELOC_HEPTANE_TPOFF64:
    case BFD_RELOC_HEPTANE_GOTOFF64:
    case BFD_RELOC_HEPTANE_GOTPC32:
    case BFD_RELOC_HEPTANE_GOT64:
    case BFD_RELOC_HEPTANE_GOTPCREL64:
    case BFD_RELOC_HEPTANE_GOTPC64:
    case BFD_RELOC_HEPTANE_GOTPLT64:
    case BFD_RELOC_HEPTANE_PLTOFF64:
    case BFD_RELOC_HEPTANE_GOTPC32_TLSDESC:
    case BFD_RELOC_HEPTANE_TLSDESC_CALL:
    case BFD_RELOC_RVA:
    case BFD_RELOC_VTABLE_ENTRY:
    case BFD_RELOC_VTABLE_INHERIT:
#ifdef TE_PE
    case BFD_RELOC_32_SECREL:
#endif
      code = fixp->fx_r_type;
      break;
    case BFD_RELOC_HEPTANE_32S:
      if (!fixp->fx_pcrel)
	{
	  /* Don't turn BFD_RELOC_X86_64_32S into BFD_RELOC_32.  */
	  code = fixp->fx_r_type;
	  break;
	}
        /* fall through */
    default:
      if (fixp->fx_pcrel)
	{
	  switch (fixp->fx_size)
	    {
	    default:
	      as_bad_where (fixp->fx_file, fixp->fx_line,
			    _("can not do %d byte pc-relative relocation"),
			    fixp->fx_size);
	      code = BFD_RELOC_32_PCREL;
	      break;
	    case 1: code = BFD_RELOC_8_PCREL;  break;
	    case 2: code = BFD_RELOC_16_PCREL; break;
	    case 4: code = BFD_RELOC_32_PCREL; break;
#ifdef BFD64
	    case 8: code = BFD_RELOC_64_PCREL; break;
#endif
	    }
	}
      else
	{
	  switch (fixp->fx_size)
	    {
	    default:
	      as_bad_where (fixp->fx_file, fixp->fx_line,
			    _("can not do %d byte relocation"),
			    fixp->fx_size);
	      code = BFD_RELOC_32;
	      break;
	    case 1: code = BFD_RELOC_8;  break;
	    case 2: code = BFD_RELOC_16; break;
	    case 4: code = BFD_RELOC_32; break;
#ifdef BFD64
	    case 8: code = BFD_RELOC_64; break;
#endif
	    }
	}
      break;
    }

  if ((code == BFD_RELOC_32
       || code == BFD_RELOC_32_PCREL
       || code == BFD_RELOC_HEPTANE_32S)
      && GOT_symbol
      && fixp->fx_addsy == GOT_symbol)
    {
      if (!object_64bit)
	code = BFD_RELOC_386_GOTPC;
      else
	code = BFD_RELOC_HEPTANE_GOTPC32;
    }
  if ((code == BFD_RELOC_64 || code == BFD_RELOC_64_PCREL)
      && GOT_symbol
      && fixp->fx_addsy == GOT_symbol)
    {
      code = BFD_RELOC_HEPTANE_GOTPC64;
    }

  rel = (arelent *) xmalloc (sizeof (arelent));
  rel->sym_ptr_ptr = (asymbol **) xmalloc (sizeof (asymbol *));
  *rel->sym_ptr_ptr = symbol_get_bfdsym (fixp->fx_addsy);

  rel->address = fixp->fx_frag->fr_address + fixp->fx_where;

  if (!use_rela_relocations)
    {
      /* HACK: Since i386 ELF uses Rel instead of Rela, encode the
	 vtable entry to be used in the relocation's section offset.  */
      if (fixp->fx_r_type == BFD_RELOC_VTABLE_ENTRY)
	rel->address = fixp->fx_offset;
#if defined (OBJ_COFF) && defined (TE_PE)
      else if (fixp->fx_addsy && S_IS_WEAK (fixp->fx_addsy))
	rel->addend = fixp->fx_addnumber - (S_GET_VALUE (fixp->fx_addsy) * 2);
      else
#endif
      rel->addend = 0;
    }
  /* Use the rela in 64bit mode.  */
  else
    {
      if (disallow_64bit_reloc)
	switch (code)
	  {
	  case BFD_RELOC_HEPTANE_DTPOFF64:
	  case BFD_RELOC_HEPTANE_TPOFF64:
	  case BFD_RELOC_64_PCREL:
	  case BFD_RELOC_HEPTANE_GOTOFF64:
	  case BFD_RELOC_HEPTANE_GOT64:
	  case BFD_RELOC_HEPTANE_GOTPCREL64:
	  case BFD_RELOC_HEPTANE_GOTPC64:
	  case BFD_RELOC_HEPTANE_GOTPLT64:
	  case BFD_RELOC_HEPTANE_PLTOFF64:
	    as_bad_where (fixp->fx_file, fixp->fx_line,
			  _("cannot represent relocation type %s in x32 mode"),
			  bfd_get_reloc_code_name (code));
	    break;
	  default:
	    break;
	  }

      if (!fixp->fx_pcrel)
	rel->addend = fixp->fx_offset;
      else
	switch (code)
	  {
	  case BFD_RELOC_HEPTANE_PLT32:
	  case BFD_RELOC_HEPTANE_GOT32:
	  case BFD_RELOC_HEPTANE_GOTPCREL:
	  case BFD_RELOC_HEPTANE_GOTPCRELX:
	  case BFD_RELOC_HEPTANE_REX_GOTPCRELX:
	  case BFD_RELOC_HEPTANE_TLSGD:
	  case BFD_RELOC_HEPTANE_TLSLD:
	  case BFD_RELOC_HEPTANE_GOTTPOFF:
	  case BFD_RELOC_HEPTANE_GOTPC32_TLSDESC:
	  case BFD_RELOC_HEPTANE_TLSDESC_CALL:
	    rel->addend = fixp->fx_offset - fixp->fx_size;
	    break;
	  default:
	    rel->addend = (section->vma
			   - fixp->fx_size
			   + fixp->fx_addnumber
			   + md_pcrel_from (fixp));
	    break;
	  }
    }

  rel->howto = bfd_reloc_type_lookup (stdoutput, code);
  if (rel->howto == NULL)
    {
      as_bad_where (fixp->fx_file, fixp->fx_line,
		    _("cannot represent relocation type %s"),
		    bfd_get_reloc_code_name (code));
      /* Set howto to a garbage value so that we can keep going.  */
      rel->howto = bfd_reloc_type_lookup (stdoutput, BFD_RELOC_32);
      gas_assert (rel->howto != NULL);
    }

  return rel;
}

//#include "tc-i386-intel.c"

void
tc_x86_parse_to_dw2regnum (expressionS *exp)
{
//  int saved_naked_reg;
  char saved_register_dot;

//  saved_naked_reg = allow_naked_reg;
//  allow_naked_reg = 1;
  saved_register_dot = register_chars['.'];
  register_chars['.'] = '.';
//  allow_pseudo_reg = 1;
  expression_and_evaluate (exp);
//  allow_pseudo_reg = 0;
  register_chars['.'] = saved_register_dot;
//  allow_naked_reg = saved_naked_reg;

  if (exp->X_op == O_register && exp->X_add_number >= 0)
    {
      if ((addressT) exp->X_add_number < heptane_regtab_size)
	{
	  exp->X_op = O_constant;
	//  exp->X_add_number = heptane_regtab[exp->X_add_number]
	//		      .dw2_regnum[flag_code >> 1];
        //WARNING: NEED TO ADD DW2 REGNUM
	}
      else
	exp->X_op = O_illegal;
    }
}

void
tc_x86_frame_initial_instructions (void)
{
  static unsigned int sp_regno[2];

  if (!sp_regno[flag_code >> 1])
    {
      char *saved_input = input_line_pointer;
      char sp[][4] = {"esp", "rsp"};
      expressionS exp;

      input_line_pointer = sp[flag_code >> 1];
      tc_x86_parse_to_dw2regnum (&exp);
      gas_assert (exp.X_op == O_constant);
      sp_regno[flag_code >> 1] = exp.X_add_number;
      input_line_pointer = saved_input;
    }

  cfi_add_CFA_def_cfa (sp_regno[flag_code >> 1], -x86_cie_data_alignment);
  cfi_add_CFA_offset (x86_dwarf2_return_column, x86_cie_data_alignment);
}

int
x86_dwarf2_addr_size (void)
{
  return bfd_arch_bits_per_address (stdoutput) / 8;
}

int
i386_elf_section_type (const char *str, size_t len)
{
  if (flag_code == CODE_64BIT
      && len == sizeof ("unwind") - 1
      && strncmp (str, "unwind", 6) == 0)
    return SHT_X86_64_UNWIND;

  return -1;
}

#ifdef TE_SOLARIS
void
i386_solaris_fix_up_eh_frame (segT sec)
{
  if (flag_code == CODE_64BIT)
    elf_section_type (sec) = SHT_X86_64_UNWIND;
}
#endif

#ifdef TE_PE
void
tc_pe_dwarf2_emit_offset (symbolS *symbol, unsigned int size)
{
  expressionS exp;

  exp.X_op = O_secrel;
  exp.X_add_symbol = symbol;
  exp.X_add_number = 0;
  emit_expr (&exp, size);
}
#endif

#if defined (OBJ_ELF) || defined (OBJ_MAYBE_ELF)
/* For ELF on x86-64, add support for SHF_X86_64_LARGE.  */

bfd_vma
x86_64_section_letter (int letter, char **ptr_msg)
{
  if (flag_code == CODE_64BIT)
    {
      if (letter == 'l')
	return SHF_X86_64_LARGE;

      *ptr_msg = _("bad .section directive: want a,l,w,x,M,S,G,T in string");
    }
  else
    *ptr_msg = _("bad .section directive: want a,w,x,M,S,G,T in string");
  return -1;
}

bfd_vma
x86_64_section_word (char *str, size_t len)
{
  if (len == 5 && flag_code == CODE_64BIT && CONST_STRNEQ (str, "large"))
    return SHF_X86_64_LARGE;

  return -1;
}

static void
handle_large_common (int small ATTRIBUTE_UNUSED)
{
  if (flag_code != CODE_64BIT)
    {
      s_comm_internal (0, elf_common_parse);
      as_warn (_(".largecomm supported only in 64bit mode, producing .comm"));
    }
  else
    {
      static segT lbss_section;
      asection *saved_com_section_ptr = elf_com_section_ptr;
      asection *saved_bss_section = bss_section;

      if (lbss_section == NULL)
	{
	  flagword applicable;
	  segT seg = now_seg;
	  subsegT subseg = now_subseg;

	  /* The .lbss section is for local .largecomm symbols.  */
	  lbss_section = subseg_new (".lbss", 0);
	  applicable = bfd_applicable_section_flags (stdoutput);
	  bfd_set_section_flags (stdoutput, lbss_section,
				 applicable & SEC_ALLOC);
	  seg_info (lbss_section)->bss = 1;

	  subseg_set (seg, subseg);
	}

      elf_com_section_ptr = &_bfd_elf_large_com_section;
      bss_section = lbss_section;

      s_comm_internal (0, elf_common_parse);

      elf_com_section_ptr = saved_com_section_ptr;
      bss_section = saved_bss_section;
    }
}
#endif /* OBJ_ELF || OBJ_MAYBE_ELF */

/* Declarations for Intel 80386 opcode table
   Copyright (C) 2007-2015 Free Software Foundation, Inc.

   This file is part of the GNU opcodes library.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with GAS; see the file COPYING.  If not, write to the Free
   Software Foundation, 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */

#include "opcode/heptane.h"
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

/* Position of cpu flags bitfiled.  */

enum
{
  /* i186 or better required */
  Cpu186 = 0,
  /* i286 or better required */
  Cpu286,
  /* i386 or better required */
  Cpu386,
  /* i486 or better required */
  Cpu486,
  /* i585 or better required */
  Cpu586,
  /* i686 or better required */
  Cpu686,
  /* CLFLUSH Instruction support required */
  CpuClflush,
  /* NOP Instruction support required */
  CpuNop,
  /* SYSCALL Instructions support required */
  CpuSYSCALL,
  /* Floating point support required */
  Cpu8087,
  /* i287 support required */
  Cpu287,
  /* i387 support required */
  Cpu387,
  /* i686 and floating point support required */
  Cpu687,
  /* SSE3 and floating point support required */
  CpuFISTTP,
  /* MMX support required */
  CpuMMX,
  /* SSE support required */
  CpuSSE,
  /* SSE2 support required */
  CpuSSE2,
  /* 3dnow! support required */
  Cpu3dnow,
  /* 3dnow! Extensions support required */
  Cpu3dnowA,
  /* SSE3 support required */
  CpuSSE3,
  /* VIA PadLock required */
  CpuPadLock,
  /* AMD Secure Virtual Machine Ext-s required */
  CpuSVME,
  /* VMX Instructions required */
  CpuVMX,
  /* SMX Instructions required */
  CpuSMX,
  /* SSSE3 support required */
  CpuSSSE3,
  /* SSE4a support required */
  CpuSSE4a,
  /* ABM New Instructions required */
  CpuABM,
  /* SSE4.1 support required */
  CpuSSE4_1,
  /* SSE4.2 support required */
  CpuSSE4_2,
  /* AVX support required */
  CpuAVX,
  /* AVX2 support required */
  CpuAVX2,
  /* Intel AVX-512 Foundation Instructions support required */
  CpuAVX512F,
  /* Intel AVX-512 Conflict Detection Instructions support required */
  CpuAVX512CD,
  /* Intel AVX-512 Exponential and Reciprocal Instructions support
     required */
  CpuAVX512ER,
  /* Intel AVX-512 Prefetch Instructions support required */
  CpuAVX512PF,
  /* Intel AVX-512 VL Instructions support required.  */
  CpuAVX512VL,
  /* Intel AVX-512 DQ Instructions support required.  */
  CpuAVX512DQ,
  /* Intel AVX-512 BW Instructions support required.  */
  CpuAVX512BW,
  /* Intel L1OM support required */
  CpuL1OM,
  /* Intel K1OM support required */
  CpuK1OM,
  /* Intel IAMCU support required */
  CpuIAMCU,
  /* Xsave/xrstor New Instructions support required */
  CpuXsave,
  /* Xsaveopt New Instructions support required */
  CpuXsaveopt,
  /* AES support required */
  CpuAES,
  /* PCLMUL support required */
  CpuPCLMUL,
  /* FMA support required */
  CpuFMA,
  /* FMA4 support required */
  CpuFMA4,
  /* XOP support required */
  CpuXOP,
  /* LWP support required */
  CpuLWP,
  /* BMI support required */
  CpuBMI,
  /* TBM support required */
  CpuTBM,
  /* MOVBE Instruction support required */
  CpuMovbe,
  /* CMPXCHG16B instruction support required.  */
  CpuCX16,
  /* EPT Instructions required */
  CpuEPT,
  /* RDTSCP Instruction support required */
  CpuRdtscp,
  /* FSGSBASE Instructions required */
  CpuFSGSBase,
  /* RDRND Instructions required */
  CpuRdRnd,
  /* F16C Instructions required */
  CpuF16C,
  /* Intel BMI2 support required */
  CpuBMI2,
  /* LZCNT support required */
  CpuLZCNT,
  /* HLE support required */
  CpuHLE,
  /* RTM support required */
  CpuRTM,
  /* INVPCID Instructions required */
  CpuINVPCID,
  /* VMFUNC Instruction required */
  CpuVMFUNC,
  /* Intel MPX Instructions required  */
  CpuMPX,
  /* 64bit support available, used by -march= in assembler.  */
  CpuLM,
  /* RDRSEED instruction required.  */
  CpuRDSEED,
  /* Multi-presisionn add-carry instructions are required.  */
  CpuADX,
  /* Supports prefetchw and prefetch instructions.  */
  CpuPRFCHW,
  /* SMAP instructions required.  */
  CpuSMAP,
  /* SHA instructions required.  */
  CpuSHA,
  /* VREX support required  */
  CpuVREX,
  /* CLFLUSHOPT instruction required */
  CpuClflushOpt,
  /* XSAVES/XRSTORS instruction required */
  CpuXSAVES,
  /* XSAVEC instruction required */
  CpuXSAVEC,
  /* PREFETCHWT1 instruction required */
  CpuPREFETCHWT1,
  /* SE1 instruction required */
  CpuSE1,
  /* CLWB instruction required */
  CpuCLWB,
  /* PCOMMIT instruction required */
  CpuPCOMMIT,
  /* Intel AVX-512 IFMA Instructions support required.  */
  CpuAVX512IFMA,
  /* Intel AVX-512 VBMI Instructions support required.  */
  CpuAVX512VBMI,
  /* mwaitx instruction required */
  CpuMWAITX,
  /* Clzero instruction required */
  CpuCLZERO,
  /* OSPKE instruction required */
  CpuOSPKE,
  /* 64bit support required  */
  Cpu64,
  /* Not supported in the 64bit mode  */
  CpuNo64,
  /* AMD64 support required  */
  CpuAMD64,
  /* Intel64 support required  */
  CpuIntel64,
  /* The last bitfield in i386_cpu_flags.  */
  CpuMax = CpuNo64
};


#define CpuNumOfUints \
  (CpuMax / sizeof (unsigned int) / CHAR_BIT + 1)
#define CpuNumOfBits \
  (CpuNumOfUints * sizeof (unsigned int) * CHAR_BIT)

/* If you get a compiler error for zero width of the unused field,
   comment it out.  */
#define CpuUnused	(CpuMax + 1)

/* We can check if an instruction is available with array instead
   of bitfield. */
typedef union i386_cpu_flags
{
  struct
    {
      unsigned int cpui186:1;
      unsigned int cpui286:1;
      unsigned int cpui386:1;
      unsigned int cpui486:1;
      unsigned int cpui586:1;
      unsigned int cpui686:1;
      unsigned int cpuclflush:1;
      unsigned int cpunop:1;
      unsigned int cpusyscall:1;
      unsigned int cpu8087:1;
      unsigned int cpu287:1;
      unsigned int cpu387:1;
      unsigned int cpu687:1;
      unsigned int cpufisttp:1;
      unsigned int cpummx:1;
      unsigned int cpusse:1;
      unsigned int cpusse2:1;
      unsigned int cpua3dnow:1;
      unsigned int cpua3dnowa:1;
      unsigned int cpusse3:1;
      unsigned int cpupadlock:1;
      unsigned int cpusvme:1;
      unsigned int cpuvmx:1;
      unsigned int cpusmx:1;
      unsigned int cpussse3:1;
      unsigned int cpusse4a:1;
      unsigned int cpuabm:1;
      unsigned int cpusse4_1:1;
      unsigned int cpusse4_2:1;
      unsigned int cpuavx:1;
      unsigned int cpuavx2:1;
      unsigned int cpuavx512f:1;
      unsigned int cpuavx512cd:1;
      unsigned int cpuavx512er:1;
      unsigned int cpuavx512pf:1;
      unsigned int cpuavx512vl:1;
      unsigned int cpuavx512dq:1;
      unsigned int cpuavx512bw:1;
      unsigned int cpul1om:1;
      unsigned int cpuk1om:1;
      unsigned int cpuiamcu:1;
      unsigned int cpuxsave:1;
      unsigned int cpuxsaveopt:1;
      unsigned int cpuaes:1;
      unsigned int cpupclmul:1;
      unsigned int cpufma:1;
      unsigned int cpufma4:1;
      unsigned int cpuxop:1;
      unsigned int cpulwp:1;
      unsigned int cpubmi:1;
      unsigned int cputbm:1;
      unsigned int cpumovbe:1;
      unsigned int cpucx16:1;
      unsigned int cpuept:1;
      unsigned int cpurdtscp:1;
      unsigned int cpufsgsbase:1;
      unsigned int cpurdrnd:1;
      unsigned int cpuf16c:1;
      unsigned int cpubmi2:1;
      unsigned int cpulzcnt:1;
      unsigned int cpuhle:1;
      unsigned int cpurtm:1;
      unsigned int cpuinvpcid:1;
      unsigned int cpuvmfunc:1;
      unsigned int cpumpx:1;
      unsigned int cpulm:1;
      unsigned int cpurdseed:1;
      unsigned int cpuadx:1;
      unsigned int cpuprfchw:1;
      unsigned int cpusmap:1;
      unsigned int cpusha:1;
      unsigned int cpuvrex:1;
      unsigned int cpuclflushopt:1;
      unsigned int cpuxsaves:1;
      unsigned int cpuxsavec:1;
      unsigned int cpuprefetchwt1:1;
      unsigned int cpuse1:1;
      unsigned int cpuclwb:1;
      unsigned int cpupcommit:1;
      unsigned int cpuavx512ifma:1;
      unsigned int cpuavx512vbmi:1;
      unsigned int cpumwaitx:1;
      unsigned int cpuclzero:1;
      unsigned int cpuospke:1;
      unsigned int cpu64:1;
      unsigned int cpuno64:1;
      unsigned int cpuamd64:1;
      unsigned int cpuintel64:1;
#ifdef CpuUnused
      unsigned int unused:(CpuNumOfBits - CpuUnused);
#endif
    } bitfield;
  unsigned int array[CpuNumOfUints];
} i386_cpu_flags;






typedef struct i386_opcode_modifier
{
  unsigned int d:1;
  unsigned int w:1;
  unsigned int s:1;
  unsigned int modrm:1;
  unsigned int shortform:1;
  unsigned int jump:1;
  unsigned int jumpdword:1;
  unsigned int jumpbyte:1;
  unsigned int jumpintersegment:1;
  unsigned int floatmf:1;
  unsigned int floatr:1;
  unsigned int floatd:1;
  unsigned int size16:1;
  unsigned int size32:1;
  unsigned int size64:1;
  unsigned int checkregsize:1;
  unsigned int ignoresize:1;
  unsigned int defaultsize:1;
  unsigned int no_bsuf:1;
  unsigned int no_wsuf:1;
  unsigned int no_lsuf:1;
  unsigned int no_ssuf:1;
  unsigned int no_qsuf:1;
  unsigned int no_ldsuf:1;
  unsigned int fwait:1;
  unsigned int isstring:1;
  unsigned int bndprefixok:1;
  unsigned int islockable:1;
  unsigned int regkludge:1;
  unsigned int firstxmm0:1;
  unsigned int implicit1stxmm0:1;
  unsigned int hleprefixok:2;
  unsigned int repprefixok:1;
  unsigned int todword:1;
  unsigned int toqword:1;
  unsigned int addrprefixop0:1;
  unsigned int isprefix:1;
  unsigned int immext:1;
  unsigned int norex64:1;
  unsigned int rex64:1;
  unsigned int ugh:1;
  unsigned int vex:2;
  unsigned int vexvvvv:2;
  unsigned int vexw:2;
  unsigned int vexopcode:3;
  unsigned int vexsources:2;
  unsigned int veximmext:1;
  unsigned int vecsib:2;
  unsigned int sse2avx:1;
  unsigned int noavx:1;
  unsigned int evex:3;
  unsigned int masking:2;
  unsigned int vecesize:1;
  unsigned int broadcast:3;
  unsigned int staticrounding:1;
  unsigned int sae:1;
  unsigned int disp8memshift:3;
  unsigned int nodefmask:1;
  unsigned int oldgcc:1;
  unsigned int attmnemonic:1;
  unsigned int attsyntax:1;
  unsigned int intelsyntax:1;
} i386_opcode_modifier;

enum _instrg_ {
  instrg_zero,
  instrg_isBasicALU,
  instrg_isBasicShift,
  instrg_isBasicCmpTest,
  instrg_isCmpTestExtra,   
  
  instrg_isBaseLoadStore,
  instrg_isBaseIndexLoadStore,
  instrg_isBaseSpecLoad,
  instrg_isBaseIndexSpecLoad,
  instrg_isImmLoadStore,
  instrg_isImmSpecLoad,
  instrg_isBaseLoadStoreF,
  instrg_isBaseIndexLoadStoreF,
  instrg_isBaseSpecLoadF,
  instrg_isBaseIndexSpecLoadF,
  instrg_isImmLoadStoreF,
  instrg_isImmSpecLoadF,
  
  instrg_isIMulShort,

  instrg_isCondJump,
  instrg_isUncondJump,
  
  instrg_isMov,
  instrg_isExt,
  instrg_isCmov,
  instrg_isCSet,
  instrg_isBasicAddNoFl,
  instrg_isAddNoFlExtra,
  instrg_isShiftNoFl,
  instrg_isRegImul,
  
  instrg_isBigIMul,
  
  instrg_isIndirJump,
  instrg_isCall,
  instrg_isRet,

  instrg_push_pop,

  instrg_mov_abs,
 
  instrg_mov_xmm_i,
  instrg_mov_xmm,
 
  instrg_isFPU23Op,
  instrg_isFPU2Op,
  instrg_isFPU23OpImm,
  instrg_isFPU2OpImm,
  instrg_isMI3_3,
  instrg_isMI3_2,
  instrg_isMI2_3,
  instrg_isMI2_2
};

/* Position of operand_type bits.  */

enum
{
  /* 8bit register */
  Reg8 = 0,
  /* 16bit register */
  Reg16,
  /* 32bit register */
  Reg32,
  /* 64bit register */
  Reg64,
  /* Floating pointer stack register */
  FloatReg,
  /* MMX register */
  RegMMX,
  /* SSE register */
  RegXMM,
  /* AVX registers */
  RegYMM,
  /* AVX512 registers */
  RegZMM,
  /* Vector Mask registers */
  RegMask,
  /* Control register */
  Control,
  /* Debug register */
  Debug,
  /* Test register */
  Test,
  /* 2 bit segment register */
  SReg2,
  /* 3 bit segment register */
  SReg3,
  /* 8 bit immediate */
  Imm8,
  /* 13 bit immediate sign extended */
  Imm13s,
  /* 32 bit immediate */
  Imm32,
  /* 32 bit immediate sign extended */
  Imm32S,
  /* 64 bit immediate */
  Imm64,
  /* 8bit/16bit/32bit displacements are used in different ways,
     depending on the instruction.  For jumps, they specify the
     size of the PC relative displacement, for instructions with
     memory operand, they specify the size of the offset relative
     to the base register, and for instructions with memory offset
     such as `mov 1234,%al' they specify the size of the offset
     relative to the segment base.  */
  /* 16 bit displacement */
  Disp14s,
  /* 32 bit displacement */
  Disp32,
  /* 32 bit signed displacement */
  Disp32S,
  /* 64 bit displacement */
  Disp64,
  /* Floating pointer top stack register %st(0) */
  FloatAcc,
  /* Register which can be used for base or index in memory operand.  */
  BaseIndex,
  /* Register to hold in/out port addr = dx */
  InOutPortReg,
  /* Register to hold shift count = cl */
  ShiftCount,
  /* Absolute address for jump.  */
  JumpAbsolute,
  /* RegMem is for instructions with a modrm byte where the register
     destination operand should be encoded in the mod and regmem fields.
     Normally, it will be encoded in the reg field. We add a RegMem
     flag to the destination register operand to indicate that it should
     be encoded in the regmem field.  */
  RegMem,
  /* Memory.  */
  Mem,
  /* BYTE memory. */
  Byte,
  /* WORD memory. 2 byte */
  Word,
  /* DWORD memory. 4 byte */
  Dword,
  /* FWORD memory. 6 byte */
  Fword,
  /* QWORD memory. 8 byte */
  Qword,
  /* TBYTE memory. 10 byte */
  Tbyte,
  /* XMMWORD memory. */
  Xmmword,
  /* YMMWORD memory. */
  Ymmword,
  /* ZMMWORD memory.  */
  Zmmword,
  /* Unspecified memory size.  */
  Unspecified,
  /* Any memory size.  */
  Anysize,

  /* Vector 4 bit immediate.  */
  Vec_Imm4,


  /* Vector 8bit displacement */
  Vec_Disp8,

  /* The last bitfield in i386_operand_type.  */
  OTMax
};

#define OTNumOfUints \
  (OTMax / sizeof (unsigned int) / CHAR_BIT + 1)
#define OTNumOfBits \
  (OTNumOfUints * sizeof (unsigned int) * CHAR_BIT)

/* If you get a compiler error for zero width of the unused field,
   comment it out.  */
//#define OTUnused		(OTMax + 1)

typedef union i386_operand_type
{
  struct
    {
      unsigned int reg8:1;
      unsigned int reg16:1;
      unsigned int reg32:1;
      unsigned int reg64:1;
      unsigned int floatreg:1;
      unsigned int regmmx:1;
      unsigned int regxmm:1;
      unsigned int regymm:1;
      unsigned int regzmm:1;
      unsigned int regmask:1;
      unsigned int control:1;
      unsigned int debug:1;
      unsigned int test:1;
      unsigned int sreg2:1;
      unsigned int sreg3:1;
      unsigned int imm8:1;
      unsigned int imm13s:1;
      unsigned int imm32:1;
      unsigned int imm32s:1;
      unsigned int imm64:1;
      unsigned int disp14s:1;
      unsigned int disp32:1;
      unsigned int disp32s:1;
      unsigned int disp64:1;
      unsigned int floatacc:1;
      unsigned int baseindex:1;
      unsigned int inoutportreg:1;
      unsigned int shiftcount:1;
      unsigned int jumpabsolute:1;
      unsigned int regmem:1;
      unsigned int mem:1;
      unsigned int byte:1;
      unsigned int word:1;
      unsigned int dword:1;
      unsigned int fword:1;
      unsigned int qword:1;
      unsigned int tbyte:1;
      unsigned int xmmword:1;
      unsigned int ymmword:1;
      unsigned int zmmword:1;
      unsigned int unspecified:1;
      unsigned int anysize:1;
      unsigned int vec_imm4:1;
      unsigned int vec_disp8:1;
#ifdef OTUnused
      unsigned int unused:(OTNumOfBits - OTUnused);
#endif
    } bitfield;
  unsigned int array[OTNumOfUints];
} i386_operand_type;

typedef struct insn_template
{
  /* instruction name sans width suffix ("mov" for movl insns) */
  char *name;

  /* instruction group */
  enum _instrg_ group;

  /* base_opcode is the fundamental opcode byte without optional
     prefix(es).  */
  unsigned int base_opcode;

  unsigned int extension_opcode;
#define None 0xffff		/* If no extension_opcode is possible.  */
  
  unsigned int size_offsets; 

}
insn_template;

extern const insn_template heptane_optab[];

/* these are for register name --> number & type hash lookup */
typedef struct
{
  char *reg_name;
  int reg_num;
  i386_operand_type reg_type;
}
reg_entry;


/* Entries in i386_regtab.  */
//#define REGNAM_AL 1
//#define REGNAM_AX 25
//#define REGNAM_EAX 41
#define REGNAM_RIP 255

extern const reg_entry heptane_regtab[];
extern const unsigned int heptane_regtab_size;

typedef struct
{
  char *seg_name;
  unsigned int seg_prefix;
}
seg_entry;

extern const seg_entry cs;
extern const seg_entry ds;
extern const seg_entry ss;
extern const seg_entry es;
extern const seg_entry fs;
extern const seg_entry gs;

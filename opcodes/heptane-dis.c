/* Print i386 instructions for GDB, the GNU debugger.
   Copyright (C) 1988-2015 Free Software Foundation, Inc.

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
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */


/* 80386 instruction printer by Pace Willisson (pace@prep.ai.mit.edu)
   July 1988
    modified by John Hassey (hassey@dg-rtp.dg.com)
    x86-64 support added by Jan Hubicka (jh@suse.cz)
    VIA PadLock support by Michal Ludvig (mludvig@suse.cz).  */

/* The main tables describing the instructions is essentially a copy
   of the "Opcode Map" chapter (Appendix A) of the Intel 80386
   Programmers Manual.  Usually, there is a capital letter, followed
   by a small letter.  The capital letter tell the addressing mode,
   and the small letter tells about the operand size.  Refer to
   the Intel manual for details.  */

#include "sysdep.h"
#include "dis-asm.h"
#include "opintl.h"
#include "opcode/heptane.h"
#include "libiberty.h"

#include <setjmp.h>


struct dis_private {
  /* Points to first byte not fetched.  */
  bfd_byte *max_fetched;
  bfd_byte the_buffer[MAX_MNEM_SIZE];
  bfd_vma insn_start;
  int orig_sizeflag;
  OPCODES_SIGJMP_BUF bailout;
};

enum address_mode
{
  mode_32bit,
  mode_64bit
};

enum address_mode address_mode;
/*
static char reg64[][8]={
"%rax","%rbx","%rcx","%rdx","%rbp","%rsp","%rsi","%rdi",
"%r8","%r9","%r10","%r11","%r12","%r13","%r14","%r15",
"%r16","%r17","%r18","%r19","%r20","%r21","%r22","%r23",
"%r24","%r25","%r26","%r27","%r28","%r29","%r30","%r31"
};
static char reg32[][8]={
"%eax","%ebx","%ecx","%edx","%ebp","%esp","%esi","%edi",
"%r8d","%r9d","%r10d","%r11d","%r12d","%r13d","%r14d","%r15d",
"%r16d","%r17d","%r18d","%r19d","%r20d","%r21d","%r22d","%r23d",
"%r24d","%r25d","%r26d","%r27d","%r28d","%r29d","%r30d","%r31d"
};
static char reg16[][8]={
"%ax","%bx","%cx","%dx","%bp","%sp","%si","%di",
"%r8w","%r9w","%r10w","%r11w","%r12w","%r13w","%r14w","%r15w",
"%r16w","%r17w","%r18w","%r19w","%r20w","%r21w","%r22w","%r23w",
"%r24w","%r25w","%r26w","%r27w","%r28w","%r29w","%r30w","%r31w"
};
static char reg8[][8]={
"%al","%bl","%cl","%dl","%bpl","%spl","%sil","%dil",
"%r8l","%r9l","%r10l","%r11l","%r12l","%r13l","%r14l","%r15l",
"%r16l","%r17l","%r18l","%r19l","%r20l","%r21l","%r22l","%r23l",
"%r24l","%r25l","%r26l","%r27l","%r28l","%r29l","%r30l","%r31l",
"%ah","%bh","%ch","%dh","%bph","%sph","%sih","%dih",
"%r8h","%r9h","%r10h","%r11h","%r12h","%r13h","%r14h","%r15h",
"%r16h","%r17h","%r18h","%r19h","%r20h","%r21h","%r22h","%r23h",
"%r24h","%r25h","%r26h","%r27h","%r28h","%r29h","%r30h","%r31h"
};


static void print_regi(disassemble_info *info, int regnum, int sz) {
  switch(sz) {
case 0:
    (*info->fprintf_func)(info->stream,"%s",reg8[regnum<0 ? 32-regnum : regnum]);
    break;
case 1:
    (*info->fprintf_func)(info->stream,"%s",reg16[regnum]);
    break;
case 2:
    (*info->fprintf_func)(info->stream,"%s",reg32[regnum]);
    break;
case 3:
    (*info->fprintf_func)(info->stream,"%s",reg64[regnum]);
    break;
  }
} 
*/




int
print_insn_heptane ( bfd_vma pc , disassemble_info *info)
{
  bfd_byte buf[32];
  long long  off;
  long long len=32-(off=pc&0x1f);
  unsigned short bits;
  (*info->read_memory_func)(pc,buf,len,info);
  bits=buf[len-1]*256+buf[len-2];
  bits<<=(off>>1);
  (void) bits;
  return 0;
}

void
print_heptane_disassembler_options (FILE *stream)
{
  fprintf (stream, _("\n\
The following i386/x86-64 specific disassembler options are supported for use\n\
with the -M switch (multiple options should be separated by commas):\n"));

  fprintf (stream, _("  x86-64      Disassemble in 64bit mode\n"));
  fprintf (stream, _("  i386        Disassemble in 32bit mode\n"));
  fprintf (stream, _("  i8086       Disassemble in 16bit mode\n"));
  fprintf (stream, _("  att         Display instruction in AT&T syntax\n"));
  fprintf (stream, _("  intel       Display instruction in Intel syntax\n"));
  fprintf (stream, _("  att-mnemonic\n"
		     "              Display instruction in AT&T mnemonic\n"));
  fprintf (stream, _("  intel-mnemonic\n"
		     "              Display instruction in Intel mnemonic\n"));
  fprintf (stream, _("  addr64      Assume 64bit address size\n"));
  fprintf (stream, _("  addr32      Assume 32bit address size\n"));
  fprintf (stream, _("  addr16      Assume 16bit address size\n"));
  fprintf (stream, _("  data32      Assume 32bit data size\n"));
  fprintf (stream, _("  data16      Assume 16bit data size\n"));
  fprintf (stream, _("  suffix      Always display instruction suffix in AT&T syntax\n"));
  fprintf (stream, _("  amd64       Display instruction in AMD64 ISA\n"));
  fprintf (stream, _("  intel64     Display instruction in Intel64 ISA\n"));
}



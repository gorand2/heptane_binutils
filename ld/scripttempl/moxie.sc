# Copyright (C) 2014-2015 Free Software Foundation, Inc.
# 
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.

TORS=".tors :
  {
    ___ctors = . ;
    *(.ctors)
    ___ctors_end = . ;
    ___dtors = . ;
    *(.dtors)
    ___dtors_end = . ;
  } > ram"

cat <<EOF
/* Copyright (C) 2014-2015 Free Software Foundation, Inc.

   Copying and distribution of this script, with or without modification,
   are permitted in any medium without royalty provided the copyright
   notice and this notice are preserved.  */

OUTPUT_FORMAT("${OUTPUT_FORMAT}")
OUTPUT_ARCH(${ARCH})

SECTIONS
{
  .text :
  {
    *(.text)
      .init : { KEEP (*(.init)) } =0
      .fini : { KEEP (*(.fini)) } =0
    *(.strings)
    ${RELOCATING+ _etext = . ; }
  } ${RELOCATING+ > ram}
  ${CONSTRUCTING+${TORS}}
  .data :
  {
    *(.data)
    ${RELOCATING+ _edata = . ; }
  } ${RELOCATING+ > ram}
  .bss :
  {
    ${RELOCATING+ _bss_start = . ; }
    *(.bss)
    *(COMMON)
    ${RELOCATING+ _end = . ;  }
  } ${RELOCATING+ > ram}
  .stack ${RELOCATING+ 0x30000 }  :
  {
    ${RELOCATING+ _stack = . ; }
    *(.stack)
  } ${RELOCATING+ > ram}
  .stab 0 ${RELOCATING+(NOLOAD)} :
  {
    *(.stab)
  }
  .stabstr 0 ${RELOCATING+(NOLOAD)} :
  {
    *(.stabstr)
  }
}
EOF

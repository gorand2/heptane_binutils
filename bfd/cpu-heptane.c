/* BFD support for the Intel 386 architecture.
   Copyright (C) 1992-2015 Free Software Foundation, Inc.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "libiberty.h"



const bfd_arch_info_type bfd_heptane_arch __attribute__((used)) =
{
  64, /* 64 bits in a word */
  64, /* 64 bits in an address */
  8,  /* 8 bits in a byte */
  bfd_arch_heptane,
  bfd_mach_heptane,
  "heptane",
  "heptane:heptane",
  5,
  TRUE,
  bfd_default_compatible,
  bfd_default_scan,
  bfd_arch_default_fill,
  NULL
};

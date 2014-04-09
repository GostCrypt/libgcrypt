/* gost-s-box.c - GOST 28147-89 S-Box expander
 * Copyright (C) 2013 Dmitry Eremin-Solenikov
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>

#define DIM(v) (sizeof(v)/sizeof((v)[0]))

struct gost_sbox
{
  const char *name;
  const char *oid;
  unsigned char sbox[16*8];
} gost_sboxes[] = {
  { "test_3411", "1.2.643.2.2.30.0", {
      0x4, 0xE, 0x5, 0x7, 0x6, 0x4, 0xD, 0x1,
      0xA, 0xB, 0x8, 0xD, 0xC, 0xB, 0xB, 0xF,
      0x9, 0x4, 0x1, 0xA, 0x7, 0xA, 0x4, 0xD,
      0x2, 0xC, 0xD, 0x1, 0x1, 0x0, 0x1, 0x0,

      0xD, 0x6, 0xA, 0x0, 0x5, 0x7, 0x3, 0x5,
      0x8, 0xD, 0x3, 0x8, 0xF, 0x2, 0xF, 0x7,
      0x0, 0xF, 0x4, 0x9, 0xD, 0x1, 0x5, 0xA,
      0xE, 0xA, 0x2, 0xF, 0x8, 0xD, 0x9, 0x4,

      0x6, 0x2, 0xE, 0xE, 0x4, 0x3, 0x0, 0x9,
      0xB, 0x3, 0xF, 0x4, 0xA, 0x6, 0xA, 0x2,
      0x1, 0x8, 0xC, 0x6, 0x9, 0x8, 0xE, 0x3,
      0xC, 0x1, 0x7, 0xC, 0xE, 0x5, 0x7, 0xE,

      0x7, 0x0, 0x6, 0xB, 0x0, 0x9, 0x6, 0x6,
      0xF, 0x7, 0x0, 0x2, 0x3, 0xC, 0x8, 0xB,
      0x5, 0x5, 0x9, 0x5, 0xB, 0xF, 0x2, 0x8,
      0x3, 0x9, 0xB, 0x3, 0x2, 0xE, 0xC, 0xC,
    }
  },
  { "CryptoPro_3411", "1.2.643.2.2.30.1", {
      0xA, 0x5, 0x7, 0x4, 0x7, 0x7, 0xD, 0x1,
      0x4, 0xF, 0xF, 0xA, 0x6, 0x6, 0xE, 0x3,
      0x5, 0x4, 0xC, 0x7, 0x4, 0x2, 0x4, 0xA,
      0x6, 0x0, 0xE, 0xC, 0xB, 0x4, 0x1, 0x9,

      0x8, 0x2, 0x9, 0x0, 0x9, 0xD, 0x7, 0x5,
      0x1, 0xD, 0x4, 0xF, 0xC, 0x9, 0x0, 0xB,
      0x3, 0xB, 0x1, 0x2, 0x2, 0xF, 0x5, 0x4,
      0x7, 0x9, 0x0, 0x8, 0xA, 0x0, 0xA, 0xF,

      0xD, 0x1, 0x3, 0xE, 0x1, 0xA, 0x3, 0x8,
      0xC, 0x7, 0xB, 0x1, 0x8, 0x1, 0xC, 0x6,
      0xE, 0x6, 0x5, 0x6, 0x0, 0x5, 0x8, 0x7,
      0x0, 0x3, 0x2, 0x5, 0xE, 0xB, 0xF, 0xE,

      0x9, 0xC, 0x6, 0xD, 0xF, 0x8, 0x6, 0xD,
      0x2, 0xE, 0xA, 0xB, 0xD, 0xE, 0x2, 0x0,
      0xB, 0xA, 0x8, 0x9, 0x3, 0xC, 0x9, 0x2,
      0xF, 0x8, 0xD, 0x3, 0x5, 0x3, 0xB, 0xC,
    }
  },
  { "Test_89", "1.2.643.2.2.31.0", {
      0x4, 0xC, 0xD, 0xE, 0x3, 0x8, 0x9, 0xC,
      0x2, 0x9, 0x8, 0x9, 0xE, 0xF, 0xB, 0x6,
      0xF, 0xF, 0xE, 0xB, 0x5, 0x6, 0xC, 0x5,
      0x5, 0xE, 0xC, 0x2, 0x9, 0xB, 0x0, 0x2,

      0x9, 0x8, 0x7, 0x5, 0x6, 0x1, 0x3, 0xB,
      0x1, 0x1, 0x3, 0xF, 0x8, 0x9, 0x6, 0x0,
      0x0, 0x3, 0x9, 0x7, 0x0, 0xC, 0x7, 0x9,
      0x8, 0xA, 0xA, 0x1, 0xD, 0x5, 0x5, 0xD,

      0xE, 0x2, 0x1, 0x0, 0xA, 0xD, 0x4, 0x3,
      0x3, 0x7, 0x5, 0xD, 0xB, 0x3, 0x8, 0xE,
      0xB, 0x4, 0x2, 0xC, 0x7, 0x7, 0xE, 0x7,
      0xC, 0xD, 0x4, 0x6, 0xC, 0xA, 0xF, 0xA,

      0xD, 0x6, 0x6, 0xA, 0x2, 0x0, 0x1, 0xF,
      0x7, 0x0, 0xF, 0x4, 0x1, 0xE, 0xA, 0x4,
      0xA, 0xB, 0x0, 0x3, 0xF, 0x2, 0x2, 0x1,
      0x6, 0x5, 0xB, 0x8, 0x4, 0x4, 0xD, 0x8,
    }
  },
  { "CryptoPro_A", "1.2.643.2.2.31.1", {
      0x9, 0x3, 0xE, 0xE, 0xB, 0x3, 0x1, 0xB,
      0x6, 0x7, 0x4, 0x7, 0x5, 0xA, 0xD, 0xA,
      0x3, 0xE, 0x6, 0xA, 0x1, 0xD, 0x2, 0xF,
      0x2, 0x9, 0x2, 0xC, 0x9, 0xC, 0x9, 0x5,

      0x8, 0x8, 0xB, 0xD, 0x8, 0x1, 0x7, 0x0,
      0xB, 0xA, 0x3, 0x1, 0xD, 0x2, 0xA, 0xC,
      0x1, 0xF, 0xD, 0x3, 0xF, 0x0, 0x6, 0xE,
      0x7, 0x0, 0x8, 0x9, 0x0, 0xB, 0x0, 0x8,

      0xA, 0x5, 0xC, 0x0, 0xE, 0x7, 0x8, 0x6,
      0x4, 0x2, 0xF, 0x2, 0x4, 0x5, 0xC, 0x2,
      0xE, 0x6, 0x5, 0xB, 0x2, 0x9, 0x4, 0x3,
      0xF, 0xC, 0xA, 0x4, 0x3, 0x4, 0x5, 0x9,

      0xC, 0xB, 0x0, 0xF, 0xC, 0x8, 0xF, 0x1,
      0x0, 0x4, 0x7, 0x8, 0x7, 0xF, 0x3, 0x7,
      0xD, 0xD, 0x1, 0x5, 0xA, 0xE, 0xB, 0xD,
      0x5, 0x1, 0x9, 0x6, 0x6, 0x6, 0xE, 0x4,
    }
  },
  { "CryptoPro_B", "1.2.643.2.2.31.2", {
      0x8, 0x0, 0xE, 0x7, 0x2, 0x8, 0x5, 0x0,
      0x4, 0x1, 0xC, 0x5, 0x7, 0x3, 0x2, 0x4,
      0xB, 0x2, 0x0, 0x0, 0xC, 0x2, 0xA, 0xB,
      0x1, 0xA, 0xA, 0xD, 0xF, 0x6, 0xB, 0xE,

      0x3, 0x4, 0x9, 0xB, 0x9, 0x4, 0x9, 0x8,
      0x5, 0xD, 0x2, 0x6, 0x5, 0xD, 0x1, 0x3,
      0x0, 0x5, 0xD, 0x1, 0xA, 0xE, 0xC, 0x7,
      0x9, 0xC, 0xB, 0x2, 0xB, 0xB, 0x3, 0x1,

      0x2, 0x9, 0x7, 0x3, 0x1, 0xC, 0x7, 0xA,
      0xE, 0x7, 0x5, 0xA, 0x4, 0x1, 0x4, 0x2,
      0xA, 0x3, 0x8, 0xC, 0x0, 0x7, 0xD, 0x9,
      0xC, 0xF, 0xF, 0xF, 0xD, 0xF, 0x0, 0x6,

      0x6, 0x8, 0x6, 0xE, 0x8, 0x0, 0xF, 0xD,
      0x7, 0x6, 0x1, 0x9, 0xE, 0x9, 0x8, 0x5,
      0xF, 0xE, 0x4, 0x8, 0x3, 0x5, 0xE, 0xC,
    }
  },
  { "CryptoPro_C", "1.2.643.2.2.31.3", {
      0x1, 0x0, 0x8, 0x3, 0x8, 0xC, 0xA, 0x7,
      0xB, 0x1, 0x2, 0x6, 0xD, 0x9, 0x9, 0x4,
      0xC, 0x7, 0x5, 0x0, 0xB, 0xB, 0x6, 0x0,
      0x2, 0xD, 0x0, 0x1, 0x0, 0x1, 0x8, 0x5,

      0x9, 0xB, 0x4, 0x5, 0x4, 0x8, 0xD, 0xA,
      0xD, 0x4, 0x9, 0xD, 0x5, 0xE, 0xE, 0x2,
      0x0, 0x5, 0xF, 0xA, 0x1, 0x2, 0x2, 0xF,
      0xF, 0x2, 0xA, 0x8, 0x2, 0x4, 0x0, 0xE,

      0x4, 0x8, 0x3, 0xB, 0x9, 0x7, 0xF, 0xC,
      0x5, 0xE, 0x7, 0x2, 0x3, 0x3, 0x3, 0x6,
      0x8, 0xF, 0xC, 0x9, 0xC, 0x6, 0x5, 0x1,
      0xE, 0xC, 0xD, 0x7, 0xE, 0x5, 0xB, 0xB,

      0xA, 0x9, 0x6, 0xE, 0x6, 0xA, 0x4, 0xD,
      0x7, 0xA, 0xE, 0xF, 0xF, 0x0, 0x1, 0x9,
      0x6, 0x6, 0x1, 0xC, 0xA, 0xF, 0xC, 0x3,
      0x3, 0x3, 0xB, 0x4, 0x7, 0xD, 0x7, 0x8,
    }
  },
  { "CryptoPro_D", "1.2.643.2.2.31.4", {
      0xF, 0xB, 0x1, 0x1, 0x0, 0x8, 0x3, 0x1,
      0xC, 0x6, 0xC, 0x5, 0xC, 0x0, 0x0, 0xA,
      0x2, 0x3, 0xB, 0xE, 0x8, 0xF, 0x6, 0x6,
      0xA, 0x4, 0x0, 0xC, 0x9, 0x3, 0xF, 0x8,

      0x6, 0xC, 0xF, 0xA, 0xD, 0x2, 0x1, 0xF,
      0x4, 0xF, 0xE, 0x7, 0x2, 0x5, 0xE, 0xB,
      0x5, 0xE, 0x6, 0x0, 0xA, 0xE, 0x9, 0x0,
      0x0, 0x2, 0x5, 0xD, 0xB, 0xB, 0x2, 0x4,

      0x7, 0x7, 0xA, 0x6, 0x7, 0x1, 0xD, 0xC,
      0x9, 0xD, 0xD, 0x2, 0x3, 0xA, 0x8, 0x3,
      0xE, 0x8, 0x4, 0xB, 0x6, 0x4, 0xC, 0x5,
      0xD, 0x0, 0x8, 0x4, 0x5, 0x7, 0x4, 0x9,

      0x1, 0x5, 0x9, 0x9, 0x4, 0xC, 0xB, 0x7,
      0xB, 0xA, 0x3, 0x3, 0xE, 0x9, 0xA, 0xD,
      0x8, 0x9, 0x7, 0xF, 0xF, 0xD, 0x5, 0x2,
      0x3, 0x1, 0x2, 0x8, 0x1, 0x6, 0x7, 0xE,
    }
  },
  { "TC26_A", "1.2.643.7.1.2.5.1.1", {
      0xc, 0x6, 0xb, 0xc, 0x7, 0x5, 0x8, 0x1,
      0x4, 0x8, 0x3, 0x8, 0xf, 0xd, 0xe, 0x7,
      0x6, 0x2, 0x5, 0x2, 0x5, 0xf, 0x2, 0xe,
      0x2, 0x3, 0x8, 0x1, 0xa, 0x6, 0x5, 0xd,

      0xa, 0x9, 0x2, 0xd, 0x8, 0x9, 0x6, 0x0,
      0x5, 0xa, 0xf, 0x4, 0x1, 0x2, 0x9, 0x5,
      0xb, 0x5, 0xa, 0xf, 0x6, 0xc, 0x1, 0x8,
      0x9, 0xc, 0xd, 0x6, 0xd, 0xa, 0xc, 0x3,

      0xe, 0x1, 0xe, 0x7, 0x0, 0xb, 0xf, 0x4,
      0x8, 0xe, 0x1, 0x0, 0x9, 0x7, 0x4, 0xf,
      0xd, 0x4, 0x7, 0xa, 0x3, 0x8, 0xb, 0xa,
      0x7, 0x7, 0x4, 0x5, 0xe, 0x1, 0x0, 0x6,

      0x0, 0xb, 0xc, 0x3, 0xb, 0x4, 0xd, 0x9,
      0x3, 0xd, 0x9, 0xe, 0x4, 0x3, 0xa, 0xc,
      0xf, 0x0, 0x6, 0x9, 0x2, 0xe, 0x3, 0xb,
      0x1, 0xf, 0x0, 0xb, 0xc, 0x0, 0x7, 0x2,
    }
  },
  { "DKE_1", NULL, {
      0xa, 0x8, 0xf, 0x3, 0xf, 0x2, 0x3, 0x1,
      0x9, 0x0, 0x6, 0x8, 0x8, 0x8, 0x8, 0x2,
      0xd, 0xc, 0x5, 0xd, 0xe, 0x9, 0xb, 0x3,
      0x6, 0x4, 0x8, 0x9, 0x9, 0x7, 0x5, 0xe,

      0xe, 0x9, 0xe, 0x6, 0x7, 0x5, 0x6, 0x6,
      0xb, 0x6, 0xb, 0xb, 0x2, 0xf, 0x4, 0xd,
      0x4, 0x7, 0xa, 0xf, 0x0, 0x0, 0xe, 0xb,
      0x5, 0xb, 0x4, 0x0, 0xd, 0xb, 0xa, 0x8,

      0xf, 0x2, 0xc, 0x2, 0xc, 0xc, 0x2, 0xf,
      0x1, 0x3, 0x0, 0x5, 0x6, 0x1, 0xc, 0xa,
      0x3, 0x1, 0x3, 0xc, 0x1, 0xd, 0x1, 0xc,
      0xc, 0xf, 0x7, 0xa, 0x5, 0xe, 0x7, 0x5,

      0x7, 0x5, 0x2, 0x4, 0xb, 0xa, 0x9, 0x7,
      0x0, 0xe, 0x9, 0xe, 0x4, 0x3, 0xf, 0x9,
      0x8, 0xa, 0x1, 0x1, 0x3, 0x6, 0xd, 0x0,
      0x2, 0xd, 0xd, 0x7, 0xa, 0x4, 0x0, 0x4,
    }
  },
  { "DKE_2", NULL, {
      0xe, 0xa, 0x4, 0x4, 0xc, 0x8, 0xf, 0x4,
      0x9, 0xd, 0xb, 0x5, 0xb, 0x7, 0x0, 0x3,
      0x3, 0xc, 0x1, 0x1, 0x3, 0x3, 0xe, 0xe,
      0x7, 0x7, 0xf, 0xc, 0x9, 0xa, 0x6, 0xd,

      0xf, 0x6, 0x9, 0x7, 0xf, 0x9, 0x8, 0x5,
      0x4, 0xe, 0x2, 0xe, 0x0, 0x6, 0xd, 0x0,
      0xc, 0x8, 0xe, 0x9, 0x4, 0xe, 0x5, 0x2,
      0xb, 0x1, 0xc, 0x2, 0x5, 0x5, 0x9, 0xb,

      0x6, 0xf, 0x6, 0xa, 0x7, 0xd, 0xa, 0x1,
      0xa, 0x3, 0xa, 0xf, 0x2, 0x0, 0x3, 0xa,
      0xd, 0xb, 0x8, 0xb, 0xe, 0x4, 0x1, 0x7,
      0x1, 0x4, 0x7, 0xd, 0xd, 0xc, 0xc, 0x6,

      0x0, 0x0, 0x3, 0x0, 0x1, 0x1, 0x4, 0x9,
      0x5, 0x9, 0x5, 0x8, 0xa, 0x2, 0xb, 0xf,
      0x8, 0x5, 0x0, 0x6, 0x8, 0xf, 0x7, 0x8,
      0x2, 0x2, 0xd, 0x3, 0x6, 0xb, 0x2, 0xc,
    }
  },
  { "DKE_3", NULL, {
      0xd, 0x7, 0xa, 0xb, 0x5, 0x4, 0x3, 0x6,
      0x9, 0x8, 0x5, 0xa, 0xb, 0x3, 0x7, 0xd,
      0x1, 0x6, 0x3, 0xc, 0x3, 0xb, 0x8, 0xc,
      0xe, 0xb, 0xc, 0x1, 0x0, 0xd, 0xb, 0xa,

      0x7, 0x0, 0x9, 0x5, 0xf, 0x1, 0x1, 0xb,
      0x2, 0x3, 0x8, 0x6, 0x9, 0xf, 0xe, 0x7,
      0xc, 0x4, 0xd, 0x9, 0xe, 0x8, 0x5, 0x9,
      0x5, 0xd, 0x6, 0xe, 0x4, 0x2, 0x0, 0x3,

      0x4, 0x9, 0x4, 0x2, 0x1, 0x7, 0xd, 0xf,
      0xb, 0x5, 0xf, 0xd, 0xc, 0xe, 0x4, 0xe,
      0x6, 0xf, 0xe, 0xf, 0x8, 0xc, 0xc, 0x1,
      0xf, 0xe, 0x0, 0x7, 0x6, 0x9, 0xa, 0x2,

      0x3, 0xa, 0x2, 0x0, 0x2, 0xa, 0x2, 0x0,
      0x8, 0xc, 0xb, 0x4, 0xa, 0x0, 0x9, 0x8,
      0xa, 0x2, 0x1, 0x3, 0x7, 0x6, 0xf, 0x4,
      0x0, 0x1, 0x7, 0x8, 0xd, 0x5, 0x6, 0x5,
    }
  },
  { "DKE_4", NULL, {
      0x9, 0xa, 0x4, 0x3, 0x2, 0xe, 0xe, 0x1,
      0xc, 0x5, 0xc, 0x9, 0x9, 0x5, 0x6, 0x9,
      0x3, 0xb, 0x3, 0x4, 0xc, 0xd, 0x5, 0xc,
      0xd, 0xe, 0x0, 0x5, 0xf, 0xb, 0xa, 0xb,

      0x7, 0x7, 0xd, 0xe, 0xd, 0x1, 0x9, 0x7,
      0x6, 0x6, 0x2, 0x7, 0xb, 0x9, 0xd, 0x6,
      0xe, 0x0, 0xe, 0x8, 0x4, 0x4, 0x4, 0x8,
      0x1, 0xc, 0xb, 0x6, 0x1, 0x2, 0x8, 0x3,

      0xa, 0x2, 0x7, 0xd, 0x7, 0xf, 0xb, 0x2,
      0x2, 0x8, 0xf, 0x0, 0x5, 0x8, 0xc, 0xf,
      0x0, 0xf, 0x5, 0x2, 0x3, 0x7, 0x0, 0xe,
      0x4, 0x4, 0x9, 0xf, 0xe, 0x0, 0x3, 0x0,

      0x8, 0xd, 0x1, 0xb, 0x6, 0x3, 0x7, 0x5,
      0xf, 0x3, 0x8, 0xc, 0x8, 0xc, 0x1, 0xa,
      0x5, 0x9, 0xa, 0xa, 0xa, 0xa, 0xf, 0x4,
      0xb, 0x1, 0x6, 0x1, 0x0, 0x6, 0x2, 0xd,
    }
  },
  { "DKE_5", NULL, {
      0x3, 0xc, 0xe, 0x3, 0x5, 0x1, 0x9, 0xe,
      0x4, 0x7, 0x4, 0x9, 0xc, 0x8, 0xb, 0x9,
      0xd, 0x6, 0x8, 0x6, 0xa, 0xb, 0xa, 0x1,
      0x8, 0x9, 0x7, 0xd, 0x7, 0xe, 0xd, 0x8,

      0xc, 0x3, 0xb, 0x8, 0x2, 0x7, 0x5, 0x5,
      0x7, 0x8, 0x3, 0xf, 0x1, 0x4, 0xe, 0xf,
      0xa, 0xb, 0xa, 0xa, 0xf, 0xa, 0x2, 0xb,
      0x2, 0x5, 0xc, 0x2, 0xd, 0x0, 0x3, 0x0,

      0x0, 0xf, 0x1, 0x7, 0xe, 0xc, 0x0, 0x6,
      0xe, 0xa, 0x2, 0xe, 0x3, 0x3, 0x6, 0x2,
      0x9, 0x0, 0x6, 0xc, 0xb, 0x5, 0x4, 0xc,
      0xf, 0xd, 0x9, 0x0, 0x4, 0xd, 0xc, 0x7,

      0xb, 0x4, 0xd, 0xb, 0x0, 0x9, 0xf, 0xa,
      0x1, 0x2, 0xf, 0x4, 0x8, 0xf, 0x1, 0x4,
      0x5, 0x1, 0x0, 0x1, 0x9, 0x6, 0x7, 0xd,
      0x6, 0xe, 0x5, 0x5, 0x6, 0x2, 0x8, 0x3,
    }
  },
  { "DKE_6", NULL, {
      0xf, 0xe, 0x5, 0x1, 0xf, 0xb, 0x7, 0x1,
      0xc, 0xc, 0x6, 0xf, 0x9, 0x0, 0xe, 0x5,
      0x9, 0x5, 0xd, 0x7, 0xe, 0xd, 0xf, 0xe,
      0x6, 0x0, 0x9, 0x4, 0x6, 0x7, 0x8, 0xb,

      0xe, 0x7, 0xb, 0x2, 0xd, 0xc, 0xd, 0x2,
      0x2, 0x4, 0xe, 0xe, 0x1, 0xe, 0x0, 0xc,
      0x1, 0xa, 0xa, 0xc, 0x5, 0x1, 0xb, 0x3,
      0xb, 0x3, 0x3, 0x3, 0x8, 0x4, 0x3, 0x8,

      0x0, 0x2, 0xf, 0x6, 0x4, 0x2, 0xa, 0xa,
      0xd, 0x6, 0x2, 0xb, 0x2, 0x3, 0x1, 0x0,
      0x4, 0x1, 0x8, 0x9, 0x3, 0x6, 0x4, 0x9,
      0xa, 0xd, 0x1, 0x8, 0xc, 0x8, 0x2, 0x7,

      0x7, 0x9, 0x4, 0x0, 0xa, 0xa, 0x9, 0xf,
      0x8, 0xb, 0x0, 0x5, 0xb, 0x5, 0xc, 0x6,
      0x3, 0xf, 0x7, 0xa, 0x0, 0xf, 0x6, 0x4,
      0x5, 0x8, 0xc, 0xd, 0x7, 0x9, 0x5, 0xd,
    }
  },
  { "DKE_7", NULL, {
      0xf, 0x2, 0x3, 0x4, 0xf, 0xc, 0xd, 0x1,
      0xd, 0x5, 0xe, 0xa, 0x6, 0xb, 0x2, 0x5,
      0xa, 0xa, 0x4, 0xb, 0x5, 0xf, 0x4, 0x0,
      0x5, 0x0, 0xb, 0x9, 0x8, 0x4, 0x8, 0xf,

      0xc, 0x6, 0x5, 0xf, 0x9, 0x5, 0xb, 0x6,
      0x0, 0x9, 0x9, 0x2, 0x7, 0x1, 0xc, 0xa,
      0x1, 0x1, 0x1, 0xe, 0xc, 0xe, 0x1, 0x3,
      0x6, 0xf, 0x2, 0x5, 0xb, 0x9, 0x3, 0xe,

      0x9, 0xd, 0xf, 0xd, 0x0, 0x0, 0xa, 0x7,
      0x2, 0x4, 0x6, 0x1, 0xa, 0x8, 0x5, 0x2,
      0xe, 0x7, 0x8, 0x3, 0x3, 0xd, 0x9, 0xc,
      0x7, 0xe, 0xd, 0x6, 0x1, 0x2, 0xe, 0xd,

      0x3, 0xb, 0x7, 0x0, 0x2, 0xa, 0x7, 0xb,
      0xb, 0x3, 0x0, 0x7, 0x4, 0x7, 0xf, 0x8,
      0x4, 0x8, 0xa, 0xc, 0xd, 0x3, 0x0, 0x9,
      0x8, 0xc, 0xc, 0x8, 0xe, 0x6, 0x6, 0x4,
    }
  },
  { "DKE_8", NULL, {
      0xe, 0x3, 0x5, 0xc, 0x6, 0x6, 0x2, 0x3,
      0x4, 0xe, 0x2, 0xa, 0x3, 0xd, 0xf, 0x0,
      0xb, 0xc, 0x8, 0x7, 0xf, 0xf, 0xc, 0x5,
      0x2, 0xa, 0x7, 0xd, 0x7, 0x1, 0x5, 0xc,

      0x8, 0x6, 0x1, 0xe, 0x0, 0x5, 0xb, 0x8,
      0x7, 0x2, 0xf, 0x3, 0x9, 0x3, 0x1, 0xf,
      0x5, 0xd, 0xe, 0x0, 0xa, 0x8, 0x3, 0xd,
      0xc, 0x1, 0x6, 0x2, 0x8, 0x0, 0xe, 0xe,

      0x9, 0x9, 0x4, 0x9, 0xb, 0xb, 0x0, 0xb,
      0xd, 0x8, 0xd, 0x5, 0xc, 0xa, 0x6, 0x6,
      0x0, 0x7, 0xb, 0x1, 0x4, 0xe, 0xd, 0x2,
      0x3, 0x4, 0x0, 0x6, 0x1, 0x4, 0xa, 0x9,

      0x1, 0x0, 0xa, 0xb, 0x5, 0x9, 0x7, 0x7,
      0xf, 0xf, 0x3, 0x4, 0x2, 0xc, 0x9, 0x1,
      0x6, 0x5, 0xc, 0xf, 0xd, 0x2, 0x4, 0x4,
      0xa, 0xb, 0x9, 0x8, 0xe, 0x7, 0x8, 0xa,
    }
  },
  { "DKE_9", NULL, {
      0x9, 0x3, 0x8, 0x5, 0x7, 0x7, 0x7, 0xe,
      0x0, 0x5, 0x4, 0x4, 0xc, 0x4, 0xe, 0x2,
      0xb, 0x0, 0x5, 0xf, 0x3, 0x3, 0x9, 0x8,
      0xc, 0xf, 0xa, 0x0, 0x0, 0xb, 0xf, 0xf,

      0x2, 0x8, 0xe, 0xc, 0x6, 0x6, 0x1, 0x3,
      0x4, 0x7, 0xb, 0xb, 0x8, 0xa, 0x4, 0x0,
      0x3, 0xe, 0xd, 0xa, 0xe, 0x8, 0x8, 0x7,
      0xf, 0xc, 0x6, 0x9, 0xb, 0x1, 0x3, 0xc,

      0xd, 0xd, 0xc, 0x1, 0x1, 0x9, 0xb, 0xb,
      0x6, 0xa, 0xf, 0xe, 0xf, 0xc, 0xd, 0xd,
      0xe, 0x1, 0x7, 0x8, 0xd, 0xe, 0x0, 0x1,
      0x1, 0x6, 0x9, 0x6, 0xa, 0xd, 0x2, 0x5,

      0xa, 0xb, 0x3, 0x3, 0x9, 0x0, 0x6, 0x6,
      0x7, 0x2, 0x1, 0x2, 0x5, 0xf, 0xa, 0x4,
      0x5, 0x4, 0x2, 0xd, 0x2, 0x2, 0x5, 0x9,
      0x8, 0x9, 0x0, 0x7, 0x4, 0x5, 0xc, 0xa,
    }
  },
  { "DKE_10", NULL, {
      0x8, 0x7, 0xc, 0x2, 0x8, 0x4, 0x5, 0xa,
      0x4, 0xd, 0x8, 0xb, 0x3, 0xc, 0x8, 0x3,
      0x6, 0x1, 0xd, 0x3, 0xd, 0x9, 0xe, 0x5,
      0x9, 0x8, 0x1, 0x4, 0xa, 0xb, 0x7, 0x9,

      0xb, 0xa, 0xa, 0xc, 0xe, 0xe, 0x3, 0x0,
      0xc, 0xe, 0x2, 0x7, 0xf, 0xa, 0x0, 0xd,
      0x1, 0x4, 0x9, 0x9, 0x5, 0x7, 0x1, 0x7,
      0x2, 0xf, 0x6, 0xd, 0x1, 0x6, 0xd, 0x8,

      0x3, 0x9, 0x3, 0xf, 0x4, 0x3, 0xa, 0xc,
      0x7, 0x0, 0x4, 0x8, 0x7, 0x5, 0x6, 0x4,
      0xe, 0x6, 0xe, 0x5, 0xb, 0x0, 0x9, 0x1,
      0x0, 0x3, 0x7, 0x0, 0xc, 0xf, 0x2, 0x6,

      0xd, 0x2, 0x5, 0x1, 0x2, 0x1, 0xf, 0xb,
      0xa, 0xc, 0xf, 0xe, 0x0, 0x2, 0xb, 0xf,
      0xf, 0xb, 0x0, 0xa, 0x6, 0x8, 0xc, 0x2,
      0x5, 0x5, 0xb, 0x6, 0x9, 0xd, 0x4, 0xe,
    }
  },
};

int main(int argc, char **argv)
{
  unsigned int i, j, s;
  FILE *f;

  if (argc == 1)
    f = stdin;
  else
    f = fopen(argv[1], "w");

  if (!f)
    {
      perror("fopen");
      exit(1);
    }

  for (s = 0; s < DIM(gost_sboxes); s++)
    {
      unsigned char *sbox = gost_sboxes[s].sbox;
      fprintf (f, "static const u32 sbox_%s[4*256] =\n  {", gost_sboxes[s].name);
      for (i = 0; i < 4; i++) {
        fprintf (f, "\n    /* %d */\n   ", i);
        for (j = 0; j < 256; j++) {
          unsigned int val;
          if (j % 4 == 0 && j != 0)
            fprintf (f, "\n   ");
          val = sbox[ (j & 0xf) * 8 + 2 * i + 0] |
               (sbox[ (j >> 4)  * 8 + 2 * i + 1] << 4);
          val <<= (8*i);
          val = (val << 11) | (val >> 21);
          fprintf (f, " 0x%08x,", val);
        }
      }
      fprintf (f, "\n  };\n\n");
    }

  fprintf (f, "static struct\n{\n  const char *oid;\n  const u32 *sbox;\n} gost_oid_map[] = {\n");

  for (s = 0; s < DIM(gost_sboxes); s++)
    {
      fprintf (f, "  { \"%s\", sbox_%s },\n", gost_sboxes[s].name, gost_sboxes[s].name );
      if (gost_sboxes[s].oid)
        fprintf (f, "  { \"%s\", sbox_%s },\n", gost_sboxes[s].oid, gost_sboxes[s].name );
    }

  fprintf(f, "  { NULL, NULL }\n};\n");

  fclose (f);

  return 0;
}

/* gost3411.c - GOST R 34.11-94 hash function
 * Copyright (C) 2012 Free Software Foundation, Inc.
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


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g10lib.h"
#include "bithelp.h"
#include "cipher.h"
#include "hash-common.h"


typedef struct {
  gcry_md_block_ctx_t bctx;
  byte h[32];
  byte sigma[32];
  u32 len;
} GOST3411_CONTEXT;

static void
transform (void *c, const unsigned char *data);

static void
gost3411_init (void *context)
{
  GOST3411_CONTEXT *hd = context;

  memset (hd->h, 0, 32);
  memset (hd->sigma, 0, 32);

  hd->bctx.nblocks = 0;
  hd->bctx.count = 0;
  hd->bctx.blocksize = 32;
  hd->bctx.bwrite = transform;
}

static void
do_p (unsigned char *p, unsigned char *u, unsigned char *v)
{
  int i, k;
  for (k = 0; k < 8; k++)
    {
      for (i = 0; i < 4; i++)
        {
          p[i + 4 * k] = u[8 * i + k] ^ v[8 * i + k];
        }
    }
}

static void
do_a (unsigned char *u)
{
  unsigned char temp[8];
  int i;
  memcpy (temp, u, 8);
  memmove (u, u+8, 24);
  for (i = 0; i < 8; i++)
    {
      u[24 + i] = u[i] ^ temp[i];
    }
}
/* apply do_a twice: 1 2 3 4 -> 3 4 1^2 2^3 */
static void
do_a2 (unsigned char *u)
{
  unsigned char temp[16];
  int i;
  memcpy (temp, u, 16);
  memcpy (u, u + 16, 16);
  for (i = 0; i < 8; i++)
    {
      u[16 + i] = temp[i] ^ temp[8 + i];
      u[24 + i] =    u[i] ^ temp[8 + i];
    }
}

static void
do_apply_c2 (unsigned char *u)
{
  u[ 1] ^= 0xff;
  u[ 3] ^= 0xff;
  u[ 5] ^= 0xff;
  u[ 7] ^= 0xff;

  u[ 8] ^= 0xff;
  u[10] ^= 0xff;
  u[12] ^= 0xff;
  u[14] ^= 0xff;

  u[17] ^= 0xff;
  u[18] ^= 0xff;
  u[20] ^= 0xff;
  u[23] ^= 0xff;

  u[24] ^= 0xff;
  u[28] ^= 0xff;
  u[29] ^= 0xff;
  u[31] ^= 0xff;
}

#define do_phi_step(e, i) \
  e[(0 + 2*i) % 32] ^= e[(2 + 2*i) % 32] ^ e[(4 + 2*i) % 32] ^ e[(6 + 2*i) % 32] ^ e[(24 + 2*i) % 32] ^ e[(30 + 2*i) % 32]; \
  e[(1 + 2*i) % 32] ^= e[(3 + 2*i) % 32] ^ e[(5 + 2*i) % 32] ^ e[(7 + 2*i) % 32] ^ e[(25 + 2*i) % 32] ^ e[(31 + 2*i) % 32];

static void
do_phi_submix (unsigned char *e, unsigned char *x, int round)
{
  int i;
  round *= 2;
  for (i = 0; i < 32; i++)
    {
      e[(i + round) % 32] ^= x[i];
    }
}

static void
do_add (unsigned char *s, unsigned char *a)
{
  unsigned temp = 0;
  int i;

  for (i = 0; i < 32; i++)
    {
      temp = s[i] + a[i] + (temp >> 8);
      s[i] = temp & 0xff;
    }
}

static void
do_hash_step (unsigned char *h, unsigned char *m)
{
  unsigned char u[32], v[32], s[32];
  unsigned char k[32];
  int i;

  gcry_cipher_hd_t hd;
  gcry_error_t err;

  err = gcry_cipher_open (&hd, GCRY_CIPHER_GOST28147, GCRY_CIPHER_MODE_ECB, 0);
  if (err) {
    fprintf (stderr, "LibGCrypt error %s/%s\n",
        gcry_strsource (err),
        gcry_strerror (err));
    exit (1);
  }

  memcpy (u, h, 32);
  memcpy (v, m, 32);

  for (i = 0; i < 4; i++) {
    do_p (k, u, v);

    err = gcry_cipher_setkey (hd, k, sizeof (k));
    if (err) {
      fprintf (stderr, "LibGCrypt error %s/%s\n",
          gcry_strsource (err),
          gcry_strerror (err));
      exit (1);
    }

    err = gcry_cipher_encrypt (hd, s+i * 8, 8, h+i*8, 8);
    if (err) {
      fprintf (stderr, "LibGCrypt error %s/%s\n",
          gcry_strsource (err),
          gcry_strerror (err));
      exit (1);
    }

    do_a (u);
    if (i == 1)
      do_apply_c2 (u);
    do_a2 (v);
  }

  for (i = 0; i < 5; i++)
    {
      do_phi_step (s, 0);
      do_phi_step (s, 1);
      do_phi_step (s, 2);
      do_phi_step (s, 3);
      do_phi_step (s, 4);
      do_phi_step (s, 5);
      do_phi_step (s, 6);
      do_phi_step (s, 7);
      do_phi_step (s, 8);
      do_phi_step (s, 9);
      /* That is in total 12 + 1 + 61 = 74 = 16 * 4 + 10 rounds */
      if (i == 4)
        break;
      do_phi_step (s, 10);
      do_phi_step (s, 11);
      if (i == 0)
        do_phi_submix(s, m, 12);
      do_phi_step (s, 12);
      if (i == 0)
        do_phi_submix(s, h, 13);
      do_phi_step (s, 13);
      do_phi_step (s, 14);
      do_phi_step (s, 15);
    }

  memcpy (h, s+20, 12);
  memcpy (h+12, s, 20);

  gcry_cipher_close (hd);
}


static void
transform (void *ctx, const unsigned char *data)
{
  GOST3411_CONTEXT *hd = ctx;
  byte m[32];

  memcpy (m, data, 32);
  do_hash_step (hd->h, m);
  do_add (hd->sigma, m);
}

/*
   The routine finally terminates the computation and returns the
   digest.  The handle is prepared for a new cycle, but adding bytes
   to the handle will the destroy the returned buffer.  Returns: 32
   bytes with the message the digest.  */
static void
gost3411_final (void *context)
{
  GOST3411_CONTEXT *hd = context;
  size_t padlen = 0;
  byte l[32];
  int i;
  u32 nblocks;

  if (hd->bctx.count > 0)
    {
      padlen = 32 - hd->bctx.count;
      memset (hd->bctx.buf + hd->bctx.count, 0, padlen);
      hd->bctx.count += padlen;
      _gcry_md_block_write (hd, NULL, 0); /* flush */;
    }

  if (hd->bctx.count != 0)
    return; /* Something went wrong */

  memset (l, 0, 32);

  nblocks = hd->bctx.nblocks;
  if (padlen)
    {
      nblocks --;
      l[0] = 256 - padlen * 8;
    }

  for (i = 1; i < 32 && nblocks != 0; i++)
    {
      l[i] = nblocks % 256;
      nblocks /= 256;
    }

  do_hash_step (hd->h, l);
  do_hash_step (hd->h, hd->sigma);
}

static byte *
gost3411_read (void *context)
{
  GOST3411_CONTEXT *hd = context;

  return hd->h;
}
gcry_md_spec_t _gcry_digest_spec_gost3411 =
  {
    "GOST34.11", NULL, 0, NULL, 32,
    gost3411_init, _gcry_md_block_write, gost3411_final, gost3411_read,
    sizeof (GOST3411_CONTEXT)
  };

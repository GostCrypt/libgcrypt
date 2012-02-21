/* cipher-gostofb.c  - Generic OFB-like mode implementation from GOST 28147-89
 * Copyright (C) 2012 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
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

#include "g10lib.h"
#include "cipher.h"
#include "bufhelp.h"
#include "./cipher-internal.h"

/* We require a cipher with a 64 bit block length.  */
static void
_gcry_cipher_cntgost_transform(unsigned char *buf)
{
  u32 val, val2;

  val =  buf[0] |
        (buf[1] << 8) |
        (buf[2] << 16) |
        (buf[3] << 24);
  val2 = val + 0x01010101;
  buf[0] = val2 & 0xff;
  buf[1] = (val2 >> 8) & 0xff;
  buf[2] = (val2 >> 16) & 0xff;
  buf[3] = (val2 >> 24) & 0xff;

  buf += 4;

  /* It's an (A + B) mod (2^32 - 1) part.
   * If we got an overflow, we have just to add 1 */
  val =  buf[0] |
        (buf[1] << 8) |
        (buf[2] << 16) |
        (buf[3] << 24);
  val2 = val + 0x01010104;
  if (val2 < val)
    val2 ++;
  buf[0] = val2 & 0xff;
  buf[1] = (val2 >> 8) & 0xff;
  buf[2] = (val2 >> 16) & 0xff;
  buf[3] = (val2 >> 24) & 0xff;
}

gcry_err_code_t
_gcry_cipher_cntgost_encrypt (gcry_cipher_hd_t c,
                          unsigned char *outbuf, unsigned int outbuflen,
                          const unsigned char *inbuf, unsigned int inbuflen)
{
  unsigned int n;
  int i;
  unsigned int blocksize = c->spec->blocksize;
  unsigned int nblocks;
  unsigned int burn, nburn;

  if (outbuflen < inbuflen)
    return GPG_ERR_BUFFER_TOO_SHORT;

  burn = 0;

  /* First process a left over encrypted counter.  */
  if (c->unused)
    {
      gcry_assert (c->unused < blocksize);
      i = blocksize - c->unused;
      n = c->unused > inbuflen ? inbuflen : c->unused;
      buf_xor(outbuf, inbuf, &c->lastiv[i], n);
      c->unused -= n;
      inbuf  += n;
      outbuf += n;
      inbuflen -= n;
    }

  /* If we don't have a bulk method use the standard method.  We also
     use this method for the a remaining partial block.  */
  if (inbuflen)
    {
      unsigned char tmp[MAX_BLOCKSIZE];

      do {
        nburn = c->spec->encrypt (&c->context.c, tmp, c->u_ctr.ctr);
        burn = nburn > burn ? nburn : burn;

        _gcry_cipher_cntgost_transform (c->u_ctr.ctr);

        n = blocksize < inbuflen ? blocksize : inbuflen;
        buf_xor(outbuf, inbuf, tmp, n);

        inbuflen -= n;
        outbuf += n;
        inbuf += n;
      } while (inbuflen);

      /* Save the unused bytes of the counter.  */
      c->unused = blocksize - n;
      if (c->unused)
        memcpy (c->lastiv+n, tmp+n, c->unused);

      wipememory (tmp, sizeof tmp);
    }

  if (burn > 0)
    _gcry_burn_stack (burn + 4 * sizeof(void *));

  return 0;
}

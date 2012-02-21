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
#include "./cipher-internal.h"

static gcry_err_code_t
_gcry_cipher_ofbgost_transform(unsigned char *buf, unsigned int blocksize)
{
  u32 val, val2;

  /* We require a cipher with a 64 bit block length.  */
  if (blocksize != 8)
    return GPG_ERR_INV_LENGTH;

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

  return GPG_ERR_NO_ERROR;
}

gcry_err_code_t
_gcry_cipher_ofbgost_encrypt (gcry_cipher_hd_t c,
                          unsigned char *outbuf, unsigned int outbuflen,
                          const unsigned char *inbuf, unsigned int inbuflen)
{
  unsigned char *ivp;
  size_t blocksize = c->cipher->blocksize;

  if (outbuflen < inbuflen)
    return GPG_ERR_BUFFER_TOO_SHORT;

  if ( inbuflen <= c->unused )
    {
      /* Short enough to be encoded by the remaining XOR mask. */
      /* XOR the input with the IV */
      for (ivp=c->u_iv.iv+c->cipher->blocksize - c->unused;
           inbuflen;
           inbuflen--, c->unused-- )
        *outbuf++ = (*ivp++ ^ *inbuf++);
      return 0;
    }

  if( c->unused )
    {
      inbuflen -= c->unused;
      for(ivp=c->u_iv.iv+blocksize - c->unused; c->unused; c->unused-- )
        *outbuf++ = (*ivp++ ^ *inbuf++);
    }

  /* Now we can process complete blocks. */
  while ( inbuflen >= blocksize )
    {
      int i;
      gcry_err_code_t err;
      /* Encrypt the IV (and save the current one). */
      memcpy( c->lastiv, c->u_iv.iv, blocksize );
      c->cipher->encrypt ( &c->context.c, c->u_iv.iv, c->u_iv.iv );

      err = _gcry_cipher_ofbgost_transform ( c->u_iv.iv, blocksize );
      if (err)
        return err;

      for (ivp=c->u_iv.iv,i=0; i < blocksize; i++ )
        *outbuf++ = (*ivp++ ^ *inbuf++);
      inbuflen -= blocksize;
    }
  if ( inbuflen )
    { /* process the remaining bytes */
      memcpy( c->lastiv, c->u_iv.iv, blocksize );
      c->cipher->encrypt ( &c->context.c, c->u_iv.iv, c->u_iv.iv );
      c->unused = blocksize;
      c->unused -= inbuflen;
      for(ivp=c->u_iv.iv; inbuflen; inbuflen-- )
        *outbuf++ = (*ivp++ ^ *inbuf++);
    }
  return 0;
}


gcry_err_code_t
_gcry_cipher_ofbgost_decrypt (gcry_cipher_hd_t c,
                          unsigned char *outbuf, unsigned int outbuflen,
                          const unsigned char *inbuf, unsigned int inbuflen)
{
  unsigned char *ivp;
  size_t blocksize = c->cipher->blocksize;

  if (outbuflen < inbuflen)
    return GPG_ERR_BUFFER_TOO_SHORT;

  if( inbuflen <= c->unused )
    {
      /* Short enough to be encoded by the remaining XOR mask. */
      for (ivp=c->u_iv.iv+blocksize - c->unused; inbuflen; inbuflen--,c->unused--)
        *outbuf++ = *ivp++ ^ *inbuf++;
      return 0;
    }

  if ( c->unused )
    {
      inbuflen -= c->unused;
      for (ivp=c->u_iv.iv+blocksize - c->unused; c->unused; c->unused-- )
        *outbuf++ = *ivp++ ^ *inbuf++;
    }

  /* Now we can process complete blocks. */
  while ( inbuflen >= blocksize )
    {
      int i;
      gcry_err_code_t err;
      /* Encrypt the IV (and save the current one). */
      memcpy( c->lastiv, c->u_iv.iv, blocksize );
      c->cipher->encrypt ( &c->context.c, c->u_iv.iv, c->u_iv.iv );

      err = _gcry_cipher_ofbgost_transform ( c->u_iv.iv, blocksize );
      if (err)
        return err;

      for (ivp=c->u_iv.iv,i=0; i < blocksize; i++ )
        *outbuf++ = *ivp++ ^ *inbuf++;
      inbuflen -= blocksize;
    }
  if ( inbuflen )
    { /* Process the remaining bytes. */
      /* Encrypt the IV (and save the current one). */
      memcpy( c->lastiv, c->u_iv.iv, blocksize );
      c->cipher->encrypt ( &c->context.c, c->u_iv.iv, c->u_iv.iv );
      c->unused = blocksize;
      c->unused -= inbuflen;
      for (ivp=c->u_iv.iv; inbuflen; inbuflen-- )
        *outbuf++ = *ivp++ ^ *inbuf++;
    }
  return 0;
}

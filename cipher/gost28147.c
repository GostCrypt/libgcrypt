/* gost28147.c - GOST 28147-89 implementation for Libgcrypt
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

/* GOST 28147-89 defines several modes of encryption:
 * - ECB which should be used only for key transfer
 * - CFB mode
 * - OFB-like mode with additional transformation on keystream
 *   RFC 5830 names this 'counter encryption' mode
 *   Original GOST text uses the term 'gammirovanie'
 * - MAC mode
 *
 * This implementation handles ECB and CFB modes via usual libgcrypt handling.
 * OFB-like 'counter encryption' mode is implemented via generic cipher mode
 * (GCRY_CIPHER_OFBGOST).
 * MAC mode is unsupported.
 */

#include <config.h>
#include "types.h"
#include "g10lib.h"
#include "cipher.h"
#include "mac-internal.h"
#include "bufhelp.h"

#include "gost.h"
#include "gost-sb.h"

static gcry_err_code_t
gost_setkey (void *c, const byte *key, unsigned keylen)
{
  int i;
  GOST28147_context *ctx = c;

  if (keylen != 256 / 8)
    return GPG_ERR_INV_KEYLEN;

  if (!ctx->sbox)
    ctx->sbox = sbox_test_3411;

  for (i = 0; i < 8; i++)
    {
      ctx->key[i] = buf_get_le32(&key[4*i]);
    }
  return GPG_ERR_NO_ERROR;
}

static u32
gost_val (GOST28147_context *ctx, u32 cm1, int subkey)
{
  cm1 += ctx->key[subkey];
  cm1 = ctx->sbox[0*256 + ((cm1 >>  0) & 0xff)] |
        ctx->sbox[1*256 + ((cm1 >>  8) & 0xff)] |
        ctx->sbox[2*256 + ((cm1 >> 16) & 0xff)] |
        ctx->sbox[3*256 + ((cm1 >> 24) & 0xff)];
  return cm1;
}

static unsigned int
_gost_encrypt_data (void *c, u32 *o1, u32 *o2, u32 n1, u32 n2)
{
  GOST28147_context *ctx = c;

  n2 ^= gost_val (ctx, n1, 0); n1 ^= gost_val (ctx, n2, 1);
  n2 ^= gost_val (ctx, n1, 2); n1 ^= gost_val (ctx, n2, 3);
  n2 ^= gost_val (ctx, n1, 4); n1 ^= gost_val (ctx, n2, 5);
  n2 ^= gost_val (ctx, n1, 6); n1 ^= gost_val (ctx, n2, 7);

  n2 ^= gost_val (ctx, n1, 0); n1 ^= gost_val (ctx, n2, 1);
  n2 ^= gost_val (ctx, n1, 2); n1 ^= gost_val (ctx, n2, 3);
  n2 ^= gost_val (ctx, n1, 4); n1 ^= gost_val (ctx, n2, 5);
  n2 ^= gost_val (ctx, n1, 6); n1 ^= gost_val (ctx, n2, 7);

  n2 ^= gost_val (ctx, n1, 0); n1 ^= gost_val (ctx, n2, 1);
  n2 ^= gost_val (ctx, n1, 2); n1 ^= gost_val (ctx, n2, 3);
  n2 ^= gost_val (ctx, n1, 4); n1 ^= gost_val (ctx, n2, 5);
  n2 ^= gost_val (ctx, n1, 6); n1 ^= gost_val (ctx, n2, 7);

  n2 ^= gost_val (ctx, n1, 7); n1 ^= gost_val (ctx, n2, 6);
  n2 ^= gost_val (ctx, n1, 5); n1 ^= gost_val (ctx, n2, 4);
  n2 ^= gost_val (ctx, n1, 3); n1 ^= gost_val (ctx, n2, 2);
  n2 ^= gost_val (ctx, n1, 1); n1 ^= gost_val (ctx, n2, 0);

  *o1 = n2;
  *o2 = n1;

  return /* burn_stack */ 4*sizeof(void*) /* func call */ +
                          3*sizeof(void*) /* stack */ +
                          4*sizeof(void*) /* gost_val call */;
}

static unsigned int
gost_encrypt_block (void *c, byte *outbuf, const byte *inbuf)
{
  GOST28147_context *ctx = c;
  u32 n1, n2;
  unsigned int burn;

  n1 = buf_get_le32 (inbuf);
  n2 = buf_get_le32 (inbuf+4);

  burn = _gost_encrypt_data(ctx, &n1, &n2, n1, n2);

  buf_put_le32 (outbuf+0, n1);
  buf_put_le32 (outbuf+4, n2);

  return /* burn_stack */ burn + 6*sizeof(void*) /* func call */;
}

unsigned int _gcry_gost_enc_data (GOST28147_context *c, const u32 *key,
    u32 *o1, u32 *o2, u32 n1, u32 n2, int cryptopro)
{
  if (cryptopro)
    c->sbox = sbox_CryptoPro_3411;
  else
    c->sbox = sbox_test_3411;
  memcpy (c->key, key, 8*4);
  return _gost_encrypt_data (c, o1, o2, n1, n2) + 7 * sizeof(void *);
}

static unsigned int
gost_decrypt_block (void *c, byte *outbuf, const byte *inbuf)
{
  GOST28147_context *ctx = c;
  u32 n1, n2;

  n1 = buf_get_le32 (inbuf);
  n2 = buf_get_le32 (inbuf+4);

  n2 ^= gost_val (ctx, n1, 0); n1 ^= gost_val (ctx, n2, 1);
  n2 ^= gost_val (ctx, n1, 2); n1 ^= gost_val (ctx, n2, 3);
  n2 ^= gost_val (ctx, n1, 4); n1 ^= gost_val (ctx, n2, 5);
  n2 ^= gost_val (ctx, n1, 6); n1 ^= gost_val (ctx, n2, 7);

  n2 ^= gost_val (ctx, n1, 7); n1 ^= gost_val (ctx, n2, 6);
  n2 ^= gost_val (ctx, n1, 5); n1 ^= gost_val (ctx, n2, 4);
  n2 ^= gost_val (ctx, n1, 3); n1 ^= gost_val (ctx, n2, 2);
  n2 ^= gost_val (ctx, n1, 1); n1 ^= gost_val (ctx, n2, 0);

  n2 ^= gost_val (ctx, n1, 7); n1 ^= gost_val (ctx, n2, 6);
  n2 ^= gost_val (ctx, n1, 5); n1 ^= gost_val (ctx, n2, 4);
  n2 ^= gost_val (ctx, n1, 3); n1 ^= gost_val (ctx, n2, 2);
  n2 ^= gost_val (ctx, n1, 1); n1 ^= gost_val (ctx, n2, 0);

  n2 ^= gost_val (ctx, n1, 7); n1 ^= gost_val (ctx, n2, 6);
  n2 ^= gost_val (ctx, n1, 5); n1 ^= gost_val (ctx, n2, 4);
  n2 ^= gost_val (ctx, n1, 3); n1 ^= gost_val (ctx, n2, 2);
  n2 ^= gost_val (ctx, n1, 1); n1 ^= gost_val (ctx, n2, 0);

  buf_put_le32 (outbuf+0, n2);
  buf_put_le32 (outbuf+4, n1);

  return /* burn_stack */ 4*sizeof(void*) /* func call */ +
                          3*sizeof(void*) /* stack */ +
                          4*sizeof(void*) /* gost_val call */;
}

static gpg_err_code_t
gost_set_sbox (GOST28147_context *ctx, const char *oid)
{
  int i;

  for (i = 0; gost_oid_map[i].oid; i++)
    {
      if (!strcmp(gost_oid_map[i].oid, oid))
        {
          ctx->sbox = gost_oid_map[i].sbox;
          return 0;
        }
    }
  return GPG_ERR_VALUE_NOT_FOUND;
}

static gpg_err_code_t
gost_set_extra_info (void *c, int what, const void *buffer, size_t buflen)
{
  GOST28147_context *ctx = c;
  gpg_err_code_t ec = 0;

  (void)buffer;
  (void)buflen;

  switch (what)
    {
    case GCRYCTL_SET_SBOX:
      ec = gost_set_sbox (ctx, buffer);
      break;

    default:
      ec = GPG_ERR_INV_OP;
      break;
    }
  return ec;
}

static gcry_cipher_oid_spec_t oids_gost28147[] =
  {
    /* { "1.2.643.2.2.31.0", GCRY_CIPHER_MODE_CNTGOST }, */
    { "1.2.643.2.2.31.1", GCRY_CIPHER_MODE_CFB },
    { "1.2.643.2.2.31.2", GCRY_CIPHER_MODE_CFB },
    { "1.2.643.2.2.31.3", GCRY_CIPHER_MODE_CFB },
    { "1.2.643.2.2.31.4", GCRY_CIPHER_MODE_CFB },
    { NULL }
  };

gcry_cipher_spec_t _gcry_cipher_spec_gost28147 =
  {
    GCRY_CIPHER_GOST28147, {0, 0},
    "GOST28147", NULL, oids_gost28147, 8, 256,
    sizeof (GOST28147_context),
    gost_setkey,
    gost_encrypt_block,
    gost_decrypt_block,
    NULL, NULL, NULL, gost_set_extra_info,
  };

static gcry_err_code_t
gost_imit_open (gcry_mac_hd_t h)
{
  (void) h;
  memset(&h->u.imit, 0, sizeof(h->u.imit));
  return 0;
}

static void
gost_imit_close (gcry_mac_hd_t h)
{
  (void) h;
}

static gcry_err_code_t
gost_imit_setkey (gcry_mac_hd_t h, const unsigned char *key, size_t keylen)
{
  h->u.imit.ctx.sbox = sbox_CryptoPro_A;
  return gost_setkey (&h->u.imit.ctx, key, keylen);
}


static gcry_err_code_t
gost_imit_reset (gcry_mac_hd_t h)
{
  h->u.imit.n1 = h->u.imit.n2 = 0;
  h->u.imit.unused = 0;
  return 0;
}

static int
gost_imit_block(gcry_mac_hd_t h, u32 n1, u32 n2)
{
  GOST28147_context *ctx = &h->u.imit.ctx;
  n1 ^= h->u.imit.n1;
  n2 ^= h->u.imit.n2;

  n2 ^= gost_val (ctx, n1, 0); n1 ^= gost_val (ctx, n2, 1);
  n2 ^= gost_val (ctx, n1, 2); n1 ^= gost_val (ctx, n2, 3);
  n2 ^= gost_val (ctx, n1, 4); n1 ^= gost_val (ctx, n2, 5);
  n2 ^= gost_val (ctx, n1, 6); n1 ^= gost_val (ctx, n2, 7);

  n2 ^= gost_val (ctx, n1, 0); n1 ^= gost_val (ctx, n2, 1);
  n2 ^= gost_val (ctx, n1, 2); n1 ^= gost_val (ctx, n2, 3);
  n2 ^= gost_val (ctx, n1, 4); n1 ^= gost_val (ctx, n2, 5);
  n2 ^= gost_val (ctx, n1, 6); n1 ^= gost_val (ctx, n2, 7);

  h->u.imit.n1 = n1;
  h->u.imit.n2 = n2;

  return /* burn_stack */ 4*sizeof(void*) /* func call */ +
                          3*sizeof(void*) /* stack */ +
                          4*sizeof(void*) /* gost_val call */;
}

static gcry_err_code_t
gost_imit_write (gcry_mac_hd_t h, const unsigned char *buf, size_t buflen)
{
  const int blocksize = 8;
  unsigned int burn = 0;
  if (!buflen || !buf)
    return GPG_ERR_NO_ERROR;

  if (h->u.imit.unused)
    {
      for (; buflen && h->u.imit.unused < blocksize; buflen --)
        h->u.imit.lastiv[h->u.imit.unused++] = *buf++;

      if (h->u.imit.unused < blocksize)
        return GPG_ERR_NO_ERROR;

      burn = gost_imit_block (h,
          buf_get_le32 (h->u.imit.lastiv+0),
          buf_get_le32 (h->u.imit.lastiv+4));

      h->u.imit.unused = 0;
    }

  while (buflen >= blocksize)
    {
      burn = gost_imit_block (h,
            buf_get_le32 (buf+0), buf_get_le32 (buf+4));
      buf += blocksize;
      buflen -= blocksize;
    }

  for (; buflen; buflen--)
    h->u.imit.lastiv[h->u.imit.unused++] = *buf++;

  return GPG_ERR_NO_ERROR;
}


static gcry_err_code_t
gost_imit_read (gcry_mac_hd_t h, unsigned char *outbuf, size_t * outlen)
{
  unsigned int dlen = 8;
  char digest[8];

  buf_put_le32 (digest+0, h->u.imit.n1);
  buf_put_le32 (digest+4, h->u.imit.n2);

  if (*outlen <= dlen)
    buf_cpy (outbuf, digest, *outlen);
  else
    {
      buf_cpy (outbuf, digest, dlen);
      *outlen = dlen;
    }
  return 0;
}


static gcry_err_code_t
gost_imit_verify (gcry_mac_hd_t h, const unsigned char *buf, size_t buflen)
{
  char tbuf[8];

  buf_put_le32 (tbuf+0, h->u.imit.n1);
  buf_put_le32 (tbuf+4, h->u.imit.n2);

  return buf_eq_const(tbuf, buf, buflen) ?
             GPG_ERR_NO_ERROR : GPG_ERR_CHECKSUM;
}


static unsigned int
gost_imit_get_maclen (int algo)
{
  (void) algo;
  return 4; /* or 8 */
}


static unsigned int
gost_imit_get_keylen (int algo)
{
  (void) algo;
  return 256 / 8;
}

static gcry_mac_spec_ops_t gost_imit_ops = {
  gost_imit_open,
  gost_imit_close,
  gost_imit_setkey,
  NULL,
  gost_imit_reset,
  gost_imit_write,
  gost_imit_read,
  gost_imit_verify,
  gost_imit_get_maclen,
  gost_imit_get_keylen,
};

gcry_mac_spec_t _gcry_mac_type_spec_gost28147_imit =
  {
    GCRY_MAC_GOST28147_IMIT, {0, 0}, "GOST28147_IMIT",
    &gost_imit_ops
  };

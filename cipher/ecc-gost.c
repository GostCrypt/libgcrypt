/* ecc-gots.c  -  Elliptic Curve GOST signatures
 * Copyright (C) 2007, 2008, 2010, 2011 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "g10lib.h"
#include "mpi.h"
#include "cipher.h"
#include "context.h"
#include "ec-context.h"
#include "ecc-common.h"
#include "pubkey-internal.h"

static gpg_err_code_t
_gcry_gost_normalize_hash (gcry_mpi_t input,
                           gcry_mpi_t *out,
                           unsigned int qbits)
{
  gpg_err_code_t rc = 0;
  byte*abuf;
  unsigned int abytes;
  gcry_mpi_t hash;
  unsigned int qbytes = (qbits + 7)/8;
  byte arr[qbytes];
  int i, j;

  if (mpi_is_opaque (input))
    {
      abuf = mpi_get_opaque (input, &abytes);
      abytes = (abytes + 7)/8;
    }
  else
    {
      size_t temp;
      rc = _gcry_mpi_aprint (GCRYMPI_FMT_USG, &abuf, &temp, input);
      abytes = temp;
    }

  if (abytes != qbytes)
    {
      memset(arr+abytes, 0, qbytes - abytes);
    }

  for (i = 0, j = abytes-1; i < abytes; i++, j--)
    arr[j] = abuf[i];

  rc = _gcry_mpi_scan (&hash, GCRYMPI_FMT_USG, arr, qbytes, NULL);

  *out = hash;

  if (!mpi_is_opaque (input))
    xfree (abuf);

  return rc;
}


/* Compute an GOST R 34.10-01/-12 signature.
 * Return the signature struct (r,s) from the message hash.  The caller
 * must have allocated R and S.
 */
gpg_err_code_t
_gcry_ecc_gost_sign (gcry_mpi_t input, ECC_secret_key *skey,
                     gcry_mpi_t r, gcry_mpi_t s)
{
  gpg_err_code_t rc = 0;
  gcry_mpi_t k, dr, sum, ke, x, e;
  mpi_point_struct I;
  gcry_mpi_t hash;
  unsigned int qbits;
  mpi_ec_t ctx;

  if (DBG_CIPHER)
    log_mpidump ("gost sign hash  ", input );

  qbits = mpi_get_nbits (skey->E.n);

  /* Convert the INPUT into an MPI if needed.  */
  rc = _gcry_gost_normalize_hash (input, &hash, qbits);
  if (rc)
    return rc;

  k = NULL;
  dr = mpi_alloc (0);
  sum = mpi_alloc (0);
  ke = mpi_alloc (0);
  e = mpi_alloc (0);
  x = mpi_alloc (0);
  point_init (&I);

  ctx = _gcry_mpi_ec_p_internal_new (skey->E.model, skey->E.dialect, 0,
                                     skey->E.p, skey->E.a, skey->E.b);

  mpi_mod (e, hash, skey->E.n); /* e = hash mod n */

  if (!mpi_cmp_ui (e, 0))
    mpi_set_ui (e, 1);

  /* Two loops to avoid R or S are zero.  This is more of a joke than
     a real demand because the probability of them being zero is less
     than any hardware failure.  Some specs however require it.  */
  do
    {
      do
        {
          mpi_free (k);
          k = _gcry_dsa_gen_k (skey->E.n, GCRY_STRONG_RANDOM);

          _gcry_mpi_ec_mul_point (&I, k, &skey->E.G, ctx);
          if (_gcry_mpi_ec_get_affine (x, NULL, &I, ctx))
            {
              if (DBG_CIPHER)
                log_debug ("ecc sign: Failed to get affine coordinates\n");
              rc = GPG_ERR_BAD_SIGNATURE;
              goto leave;
            }
          mpi_mod (r, x, skey->E.n);  /* r = x mod n */
        }
      while (!mpi_cmp_ui (r, 0));
      mpi_mulm (dr, skey->d, r, skey->E.n); /* dr = d*r mod n  */
      mpi_mulm (ke, k, e, skey->E.n); /* ke = k*e mod n */
      mpi_addm (s, ke, dr, skey->E.n); /* sum = (k*e+ d*r) mod n  */
    }
  while (!mpi_cmp_ui (s, 0));

  if (DBG_CIPHER)
    {
      log_mpidump ("gost sign result r ", r);
      log_mpidump ("gost sign result s ", s);
    }

 leave:
  _gcry_mpi_ec_free (ctx);
  point_free (&I);
  mpi_free (x);
  mpi_free (e);
  mpi_free (ke);
  mpi_free (sum);
  mpi_free (dr);
  mpi_free (k);

  if (hash != input)
    mpi_free (hash);

  return rc;
}


/* Verify a GOST R 34.10-01/-12 signature.
 * Check if R and S verifies INPUT.
 */
gpg_err_code_t
_gcry_ecc_gost_verify (gcry_mpi_t input, ECC_public_key *pkey,
                       gcry_mpi_t r, gcry_mpi_t s)
{
  gpg_err_code_t err = 0;
  gcry_mpi_t hash, e, x, z1, z2, v, rv, zero;
  mpi_point_struct Q, Q1, Q2;
  mpi_ec_t ctx;

  if( !(mpi_cmp_ui (r, 0) > 0 && mpi_cmp (r, pkey->E.n) < 0) )
    return GPG_ERR_BAD_SIGNATURE; /* Assertion	0 < r < n  failed.  */
  if( !(mpi_cmp_ui (s, 0) > 0 && mpi_cmp (s, pkey->E.n) < 0) )
    return GPG_ERR_BAD_SIGNATURE; /* Assertion	0 < s < n  failed.  */

  x = mpi_alloc (0);
  e = mpi_alloc (0);
  z1 = mpi_alloc (0);
  z2 = mpi_alloc (0);
  v = mpi_alloc (0);
  rv = mpi_alloc (0);
  zero = mpi_alloc (0);

  point_init (&Q);
  point_init (&Q1);
  point_init (&Q2);

  ctx = _gcry_mpi_ec_p_internal_new (pkey->E.model, pkey->E.dialect, 0,
                                     pkey->E.p, pkey->E.a, pkey->E.b);

  /* Convert the INPUT into an MPI if needed.  */
  err = _gcry_gost_normalize_hash (input, &hash, mpi_get_nbits (pkey->E.n));
  if (err)
    return err;

  mpi_mod (e, hash, pkey->E.n); /* e = hash mod n */
  if (!mpi_cmp_ui (e, 0))
    mpi_set_ui (e, 1);
  mpi_invm (v, e, pkey->E.n); /* v = e^(-1) (mod n) */
  mpi_mulm (z1, s, v, pkey->E.n); /* z1 = s*v (mod n) */
  mpi_mulm (rv, r, v, pkey->E.n); /* rv = s*v (mod n) */
  mpi_subm (z2, zero, rv, pkey->E.n); /* z2 = -r*v (mod n) */

  _gcry_mpi_ec_mul_point (&Q1, z1, &pkey->E.G, ctx);
/*   log_mpidump ("Q1.x", Q1.x); */
/*   log_mpidump ("Q1.y", Q1.y); */
/*   log_mpidump ("Q1.z", Q1.z); */
  _gcry_mpi_ec_mul_point (&Q2, z2, &pkey->Q, ctx);
/*   log_mpidump ("Q2.x", Q2.x); */
/*   log_mpidump ("Q2.y", Q2.y); */
/*   log_mpidump ("Q2.z", Q2.z); */
  _gcry_mpi_ec_add_points (&Q, &Q1, &Q2, ctx);
/*   log_mpidump (" Q.x", Q.x); */
/*   log_mpidump (" Q.y", Q.y); */
/*   log_mpidump (" Q.z", Q.z); */

  if (!mpi_cmp_ui (Q.z, 0))
    {
      if (DBG_CIPHER)
          log_debug ("ecc verify: Rejected\n");
      err = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }
  if (_gcry_mpi_ec_get_affine (x, NULL, &Q, ctx))
    {
      if (DBG_CIPHER)
        log_debug ("ecc verify: Failed to get affine coordinates\n");
      err = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }
  mpi_mod (x, x, pkey->E.n); /* x = x mod E_n */
  if (mpi_cmp (x, r))   /* x != r */
    {
      if (DBG_CIPHER)
        {
          log_mpidump ("     x", x);
          log_mpidump ("     r", r);
          log_mpidump ("     s", s);
          log_debug ("ecc verify: Not verified\n");
        }
      err = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }
  if (DBG_CIPHER)
    log_debug ("ecc verify: Accepted\n");

 leave:
  _gcry_mpi_ec_free (ctx);
  point_free (&Q2);
  point_free (&Q1);
  point_free (&Q);
  mpi_free (zero);
  mpi_free (rv);
  mpi_free (v);
  mpi_free (z2);
  mpi_free (z1);
  mpi_free (x);
  mpi_free (e);

  if (hash != input)
    mpi_free (hash);

  return err;
}

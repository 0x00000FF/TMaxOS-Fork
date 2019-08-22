/***
  This file is part of PulseAudio.

  Copyright 2013 Martin Blanchard

  PulseAudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published
  by the Free Software Foundation; either version 2.1 of the License,
  or (at your option) any later version.

  PulseAudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with PulseAudio; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>

#include <pulse/xmalloc.h>

#include <pulsecore/macro.h>
#include <pulsecore/random.h>

#include "raop-crypto.h"
#include "raop-util.h"

#define AES_CHUNK_SIZE 16

/* Openssl 1.1.0 broke compatibility. Before 1.1.0 we had to set RSA->n and
 * RSA->e manually, but after 1.1.0 the RSA struct is opaque and we have to use
 * RSA_set0_key(). RSA_set0_key() is a new function added in 1.1.0. We could
 * depend on openssl 1.1.0, but it may take some time before distributions will
 * be able to upgrade to the new openssl version. To insulate ourselves from
 * such transition problems, let's implement RSA_set0_key() ourselves if it's
 * not available. */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
static int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
    r->n = n;
    r->e = e;
    return 1;
}
#endif

struct pa_raop_secret {
    uint8_t key[AES_CHUNK_SIZE]; /* Key for aes-cbc */
    uint8_t iv[AES_CHUNK_SIZE];  /* Initialization vector for cbc */
    AES_KEY aes;                 /* AES encryption */
};

static const char rsa_modulus[] =
    "59dE8qLieItsH1WgjrcFRKj6eUWqi+bGLOX1HL3U3GhC/j0Qg90u3sG/1CUtwC"
    "5vOYvfDmFI6oSFXi5ELabWJmT2dKHzBJKa3k9ok+8t9ucRqMd6DZHJ2YCCLlDR"
    "KSKv6kDqnw4UwPdpOMXziC/AMj3Z/lUVX1G7WSHCAWKf1zNS1eLvqr+boEjXuB"
    "OitnZ/bDzPHrTOZz0Dew0uowxf/+sG+NCK3eQJVxqcaJ/vEHKIVd2M+5qL71yJ"
    "Q+87X6oV3eaYvt3zWZYD6z5vYTcrtij2VZ9Zmni/UAaHqn9JdsBWLUEpVviYnh"
    "imNVvYFZeCXg/IdTQ+x4IRdiXNv5hEew==";

static const char rsa_exponent[] =
    "AQAB";

static int rsa_encrypt(uint8_t *data, int len, uint8_t *str) {
    uint8_t modules[256];
    uint8_t exponent[8];
    int size;
    RSA *rsa;
    BIGNUM *n_bn;
    BIGNUM *e_bn;

    pa_assert(data);
    pa_assert(str);

    rsa = RSA_new();
    size = pa_raop_base64_decode(rsa_modulus, modules);
    n_bn = BN_bin2bn(modules, size, NULL);
    size = pa_raop_base64_decode(rsa_exponent, exponent);
    e_bn = BN_bin2bn(exponent, size, NULL);
    RSA_set0_key(rsa, n_bn, e_bn, NULL);

    size = RSA_public_encrypt(len, data, str, rsa, RSA_PKCS1_OAEP_PADDING);

    RSA_free(rsa);
    return size;
}

pa_raop_secret* pa_raop_secret_new(void) {
    pa_raop_secret *s = pa_xnew0(pa_raop_secret, 1);

    pa_assert(s);

    pa_random(s->key, sizeof(s->key));
    AES_set_encrypt_key(s->key, 128, &s->aes);
    pa_random(s->iv, sizeof(s->iv));

    return s;
}

void pa_raop_secret_free(pa_raop_secret *s) {
    pa_assert(s);

    pa_xfree(s);
}

char* pa_raop_secret_get_iv(pa_raop_secret *s) {
    char *base64_iv = NULL;

    pa_assert(s);

    pa_raop_base64_encode(s->iv, AES_CHUNK_SIZE, &base64_iv);

    return base64_iv;
}

char* pa_raop_secret_get_key(pa_raop_secret *s) {
    char *base64_key = NULL;
    uint8_t rsa_key[512];
    int size = 0;

    pa_assert(s);

    /* Encrypt our AES public key to send to the device */
    size = rsa_encrypt(s->key, AES_CHUNK_SIZE, rsa_key);
    pa_raop_base64_encode(rsa_key, size, &base64_key);

    return base64_key;
}

int pa_raop_aes_encrypt(pa_raop_secret *s, uint8_t *data, int len) {
    static uint8_t nv[AES_CHUNK_SIZE];
    uint8_t *buffer;
    int i = 0, j;

    pa_assert(s);
    pa_assert(data);

    memcpy(nv, s->iv, AES_CHUNK_SIZE);

    while (i + AES_CHUNK_SIZE <= len) {
        buffer = data + i;
        for (j = 0; j < AES_CHUNK_SIZE; ++j)
            buffer[j] ^= nv[j];

        AES_encrypt(buffer, buffer, &s->aes);

        memcpy(nv, buffer, AES_CHUNK_SIZE);
        i += AES_CHUNK_SIZE;
    }

    return i;
}

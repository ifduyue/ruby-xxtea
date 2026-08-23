/*
 * Copyright (c) 2014-2026, Yue Du
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Default ciphertext is compatible with the Python xxtea package
 * (https://github.com/ifduyue/xxtea): little-endian 32-bit words and
 * :pkcs7_4_min8 padding (4-byte PKCS#7-like, pad+4 for inputs shorter than 4 bytes).
 * padding: :pkcs7_8 uses 8-byte PKCS#7, compatible with Python xxteang
 * (https://github.com/ifduyue/xxteang); :length_word_prefix and
 * :length_word_suffix prepend/append a little-endian uint32 length word
 * with zero padding, matching Python xxtea 6.2.0.
 */

#include "ruby.h"
#include "ruby/encoding.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

#define DELTA 0x9e3779b9U
#define MX (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)))

#if defined(WORDS_BIGENDIAN)
# define XXTEA_LITTLE_ENDIAN 0
#else
# define XXTEA_LITTLE_ENDIAN 1
#endif

static ID id_padding;
static ID id_rounds;
static ID id_none;
static ID id_pkcs7_4_min8;
static ID id_pkcs7_8;
static ID id_length_word_prefix;
static ID id_length_word_suffix;
static VALUE cXXTEA;

typedef struct {
    char key[16];
    unsigned int rounds;
    int padding;
} xxtea_cipher_t;

static const rb_data_type_t xxtea_cipher_type = {
    .wrap_struct_name = "XXTEA",
    .function = {
        .dmark = NULL,
        .dfree = RUBY_DEFAULT_FREE,
        .dsize = NULL,
    },
    .flags = RUBY_TYPED_FREE_IMMEDIATELY,
};

static inline xxtea_cipher_t *
xxtea_get(VALUE obj)
{
    xxtea_cipher_t *cipher;
    TypedData_Get_Struct(obj, xxtea_cipher_t, &xxtea_cipher_type, cipher);
    return cipher;
}

static void
btea(uint32_t *v, int n, uint32_t const key[4], unsigned int rounds)
{
    uint32_t y, z, sum;
    unsigned p, e;

    if (n > 1) {          /* Coding Part */
        rounds = rounds == 0 ? (unsigned)(6 + 52 / n) : rounds;
        sum = 0;
        z = v[n - 1];

        do {
            sum += DELTA;
            e = (sum >> 2) & 3;

            for (p = 0; p < (unsigned)(n - 1); p++) {
                y = v[p + 1];
                z = v[p] += MX;
            }

            y = v[0];
            z = v[n - 1] += MX;
        } while (--rounds);
    }
    else if (n < -1) {    /* Decoding Part */
        n = -n;
        rounds = rounds == 0 ? (unsigned)(6 + 52 / n) : rounds;
        sum = (uint32_t)(rounds * DELTA);
        y = v[0];

        do {
            e = (sum >> 2) & 3;

            for (p = (unsigned)(n - 1); p > 0; p--) {
                z = v[p - 1];
                y = v[p] -= MX;
            }

            z = v[n - 1];
            y = v[0] -= MX;
            sum -= DELTA;
        } while (--rounds);
    }
}

static void
bytes2longs(const char *in, long inlen, uint32_t *out, int padding)
{
    long i, nwords;
    int pad;
    const unsigned char *s = (const unsigned char *)in;
    uint32_t *dst = out;

    if (padding == 2) {
        /* uint32 store, not memcpy(&inlen): 64-bit would copy the high half. */
        out[0] = (uint32_t)inlen;
        dst = out + 1;
    }

    nwords = inlen >> 2;
    for (i = 0; i < nwords; i++) {
#if XXTEA_LITTLE_ENDIAN
        memcpy(&dst[i], s + 4 * i, 4);
#else
        const unsigned char *p = s + 4 * i;
        dst[i] = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                 ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
#endif
    }

    i = nwords << 2;

    if (padding == 1 || padding == 2) {
        /* XXTEA needs two words, so empty input gets an extra zero word. */
        uint32_t w = 0;
        int shift = 0;
        for (; i < inlen; i++, shift += 8) {
            w |= (uint32_t)s[i] << shift;
        }
        if ((inlen & 3) != 0) {
            dst[nwords] = w;
            nwords++;
        }
        if (nwords < 1) {
            dst[nwords++] = 0;
        }
        if (padding == 1) {
            dst[nwords] = (uint32_t)inlen;
        }
        return;
    }

    if (padding == 8) {
        /*
         * 8-byte PKCS#7 (xxteang): pad = 8 - (len & 7), range 1-8.
         * Completes the partial word, then adds a whole extra pad word
         * unless the length is 4 mod 8.
         */
        uint32_t w = 0;
        int r = (int)(inlen & 3);
        int shift = 0;
        uint32_t pw;
        for (; i < inlen; i++, shift += 8) {
            w |= (uint32_t)s[i] << shift;
        }
        pad = 8 - (int)(inlen & 7);
        pw = (uint32_t)pad * 0x01010101u;
        w |= pw & (~0u << (8 * r));
        out[nwords] = w;
        if ((inlen & 4) == 0) {
            out[nwords + 1] = pw;
        }
        return;
    }

    /*
     * :pkcs7_4_min8 (default): 4-byte PKCS#7-like, but inputs shorter
     * than 4 bytes are padded to two words (pad values 5-8) for XXTEA's
     * 2-word minimum.  Not standard PKCS#7.
     */
    if (padding == 4 || (inlen & 3) != 0) {
        uint32_t w = 0;
        int r = (int)(inlen & 3);
        int shift = 0;
        for (; i < inlen; i++, shift += 8) {
            w |= (uint32_t)s[i] << shift;
        }
        if (padding == 4) {
            pad = 4 - r;
            if (inlen < 4) {
                pad += 4;
            }
            w |= (uint32_t)pad * 0x01010101u & (~0u << (8 * r));
            if (inlen < 4) {
                out[nwords + 1] = (uint32_t)pad * 0x01010101u;
            }
        }
        out[nwords] = w;
    }
}

static long
longs2bytes(const uint32_t *in, long inlen, char *out, int padding)
{
    long i, outlen;
    int pad;
    unsigned char *s = (unsigned char *)out;

#if XXTEA_LITTLE_ENDIAN
    /* Callers always pass the same buffer; words are already LE bytes. */
    (void)in;
#else
    /*
     * Big endian: write each word as little-endian bytes.  Snapshot the
     * whole word first because in and out alias.
     */
    for (i = 0; i < inlen; i++) {
        uint32_t word = in[i];
        s[4 * i]     = (unsigned char)(word & 0xFF);
        s[4 * i + 1] = (unsigned char)((word >> 8) & 0xFF);
        s[4 * i + 2] = (unsigned char)((word >> 16) & 0xFF);
        s[4 * i + 3] = (unsigned char)((word >> 24) & 0xFF);
    }
#endif

    outlen = inlen * 4;

    if (padding == 1 || padding == 2) {
        int prefix = padding == 2;
        long n = outlen - 4;
        long leftover, pad_from, pad_to;
        uint32_t m32;
        if (prefix) {
            m32 = (uint32_t)s[0] | ((uint32_t)s[1] << 8) |
                  ((uint32_t)s[2] << 16) | ((uint32_t)s[3] << 24);
        }
        else {
            m32 = (uint32_t)s[n] | ((uint32_t)s[n + 1] << 8) |
                  ((uint32_t)s[n + 2] << 16) | ((uint32_t)s[n + 3] << 24);
        }
        if ((size_t)m32 > (size_t)n) {
            return -1;
        }
        leftover = n - (long)m32;
        pad_from = prefix ? 4 + (long)m32 : (long)m32;
        pad_to = prefix ? outlen : n;
        /* leftover 4 is the empty 2-word case; otherwise 0-3 zero-pad bytes. */
        if (leftover > 3 && !(m32 == 0 && leftover == 4)) {
            return -1;
        }
        for (i = pad_from; i < pad_to; i++) {
            if (s[i] != 0) {
                return -1;
            }
        }
        if (prefix && m32 != 0) {
            memmove(s, s + 4, (size_t)m32);
        }
        outlen = (long)m32;
    }
    /* PKCS#7-style unpadding (4-byte or 8-byte; pad values 1-8). */
    else if (padding) {
        pad = s[outlen - 1];
        outlen -= pad;

        if (pad < 1 || pad > 8) {
            return -1;
        }

        if (outlen < 0) {
            return -2;
        }

        for (i = outlen; i < inlen * 4; i++) {
            if (s[i] != pad) {
                return -3;
            }
        }
    }

    s[outlen] = '\0';
    return outlen;
}

typedef struct {
    const char *data;
    long data_len;
    char key[16];
    uint32_t *buf;
    int n;
    int padding;
    unsigned int rounds;
    long rc;
} crypt_job;

static void *
encrypt_nogvl(void *ptr)
{
    crypt_job *j = (crypt_job *)ptr;
    uint32_t k[4];

    bytes2longs(j->data, j->data_len, j->buf, j->padding);
    bytes2longs(j->key, 16, k, 0);
    btea(j->buf, j->n, k, j->rounds);
#if !XXTEA_LITTLE_ENDIAN
    longs2bytes(j->buf, j->n, (char *)j->buf, 0);
#endif
    return NULL;
}

static void *
decrypt_nogvl(void *ptr)
{
    crypt_job *j = (crypt_job *)ptr;
    uint32_t k[4];

    bytes2longs(j->data, j->data_len, j->buf, 0);
    bytes2longs(j->key, 16, k, 0);
    btea(j->buf, -j->n, k, j->rounds);
    j->rc = longs2bytes(j->buf, j->n, (char *)j->buf, j->padding);
    return NULL;
}

static unsigned int
parse_rounds(VALUE obj)
{
    if (!RB_INTEGER_TYPE_P(obj)) {
        rb_raise(rb_eTypeError, "rounds must be an Integer");
    }
    if (RTEST(rb_funcall(obj, rb_intern("<"), 1, INT2FIX(0))) ||
        RTEST(rb_funcall(obj, rb_intern(">"), 1, UINT2NUM(UINT_MAX)))) {
        rb_raise(rb_eRangeError, "rounds value too large");
    }
    return NUM2UINT(obj);
}

/* 0 = none, 1 = :length_word_suffix, 2 = :length_word_prefix,
 * 4 = :pkcs7_4_min8 (default), 8 = :pkcs7_8. */
static int
parse_padding(VALUE obj)
{
    ID id;

    if (obj == Qfalse) {
        return 0;
    }
    if (obj == Qtrue) {
        return 4;
    }
    if (RB_TYPE_P(obj, T_STRING)) {
        obj = rb_str_intern(obj);
    }
    if (!SYMBOL_P(obj)) {
        rb_raise(rb_eTypeError,
                 "padding must be true, false, :none, :pkcs7_4_min8, "
                 ":pkcs7_8, :length_word_prefix, or :length_word_suffix");
    }
    id = SYM2ID(obj);
    if (id == id_none) {
        return 0;
    }
    if (id == id_length_word_suffix) {
        return 1;
    }
    if (id == id_length_word_prefix) {
        return 2;
    }
    if (id == id_pkcs7_4_min8) {
        return 4;
    }
    if (id == id_pkcs7_8) {
        return 8;
    }
    rb_raise(rb_eArgError,
             "unknown padding %+"PRIsVALUE" (expected :none, :pkcs7_4_min8, "
             ":pkcs7_8, :length_word_prefix, or :length_word_suffix)",
             obj);
}

static void
parse_opts(VALUE opts, int *padding, unsigned int *rounds)
{
    ID kwids[2];
    VALUE kwvals[2];

    *padding = 4;
    *rounds = 0;
    if (NIL_P(opts)) {
        return;
    }

    kwids[0] = id_padding;
    kwids[1] = id_rounds;
    rb_get_kwargs(opts, kwids, 0, 2, kwvals);

    if (kwvals[0] != Qundef) {
        *padding = parse_padding(kwvals[0]);
    }
    if (kwvals[1] != Qundef) {
        *rounds = parse_rounds(kwvals[1]);
    }
}

static void
require_key(VALUE key, char out[16])
{
    StringValue(key);
    if (RSTRING_LEN(key) != 16) {
        rb_raise(rb_eArgError, "Need a 16-byte key.");
    }
    memcpy(out, RSTRING_PTR(key), 16);
}

static VALUE
encrypt_impl(VALUE data, const char key[16], int padding, unsigned int rounds)
{
    crypt_job job;
    VALUE retval;
    long data_len, alen;

    StringValue(data);
    data_len = RSTRING_LEN(data);

    if (!padding && (data_len < 8 || (data_len & 3) != 0)) {
        rb_raise(rb_eArgError,
                 "Data length must be a multiple of 4 bytes and must not be less than 8 bytes");
    }

    if (padding == 8) {
        if (data_len > LONG_MAX - 8) {
            rb_raise(rb_eRangeError, "data too large");
        }
        alen = ((data_len & ~7L) + 8) >> 2;
    }
    else if (padding == 4) {
        alen = data_len < 4 ? 2 : (data_len >> 2) + 1;
    }
    else if (padding == 1 || padding == 2) {
        /* The length word is a uint32, so the plaintext length must fit. */
#if LONG_MAX > 2147483647L
        if (data_len > 0xFFFFFFFFL) {
            rb_raise(rb_eRangeError, "data too large");
        }
#endif
        if (data_len > LONG_MAX - 4) {
            rb_raise(rb_eRangeError, "data too large");
        }
        alen = (data_len >> 2) + ((data_len & 3) != 0 ? 1 : 0) + 1;
        if (alen < 2) {
            alen = 2;
        }
    }
    else {
        alen = data_len >> 2;
    }
    if (alen > INT_MAX || alen > LONG_MAX / 4) {
        rb_raise(rb_eRangeError, "data too large");
    }

    retval = rb_str_new(NULL, alen << 2);
    rb_enc_associate(retval, rb_ascii8bit_encoding());

    memset(&job, 0, sizeof(job));
    job.data = RSTRING_PTR(data);
    job.data_len = data_len;
    memcpy(job.key, key, 16);
    job.buf = (uint32_t *)RSTRING_PTR(retval);
    job.n = (int)alen;
    job.padding = padding;
    job.rounds = rounds;

    encrypt_nogvl(&job);
    RB_GC_GUARD(data);
    return retval;
}

static VALUE
decrypt_impl(VALUE data, const char key[16], int padding, unsigned int rounds)
{
    crypt_job job;
    VALUE retval;
    long data_len, alen;

    StringValue(data);
    data_len = RSTRING_LEN(data);

    if (data_len & 3 || data_len < 8) {
        rb_raise(rb_eArgError,
                 "Data length must be a multiple of 4 bytes and must not be less than 8 bytes");
    }

    alen = data_len / 4;
    if (alen > INT_MAX || alen > LONG_MAX / 4) {
        rb_raise(rb_eRangeError, "data too large");
    }

    retval = rb_str_new(NULL, data_len);
    rb_enc_associate(retval, rb_ascii8bit_encoding());

    memset(&job, 0, sizeof(job));
    job.data = RSTRING_PTR(data);
    job.data_len = data_len;
    memcpy(job.key, key, 16);
    job.buf = (uint32_t *)RSTRING_PTR(retval);
    job.n = (int)alen;
    job.padding = padding;
    job.rounds = rounds;

    decrypt_nogvl(&job);
    RB_GC_GUARD(data);

    if (padding) {
        if (job.rc < 0) {
            rb_raise(rb_eArgError,
                     "Invalid data, illegal padding. Could be using a wrong key.");
        }
        rb_str_resize(retval, job.rc);
    }

    return retval;
}

static VALUE
bytes_to_hex(VALUE bytes)
{
    static const char hex[] = "0123456789abcdef";
    const unsigned char *s;
    char *d;
    long i, len;
    VALUE out;

    StringValue(bytes);
    len = RSTRING_LEN(bytes);
    out = rb_usascii_str_new(NULL, len * 2);
    s = (const unsigned char *)RSTRING_PTR(bytes);
    d = RSTRING_PTR(out);
    for (i = 0; i < len; i++) {
        d[i * 2]     = hex[s[i] >> 4];
        d[i * 2 + 1] = hex[s[i] & 0x0f];
    }
    return out;
}

static int
hex_nibble(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static VALUE
hex_to_bytes(VALUE hex)
{
    const unsigned char *s;
    unsigned char *d;
    long i, len;
    VALUE out;

    StringValue(hex);
    len = RSTRING_LEN(hex);
    if (len & 1) {
        rb_raise(rb_eArgError, "Odd-length string");
    }

    out = rb_str_new(NULL, len / 2);
    rb_enc_associate(out, rb_ascii8bit_encoding());
    s = (const unsigned char *)RSTRING_PTR(hex);
    d = (unsigned char *)RSTRING_PTR(out);

    for (i = 0; i < len; i += 2) {
        int hi = hex_nibble(s[i]);
        int lo = hex_nibble(s[i + 1]);
        if (hi < 0 || lo < 0) {
            rb_raise(rb_eArgError, "Non-hexadecimal digit found");
        }
        d[i / 2] = (unsigned char)((hi << 4) | lo);
    }
    return out;
}

static VALUE
xxtea_s_encrypt(int argc, VALUE *argv, VALUE klass)
{
    VALUE data, key, opts;
    int padding;
    unsigned int rounds;
    char keybuf[16];

    (void)klass;
    rb_scan_args(argc, argv, "2:", &data, &key, &opts);
    parse_opts(opts, &padding, &rounds);
    require_key(key, keybuf);
    return encrypt_impl(data, keybuf, padding, rounds);
}

static VALUE
xxtea_s_decrypt(int argc, VALUE *argv, VALUE klass)
{
    VALUE data, key, opts;
    int padding;
    unsigned int rounds;
    char keybuf[16];

    (void)klass;
    rb_scan_args(argc, argv, "2:", &data, &key, &opts);
    parse_opts(opts, &padding, &rounds);
    require_key(key, keybuf);
    return decrypt_impl(data, keybuf, padding, rounds);
}

static VALUE
xxtea_s_encrypt_hex(int argc, VALUE *argv, VALUE klass)
{
    return bytes_to_hex(xxtea_s_encrypt(argc, argv, klass));
}

static VALUE
xxtea_s_decrypt_hex(int argc, VALUE *argv, VALUE klass)
{
    VALUE data, key, opts;
    int padding;
    unsigned int rounds;
    char keybuf[16];
    VALUE raw;

    rb_scan_args(argc, argv, "2:", &data, &key, &opts);
    parse_opts(opts, &padding, &rounds);
    raw = hex_to_bytes(data);
    require_key(key, keybuf);
    return decrypt_impl(raw, keybuf, padding, rounds);
}

static VALUE
xxtea_alloc(VALUE klass)
{
    xxtea_cipher_t *cipher;
    VALUE obj = TypedData_Make_Struct(klass, xxtea_cipher_t, &xxtea_cipher_type, cipher);
    memset(cipher, 0, sizeof(*cipher));
    cipher->padding = 4;
    cipher->rounds = 0;
    return obj;
}

static VALUE
xxtea_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE key, opts;
    xxtea_cipher_t *cipher = xxtea_get(self);
    int padding;
    unsigned int rounds;

    rb_scan_args(argc, argv, "1:", &key, &opts);
    parse_opts(opts, &padding, &rounds);
    require_key(key, cipher->key);
    cipher->padding = padding;
    cipher->rounds = rounds;
    return self;
}

static VALUE
xxtea_encrypt(VALUE self, VALUE data)
{
    xxtea_cipher_t *cipher = xxtea_get(self);
    return encrypt_impl(data, cipher->key, cipher->padding, cipher->rounds);
}

static VALUE
xxtea_decrypt(VALUE self, VALUE data)
{
    xxtea_cipher_t *cipher = xxtea_get(self);
    return decrypt_impl(data, cipher->key, cipher->padding, cipher->rounds);
}

static VALUE
xxtea_encrypt_hex(VALUE self, VALUE data)
{
    return bytes_to_hex(xxtea_encrypt(self, data));
}

static VALUE
xxtea_decrypt_hex(VALUE self, VALUE data)
{
    xxtea_cipher_t *cipher = xxtea_get(self);
    VALUE raw = hex_to_bytes(data);
    return decrypt_impl(raw, cipher->key, cipher->padding, cipher->rounds);
}

static VALUE
xxtea_inspect(VALUE self)
{
    xxtea_cipher_t *cipher = xxtea_get(self);
    return rb_sprintf("#<%s:%p padding=%s rounds=%u>",
                      rb_obj_classname(self), (void *)self,
                      cipher->padding == 0 ? "false" :
                      cipher->padding == 1 ? "length_word_suffix" :
                      cipher->padding == 2 ? "length_word_prefix" :
                      cipher->padding == 4 ? "pkcs7_4_min8" : "pkcs7_8",
                      cipher->rounds);
}

void
Init_xxtea(void)
{
    rb_ext_ractor_safe(true);

    id_padding = rb_intern("padding");
    id_rounds = rb_intern("rounds");
    id_none = rb_intern("none");
    id_pkcs7_4_min8 = rb_intern("pkcs7_4_min8");
    id_pkcs7_8 = rb_intern("pkcs7_8");
    id_length_word_prefix = rb_intern("length_word_prefix");
    id_length_word_suffix = rb_intern("length_word_suffix");

    cXXTEA = rb_define_class("XXTEA", rb_cObject);
    rb_define_alloc_func(cXXTEA, xxtea_alloc);

    rb_define_singleton_method(cXXTEA, "encrypt", xxtea_s_encrypt, -1);
    rb_define_singleton_method(cXXTEA, "decrypt", xxtea_s_decrypt, -1);
    rb_define_singleton_method(cXXTEA, "encrypt_hex", xxtea_s_encrypt_hex, -1);
    rb_define_singleton_method(cXXTEA, "decrypt_hex", xxtea_s_decrypt_hex, -1);

    rb_define_method(cXXTEA, "initialize", xxtea_initialize, -1);
    rb_define_method(cXXTEA, "encrypt", xxtea_encrypt, 1);
    rb_define_method(cXXTEA, "decrypt", xxtea_decrypt, 1);
    rb_define_method(cXXTEA, "encrypt_hex", xxtea_encrypt_hex, 1);
    rb_define_method(cXXTEA, "decrypt_hex", xxtea_decrypt_hex, 1);
    rb_define_method(cXXTEA, "inspect", xxtea_inspect, 0);

    rb_define_const(cXXTEA, "PKCS7_4_MIN8", ID2SYM(id_pkcs7_4_min8));
    rb_define_const(cXXTEA, "PKCS7_8", ID2SYM(id_pkcs7_8));
    rb_define_const(cXXTEA, "LENGTH_WORD_PREFIX", ID2SYM(id_length_word_prefix));
    rb_define_const(cXXTEA, "LENGTH_WORD_SUFFIX", ID2SYM(id_length_word_suffix));
}

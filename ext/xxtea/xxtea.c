
#include <stdint.h>
#include <stdlib.h>
#include <ruby.h>


#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))

static void btea(uint32_t *v, int n, uint32_t const key[4])
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;

    if (n > 1) {          /* Coding Part */
        rounds = 6 + 52 / n;
        sum = 0;
        z = v[n - 1];

        do {
            sum += DELTA;
            e = (sum >> 2) & 3;

            for (p = 0; p < n - 1; p++) {
                y = v[p + 1];
                z = v[p] += MX;
            }

            y = v[0];
            z = v[n - 1] += MX;
        }
        while (--rounds);
    }
    else if (n < -1) {    /* Decoding Part */
        n = -n;
        rounds = 6 + 52 / n;
        sum = rounds * DELTA;
        y = v[0];

        do {
            e = (sum >> 2) & 3;

            for (p = n - 1; p > 0; p--) {
                z = v[p - 1];
                y = v[p] -= MX;
            }

            z = v[n - 1];
            y = v[0] -= MX;
            sum -= DELTA;
        }
        while (--rounds);
    }
}

static int bytes2longs(const char *in, int inlen, uint32_t *out, int padding)
{
    int i, pad;
    const unsigned char *s;

    s = (const unsigned char *)in;

    /* (i & 3) << 3 -> [0, 8, 16, 24] */
    for (i = 0; i < inlen;  i++) {
        out[i >> 2] |= s[i] << ((i & 3) << 3);
    }

    /* PKCS#7 padding */
    if (padding) {
        pad = 4 - (inlen & 3);
        /* make sure lenght of out >= 2 */
        pad = (inlen < 4) ? pad + 4 : pad;
        for (i = inlen; i < inlen + pad; i++) {
            out[i >> 2] |= pad << ((i & 3) << 3);
        }
    }

    /* Divided by 4, and then rounded up (ceil) to an integer.
     * Which is the number of how many longs we've got.
     */
    return ((i - 1) >> 2) + 1;
}

static int longs2bytes(uint32_t *in, int inlen, char *out, int padding)
{
    int i, pad;
    unsigned char *s;

    s = (unsigned char *)out;

    for (i = 0; i < inlen; i++) {
        s[4 * i] = in[i] & 0xFF;
        s[4 * i + 1] = (in[i] >> 8) & 0xFF;
        s[4 * i + 2] = (in[i] >> 16) & 0xFF;
        s[4 * i + 3] = (in[i] >> 24) & 0xFF;
    }

    i *= 4;

    /* PKCS#7 unpadding */
    if (padding) {
        pad = s[i - 1];
        i -= pad;
    }

    s[i] = '\0';

    /* How many bytes we've got */
    return i;
}

VALUE xxtea_encrypt(VALUE mod, VALUE data, VALUE key)
{
    int alen, dlen, klen;
    uint32_t *d, k[4];
    VALUE retval;
    char *retbuf;

    d = NULL;
    k[0] = k[1] = k[2] = k[3] = 0;

    Check_Type(data, T_STRING);
    Check_Type(key, T_STRING);

    dlen = RSTRING_LEN(data);
    klen = RSTRING_LEN(key);

    if (klen != 16) {
        rb_raise(rb_eArgError, "Need a 16-byte key.");
        return Qnil;
    }

    alen = dlen < 4 ? 2 : (dlen >> 2) + 1;
    d = (uint32_t *)calloc(alen, sizeof(uint32_t));

    if (!d) {
      rb_raise(rb_eNoMemError, "calloc failed.");
      return Qnil;
    }

    bytes2longs(StringValuePtr(data), dlen, d, 1);
    bytes2longs(StringValuePtr(key), klen, k, 0);
    btea(d, alen, k);

    retval = rb_str_new(NULL, (alen << 2));

    if (!retval) {
        free(d);
        return Qnil;
    }

    retbuf = RSTRING_PTR(retval);
    longs2bytes(d, alen, retbuf, 0);

    return retval;
}

VALUE xxtea_decrypt(VALUE mod, VALUE data, VALUE key)
{
    int alen, dlen, klen, rc;
    uint32_t *d, k[4];
    VALUE retval;
    char *retbuf;

    d = NULL;
    k[0] = k[1] = k[2] = k[3] = 0;

    Check_Type(data, T_STRING);
    Check_Type(key, T_STRING);

    dlen = RSTRING_LEN(data);
    klen = RSTRING_LEN(key);

    if (klen != 16) {
        rb_raise(rb_eArgError, "Need a 16-byte key.");
        return Qnil;
    }

    /* not divided by 4, or length < 8 */
    if (dlen & 3 || dlen < 8) {
        rb_raise(rb_eArgError, "Invalid data.");
        return Qnil;
    }

    retval = rb_str_new(NULL, dlen);

    if (!retval) {
        free(d);
        return Qnil;
    }

    retbuf = RSTRING_PTR(retval);

    alen = dlen >> 2;
    d = (uint32_t *)calloc(alen, sizeof(uint32_t));

    if (!d) {
        rb_raise(rb_eNoMemError, "calloc failed.");
        return Qnil;
    }

    retval = rb_str_new(NULL, (alen << 2));

    if (!retval) {
        free(d);
        return NULL;
    }

    retbuf = RSTRING_PTR(retval);

    bytes2longs(StringValuePtr(data), dlen, d, 0);
    bytes2longs(StringValuePtr(key), klen, k, 0);
    btea(d, -alen, k);

    if ((rc = longs2bytes(d, alen, retbuf, 1)) != dlen) {
        /* Remove PKCS#7 padded chars */
        rb_str_resize(retval, rc);
    }

    return retval;
}


void Init_xxtea()
{
    VALUE mXXTEA = rb_define_module("XXTEA");
    rb_define_singleton_method(mXXTEA, "encrypt", xxtea_encrypt, 2);
    rb_define_singleton_method(mXXTEA, "decrypt", xxtea_decrypt, 2);
}

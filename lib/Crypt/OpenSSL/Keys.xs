#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>

/*
 * _key_xs_is_public_rsa
 * _key_xs_is_public_dsa
 * _key_xs_is_public_ec
 * _key_xs_is_private_pkcs8_rsa
 * _key_xs_is_private_pkcs8_dsa
 * _key_xs_is_private_pkcs8_ec
 * _key_xs_convert_public_der_to_pem
 * _key_xs_convert_private_der_to_pem
 * _key_xs_convert_private_pkcs8_der_to_pem
 * _key_xs_decrypt_private
 * _key_xs_decrypt_private_pkcs8
 */

#define KEY_XS_FORMAT_DER 0
#define KEY_XS_FORMAT_PEM 1

void _key_xs_throw(char* file, int line, char *msg) {
    const char* error;

    if (msg) {
        error = msg;
    }
    else {
        error = ERR_reason_error_string(ERR_get_error());
        ERR_clear_error();
    }

    croak("%s:%d: error: %s", file, line, error);

    return;
}

#define _key_xs_check(object) if (!(object)) _key_xs_throw(__FILE__, __LINE__, NULL);

SV* _key_xs_bio2sv(BIO* in) {
    SV* sv;
    BUF_MEM* buf;

    _key_xs_check(BIO_flush(in) == 1);
    BIO_get_mem_ptr(in, &buf);
    sv = newSVpv(buf->data, buf->length);

    _key_xs_check(BIO_set_close(in, BIO_CLOSE) == 1);
    BIO_free(in);

    return sv;
}

int _key_xs_password_callback(char *buf, int size, int rwflag, void *u) {
    size_t len = 0;

    len = strlen(u);
    memcpy(buf, u, len);

     return len;
}

int _key_xs_get_public_algorithm(SV *sv_pem) {
    EVP_PKEY *key = NULL;
    BIO *in = NULL;
    void *pem = NULL;
    STRLEN len = 0;
    int id = 0;

    pem = SvPV(sv_pem, len);

    in = BIO_new_mem_buf((void*)pem, len);
    _key_xs_check(in);

    key = PEM_read_bio_PUBKEY(in, NULL, NULL, NULL);
    _key_xs_check(key);

    id = EVP_PKEY_base_id(key);

    BIO_free(in);
    EVP_PKEY_free(key);

    return id;
}

int _key_xs_get_private_pkcs8_algorithm(SV *sv_pem) {
    EVP_PKEY *key = NULL;
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
    BIO *in = NULL;
    void *pem = NULL;
    STRLEN len = 0;
    int id = 0;

    pem = SvPV(sv_pem, len);

    in = BIO_new_mem_buf((void*)pem, len);
    _key_xs_check(in);

    p8inf = PEM_read_bio_PKCS8_PRIV_KEY_INFO(in, NULL, NULL, NULL);
    _key_xs_check(p8inf);

    key = EVP_PKCS82PKEY(p8inf);
    _key_xs_check(key);

    id = EVP_PKEY_base_id(key);

    BIO_free(in);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    EVP_PKEY_free(key);

    return id;
}


MODULE = Crypt::OpenSSL::Keys PACKAGE = Crypt::OpenSSL::Keys
PROTOTYPES: DISABLE


int
_key_xs_is_public_rsa(sv_pem)
    SV *sv_pem;

  PREINIT:
    int id = 0;
    int is = 0;

  CODE:
    id = _key_xs_get_public_algorithm(sv_pem);

    if (id == EVP_PKEY_RSA) {
        is = 1;
    }

    RETVAL = is;

  OUTPUT:
    RETVAL

int
_key_xs_is_public_dsa(sv_pem)
    SV *sv_pem;

  PREINIT:
    int id = 0;
    int is = 0;

  CODE:
    id = _key_xs_get_public_algorithm(sv_pem);

    if (id == EVP_PKEY_DSA) {
        is = 1;
    }

    RETVAL = is;

  OUTPUT:
    RETVAL

int
_key_xs_is_public_ec(sv_pem)
    SV *sv_pem;

  PREINIT:
    int id = 0;
    int is = 0;

  CODE:
    id = _key_xs_get_public_algorithm(sv_pem);

    if (id == EVP_PKEY_EC) {
        is = 1;
    }

    RETVAL = is;

  OUTPUT:
    RETVAL

int
_key_xs_is_private_pkcs8_rsa(sv_pem)
    SV *sv_pem;

  PREINIT:
    int id = 0;
    int is = 0;

  CODE:
    id = _key_xs_get_private_pkcs8_algorithm(sv_pem);

    if (id == EVP_PKEY_RSA) {
        is = 1;
    }

    RETVAL = is;

  OUTPUT:
    RETVAL

int
_key_xs_is_private_pkcs8_dsa(sv_pem)
    SV *sv_pem;

  PREINIT:
    int id = 0;
    int is = 0;

  CODE:
    id = _key_xs_get_private_pkcs8_algorithm(sv_pem);

    if (id == EVP_PKEY_DSA) {
        is = 1;
    }

    RETVAL = is;

  OUTPUT:
    RETVAL

int
_key_xs_is_private_pkcs8_ec(sv_pem)
    SV *sv_pem;

  PREINIT:
    int id = 0;
    int is = 0;

  CODE:
    id = _key_xs_get_private_pkcs8_algorithm(sv_pem);

    if (id == EVP_PKEY_EC) {
        is = 1;
    }

    RETVAL = is;

  OUTPUT:
    RETVAL

SV *
_key_xs_convert_public_der_to_pem(sv_der)
    SV *sv_der;

  PREINIT:
    char *der = NULL;
    STRLEN len = 0;
    BIO *in = NULL;
    EVP_PKEY *key = NULL;
    BIO *out = NULL;

  CODE:
     der = SvPV(sv_der, len);

    in = BIO_new_mem_buf((void*)der, len);
    _key_xs_check(in);

    key = d2i_PUBKEY_bio(in, NULL);
    _key_xs_check(key);

    out = BIO_new(BIO_s_mem());
    _key_xs_check(out);

    switch(EVP_PKEY_base_id(key)) {
        case EVP_PKEY_EC:
            PEM_write_bio_EC_PUBKEY(out, EVP_PKEY_get0_EC_KEY(key));
            break;
        case EVP_PKEY_RSA:
            PEM_write_bio_RSA_PUBKEY(out, EVP_PKEY_get0_RSA(key));
            break;
        case EVP_PKEY_DSA:
            PEM_write_bio_DSA_PUBKEY(out, EVP_PKEY_get0_DSA(key));
            break;
        default:
            _key_xs_throw(__FILE__, __LINE__, "unknow_key_algorithm");
            break;
    };

    BIO_free(in);
    EVP_PKEY_free(key);

    RETVAL = _key_xs_bio2sv(out);

  OUTPUT:
    RETVAL

SV *
_key_xs_convert_private_der_to_pem(sv_der)
    SV *sv_der;

  PREINIT:
    char *der = NULL;
    STRLEN len = 0;
    BIO *in = NULL;
    EVP_PKEY *key = NULL;
    BIO *out = NULL;

  CODE:
     der = SvPV(sv_der, len);

    in = BIO_new_mem_buf((void*)der, len);
    _key_xs_check(in);

    key = d2i_PrivateKey_bio(in, NULL);
    _key_xs_check(key);

    out = BIO_new(BIO_s_mem());
    _key_xs_check(out);

    switch(EVP_PKEY_base_id(key)) {
        case EVP_PKEY_EC:
            PEM_write_bio_ECPrivateKey(out, EVP_PKEY_get0_EC_KEY(key), NULL, NULL, 0, 0, NULL);
            break;
        case EVP_PKEY_RSA:
            PEM_write_bio_RSAPrivateKey(out, EVP_PKEY_get0_RSA(key), NULL, NULL, 0, 0, NULL);
            break;
        case EVP_PKEY_DSA:
            PEM_write_bio_DSAPrivateKey(out, EVP_PKEY_get0_DSA(key), NULL, NULL, 0, 0, NULL);
            break;
        default:
            _key_xs_throw(__FILE__, __LINE__, "unknow_key_algorithm");
            break;
    };

    BIO_free(in);
    EVP_PKEY_free(key);

    RETVAL = _key_xs_bio2sv(out);

  OUTPUT:
    RETVAL

SV *
_key_xs_convert_private_pkcs8_der_to_pem(sv_der)
    SV *sv_der;

  PREINIT:
    BIO *in = NULL;
    char *der = NULL;
    STRLEN len = 0;
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
    EVP_PKEY *key = NULL;
    BIO *out = NULL;

  CODE:
    der = SvPV(sv_der, len);

    in = BIO_new_mem_buf((void*)der, len);
    _key_xs_check(in);

    p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(in, NULL);
    _key_xs_check(p8inf);

    out = BIO_new(BIO_s_mem());
    _key_xs_check(out);

    PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8inf);

    RETVAL = _key_xs_bio2sv(out);

    BIO_free(in);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    EVP_PKEY_free(key);

  OUTPUT:
    RETVAL

SV *
_key_xs_decrypt_private(pem, password)
    char *pem;
    char *password;

  PREINIT:
    BIO *in = NULL;
    EVP_PKEY *key = NULL;
    BIO *out = NULL;

  CODE:
    in = BIO_new_mem_buf((void*)pem, strlen(pem));
    _key_xs_check(in);

    key = PEM_read_bio_PrivateKey(in, NULL, &_key_xs_password_callback, password);
    _key_xs_check(key);

    out = BIO_new(BIO_s_mem());
    _key_xs_check(out);

    switch(EVP_PKEY_base_id(key)) {
        case EVP_PKEY_EC:
            PEM_write_bio_ECPrivateKey(out, EVP_PKEY_get0_EC_KEY(key), NULL, NULL, 0, 0, NULL);
            break;
        case EVP_PKEY_RSA:
            PEM_write_bio_RSAPrivateKey(out, EVP_PKEY_get0_RSA(key), NULL, NULL, 0, 0, NULL);
            break;
        case EVP_PKEY_DSA:
            PEM_write_bio_DSAPrivateKey(out, EVP_PKEY_get0_DSA(key), NULL, NULL, 0, 0, NULL);
            break;
        default:
            _key_xs_throw(__FILE__, __LINE__, "unknow_key_algorithm");
            break;
    };

    BIO_free(in);
    EVP_PKEY_free(key);

    RETVAL = _key_xs_bio2sv(out);

  OUTPUT:
    RETVAL

SV *
_key_xs_decrypt_private_pkcs8(sv_key, password, format)
    SV *sv_key;
    char *password;
    int format;

  PREINIT:
    char *key = NULL;
    STRLEN len = 0;
    BIO *in = NULL;
    EVP_PKEY *pkey;
    PKCS8_PRIV_KEY_INFO *p8inf;
    X509_SIG *p8;
    BIO *out = NULL;

  CODE:
    key = SvPV(sv_key, len);

    in = BIO_new_mem_buf((void*)key, len);
    _key_xs_check(in);

    out = BIO_new(BIO_s_mem());
    _key_xs_check(out);

    if (format == KEY_XS_FORMAT_DER) {
        p8 = d2i_PKCS8_bio(in, NULL);
        _key_xs_check(p8);

        p8inf = PKCS8_decrypt(p8, password, strlen(password));
        _key_xs_check(p8inf);

        i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8inf);
    }

    if (format == KEY_XS_FORMAT_PEM) {
        p8 = PEM_read_bio_PKCS8(in, NULL, NULL, NULL);
        _key_xs_check(p8);

        p8inf = PKCS8_decrypt(p8, password, strlen(password));
        _key_xs_check(p8inf);

        PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8inf);
    }

    RETVAL = _key_xs_bio2sv(out);

    BIO_free(in);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    X509_SIG_free(p8);

  OUTPUT:
    RETVAL

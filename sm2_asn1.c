#include <errno.h>
#include <string.h>
#include "sm2_asn1.h"

// SM2加密
typedef struct SM2Cipher_st {
    ASN1_INTEGER *xCoordinate;                                              // x分量
    ASN1_INTEGER *yCoordinate;                                              // y分量
    ASN1_OCTET_STRING *hash;                                                // 杂凑值
    ASN1_OCTET_STRING *cipherText;                                          // 密文
} SM2Cipher;

ASN1_SEQUENCE(SM2Cipher) = {
    ASN1_SIMPLE(SM2Cipher, xCoordinate, ASN1_INTEGER),
    ASN1_SIMPLE(SM2Cipher, yCoordinate, ASN1_INTEGER),
    ASN1_SIMPLE(SM2Cipher, hash, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SM2Cipher, cipherText, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(SM2Cipher);
DECLARE_ASN1_FUNCTIONS(SM2Cipher);
IMPLEMENT_ASN1_FUNCTIONS(SM2Cipher);

// SM2签名
typedef struct SM2Signature_st {
    ASN1_INTEGER *r;
    ASN1_INTEGER *s;
} SM2Signature;

ASN1_SEQUENCE(SM2Signature) = {
    ASN1_SIMPLE(SM2Signature, r, ASN1_INTEGER),                             // 签名值的第一部分
    ASN1_SIMPLE(SM2Signature, s, ASN1_INTEGER),                             // 签名值的第二部分
} ASN1_SEQUENCE_END(SM2Signature);
DECLARE_ASN1_FUNCTIONS(SM2Signature);
IMPLEMENT_ASN1_FUNCTIONS(SM2Signature);

// SM2信封
typedef struct AlgorithmIdentifier_st {
    ASN1_OBJECT *algorithm;
    ASN1_TYPE *parameter;
}AlgorithmIdentifier;

ASN1_SEQUENCE(AlgorithmIdentifier) = {
        ASN1_SIMPLE(AlgorithmIdentifier, algorithm, ASN1_OBJECT),
        ASN1_OPT(AlgorithmIdentifier, parameter, ASN1_ANY)
} ASN1_SEQUENCE_END(AlgorithmIdentifier)
DECLARE_ASN1_FUNCTIONS(AlgorithmIdentifier);
IMPLEMENT_ASN1_FUNCTIONS(AlgorithmIdentifier);

typedef struct SM2EnvelopedKey_st {
    AlgorithmIdentifier *symAlgID;                                          // 对称密码算法标识
    SM2Cipher *symEncryptedKey;                                             // 对称密钥密文
    ASN1_BIT_STRING *sm2PublicKey;                                          // SM2公钥
    ASN1_BIT_STRING *sm2EncryptedPrivateKey;                                // SM2私钥密文
}SM2EnvelopedKey;

ASN1_SEQUENCE(SM2EnvelopedKey) = {
    ASN1_SIMPLE(SM2EnvelopedKey, symAlgID, AlgorithmIdentifier),
    ASN1_SIMPLE(SM2EnvelopedKey, symEncryptedKey, SM2Cipher),
    ASN1_SIMPLE(SM2EnvelopedKey, sm2PublicKey, ASN1_BIT_STRING),
    ASN1_SIMPLE(SM2EnvelopedKey, sm2EncryptedPrivateKey, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(SM2EnvelopedKey);
DECLARE_ASN1_FUNCTIONS(SM2EnvelopedKey);
IMPLEMENT_ASN1_FUNCTIONS(SM2EnvelopedKey);

int sm2cipher_encode(unsigned char *xCoordinate, int xCoordinateLen, unsigned char *yCoordinate, int yCoordinateLen, unsigned char *hash, int hashLen, \
    unsigned char *cipherText, int cipherTextLen, unsigned char *outData, int *outLen)
{
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    SM2Cipher *sm2cipher = NULL;

    if(hashLen != 32)
    {
        fprintf(stderr, "%s:%d %s - %d:%s\n", __FILE__, __LINE__, __FUNCTION__, errno, strerror(errno));
        goto ErrP;
    }

    sm2cipher = SM2Cipher_new();

    x = BN_bin2bn(xCoordinate, xCoordinateLen, NULL);
    y = BN_bin2bn(yCoordinate, yCoordinateLen, NULL);
    BN_to_ASN1_INTEGER(x, sm2cipher->xCoordinate);
    BN_to_ASN1_INTEGER(y, sm2cipher->yCoordinate);

    M_ASN1_OCTET_STRING_set(sm2cipher->hash, hash, hashLen);
    M_ASN1_OCTET_STRING_set(sm2cipher->cipherText, cipherText, cipherTextLen);

    *outLen = i2d_SM2Cipher(sm2cipher, &outData);
    if(*outLen <= 0)
    {
        fprintf(stderr, "%s:%d %s - %d:%s\n", __FILE__, __LINE__, __FUNCTION__, errno, strerror(errno));
        goto ErrP;
    }

    if(x) BN_free(x);
    if(y) BN_free(y);
    if(sm2cipher) SM2Cipher_free(sm2cipher);
    return 1;
ErrP:
    ERR_print_errors_fp(stderr);
    if(x) BN_free(x);
    if(y) BN_free(y);
    if(sm2cipher) SM2Cipher_free(sm2cipher);
    return 0;
}

int sm2cipher_decode(unsigned char *inData, int inLen, unsigned char *xCoordinate, int *xCoordinateLen, unsigned char *yCoordinate, int *yCoordinateLen, \
    unsigned char *hash, int *hashLen, unsigned char *cipherText, int *cipherTextLen)
{
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    SM2Cipher *sm2cipher = NULL;

    int length = 0;
    unsigned char *data = NULL;

    sm2cipher = d2i_SM2Cipher(NULL, (const unsigned char**)&inData, inLen);
    if(sm2cipher == NULL)
    {
        fprintf(stderr, "%s:%d %s - %d:%s\n", __FILE__, __LINE__, __FUNCTION__, errno, strerror(errno));
        goto ErrP;
    }

    x = ASN1_INTEGER_to_BN(sm2cipher->xCoordinate, NULL);
    y = ASN1_INTEGER_to_BN(sm2cipher->yCoordinate, NULL);
    *xCoordinateLen = BN_bn2bin(x, xCoordinate);
    *yCoordinateLen = BN_bn2bin(y, yCoordinate);

    length = M_ASN1_STRING_length(sm2cipher->hash);
    data = M_ASN1_STRING_data(sm2cipher->hash);
    *hashLen = length;
    memcpy(hash, data, length);

    length = M_ASN1_STRING_length(sm2cipher->cipherText);
    data = M_ASN1_STRING_data(sm2cipher->cipherText);
    *cipherTextLen = length;
    memcpy(cipherText, data, length);

    if(*hashLen != 32)
    {
        fprintf(stderr, "%s:%d %s - %d:%s\n", __FILE__, __LINE__, __FUNCTION__, errno, strerror(errno));
        goto ErrP;
    }

    if(x) BN_free(x);
    if(y) BN_free(y);
    if(sm2cipher) SM2Cipher_free(sm2cipher);
    return 1;
ErrP:
    ERR_print_errors_fp(stderr);
    if(x) BN_free(x);
    if(y) BN_free(y);
    if(sm2cipher) SM2Cipher_free(sm2cipher);
    return 0;
}

int sm2signature_encode(unsigned char *r, int rLen, unsigned char *s, int sLen, unsigned char *outData, int *outLen)
{
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    SM2Signature *sm2signature = NULL;

    sm2signature = SM2Signature_new();

    a = BN_bin2bn(r, rLen, NULL);
    b = BN_bin2bn(s, sLen, NULL);
    BN_to_ASN1_INTEGER(a, sm2signature->r);
    BN_to_ASN1_INTEGER(b, sm2signature->s);

    *outLen = i2d_SM2Signature(sm2signature, &outData);
    if(*outLen <= 0)
    {
        fprintf(stderr, "%s:%d %s - %d:%s\n", __FILE__, __LINE__, __FUNCTION__, errno, strerror(errno));
        goto ErrP;
    }

    if(a) BN_free(a);
    if(b) BN_free(b);
    if(sm2signature) SM2Signature_free(sm2signature);
    return 1;
ErrP:
    ERR_print_errors_fp(stderr);
    if(a) BN_free(a);
    if(b) BN_free(b);
    if(sm2signature) SM2Signature_free(sm2signature);
    return 0;
}

int sm2signature_decode(unsigned char *inData, int inLen, unsigned char *r, int *rLen, unsigned char *s, int *sLen)
{
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    SM2Signature *sm2signature = NULL;

    sm2signature = d2i_SM2Signature(NULL, (const unsigned char**)&inData, inLen);
    if(sm2signature == NULL)
    {
        fprintf(stderr, "%s:%d %s - %d:%s\n", __FILE__, __LINE__, __FUNCTION__, errno, strerror(errno));
        goto ErrP;
    }

    a = ASN1_INTEGER_to_BN(sm2signature->r, NULL);
    b = ASN1_INTEGER_to_BN(sm2signature->s, NULL);
    *rLen = BN_bn2bin(a, r);
    *sLen = BN_bn2bin(b, s);

    if(a) BN_free(a);
    if(b) BN_free(b);
    if(sm2signature) SM2Signature_free(sm2signature);
    return 1;
ErrP:
    ERR_print_errors_fp(stderr);
    if(a) BN_free(a);
    if(b) BN_free(b);
    if(sm2signature) SM2Signature_free(sm2signature);
    return 0;
}

int sm2envelopedkey_encode(unsigned char *symAlgID, int symAlgIDLen, unsigned char *symEncryptedKey, int symEncryptedKeyLen, \
    unsigned char *sm2PublicKey, int sm2PublicKeyLen, unsigned char *sm2EncryptedPrivateKey, int sm2EncryptedPrivateKeyLen, unsigned char *outData, int *outLen)
{
    SM2EnvelopedKey *sm2envelopedkey = NULL;

    sm2envelopedkey = SM2EnvelopedKey_new();

    c2i_ASN1_OBJECT(&sm2envelopedkey->symAlgID->algorithm, (const unsigned char**)&symAlgID, symAlgIDLen);
    d2i_SM2Cipher(&sm2envelopedkey->symEncryptedKey, (const unsigned char**)&symEncryptedKey, symEncryptedKeyLen);

    M_ASN1_BIT_STRING_set(sm2envelopedkey->sm2PublicKey, sm2PublicKey, sm2PublicKeyLen);
    M_ASN1_BIT_STRING_set(sm2envelopedkey->sm2EncryptedPrivateKey, sm2EncryptedPrivateKey, sm2EncryptedPrivateKeyLen);

    *outLen = i2d_SM2EnvelopedKey(sm2envelopedkey, &outData);
    if(*outLen <= 0)
    {
        fprintf(stderr, "%s:%d %s - %d:%s\n", __FILE__, __LINE__, __FUNCTION__, errno, strerror(errno));
        goto ErrP;
    }

    if(sm2envelopedkey) SM2EnvelopedKey_free(sm2envelopedkey);
    return 1;
ErrP:
    if(sm2envelopedkey) SM2EnvelopedKey_free(sm2envelopedkey);
    return 0;
}

int sm2envelopedkey_decode(unsigned char *inData, int inLen, unsigned char *symAlgID, int *symAlgIDLen, \
    unsigned char *symEncryptedKey, int *symEncryptedKeyLen, unsigned char *sm2PublicKey, int *sm2PublicKeyLen, unsigned char *sm2EncryptedPrivateKey, int *sm2EncryptedPrivateKeyLen)
{
    SM2EnvelopedKey *sm2envelopedkey = NULL;

    int length = 0;
    unsigned char *data = NULL;

    sm2envelopedkey = d2i_SM2EnvelopedKey(NULL, (const unsigned char**)&inData, inLen);
    if(sm2envelopedkey == NULL)
    {
        fprintf(stderr, "%s:%d %s - %d:%s\n", __FILE__, __LINE__, __FUNCTION__, errno, strerror(errno));
        goto ErrP;
    }

    length = sm2envelopedkey->symAlgID->algorithm->length;
    data = (unsigned char*)sm2envelopedkey->symAlgID->algorithm->data;
    *symAlgIDLen = length;
    memcpy(symAlgID, data, length);

    *symEncryptedKeyLen = i2d_SM2Cipher(sm2envelopedkey->symEncryptedKey, &symEncryptedKey);

    length = M_ASN1_STRING_length(sm2envelopedkey->sm2PublicKey);
    data = M_ASN1_STRING_data(sm2envelopedkey->sm2PublicKey);
    *sm2PublicKeyLen = length;
    memcpy(sm2PublicKey, data, length);

    length = M_ASN1_STRING_length(sm2envelopedkey->sm2EncryptedPrivateKey);
    data = M_ASN1_STRING_data(sm2envelopedkey->sm2EncryptedPrivateKey);
    *sm2EncryptedPrivateKeyLen = length;
    memcpy(sm2EncryptedPrivateKey, data, length);

    if(sm2envelopedkey) SM2EnvelopedKey_free(sm2envelopedkey);
    return 1;
ErrP:
    if(sm2envelopedkey) SM2EnvelopedKey_free(sm2envelopedkey);
    return 0;
}

int oid_hex2txt(unsigned char *hex, int hexLen, char *txt, int txtLen)
{
    int ret = 0;
    ASN1_OBJECT *oid = c2i_ASN1_OBJECT(NULL, (const unsigned char**)&hex, hexLen);
    ret = OBJ_obj2txt(txt, txtLen, oid, 1);
    if(oid) ASN1_OBJECT_free(oid);
    return ret;
}

int oid_txt2hex(char *txt, int txtLen, unsigned char *hex, int hexLen)
{
    return a2d_ASN1_OBJECT(hex, hexLen, txt, txtLen);
}

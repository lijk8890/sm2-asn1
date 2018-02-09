/**
 * @author lijk@infosec.com.cn
 * @version 0.0.1
 * @date 2018-2-9 17:42:55
**/
#ifndef __SM2_ASN1_H__
#define __SM2_ASN1_H__

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

// SM2加密ASN.1编码
int sm2cipher_encode(unsigned char *xCoordinate, int xCoordinateLen, unsigned char *yCoordinate, int yCoordinateLen, unsigned char *hash, int hashLen, \
    unsigned char *cipherText, int cipherTextLen, unsigned char *outData, int *outLen);

// SM2加密ASN.1解码
int sm2cipher_decode(unsigned char *inData, int inLen, unsigned char *xCoordinate, int *xCoordinateLen, unsigned char *yCoordinate, int *yCoordinateLen, \
    unsigned char *hash, int *hashLen, unsigned char *cipherText, int *cipherTextLen);

// SM2签名ASN.1编码
int sm2signature_encode(unsigned char *r, int rLen, unsigned char *s, int sLen, unsigned char *outData, int *outLen);

// SM2签名ASN.1解码
int sm2signature_decode(unsigned char *inData, int inLen, unsigned char *r, int *rLen, unsigned char *s, int *sLen);

// SM2信封ASN.1编码
int sm2envelopedkey_encode(unsigned char *symAlgID, int symAlgIDLen, unsigned char *symEncryptedKey, int symEncryptedKeyLen, \
    unsigned char *sm2PublicKey, int sm2PublicKeyLen, unsigned char *sm2EncryptedPrivateKey, int sm2EncryptedPrivateKeyLen, unsigned char *outData, int *outLen);

// SM2信封ASN.1解码
int sm2envelopedkey_decode(unsigned char *inData, int inLen, unsigned char *symAlgID, int *symAlgIDLen, \
    unsigned char *symEncryptedKey, int *symEncryptedKeyLen, unsigned char *sm2PublicKey, int *sm2PublicKeyLen, unsigned char *sm2EncryptedPrivateKey, int *sm2EncryptedPrivateKeyLen);

// OID十六进制转字符串
int oid_hex2txt(unsigned char *hex, int hexLen, char *txt, int txtLen);

// OID字符串转十六进制
int oid_txt2hex(char *txt, int txtLen, unsigned char *hex, int hexLen);

#endif

SM2Cipher ::= SEQUENCE {
    XCoordinate     INTEGER,                    -- x分量
    YCoordinate     INTEGER,                    -- y分量
    HASH            OCTET STRING SIZE(32),      -- 杂凑值
    CipherText      OCTET STRING                -- 密文
}
SM2Signature ::= SEQUENCE {
    R               INTEGER,                    -- 签名值的第一部分
    S               INTEGER                     -- 签名值的第二部分
}
AlgorithmIdentifier ::= SEQUENCE {
    algorithm       OBJECT IDENTIFIER,
    parameters      ANY DEFINED BY algorithm OPTIONAL
}
SM2EnvelopedKey ::= SEQUENCE {
    symAlgID                AlgorithmIdentifier,        -- 对称密码算法标识
    symEncryptedKey         SM2Cipher,                  -- 对称密钥密文
    Sm2PublicKey            BIT STRING,                 -- SM2公钥
    Sm2EncryptedPrivateKey  BIT STRING                  -- SM2私钥密文
}

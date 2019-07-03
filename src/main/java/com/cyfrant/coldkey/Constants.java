package com.cyfrant.coldkey;

public class Constants {
    public static final String ALGO_ASYMMETRIC = "RSA";
    public static final String ALGO_SIGNATURE = "SHA256withRSA";
    public static final String ALGO_HASH = "SHA-256";
    public static final int KEY_LENGTH_RSA = 4096;
    public static final int KEY_LENGTH_SYMMETRIC = 256;
    public static final int PBE_ITERATIONS = 131072;
    public static final String PBE_SALT_HEX = "310345927db3ea877bd033f087ba5889260a5549353adc99cfec234f9f360d0b";
    public static final String ENCODING = "UTF-8";
    public static final String ALGO_PBE_KDF = "PBKDF2WithHmacSHA256";
    public static final String ALGO_PBE_ENCRYPTION = "AES/ECB/PKCS5Padding";
    public static final String ALGO_AES = "AES";
    public static final String ALGO_ECC = "secp256k1";
}

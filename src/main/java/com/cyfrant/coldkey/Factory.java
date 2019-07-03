package com.cyfrant.coldkey;

import com.cyfrant.coldkey.digest.RipeMD160;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

public class Factory {
    private final static SecureRandom random = new SecureRandom();

    public static MessageDigest getMessageDigest() throws Exception {
        return MessageDigest.getInstance(Constants.ALGO_HASH);
    }

    public static Signature getSignatureVerifier(PublicKey verificationKey) throws Exception {
        Signature result = Signature.getInstance(Constants.ALGO_SIGNATURE);
        result.initVerify(verificationKey);
        return result;
    }

    public static Signature getSigner(PrivateKey signingKey) throws Exception {
        Signature result = Signature.getInstance(Constants.ALGO_SIGNATURE);
        result.initSign(signingKey);
        return result;
    }

    public static Cipher getWrapper(PublicKey encryptionKey) throws Exception {
        Cipher result = Cipher.getInstance(Constants.ALGO_ASYMMETRIC);
        result.init(Cipher.ENCRYPT_MODE, encryptionKey);
        return result;
    }

    public static Cipher getUnwrapper(PrivateKey decryptionKey) throws Exception {
        Cipher result = Cipher.getInstance(Constants.ALGO_ASYMMETRIC);
        result.init(Cipher.DECRYPT_MODE, decryptionKey);
        return result;
    }

    public static KeyPair newKeyPair() throws Exception {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance(Constants.ALGO_ASYMMETRIC);
        keygen.initialize(Constants.KEY_LENGTH_RSA);
        return keygen.generateKeyPair();
    }

    public static String hex(byte[] data) {
        StringBuffer result = new StringBuffer();
        for(byte b : data) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    public static byte[] unhex(String repr) {
        byte[] result = new byte[repr.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(repr.substring(index, index + 2), 16);
            result[i] = (byte) v;
        }
        return result;
    }

    public static String string(byte[] data) throws Exception {
        return new String(data, Constants.ENCODING);
    }

    public static byte[] utf8(String string) throws Exception {
        return string.getBytes(Constants.ENCODING);
    }

    public static byte[] pbeEncrypt(byte[] data, char[] password) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(Constants.ALGO_PBE_KDF);
        KeySpec spec = new PBEKeySpec(password, Factory.unhex(Constants.PBE_SALT_HEX), Constants.PBE_ITERATIONS, Constants.KEY_LENGTH_SYMMETRIC);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), Constants.ALGO_AES);
        Cipher result = Cipher.getInstance(Constants.ALGO_PBE_ENCRYPTION);
        result.init(Cipher.ENCRYPT_MODE, secret);
        return result.doFinal(data);
    }

    public static byte[] pbeDecrypt(byte[] data, char[] password) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(Constants.ALGO_PBE_KDF);
        KeySpec spec = new PBEKeySpec(password, Factory.unhex(Constants.PBE_SALT_HEX), Constants.PBE_ITERATIONS, Constants.KEY_LENGTH_SYMMETRIC);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), Constants.ALGO_AES);
        Cipher result = Cipher.getInstance(Constants.ALGO_PBE_ENCRYPTION);
        result.init(Cipher.DECRYPT_MODE, secret);
        return result.doFinal(data);
    }

    public static UUID keyId(Key key) throws Exception {
        byte[] raw = key.getEncoded();
        byte[] hash = getMessageDigest().digest(raw);
        byte[] id = new byte[16];
        for(int i = 0; i < 16; i++) {
            id[i] = (byte) (hash[i] ^ hash[i + 16]);
        }
        ByteBuffer wrap = ByteBuffer.wrap(id);
        long msb = wrap.getLong();
        long lsb = wrap.getLong();
        UUID result = new UUID(msb, lsb);
        return result;
    }

    public static PublicKey deserializePublicKey(byte[] data) throws Exception {
        return KeyFactory.getInstance(Constants.ALGO_ASYMMETRIC).generatePublic(new X509EncodedKeySpec(data));
    }

    public static PrivateKey decryptPrivateKey(byte[] data, char[] password) throws Exception {
        byte[] repr = pbeDecrypt(data, password);
        return KeyFactory.getInstance(Constants.ALGO_ASYMMETRIC).generatePrivate(new PKCS8EncodedKeySpec(repr));
    }

    public static boolean isKeysMatchedPair(PublicKey publicKey, PrivateKey privateKey) throws Exception {
        byte[] nonce = new byte[32];
        random.nextBytes(nonce);
        Signature signer = getSigner(privateKey);
        signer.update(nonce);
        byte[] signature = signer.sign();
        Signature verifier = getSignatureVerifier(publicKey);
        verifier.update(nonce);
        return verifier.verify(signature);
    }

    public static KeyPair mergeKeys(PublicKey publicKey, PrivateKey privateKey) throws Exception {
        if (isKeysMatchedPair(publicKey, privateKey)) {
            return new KeyPair(publicKey, privateKey);
        }
        throw new IllegalArgumentException("Private key " + keyId(privateKey) + " didn't matched public key " +  keyId(publicKey));
    }

    public static byte[] randomBits(int bits) throws Exception {
        byte[] result = new byte[bits / 8];
        random.nextBytes(result);
        return result;
    }

    public static UUID contentId(byte[] data) throws Exception {
        byte[] hash = getMessageDigest().digest(data);
        byte[] id = new byte[16];
        for(int i = 0; i < 16; i++) {
            id[i] = (byte) (hash[i] ^ hash[i + 16]);
        }
        ByteBuffer wrap = ByteBuffer.wrap(id);
        long msb = wrap.getLong();
        long lsb = wrap.getLong();
        UUID result = new UUID(msb, lsb);
        return result;
    }

    public static String adjustTo64(String s) {
        switch (s.length()) {
            case 62:
                return "00" + s;
            case 63:
                return "0" + s;
            case 64:
                return s;
            default:
                throw new IllegalArgumentException("not a valid key: " + s);
        }
    }

    public static KeyPair newECKeyPair() throws Exception {
        final KeyPairGenerator kpgen = KeyPairGenerator.getInstance("EC");
        final ECGenParameterSpec ecSpec = new ECGenParameterSpec(Constants.ALGO_ECC);
        kpgen.initialize(ecSpec);
        return kpgen.generateKeyPair();
    }

    public static String privateKeyToBase58(int version, KeyPair keyPair) throws Exception {
        final MessageDigest sha = getMessageDigest();
        final ECPrivateKey epvt = (ECPrivateKey) keyPair.getPrivate();
        final String sepvt = adjustTo64(epvt.getS().toString(16)).toUpperCase();
        byte[] adjusted = Factory.unhex(sepvt);
        return Base58.encodeChecked(version, adjusted);
    }

    public static String publicKeyToAddress(int version, KeyPair keyPair) throws Exception {
        final ECPublicKey epub = (ECPublicKey) keyPair.getPublic();
        final ECPoint pt = epub.getW();
        final String sx = adjustTo64(pt.getAffineX().toString(16)).toUpperCase();
        final String sy = adjustTo64(pt.getAffineY().toString(16)).toUpperCase();
        final String bcPub = "04" + sx + sy;
        final MessageDigest sha = MessageDigest.getInstance("SHA-256");
        // 2
        final byte[] s1 = sha.digest(Factory.unhex(bcPub));
        // 3
        final byte[] r1 = RipeMD160.getHash(s1);
        // 4
        final byte[] r2 = new byte[r1.length + 1];
        r2[0] = (byte) version;
        System.arraycopy(r1, 0, r2, 1, r1.length);
        // 5
        byte[] s2 = sha.digest(r2);
        // 6
        byte[] s3 = sha.digest(s2);
        // 7 adding -04 of 6 at end of 4
        byte[] a1 = new byte[25];
        System.arraycopy(r2, 0, a1, 0, r2.length);
        System.arraycopy(s3, 0, a1, 21, 4);
        return Base58.encode(a1);
    }
}

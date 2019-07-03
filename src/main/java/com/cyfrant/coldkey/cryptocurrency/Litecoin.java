package com.cyfrant.coldkey.cryptocurrency;

import com.cyfrant.coldkey.Factory;

import java.security.KeyPair;

public class Litecoin {
    public static Address newPrivateKey() throws Exception {
        final KeyPair keyPair = Factory.newECKeyPair();
        // address gen
        final String address = Factory.publicKeyToAddress(48, keyPair);
        // key gen
        final String key = Factory.privateKeyToBase58(176, keyPair);
        return new Address(address, key);
    }
}

package com.cyfrant.coldkey.cryptocurrency;

import com.cyfrant.coldkey.Factory;

import java.security.KeyPair;

public class Bitcoin implements AddressGenerator {
    public static Address newPrivateKey() throws Exception {
        final KeyPair keyPair = Factory.newECKeyPair();
        // address gen
        final String address = Factory.publicKeyToAddress(0, keyPair);
        // key gen
        final String key = Factory.privateKeyToBase58(128, keyPair);
        return new Address(address, key);
    }

    @Override
    public Address newAddress() throws Exception {
        return newPrivateKey();
    }
}

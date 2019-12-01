package com.cyfrant.coldkey.cryptocurrency.impl;

import com.cyfrant.coldkey.Factory;
import com.cyfrant.coldkey.cryptocurrency.Address;
import com.cyfrant.coldkey.cryptocurrency.AddressGenerator;
import com.cyfrant.coldkey.registry.Registry;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class GenericAddressGenerator implements AddressGenerator {
    private final Registry.StandardNetworkParams networkParams;

    public GenericAddressGenerator(String id) {
        networkParams = Registry.getInstance().getNetworkParams(id);
    }

    @Override
    public Address newAddress() throws Exception {
        final KeyPair keyPair = Factory.newECKeyPair();
        // address gen
        final String address = Factory.publicKeyToAddress(networkParams.getPublicKeyVersion(), keyPair);
        // key gen
        final String key = Factory.privateKeyToBase58(networkParams.getPrivateKeyVersion(), keyPair);
        return new Address(address, key);
    }

    @Override
    public ECPrivateKey decodePrivateKey(String base58) throws Exception {
        int version = Factory.getVersion(base58);
        if (version != networkParams.getPrivateKeyVersion()) {
            throw new IllegalArgumentException(base58 + " represent unsuitable version " + version + " for private key");
        }
        return Factory.privateKeyFromString(base58);
    }

    @Override
    public String publicKeyToAddress(ECPublicKey publicKey) throws Exception {
        return Factory.publicKeyToAddress(networkParams.getPublicKeyVersion(), publicKey);
    }

    public Registry.StandardNetworkParams getNetworkParams() {
        return networkParams;
    }
}

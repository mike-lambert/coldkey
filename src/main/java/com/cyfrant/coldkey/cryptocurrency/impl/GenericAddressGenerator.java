package com.cyfrant.coldkey.cryptocurrency.impl;

import com.cyfrant.coldkey.Factory;
import com.cyfrant.coldkey.cryptocurrency.Address;
import com.cyfrant.coldkey.cryptocurrency.AddressGenerator;
import com.cyfrant.coldkey.registry.Registry;

import java.security.KeyPair;

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

    public Registry.StandardNetworkParams getNetworkParams() {
        return networkParams;
    }
}

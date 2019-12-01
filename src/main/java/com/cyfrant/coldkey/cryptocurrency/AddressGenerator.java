package com.cyfrant.coldkey.cryptocurrency;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public interface AddressGenerator {
    Address newAddress() throws Exception;
    ECPrivateKey decodePrivateKey(String base58) throws Exception;
    String publicKeyToAddress(ECPublicKey publicKey) throws Exception;
}

package com.cyfrant.coldkey;

import com.cyfrant.coldkey.cryptocurrency.Address;
import com.cyfrant.coldkey.cryptocurrency.AddressGenerator;
import com.cyfrant.coldkey.registry.Registry;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;


public class Main {
    public static void main(String[] args) {
        if (args == null || args.length == 0) {
            printHelp();
            System.exit(1);
            return;
        }

        if (args.length == 1) {
            generateKeyPairFor(args[0]);
            return;
        }

        if(args.length == 2 && "address".equalsIgnoreCase(args[1].trim())) {
            String pkr = args[0].trim();
            deriveAddressFrom(pkr);
            return;
        }

        if(args.length == 3 && "public".equalsIgnoreCase(args[1].trim())) {
            String pkr = args[0].trim();
            String form = args[2].trim().toLowerCase();
            derivePublicKeyFrom(pkr, form);
            return;
        }
    }

    private static void deriveAddressFrom(String pkr) {
        try {
            int version = Factory.getVersion(pkr);
            AddressGenerator generator = Registry.getInstance().getByPrivateKeyVersion(version).createAddressGenerator();
            ECPrivateKey sk = generator.decodePrivateKey(pkr);
            ECPublicKey pk = Factory.derivePublicKey(sk);
            System.out.println(generator.publicKeyToAddress(pk));
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(127);
        }
    }

    private static void derivePublicKeyFrom(String pkr, String form) {
        try {
            int version = Factory.getVersion(pkr);
            AddressGenerator generator = Registry.getInstance().getByPrivateKeyVersion(version).createAddressGenerator();
            ECPrivateKey sk = generator.decodePrivateKey(pkr);
            ECPublicKey pk = Factory.derivePublicKey(sk);
            byte[] pkdata = pk.getEncoded();
            String pkrepr = "";
            if ("base64".equalsIgnoreCase(form)) {
                pkrepr = Base64.toBase64String(pkdata);
            } else if ("hex".equalsIgnoreCase(form)) {
                pkrepr = Hex.toHexString(pkdata);
            }
            System.out.println(pkrepr);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(127);
        }
    }

    private static void generateKeyPairFor(String currency) {
        try {
            String code = currency.toUpperCase().trim();
            Address address = Registry.getInstance().getNetworkParams(code).createAddressGenerator().newAddress();
            System.out.println(address.getAddress() + " " + address.getPrivateKey());
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(127);
        }
    }

    private static void printHelp() {
        System.out.println("Usage: java -jar " + getJar() + " BTC|LTC|DASH");
        System.out.println("Output is <address> <private key>");
    }

    private static String getJar() {
        return Main.class.getProtectionDomain().getCodeSource().getLocation().toString().replace("file:/", "");
    }
}

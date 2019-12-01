package com.cyfrant.coldkey;

import com.cyfrant.coldkey.cryptocurrency.Address;
import com.cyfrant.coldkey.registry.Registry;

public class Main {
    public static void main(String[] args) {
        if (args == null || args.length == 0) {
            printHelp();
            System.exit(1);
            return;
        }

        try {
            String code = args[0].toUpperCase().trim();
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

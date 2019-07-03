package com.cyfrant.coldkey;

import com.cyfrant.coldkey.cryptocurrency.Address;
import com.cyfrant.coldkey.cryptocurrency.AddressGenerator;
import com.cyfrant.coldkey.cryptocurrency.Bitcoin;
import com.cyfrant.coldkey.cryptocurrency.Dash;
import com.cyfrant.coldkey.cryptocurrency.Litecoin;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class Main {
    public static void main(String[] args) {
        if (args == null || args.length == 0) {
            printHelp();
            System.exit(1);
            return;
        }
        final Map<String, AddressGenerator> supported = new ConcurrentHashMap<>();
        supported.put("BTC", new Bitcoin());
        supported.put("LTC", new Litecoin());
        supported.put("DASH", new Dash());
        try {
            Address address = supported.get(args[0].toUpperCase().trim()).newAddress();
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

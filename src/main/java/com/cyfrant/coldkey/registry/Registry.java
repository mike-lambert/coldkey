package com.cyfrant.coldkey.registry;

import com.cyfrant.coldkey.cryptocurrency.AddressGenerator;
import com.cyfrant.coldkey.cryptocurrency.impl.GenericAddressGenerator;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class Registry {
    private static final Object lock = new Object();
    private static Registry INSTANCE;
    static {
        synchronized (lock) {
            if (INSTANCE == null) {
                INSTANCE = new Registry();
            }
        }
    }

    public static class NetworkParams {
        protected final int publicKeyVersion;
        protected final int privateKeyVersion;

        public NetworkParams(int publicKeyVersion, int privateKeyVersion) {
            this.publicKeyVersion = publicKeyVersion;
            this.privateKeyVersion = privateKeyVersion;
        }

        public int getPublicKeyVersion() {
            return publicKeyVersion;
        }

        public int getPrivateKeyVersion() {
            return privateKeyVersion;
        }
    }

    public static class StandardNetworkParams extends NetworkParams {
        protected final String id;
        public StandardNetworkParams(int publicKeyVersion, String id) {
            super(publicKeyVersion, publicKeyVersion + 128);
            this.id = id;
        }

        public String getId() {
            return id;
        }

        public AddressGenerator createAddressGenerator() {
            return new GenericAddressGenerator(id);
        }
    }

    public static class BitcoinMainNetParams extends StandardNetworkParams {
        public BitcoinMainNetParams() {
            super(0, "BTC");
        }
    }

    public static class LitecoinMainNetParams extends StandardNetworkParams {
        public LitecoinMainNetParams() {
            super(48, "LTC");
        }
    }

    public static class DashMainNetParams extends  StandardNetworkParams {
        public DashMainNetParams() {
            super(76, "DASH");
        }
    }

    private final Map<String, StandardNetworkParams> registered;

    public Registry() {
        registered = new ConcurrentHashMap<>();
        populateRegistry();
    }

    private void populateRegistry() {
        Class r = this.getClass();
        for(Class inner : r.getClasses()) {
            try {
                Class<StandardNetworkParams> casted = inner.asSubclass(StandardNetworkParams.class);
                if (inner.equals(StandardNetworkParams.class)) {
                    continue;
                }
                StandardNetworkParams instance = casted.newInstance();
                registered.put(instance.getId(), instance);
            } catch (ClassCastException cce) {
                continue;
            } catch (IllegalAccessException e) {
                e.printStackTrace();
            } catch (InstantiationException e) {
                e.printStackTrace();
            }
        }
    }

    public static Registry getInstance() {
        synchronized (lock) {
            return INSTANCE;
        }
    }

    public StandardNetworkParams getNetworkParams(String id) {
        return registered.get(id);
    }

    public StandardNetworkParams getByPrivateKeyVersion(int version) {
        return registered.values().stream()
                .filter(p -> p.getPrivateKeyVersion() == version)
                .findFirst()
                .get();
    }
}

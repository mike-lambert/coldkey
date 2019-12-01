import com.cyfrant.coldkey.Factory;
import com.cyfrant.coldkey.cryptocurrency.Address;
import com.cyfrant.coldkey.cryptocurrency.impl.Litecoin;
import org.junit.Test;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import static org.junit.Assert.*;

public class LitecoinTest {
    @Test
    public void generateNewAddress() throws Exception {
        Address a = new Litecoin().newAddress();
        assertNotNull(a);
        System.out.println(a.getPrivateKey() + " -> " + a.getAddress());
        assertTrue(a.getAddress().startsWith("L"));
        assertTrue(a.getPrivateKey().startsWith("6"));
    }

    @Test
    public void serDesReversible() throws Exception {
        Address a = new Litecoin().newAddress();
        ECPrivateKey p = Factory.privateKeyFromString(a.getPrivateKey());
        ECPublicKey f = Factory.derivePublicKey(a.getPrivateKey());
        KeyPair k = new KeyPair(f, p);
        String address = Factory.publicKeyToAddress(48, k);
        String pke = Factory.privateKeyToBase58(176, k);
        assertTrue(address.startsWith("L"));
        assertTrue(pke.startsWith("6"));
        assertEquals(a.getAddress(), address);
        assertEquals(a.getPrivateKey(), pke);
    }

    @Test
    public void derivationReversible() throws Exception {
        Address a = new Litecoin().newAddress();
        ECPrivateKey p = Factory.privateKeyFromString(a.getPrivateKey());
        ECPublicKey f = Factory.derivePublicKey(p);
        KeyPair k = new KeyPair(f, p);
        String address = Factory.publicKeyToAddress(48, k);
        String pke = Factory.privateKeyToBase58(176, k);
        assertTrue(address.startsWith("L"));
        assertTrue(pke.startsWith("6"));
        assertEquals(a.getAddress(), address);
        assertEquals(a.getPrivateKey(), pke);
    }
}
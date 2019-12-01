import com.cyfrant.coldkey.Factory;
import com.cyfrant.coldkey.cryptocurrency.Address;
import com.cyfrant.coldkey.cryptocurrency.impl.Dash;
import org.junit.Test;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import static org.junit.Assert.*;

public class DashTest {
    @Test
    public void generateNewAddress() throws Exception {
        Address a = new Dash().newAddress();
        assertNotNull(a);
        System.out.println(a.getPrivateKey() + " -> " + a.getAddress());
        assertTrue(a.getAddress().startsWith("X"));
        assertTrue(a.getPrivateKey().startsWith("7"));
    }

    @Test
    public void serDesReversible() throws Exception {
        Address a = new Dash().newAddress();
        ECPrivateKey p = Factory.privateKeyFromString(a.getPrivateKey());
        ECPublicKey f = Factory.derivePublicKey(a.getPrivateKey());
        KeyPair k = new KeyPair(f, p);
        String address = Factory.publicKeyToAddress(76, k);
        String pke = Factory.privateKeyToBase58(204, k);
        assertTrue(address.startsWith("X"));
        assertTrue(pke.startsWith("7"));
        assertEquals(a.getAddress(), address);
        assertEquals(a.getPrivateKey(), pke);
    }

    @Test
    public void derivationReversible() throws Exception {
        Address a = new Dash().newAddress();
        ECPrivateKey p = Factory.privateKeyFromString(a.getPrivateKey());
        ECPublicKey f = Factory.derivePublicKey(p);
        KeyPair k = new KeyPair(f, p);
        String address = Factory.publicKeyToAddress(76, k);
        String pke = Factory.privateKeyToBase58(204, k);
        assertTrue(address.startsWith("X"));
        assertTrue(pke.startsWith("7"));
        assertEquals(a.getAddress(), address);
        assertEquals(a.getPrivateKey(), pke);
    }
}
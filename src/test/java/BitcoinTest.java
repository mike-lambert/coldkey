import com.cyfrant.coldkey.Factory;
import com.cyfrant.coldkey.cryptocurrency.Address;
import com.cyfrant.coldkey.cryptocurrency.Bitcoin;
import org.junit.Test;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import static org.junit.Assert.*;

public class BitcoinTest {
    @Test
    public void generateNewAddress() throws Exception {
        Address a = Bitcoin.newPrivateKey();
        assertNotNull(a);
        assertTrue(a.getAddress().startsWith("1"));
        assertTrue(a.getPrivateKey().startsWith("5"));
        System.out.println(a.getPrivateKey() + " -> " + a.getAddress());
    }

    @Test
    public void serDesReversible() throws Exception {
        Address a = Bitcoin.newPrivateKey();
        ECPrivateKey p = Factory.privateKeyFromString(a.getPrivateKey());
        ECPublicKey f = Factory.derivePublicKey(a.getPrivateKey());
        KeyPair k = new KeyPair(f, p);
        String address = Factory.publicKeyToAddress(0, k);
        String pke = Factory.privateKeyToBase58(128, k);
        assertEquals(a.getAddress(), address);
        assertEquals(a.getPrivateKey(), pke);
    }

    @Test
    public void derivationReversible() throws Exception {
        Address a = Bitcoin.newPrivateKey();
        ECPrivateKey p = Factory.privateKeyFromString(a.getPrivateKey());
        ECPublicKey f = Factory.derivePublicKey(p);
        KeyPair k = new KeyPair(f, p);
        String address = Factory.publicKeyToAddress(0, k);
        String pke = Factory.privateKeyToBase58(128, k);
        assertEquals(a.getAddress(), address);
        assertEquals(a.getPrivateKey(), pke);
    }
}
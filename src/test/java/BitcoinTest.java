import com.cyfrant.coldkey.cryptocurrency.Address;
import com.cyfrant.coldkey.cryptocurrency.Bitcoin;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class BitcoinTest {
    @Test
    public void generateNewAddress() throws Exception {
        Address a = Bitcoin.newPrivateKey();
        assertNotNull(a);
        assertTrue(a.getAddress().startsWith("1"));
        assertTrue(a.getPrivateKey().startsWith("5"));
        System.out.println(a.getPrivateKey() + " -> " + a.getAddress());
    }
}
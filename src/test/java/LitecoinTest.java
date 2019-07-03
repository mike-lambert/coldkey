import com.cyfrant.coldkey.cryptocurrency.Address;
import com.cyfrant.coldkey.cryptocurrency.Litecoin;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class LitecoinTest {
    @Test
    public void generateNewAddress() throws Exception {
        Address a = Litecoin.newPrivateKey();
        assertNotNull(a);
        System.out.println(a.getPrivateKey() + " -> " + a.getAddress());
        assertTrue(a.getAddress().startsWith("L"));
        assertTrue(a.getPrivateKey().startsWith("6"));
    }
}
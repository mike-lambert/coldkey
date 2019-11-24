import com.cyfrant.coldkey.cryptocurrency.Address;
import com.cyfrant.coldkey.cryptocurrency.Dash;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class DashTest {
    @Test
    public void generateNewAddress() throws Exception {
        Address a = Dash.newPrivateKey();
        assertNotNull(a);
        System.out.println(a.getPrivateKey() + " -> " + a.getAddress());
        assertTrue(a.getAddress().startsWith("X"));
        assertTrue(a.getPrivateKey().startsWith("7"));
    }
}
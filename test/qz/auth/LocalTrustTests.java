package qz.auth;

import org.testng.Assert;
import org.testng.annotations.Test;
import qz.common.PropertyHelper;

import java.util.Arrays;
import java.util.List;
import java.util.Properties;

public class LocalTrustTests {
    private static final List<String> HOSTS = LocalTrust.parseHosts(" db.stateartcorp.com , *.example.com ,, DB.stateartcorp.com");

    @Test
    public void testParseHosts() {
        Assert.assertEquals(HOSTS, Arrays.asList("db.stateartcorp.com", "*.example.com"));
    }

    @Test
    public void testExactAndCase() {
        Assert.assertTrue(LocalTrust.isTrustedOrigin("https://db.stateartcorp.com", HOSTS));
        Assert.assertTrue(LocalTrust.isTrustedOrigin("https://DB.StateArtCorp.com", HOSTS));
    }

    @Test
    public void testSchemeAndPortIgnored() {
        Assert.assertTrue(LocalTrust.isTrustedOrigin("http://db.stateartcorp.com:8080", HOSTS));
        Assert.assertTrue(LocalTrust.isTrustedOrigin("wss://db.stateartcorp.com:443", HOSTS));
    }

    @Test
    public void testWildcard() {
        Assert.assertTrue(LocalTrust.isTrustedOrigin("https://a.example.com", HOSTS));
        Assert.assertTrue(LocalTrust.isTrustedOrigin("https://a.b.example.com:81", HOSTS));
        Assert.assertFalse(LocalTrust.isTrustedOrigin("https://example.com", HOSTS));
        Assert.assertFalse(LocalTrust.isTrustedOrigin("https://badexample.com", HOSTS));
    }

    @Test
    public void testNonMatch() {
        Assert.assertFalse(LocalTrust.isTrustedOrigin("https://evil.com", HOSTS));
        Assert.assertFalse(LocalTrust.isTrustedOrigin("https://db.stateartcorp.com.evil.com", HOSTS));
        Assert.assertFalse(LocalTrust.isTrustedOrigin("https://x.db.stateartcorp.com", HOSTS));
    }

    @Test
    public void testMalformedOrNull() {
        Assert.assertFalse(LocalTrust.isTrustedOrigin(null, HOSTS));
        Assert.assertFalse(LocalTrust.isTrustedOrigin("", HOSTS));
        Assert.assertFalse(LocalTrust.isTrustedOrigin("null", HOSTS));
        Assert.assertFalse(LocalTrust.isTrustedOrigin("not a uri ::", HOSTS));
        Assert.assertFalse(LocalTrust.isTrustedOrigin("https://db.stateartcorp.com", null));
    }

    @Test
    public void testKeyFormat() {
        String key = LocalTrust.generateKey();
        Assert.assertEquals(key.length(), 43); // 32 bytes, unpadded base64
        Assert.assertTrue(key.matches("[A-Za-z0-9_-]+"));
        Assert.assertNotEquals(key, LocalTrust.generateKey());
    }

    @Test
    public void testVerifyAndRegenerate() {
        PropertyHelper prefs = new PropertyHelper(new Properties()) {
            @Override
            public boolean save() { return true; }
        };
        LocalTrust.init(prefs);
        String key = LocalTrust.getAccessKey();
        Assert.assertNotNull(key);
        Assert.assertEquals(prefs.getProperty(LocalTrust.ACCESS_KEY_KEY), key);
        Assert.assertEquals(prefs.getProperty(LocalTrust.TRUSTED_HOSTS_KEY), LocalTrust.DEFAULT_TRUSTED_HOSTS);
        Assert.assertTrue(LocalTrust.verifyAccessKey(key));
        Assert.assertFalse(LocalTrust.verifyAccessKey(key + "x"));
        Assert.assertFalse(LocalTrust.verifyAccessKey(null));
        Assert.assertFalse(LocalTrust.verifyAccessKey(""));

        String newKey = LocalTrust.regenerateAccessKey(prefs);
        Assert.assertNotEquals(newKey, key);
        Assert.assertFalse(LocalTrust.verifyAccessKey(key));
        Assert.assertTrue(LocalTrust.verifyAccessKey(newKey));
    }
}

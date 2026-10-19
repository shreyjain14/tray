package qz.auth;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import qz.common.PropertyHelper;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * Local trust helpers: a list of trusted website hosts and a random access key which
 * allow connections to skip the "untrusted website" prompt.
 */
public class LocalTrust {
    private static final Logger log = LogManager.getLogger(LocalTrust.class);

    public static final String TRUSTED_HOSTS_KEY = "security.trusted.hosts";
    public static final String ACCESS_KEY_KEY = "security.access.key";
    public static final String DEFAULT_TRUSTED_HOSTS = "db.stateartcorp.com";
    public static final String KEY_PREFIX = "qzkey:";

    private static volatile List<String> trustedHosts = parseHosts(DEFAULT_TRUSTED_HOSTS);
    private static volatile String accessKey = null;

    /**
     * Loads (and seeds, if absent) the trusted hosts and access key from the provided preferences
     */
    public static synchronized void init(PropertyHelper prefs) {
        boolean dirty = false;
        String hosts = prefs.getProperty(TRUSTED_HOSTS_KEY);
        if (hosts == null) {
            hosts = DEFAULT_TRUSTED_HOSTS;
            prefs.setProperty(TRUSTED_HOSTS_KEY, hosts);
            dirty = true;
        }
        trustedHosts = parseHosts(hosts);

        String key = prefs.getProperty(ACCESS_KEY_KEY);
        if (key == null || key.trim().isEmpty()) {
            key = generateKey();
            prefs.setProperty(ACCESS_KEY_KEY, key);
            dirty = true;
            log.info("Generated new access key");
        }
        accessKey = key.trim();

        if (dirty) {
            prefs.save();
        }
    }

    public static String getTrustedHostsString() {
        return String.join(",", trustedHosts);
    }

    public static synchronized void setTrustedHosts(PropertyHelper prefs, String commaList) {
        List<String> parsed = parseHosts(commaList);
        prefs.setProperty(TRUSTED_HOSTS_KEY, String.join(",", parsed));
        prefs.save();
        trustedHosts = parsed;
    }

    public static List<String> parseHosts(String commaList) {
        List<String> hosts = new ArrayList<>();
        if (commaList != null) {
            for(String s : commaList.split(",")) {
                s = s.trim().toLowerCase(Locale.ENGLISH);
                if (!s.isEmpty() && !hosts.contains(s)) {
                    hosts.add(s);
                }
            }
        }
        return hosts;
    }

    /**
     * Whether the host of the provided websocket Origin matches the trusted hosts list
     */
    public static boolean isTrustedOrigin(String origin) {
        return isTrustedOrigin(origin, trustedHosts);
    }

    public static boolean isTrustedOrigin(String origin, List<String> hosts) {
        String host = extractHost(origin);
        if (host == null || hosts == null) {
            return false;
        }
        for(String pattern : hosts) {
            if (pattern.startsWith("*.")) {
                // "*.example.com" matches any subdomain, but not "example.com" itself
                if (host.endsWith(pattern.substring(1)) && host.length() > pattern.length() - 1) {
                    return true;
                }
            } else if (pattern.equals(host)) {
                return true;
            }
        }
        return false;
    }

    private static String extractHost(String origin) {
        if (origin == null || origin.trim().isEmpty()) {
            return null;
        }
        try {
            String host = new URI(origin.trim()).getHost();
            return host == null ? null : host.toLowerCase(Locale.ENGLISH);
        }
        catch(Exception e) {
            return null;
        }
    }

    public static String generateKey() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static String getAccessKey() {
        return accessKey;
    }

    public static synchronized String regenerateAccessKey(PropertyHelper prefs) {
        String key = generateKey();
        prefs.setProperty(ACCESS_KEY_KEY, key);
        prefs.save();
        accessKey = key;
        return key;
    }

    /**
     * Constant-time comparison of the supplied key to the stored access key
     */
    public static boolean verifyAccessKey(String supplied) {
        String key = accessKey;
        if (key == null || supplied == null) {
            return false;
        }
        return MessageDigest.isEqual(key.getBytes(StandardCharsets.UTF_8), supplied.getBytes(StandardCharsets.UTF_8));
    }
}

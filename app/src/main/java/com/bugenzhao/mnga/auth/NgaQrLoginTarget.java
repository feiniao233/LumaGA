package com.bugenzhao.mnga.auth;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/** A QR is data, never a trusted navigation command. No credentials belong in this URL. */
public final class NgaQrLoginTarget {
    public final String host;
    public final String url;
    public final String authorizationUrl;
    private final String key;

    private NgaQrLoginTarget(String host, String key) {
        this.host = host;
        this.key = key;
        this.authorizationUrl = "https://" + host + "/nuke.php?__lib=login&__act=qrlogin_allow&raw=3";
        this.url = "https://" + host + "/nuke.php?__lib=login&__act=qrlogin_ui&qrkey=" + key;
    }

    public static NgaQrLoginTarget parse(String input) {
        URI uri = strictUri(input);
        Map<String, String> query = query(uri);
        if (query.size() != 3 || !"login".equals(query.get("__lib"))
                || !"qrlogin_ui".equals(query.get("__act"))) throw invalid();
        String key = query.get("qrkey");
        // The official page itself extracts qrkey using [a-zA-Z0-9]+.
        if (key == null || !key.matches("[A-Za-z0-9]{1,512}")) throw invalid();
        return new NgaQrLoginTarget(uri.getHost().toLowerCase(Locale.ROOT), key);
    }

    String key() { return key; }

    /** Only the scanned confirmation page and its official same-host form endpoint. */
    public boolean allowsRequest(String input, String method, boolean mainFrame) {
        if (!mainFrame && "about:blank".equals(input)) return true;
        try {
            URI uri = strictUri(input);
            if (!host.equalsIgnoreCase(uri.getHost())) return false;
            Map<String, String> query = query(uri);
            if ("GET".equals(method)) return url.equals(parse(input).url);
            return !mainFrame && "POST".equals(method) && query.size() == 3
                    && "login".equals(query.get("__lib"))
                    && "qrlogin_allow".equals(query.get("__act"))
                    && "3".equals(query.get("raw"));
        } catch (IllegalArgumentException ignored) {
            return false;
        }
    }

    private static URI strictUri(String input) {
        if (input == null || input.length() > 2048) throw invalid();
        try {
            URI uri = new URI(input);
            String host = uri.getHost();
            if (!"https".equalsIgnoreCase(uri.getScheme()) || host == null
                    || !(host.equalsIgnoreCase("bbs.nga.cn") || host.equalsIgnoreCase("ngabbs.com"))
                    || uri.getRawUserInfo() != null || uri.getPort() != -1
                    || !uri.getRawAuthority().equalsIgnoreCase(host)
                    || !"/nuke.php".equals(uri.getRawPath())
                    || uri.getRawFragment() != null) throw invalid();
            return uri;
        } catch (URISyntaxException ignored) {
            throw invalid();
        }
    }

    private static Map<String, String> query(URI uri) {
        String raw = uri.getRawQuery();
        if (raw == null) throw invalid();
        Map<String, String> result = new HashMap<>();
        for (String part : raw.split("&", -1)) {
            int equal = part.indexOf('=');
            if (equal <= 0 || equal != part.lastIndexOf('=')) throw invalid();
            String name = part.substring(0, equal);
            String value = part.substring(equal + 1);
            // Refuse aliases/encodings rather than rely on different URL parsers agreeing.
            if (!name.matches("[A-Za-z_]+") || !value.matches("[A-Za-z0-9_]+")
                    || result.put(name, value) != null) throw invalid();
        }
        return result;
    }

    private static IllegalArgumentException invalid() {
        // Never echo QR contents (which contain a short-lived login secret).
        return new IllegalArgumentException("Not an NGA desktop login QR code");
    }

    @Override public String toString() { return "NgaQrLoginTarget([redacted])"; }
}

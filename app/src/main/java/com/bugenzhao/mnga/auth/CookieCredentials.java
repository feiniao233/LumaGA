package com.bugenzhao.mnga.auth;

import java.util.HashMap;
import java.util.Map;

/** Only the two passport values are retained; unrelated browser cookies are discarded. */
public final class CookieCredentials {
    public final String uid;
    public final String cid;

    private CookieCredentials(String uid, String cid) {
        this.uid = uid;
        this.cid = cid;
    }

    public static CookieCredentials fromFields(String uidInput, String cidInput) {
        String uid = uidInput.trim();
        String cid = cidInput.trim();
        if (!uid.matches("[0-9]{1,20}") || uid.matches("0+")) {
            throw new IllegalArgumentException("Invalid UID");
        }
        // RFC 6265 cookie-octet; do not URL-decode, truncate at '=', or accept header injection.
        if (cid.isEmpty() || cid.length() > 4096) throw new IllegalArgumentException("Invalid CID");
        for (int i = 0; i < cid.length(); i++) {
            char c = cid.charAt(i);
            if (c < 0x21 || c > 0x7e || c == '"' || c == ',' || c == ';' || c == '\\') {
                throw new IllegalArgumentException("Invalid CID");
            }
        }
        return new CookieCredentials(uid, cid);
    }

    public static CookieCredentials fromCookieHeader(String input) {
        if (input.length() > 16384) throw new IllegalArgumentException("Cookie header too long");
        String header = input.trim();
        if (header.regionMatches(true, 0, "Cookie:", 0, 7)) header = header.substring(7).trim();
        Map<String, String> values = new HashMap<>();
        for (String part : header.split("[;\\r\\n]+")) {
            int equals = part.indexOf('=');
            if (equals < 0) continue;
            String name = part.substring(0, equals).trim();
            if (!name.equals("ngaPassportUid") && !name.equals("ngaPassportCid")) continue;
            String value = part.substring(equals + 1).trim();
            if (values.containsKey(name) && !values.get(name).equals(value)) {
                throw new IllegalArgumentException("Conflicting passport cookies");
            }
            values.put(name, value);
        }
        if (!values.containsKey("ngaPassportUid") || !values.containsKey("ngaPassportCid")) {
            throw new IllegalArgumentException("Missing passport cookies");
        }
        return fromFields(values.get("ngaPassportUid"), values.get("ngaPassportCid"));
    }

    @Override public String toString() { return "CookieCredentials([redacted])"; }
}

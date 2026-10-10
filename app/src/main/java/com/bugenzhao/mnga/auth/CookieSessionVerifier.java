package com.bugenzhao.mnga.auth;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.HttpsURLConnection;

/** Isolated read-only probe. Never switches the Rust global auth or persists browser cookies. */
public final class CookieSessionVerifier {
    private CookieSessionVerifier() {}

    public static boolean verify(CookieCredentials credentials) throws IOException {
        // Do not send passport credentials to a custom backend, proxy, or redirect target.
        HttpsURLConnection connection = (HttpsURLConnection)
            new URL("https://bbs.nga.cn/thread.php?fid=7&__output=11").openConnection();
        try {
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(15000);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("User-Agent", "NGA_WP_JW/(;WINDOWS)");
            connection.setRequestProperty("Cache-Control", "no-store");
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
            connection.setRequestProperty("Cookie", "ngaPassportUid=" + credentials.uid
                + "; ngaPassportCid=" + credentials.cid);
            byte[] body = ("access_uid=" + URLEncoder.encode(credentials.uid, "UTF-8")
                + "&access_token=" + URLEncoder.encode(credentials.cid, "UTF-8"))
                .getBytes(StandardCharsets.UTF_8);
            connection.setDoOutput(true);
            connection.setFixedLengthStreamingMode(body.length);
            try (java.io.OutputStream output = connection.getOutputStream()) { output.write(body); }
            if (connection.getResponseCode() != 200) return false;
            // NGA normally uses GB18030. Honor an explicit UTF-8 response too.
            String contentType = connection.getContentType();
            Charset charset = contentType != null && contentType.toLowerCase(java.util.Locale.ROOT).contains("utf-8")
                ? StandardCharsets.UTF_8 : Charset.forName("GB18030");
            try (InputStream input = connection.getInputStream();
                 ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[8192];
                int count;
                while ((count = input.read(buffer)) != -1) {
                    if (Thread.currentThread().isInterrupted()) throw new IOException("Canceled");
                    if (output.size() + count > 2 * 1024 * 1024) throw new IOException("Response too large");
                    output.write(buffer, 0, count);
                }
                return isAuthenticatedResponse(new String(output.toByteArray(), charset), credentials.uid);
            }
        } finally {
            connection.disconnect();
        }
    }

    /** The public profile UID is not sufficient: __CU is the server's current visitor. */
    static boolean isAuthenticatedResponse(String response, String expectedUid) {
        try {
            JSONObject root = new JSONObject(response);
            if (root.has("error")) return false;
            JSONObject data = root.optJSONObject("data");
            if (data == null || data.has("__MESSAGE")) return false;
            JSONObject currentUser = data.optJSONObject("__CU");
            return currentUser != null && expectedUid.equals(currentUser.optString("uid", ""))
                && expectedUid.matches("[0-9]{1,20}") && !expectedUid.matches("0+");
        } catch (Exception ignored) {
            // Never log or display response bodies, tokens, or raw network exceptions.
            return false;
        }
    }
}

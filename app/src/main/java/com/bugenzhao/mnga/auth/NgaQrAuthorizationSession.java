package com.bugenzhao.mnga.auth;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

import okhttp3.Authenticator;
import okhttp3.Call;
import okhttp3.CookieJar;
import okhttp3.FormBody;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okio.BufferedSink;

/** Per-attempt native HTTP. No browser, global cookies, persistence, redirects or retries. */
public final class NgaQrAuthorizationSession implements AutoCloseable {
    private final NgaQrLoginTarget target;
    private final CookieCredentials credentials;
    private final BooleanSupplier isCurrent;
    private final String userAgent;
    private final OkHttpClient client;
    private final AtomicBoolean preparedOnce = new AtomicBoolean();
    private final AtomicBoolean submittedOnce = new AtomicBoolean();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final Object lock = new Object();
    private Call activeCall;
    private NgaQrLoginForm form;

    public NgaQrAuthorizationSession(NgaQrLoginTarget target, String uid, String token,
                                     String version, BooleanSupplier isCurrent) {
        this(target, uid, token, version, isCurrent, newClientBuilder().build());
    }

    NgaQrAuthorizationSession(NgaQrLoginTarget target, String uid, String token,
                              String version, BooleanSupplier isCurrent, OkHttpClient client) {
        this.target = target;
        this.credentials = CookieCredentials.fromFields(uid, token);
        this.isCurrent = isCurrent;
        this.userAgent = "NGA_Harmony/1.0.0 LumaGA/" + version;
        this.client = client;
    }

    static OkHttpClient.Builder newClientBuilder() {
        return new OkHttpClient.Builder().cookieJar(CookieJar.NO_COOKIES)
                .authenticator(Authenticator.NONE).proxyAuthenticator(Authenticator.NONE)
                .followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false)
                .connectTimeout(10, TimeUnit.SECONDS).readTimeout(15, TimeUnit.SECONDS)
                .writeTimeout(15, TimeUnit.SECONDS).callTimeout(30, TimeUnit.SECONDS)
                .cache(null)
                .addNetworkInterceptor(chain -> {
                    AtomicBoolean sent = chain.request().tag(AtomicBoolean.class);
                    BooleanSupplier current = chain.request().tag(BooleanSupplier.class);
                    if (sent == null || current == null || !current.getAsBoolean()
                            || !sent.compareAndSet(false, true)) throw unavailable();
                    return chain.proceed(chain.request());
                });
    }

    public void prepare() throws IOException {
        if (!preparedOnce.compareAndSet(false, true) || !live()) throw unavailable();
        Document page = request(false, null, 262144);
        if (!live()) throw unavailable();
        NgaQrLoginForm parsed;
        try { parsed = NgaQrLoginForm.parse(page, target); }
        catch (IllegalArgumentException ignored) { throw unavailable(); }
        synchronized (lock) {
            if (!live()) throw unavailable();
            form = parsed;
        }
    }

    /** Call only from the native Confirm button. A consumed attempt can never submit again. */
    public NgaQrLoginResult submit() {
        NgaQrLoginForm prepared;
        synchronized (lock) {
            if (!live() || form == null || !submittedOnce.compareAndSet(false, true)) return NgaQrLoginResult.unconfirmed();
            prepared = form;
            form = null;
        }
        try {
            Document page = request(true, prepared, 65536);
            if (!live()) return NgaQrLoginResult.unconfirmed();
            return NgaQrLoginResult.parse(page).hideSecrets(credentials.cid, target.key());
        } catch (Exception ignored) {
            // The server might have committed before a timeout, disconnect, or unknown response.
            // Never retry and never tell the user this definitely failed.
            return NgaQrLoginResult.unconfirmed();
        }
    }

    public boolean wasSubmitted() { return submittedOnce.get(); }
    private boolean live() { return !closed.get() && isCurrent.getAsBoolean(); }

    private Document request(boolean post, NgaQrLoginForm prepared, int limit) throws IOException {
        if (!live()) throw unavailable();
        String url = post ? target.authorizationUrl : target.url;
        Request.Builder request = new Request.Builder().url(url).tag(AtomicBoolean.class, new AtomicBoolean()).tag(BooleanSupplier.class, this::live)
                .header("User-Agent", userAgent).header("Accept", "text/html")
                .header("Cache-Control", "no-store")
                .header("Cookie", "access_uid=" + credentials.uid + "; access_token=" + credentials.cid);
        if (post) {
            FormBody.Builder fields = new FormBody.Builder(prepared.charset);
            for (Map.Entry<String, String> field : prepared.fields.entrySet()) fields.add(field.getKey(), field.getValue());
            FormBody encoded = fields.build();
            request.header("Origin", "https://" + target.host).header("Referer", target.url)
                    .post(new RequestBody() {
                        @Override public MediaType contentType() { return encoded.contentType(); }
                        @Override public long contentLength() { return encoded.contentLength(); }
                        @Override public boolean isOneShot() { return true; }
                        @Override public void writeTo(BufferedSink sink) throws IOException {
                            // Last credential-revision/cancellation check immediately before the write.
                            if (!live()) throw unavailable();
                            encoded.writeTo(sink);
                        }
                    });
        }
        Call call = client.newCall(request.build());
        synchronized (lock) {
            if (!live() || activeCall != null) { call.cancel(); throw unavailable(); }
            activeCall = call;
        }
        try (Response response = call.execute()) {
            // This exact origin is the only destination. 3xx, 4xx and 5xx are never followed.
            if (response.code() != 200 || !response.request().url().toString().equals(url) || !live()) throw unavailable();
            ResponseBody body = response.body();
            if (body == null || body.contentLength() > limit) throw unavailable();
            MediaType type = body.contentType();
            if (type == null || !(type.type().equals("text") && type.subtype().equals("html")
                    || type.type().equals("application") && type.subtype().equals("xhtml+xml"))) throw unavailable();
            Charset charset = type.charset(null);
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try (InputStream input = body.byteStream()) {
                byte[] chunk = new byte[4096];
                int count;
                while ((count = input.read(chunk)) != -1) {
                    if (!live() || buffer.size() + count > limit) throw unavailable();
                    buffer.write(chunk, 0, count);
                }
            }
            if (!live()) throw unavailable();
            return Jsoup.parse(new ByteArrayInputStream(buffer.toByteArray()), charset == null ? null : charset.name(), target.url);
        } finally {
            synchronized (lock) { if (activeCall == call) activeCall = null; }
        }
    }

    private static IOException unavailable() { return new IOException("NGA authorization unavailable"); }

    @Override public void close() {
        if (!closed.compareAndSet(false, true)) return;
        synchronized (lock) {
            form = null;
            if (activeCall != null) activeCall.cancel();
        }
        client.connectionPool().evictAll();
        client.dispatcher().executorService().shutdown();
    }

    @Override public String toString() { return "NgaQrAuthorizationSession([redacted])"; }
}

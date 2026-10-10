package com.bugenzhao.mnga.auth;

import static com.bugenzhao.mnga.auth.NgaQrDiagnostic.*;

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
        try { this.credentials = CookieCredentials.fromFields(uid, token); }
        catch (Exception ignored) { throw CREDENTIALS_INVALID.parseFailure(); }
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
                    if (sent == null || current == null) throw REQUEST_STATE.requestFailure();
                    if (!current.getAsBoolean()) throw CANCELED.requestFailure();
                    if (!sent.compareAndSet(false, true)) throw ATTEMPT_USED.requestFailure();
                    return chain.proceed(chain.request());
                });
    }

    public void prepare() throws IOException {
        try {
            if (!preparedOnce.compareAndSet(false, true)) throw ATTEMPT_USED.requestFailure();
            if (!live()) throw CANCELED.requestFailure();
            Document page = request(false, null, 262144);
            if (!live()) throw CANCELED.requestFailure();
            NgaQrLoginForm parsed = NgaQrLoginForm.parse(page, target);
            synchronized (lock) {
                if (!live()) throw CANCELED.requestFailure();
                form = parsed;
            }
        } catch (Exception error) {
            // Create a fresh exception even for typed failures. A resource close may have
            // attached a URL-bearing suppressed exception to the original throwable.
            throw (live() ? NgaQrDiagnostic.from(error) : CANCELED).requestFailure();
        }
    }

    /** Call only from the native Confirm button. A consumed attempt can never submit again. */
    public NgaQrLoginResult submit() {
        NgaQrLoginForm prepared;
        synchronized (lock) {
            if (!live()) return NgaQrLoginResult.unconfirmed(CANCELED);
            if (submittedOnce.get()) return NgaQrLoginResult.unconfirmed(ATTEMPT_USED);
            if (form == null) return NgaQrLoginResult.unconfirmed(REQUEST_STATE);
            if (!submittedOnce.compareAndSet(false, true)) return NgaQrLoginResult.unconfirmed(ATTEMPT_USED);
            prepared = form;
            form = null;
        }
        try {
            Document page = request(true, prepared, 65536);
            if (!live()) return NgaQrLoginResult.unconfirmed(CANCELED);
            return NgaQrLoginResult.parse(page).hideSecrets(credentials.cid, target.key());
        } catch (Exception error) {
            // The server might have committed before a timeout, disconnect, or unknown response.
            // Never retry and never tell the user this definitely failed.
            return NgaQrLoginResult.unconfirmed(live() ? NgaQrDiagnostic.from(error) : CANCELED);
        }
    }

    public boolean wasSubmitted() { return submittedOnce.get(); }
    private boolean live() {
        if (closed.get()) return false;
        try { return isCurrent.getAsBoolean(); }
        catch (RuntimeException ignored) { return false; }
    }

    private Document request(boolean post, NgaQrLoginForm prepared, int limit) throws IOException {
        if (!live()) throw CANCELED.requestFailure();
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
                            if (!live()) throw CANCELED.requestFailure();
                            encoded.writeTo(sink);
                        }
                    });
        }
        Call call = client.newCall(request.build());
        synchronized (lock) {
            if (!live()) { call.cancel(); throw CANCELED.requestFailure(); }
            if (activeCall != null) { call.cancel(); throw REQUEST_STATE.requestFailure(); }
            activeCall = call;
        }
        try (Response response = call.execute()) {
            // This exact origin is the only destination. 3xx, 4xx and 5xx are never followed.
            if (!live()) throw CANCELED.requestFailure();
            if (!response.request().url().toString().equals(url)) throw DESTINATION.requestFailure();
            if (response.code() >= 300 && response.code() < 400) throw HTTP_REDIRECT.requestFailure();
            if (response.code() != 200) throw HTTP_ERROR.requestFailure();
            ResponseBody body = response.body();
            if (body == null) throw RESPONSE_EMPTY.requestFailure();
            if (body.contentLength() > limit) throw RESPONSE_SIZE.requestFailure();
            MediaType type = body.contentType();
            if (type == null || !(type.type().equals("text") && type.subtype().equals("html")
                    || type.type().equals("application") && type.subtype().equals("xhtml+xml"))) throw RESPONSE_TYPE.requestFailure();
            Charset charset = type.charset(null);
            if (type.parameter("charset") != null && charset == null) throw RESPONSE_CHARSET.requestFailure();
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try (InputStream input = body.byteStream()) {
                byte[] chunk = new byte[4096];
                int count;
                while ((count = input.read(chunk)) != -1) {
                    if (!live()) throw CANCELED.requestFailure();
                    if (buffer.size() + count > limit) throw RESPONSE_SIZE.requestFailure();
                    buffer.write(chunk, 0, count);
                }
            }
            if (!live()) throw CANCELED.requestFailure();
            if (buffer.size() == 0) throw RESPONSE_EMPTY.requestFailure();
            try {
                return Jsoup.parse(new ByteArrayInputStream(buffer.toByteArray()), charset == null ? null : charset.name(), target.url);
            } catch (java.nio.charset.UnsupportedCharsetException ignored) {
                throw RESPONSE_CHARSET.requestFailure();
            } catch (Exception ignored) { throw RESPONSE_HTML.requestFailure(); }
        } finally {
            synchronized (lock) { if (activeCall == call) activeCall = null; }
        }
    }

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

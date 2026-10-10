package com.bugenzhao.mnga.auth;

import org.junit.Test;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import javax.net.ssl.SSLHandshakeException;

import okhttp3.Interceptor;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okio.Buffer;
import okio.BufferedSource;
import okio.ForwardingSource;
import okio.Okio;

import static com.bugenzhao.mnga.auth.NgaQrDiagnostic.*;
import static org.junit.Assert.*;

/** Fully in-memory HTTP interception: no DNS, sockets, real credentials, or authorization. */
public class NgaQrAuthorizationSessionDiagnosticTest {
    private static final String KEY = "SyntheticSecretQrKey0123";
    private static final String TOKEN = "SyntheticSecretCookie9876";
    private static final String HIDDEN = "SyntheticSecretHidden5432";
    private static final NgaQrLoginTarget TARGET = NgaQrLoginTarget.parse(
            "https://bbs.nga.cn/nuke.php?__lib=login&__act=qrlogin_ui&qrkey=" + KEY);
    private static final String FORM = "<form id='loginform' method='post' action='/nuke.php?__lib=login&__act=qrlogin_allow&raw=3'>"
            + "<input type='hidden' id='qrkey' name='qrkey' value=''>"
            + "<input type='hidden' name='csrf' value='" + HIDDEN + "'>"
            + "<a id='loginsubmit' onclick='loginSubmit(this)'>Authorize</a></form>";
    private static final String RESULT = "<script>window.script_muti_get_var_store={\"data\":[\"Check computer\"]}</script>";

    @Test public void preflightTransportExceptionsHaveClassBasedSafeCodesAndConsumeAttempt() {
        Throwable[] failures = {new SocketTimeoutException(secret()), new UnknownHostException(secret()),
                new SSLHandshakeException(secret()), new IOException(secret()), new IllegalStateException(secret())};
        NgaQrDiagnostic[] diagnostics = {NETWORK_TIMEOUT, NETWORK_DNS, NETWORK_TLS, NETWORK_IO, UNKNOWN};
        for (int i = 0; i < failures.length; i++) {
            Throwable raw = failures[i];
            raw.initCause(new IllegalArgumentException("Cause " + secret()));
            raw.addSuppressed(new IOException("Suppressed " + secret()));
            expectPrepare(diagnostics[i], chain -> {
                if (raw instanceof IOException) throw (IOException) raw;
                throw (RuntimeException) raw;
            });
        }
    }

    @Test public void resourceCloseCannotAttachSecretSuppressedExceptionsToThePublicFailure() {
        for (NgaQrDiagnostic diagnostic : new NgaQrDiagnostic[]{RESPONSE_SIZE, RESPONSE_HTML, NETWORK_IO}) {
            expectPrepare(diagnostic, chain -> response(chain.request(), 200, FORM).newBuilder()
                    .body(new ResponseBody() {
                        private final BufferedSource source = Okio.buffer(new ForwardingSource(new Buffer().writeUtf8(FORM)) {
                            @Override public long read(Buffer sink, long count) throws IOException {
                                throw diagnostic.requestFailure();
                            }
                            @Override public void close() throws IOException { throw new IOException("Close " + secret()); }
                        });
                        @Override public MediaType contentType() { return MediaType.get("text/html"); }
                        @Override public long contentLength() { return -1; }
                        @Override public BufferedSource source() { return source; }
                    }).build());
        }
    }

    @Test public void redirectStatusDestinationAndMediaTypeHaveDistinctSafeCodes() {
        for (int status : new int[]{300, 301, 302, 307, 308, 399})
            expectPrepare(HTTP_REDIRECT, chain -> response(chain.request(), status, secret())
                    .newBuilder().header("Location", "https://example.test/" + TOKEN).build());
        for (int status : new int[]{201, 204, 400, 401, 403, 404, 500, 503})
            expectPrepare(HTTP_ERROR, chain -> response(chain.request(), status, secret()));
        expectPrepare(DESTINATION, chain -> response(new Request.Builder().url("https://example.test/" + KEY).build(), 200, secret()));
        for (String media : new String[]{"application/json", "text/plain", "image/png"})
            expectPrepare(RESPONSE_TYPE, chain -> response(chain.request(), 200, FORM).newBuilder()
                    .body(ResponseBody.create(FORM, MediaType.get(media))).build());
        expectPrepare(RESPONSE_TYPE, chain -> response(chain.request(), 200, FORM).newBuilder()
                .body(ResponseBody.create(FORM, (MediaType) null)).build());
    }

    @Test public void emptyOversizeAndUnsupportedCharsetDoNotBecomeCredentialFailures() {
        expectPrepare(RESPONSE_EMPTY, chain -> response(chain.request(), 200, ""));
        expectPrepare(RESPONSE_SIZE, chain -> response(chain.request(), 200, "x".repeat(262145)));
        expectPrepare(RESPONSE_SIZE, chain -> response(chain.request(), 200, FORM).newBuilder()
                .body(streamBody("x".repeat(262145), -1)).build());
        expectPrepare(RESPONSE_CHARSET, chain -> response(chain.request(), 200, FORM).newBuilder()
                .body(ResponseBody.create(FORM.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        MediaType.get("text/html; charset=Unknown" + TOKEN))).build());
    }

    @Test public void formCodeSurvivesTheRequestBoundaryWithoutRetainingTheHtml() {
        expectPrepare(KEY_MISMATCH, chain -> response(chain.request(), 200, FORM.replace("value=''", "value='" + TOKEN + "'")));
        expectPrepare(FORM_MISSING, chain -> response(chain.request(), 200, "<html>" + secret() + "</html>"));
        expectPrepare(LOGIN_NOT_RECOGNIZED, chain -> response(chain.request(), 200,
                "<form id='loginform' method='post' action='/nuke.php?__lib=login&__act=qrlogin_allow&raw=3'>"
                        + "<div class='invertblock'>你没有在这台设备上登录</div></form>"));
    }

    @Test public void postTransportFailureRetainsUncertaintyAndDoesNotRetry() throws Exception {
        IOException[] failures = {new SocketTimeoutException(secret()), new UnknownHostException(secret()),
                new SSLHandshakeException(secret()), new IOException(secret())};
        NgaQrDiagnostic[] diagnostics = {NETWORK_TIMEOUT, NETWORK_DNS, NETWORK_TLS, NETWORK_IO};
        for (int i = 0; i < failures.length; i++) {
            IOException failure = failures[i];
            AtomicInteger requests = new AtomicInteger();
            OkHttpClient client = client(chain -> {
                requests.incrementAndGet();
                if (chain.request().method().equals("GET")) return response(chain.request(), 200, FORM);
                chain.request().body().writeTo(new Buffer());
                throw failure;
            });
            try (NgaQrAuthorizationSession session = session(client, () -> true)) {
                session.prepare();
                expectResult(diagnostics[i], session.submit());
                assertTrue(session.wasSubmitted());
                expectResult(ATTEMPT_USED, session.submit());
                assertEquals(2, requests.get());
            }
        }
    }

    @Test public void postProtocolAndResultDiagnosticsRemainUnconfirmedAndOneShot() throws Exception {
        NgaQrDiagnostic[] diagnostics = {HTTP_REDIRECT, HTTP_ERROR, RESPONSE_EMPTY, RESPONSE_TYPE, RESPONSE_SIZE,
                RESPONSE_CHARSET, RESULT_ENVELOPE, RESULT_JSON, RESULT_VALUE, RESULT_REDACTED};
        for (NgaQrDiagnostic diagnostic : diagnostics) {
            AtomicInteger requests = new AtomicInteger();
            OkHttpClient client = client(chain -> {
                requests.incrementAndGet();
                Request request = chain.request();
                if (request.method().equals("GET")) return response(request, 200, FORM);
                request.body().writeTo(new Buffer());
                switch (diagnostic) {
                    case HTTP_REDIRECT: return response(request, 302, secret());
                    case HTTP_ERROR: return response(request, 503, secret());
                    case RESPONSE_EMPTY: return response(request, 200, "");
                    case RESPONSE_SIZE: return response(request, 200, "x".repeat(65537));
                    case RESPONSE_TYPE: return response(request, 200, RESULT).newBuilder().body(ResponseBody.create(RESULT, MediaType.get("application/json"))).build();
                    case RESPONSE_CHARSET: return response(request, 200, RESULT).newBuilder().body(ResponseBody.create(RESULT.getBytes(java.nio.charset.StandardCharsets.UTF_8), MediaType.get("text/html; charset=Unknown"))).build();
                    case RESULT_ENVELOPE: return response(request, 200, "<html>" + secret() + "</html>");
                    case RESULT_JSON: return response(request, 200, "<script>window.script_muti_get_var_store={broken}</script>");
                    case RESULT_VALUE: return response(request, 200, "<script>window.script_muti_get_var_store={\"data\":[true]}</script>");
                    case RESULT_REDACTED: return response(request, 200, RESULT.replace("Check computer", TOKEN));
                    default: throw new AssertionError("Missing synthetic response");
                }
            });
            try (NgaQrAuthorizationSession session = session(client, () -> true)) {
                session.prepare();
                expectResult(diagnostic, session.submit());
                expectResult(ATTEMPT_USED, session.submit());
                assertEquals(2, requests.get());
                assertTrue(session.wasSubmitted());
            }
        }
    }

    @Test public void missingPreparationAndCancellationUseLocalStateCodesWithoutHttp() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        OkHttpClient client = client(chain -> { requests.incrementAndGet(); return response(chain.request(), 200, FORM); });
        try (NgaQrAuthorizationSession session = session(client, () -> true)) {
            expectResult(REQUEST_STATE, session.submit());
            assertFalse(session.wasSubmitted());
            session.close();
            expectResult(CANCELED, session.submit());
            safe(assertThrows(RequestFailure.class, session::prepare), CANCELED);
            assertEquals(0, requests.get());
        }
        OkHttpClient staleClient = client(chain -> { fail("A stale account must not send HTTP"); return null; });
        try (NgaQrAuthorizationSession session = session(staleClient, () -> false)) {
            safe(assertThrows(RequestFailure.class, session::prepare), CANCELED);
            expectResult(CANCELED, session.submit());
        }
    }

    @Test public void cancellationImmediatelyBeforeBodyWriteProducesCanceledCodeWithoutBody() throws Exception {
        AtomicBoolean current = new AtomicBoolean(true);
        Buffer body = new Buffer();
        OkHttpClient client = client(chain -> {
            if (chain.request().method().equals("GET")) return response(chain.request(), 200, FORM);
            current.set(false);
            chain.request().body().writeTo(body);
            return response(chain.request(), 200, RESULT);
        });
        try (NgaQrAuthorizationSession session = session(client, current::get)) {
            session.prepare();
            expectResult(CANCELED, session.submit());
            assertEquals(0, body.size());
        }
    }

    @Test public void invalidCredentialsHaveOnlyTheLocalCredentialCode() {
        OkHttpClient client = client(chain -> { fail("Invalid credentials must not send HTTP"); return null; });
        try {
            ParseFailure failure = assertThrows(ParseFailure.class,
                    () -> new NgaQrAuthorizationSession(TARGET, "not-a-uid-" + KEY, TOKEN, "test", () -> true, client));
            safe(failure, CREDENTIALS_INVALID);
        } finally { client.dispatcher().executorService().shutdown(); }
    }

    @Test public void throwingAccountPredicateFailsClosedWithoutLeakingItsException() {
        OkHttpClient client = client(chain -> { fail("An unverified account must not send HTTP"); return null; });
        try (NgaQrAuthorizationSession session = session(client, () -> { throw new IllegalStateException(secret()); })) {
            safe(assertThrows(RequestFailure.class, session::prepare), CANCELED);
            expectResult(CANCELED, session.submit());
            assertFalse(session.wasSubmitted());
        }
    }

    @Test public void networkGuardDistinguishesMissingStateCancellationAndDuplicateTransmission() throws Exception {
        OkHttpClient client = NgaQrAuthorizationSession.newClientBuilder().build();
        Interceptor guard = client.networkInterceptors().get(0);
        AtomicInteger transmissions = new AtomicInteger();
        try {
            Request base = new Request.Builder().url(TARGET.url).build();
            safe(assertThrows(RequestFailure.class, () -> guard.intercept(fakeChain(base, transmissions))), REQUEST_STATE);
            Request stale = base.newBuilder().tag(AtomicBoolean.class, new AtomicBoolean())
                    .tag(BooleanSupplier.class, () -> false).build();
            safe(assertThrows(RequestFailure.class, () -> guard.intercept(fakeChain(stale, transmissions))), CANCELED);
            AtomicBoolean sent = new AtomicBoolean();
            Request current = base.newBuilder().tag(AtomicBoolean.class, sent).tag(BooleanSupplier.class, () -> true).build();
            try (Response ignored = guard.intercept(fakeChain(current, transmissions))) { assertTrue(sent.get()); }
            safe(assertThrows(RequestFailure.class, () -> guard.intercept(fakeChain(current, transmissions))), ATTEMPT_USED);
            assertEquals(1, transmissions.get());
        } finally { client.dispatcher().executorService().shutdown(); }
    }

    private static Interceptor.Chain fakeChain(Request request, AtomicInteger transmissions) {
        return (Interceptor.Chain) java.lang.reflect.Proxy.newProxyInstance(Interceptor.Chain.class.getClassLoader(),
                new Class<?>[]{Interceptor.Chain.class}, (proxy, method, args) -> {
                    if (method.getName().equals("request")) return request;
                    if (method.getName().equals("proceed")) {
                        transmissions.incrementAndGet(); return response((Request) args[0], 200, RESULT);
                    }
                    throw new UnsupportedOperationException("Unexpected fake operation");
                });
    }
    private static ResponseBody streamBody(String text, long declaredLength) {
        return new ResponseBody() {
            private final Buffer buffer = new Buffer().writeUtf8(text);
            @Override public MediaType contentType() { return MediaType.get("text/html"); }
            @Override public long contentLength() { return declaredLength; }
            @Override public BufferedSource source() { return buffer; }
        };
    }
    private static void expectPrepare(NgaQrDiagnostic diagnostic, Interceptor interceptor) {
        AtomicInteger requests = new AtomicInteger();
        OkHttpClient client = client(chain -> { requests.incrementAndGet(); return interceptor.intercept(chain); });
        try (NgaQrAuthorizationSession session = session(client, () -> true)) {
            safe(assertThrows(RequestFailure.class, session::prepare), diagnostic);
            assertFalse(session.wasSubmitted());
            expectResult(REQUEST_STATE, session.submit());
            safe(assertThrows(RequestFailure.class, session::prepare), ATTEMPT_USED);
            assertEquals(1, requests.get());
            assertFalse(session.toString().contains(KEY));
            assertFalse(session.toString().contains(TOKEN));
            assertFalse(session.toString().contains(HIDDEN));
        }
    }
    private static NgaQrAuthorizationSession session(OkHttpClient client, BooleanSupplier current) {
        return new NgaQrAuthorizationSession(TARGET, "42", TOKEN, "test", current, client);
    }
    private static OkHttpClient client(Interceptor interceptor) {
        return NgaQrAuthorizationSession.newClientBuilder().addInterceptor(interceptor).build();
    }
    private static Response response(Request request, int status, String body) {
        return new Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(status).message("Synthetic")
                .body(ResponseBody.create(body, MediaType.get("text/html; charset=UTF-8"))).build();
    }
    private static String secret() { return "url=" + TARGET.url + " Cookie=" + TOKEN + " csrf=" + HIDDEN; }
    private static void safe(Throwable error, NgaQrDiagnostic diagnostic) {
        assertSame(diagnostic, NgaQrDiagnostic.from(error));
        assertEquals("NGA QR diagnostic: " + diagnostic.code, error.getMessage());
        for (String sentinel : new String[]{KEY, TOKEN, HIDDEN, TARGET.url}) {
            assertFalse(error.getMessage().contains(sentinel));
            assertFalse(error.toString().contains(sentinel));
        }
        assertNull(error.getCause());
        assertEquals(0, error.getSuppressed().length);
    }
    private static void expectResult(NgaQrDiagnostic diagnostic, NgaQrLoginResult result) {
        assertSame(NgaQrLoginResult.Kind.UNCONFIRMED, result.kind);
        assertSame(diagnostic, result.diagnostic);
        assertEquals("", result.message);
        assertFalse(result.toString().contains(KEY));
        assertFalse(result.toString().contains(TOKEN));
        assertFalse(result.toString().contains(HIDDEN));
    }
}

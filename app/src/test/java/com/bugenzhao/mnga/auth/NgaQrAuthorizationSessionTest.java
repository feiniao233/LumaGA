package com.bugenzhao.mnga.auth;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import okhttp3.CookieJar;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okio.Buffer;
import org.junit.Test;

/** All HTTP is intercepted in memory; no network, real credentials, or approval requests. */
public class NgaQrAuthorizationSessionTest {
    private static final String KEY = "SyntheticQrKey0123";
    private static final String TOKEN = "SyntheticTestToken987";
    private static final NgaQrLoginTarget TARGET = NgaQrLoginTarget.parse(
            "https://bbs.nga.cn/nuke.php?__lib=login&__act=qrlogin_ui&qrkey=" + KEY);
    private static final String FORM = "<html><form id='loginform' method='post' target='loginframe' "
            + "action='/nuke.php?__lib=login&__act=qrlogin_allow&raw=3'>"
            + "<input type='hidden' id='qrkey' name='qrkey' value=''>"
            + "<input type='hidden' name='_csrf' value='a&amp;b=+'>"
            + "<a id='loginsubmit' onclick='loginSubmit(this)'>确认登录</a></form></html>";
    private static final String RESULT = "<script>window.script_muti_get_var_store={\"data\":{\"0\":\"请检查电脑\"}}</script>";

    private static Response response(Request request, int code, String body) {
        return new Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(code).message("Test")
                .body(ResponseBody.create(body, MediaType.get("text/html; charset=UTF-8"))).build();
    }

    @Test public void dedicatedClientDisablesSharedStateRedirectsAndRetries() {
        OkHttpClient client = NgaQrAuthorizationSession.newClientBuilder().build();
        assertSame(CookieJar.NO_COOKIES, client.cookieJar());
        assertNull(client.cache());
        assertFalse(client.followRedirects());
        assertFalse(client.followSslRedirects());
        assertFalse(client.retryOnConnectionFailure());
        assertEquals(30000, client.callTimeoutMillis());
        assertFalse(client.networkInterceptors().isEmpty());
        client.dispatcher().executorService().shutdown();
    }

    @Test public void networkGateBlocksDuplicateTransmissionAndStaleAccount() throws Exception {
        AtomicBoolean sent = new AtomicBoolean(), current = new AtomicBoolean(true);
        java.util.concurrent.atomic.AtomicInteger transmissions = new java.util.concurrent.atomic.AtomicInteger();
        Request request = new Request.Builder().url(TARGET.url)
                .tag(AtomicBoolean.class, sent).tag(java.util.function.BooleanSupplier.class, current::get).build();
        // A direct fake chain exercises the actual network guard without sockets or DNS.
        okhttp3.Interceptor.Chain chain = (okhttp3.Interceptor.Chain) java.lang.reflect.Proxy.newProxyInstance(
                okhttp3.Interceptor.Chain.class.getClassLoader(), new Class<?>[]{okhttp3.Interceptor.Chain.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("request")) return request;
                    if (method.getName().equals("proceed")) {
                        transmissions.incrementAndGet(); return response((Request) args[0], 503, "");
                    }
                    throw new UnsupportedOperationException("Unexpected fake chain operation");
                });
        OkHttpClient client = NgaQrAuthorizationSession.newClientBuilder().build();
        okhttp3.Interceptor guard = client.networkInterceptors().get(0);
        try {
            try (Response ignored = guard.intercept(chain)) { assertEquals(1, transmissions.get()); }
            assertThrows(IOException.class, () -> guard.intercept(chain));
            sent.set(false); current.set(false);
            assertThrows(IOException.class, () -> guard.intercept(chain));
            assertEquals(1, transmissions.get());
        } finally { client.dispatcher().executorService().shutdown(); }
    }

    @Test public void prepareCannotAuthorizeAndExplicitSubmitIsOneShot() throws Exception {
        List<Request> requests = new ArrayList<>();
        AtomicReference<String> posted = new AtomicReference<>();
        OkHttpClient client = NgaQrAuthorizationSession.newClientBuilder().addInterceptor(chain -> {
            Request request = chain.request(); requests.add(request);
            if (request.method().equals("POST")) {
                assertTrue(request.body().isOneShot());
                Buffer body = new Buffer(); request.body().writeTo(body); posted.set(body.readUtf8());
            }
            return response(request, 200, request.method().equals("GET") ? FORM : RESULT);
        }).build();
        try (NgaQrAuthorizationSession session = new NgaQrAuthorizationSession(TARGET, "42", TOKEN, "test", () -> true, client)) {
            assertEquals(NgaQrLoginResult.Kind.UNCONFIRMED, session.submit().kind);
            assertEquals(0, requests.size());
            session.prepare(); assertFalse(session.wasSubmitted());
            assertEquals(1, requests.size()); assertEquals("GET", requests.get(0).method());
            assertEquals(NgaQrLoginResult.Kind.SERVER_MESSAGE, session.submit().kind);
            assertEquals(NgaQrLoginResult.Kind.UNCONFIRMED, session.submit().kind);
            assertEquals(2, requests.size());
            assertEquals(TARGET.authorizationUrl, requests.get(1).url().toString());
            assertEquals("access_uid=42; access_token=" + TOKEN, requests.get(1).header("Cookie"));
            assertEquals("https://bbs.nga.cn", requests.get(1).header("Origin"));
            assertTrue(posted.get().contains("qrkey=" + KEY));
            assertTrue(posted.get().contains("_csrf=a%26b%3D%2B"));
            assertFalse(session.toString().contains(KEY)); assertFalse(session.toString().contains(TOKEN));
        }
    }

    @Test public void closeAndChangedRevisionPreventAnyPost() throws Exception {
        for (boolean cancel : new boolean[] {false, true}) {
            AtomicBoolean current = new AtomicBoolean(true);
            List<Request> requests = new ArrayList<>();
            OkHttpClient client = NgaQrAuthorizationSession.newClientBuilder().addInterceptor(chain -> {
                requests.add(chain.request()); return response(chain.request(), 200, FORM);
            }).build();
            try (NgaQrAuthorizationSession session = new NgaQrAuthorizationSession(TARGET, "42", TOKEN, "test", current::get, client)) {
                session.prepare();
                if (cancel) session.close(); else current.set(false);
                assertEquals(NgaQrLoginResult.Kind.UNCONFIRMED, session.submit().kind);
                assertEquals(1, requests.size());
            }
        }
    }

    @Test public void latePreflightAndDuplicatePrepareCannotBecomeReady() throws Exception {
        AtomicBoolean current = new AtomicBoolean(true);
        List<Request> requests = new ArrayList<>();
        OkHttpClient client = NgaQrAuthorizationSession.newClientBuilder().addInterceptor(chain -> {
            requests.add(chain.request()); current.set(false); return response(chain.request(), 200, FORM);
        }).build();
        try (NgaQrAuthorizationSession session = new NgaQrAuthorizationSession(TARGET, "42", TOKEN, "test", current::get, client)) {
            assertThrows(IOException.class, session::prepare);
            current.set(true);
            assertThrows(IOException.class, session::prepare);
            session.submit(); assertEquals(1, requests.size());
        }
    }

    @Test public void networkFailureAfterWriteRemainsUnconfirmedWithoutRetry() throws Exception {
        List<Request> requests = new ArrayList<>();
        OkHttpClient client = NgaQrAuthorizationSession.newClientBuilder().addInterceptor(chain -> {
            Request request = chain.request(); requests.add(request);
            if (request.method().equals("GET")) return response(request, 200, FORM);
            request.body().writeTo(new Buffer()); throw new IOException("Synthetic timeout after write");
        }).build();
        try (NgaQrAuthorizationSession session = new NgaQrAuthorizationSession(TARGET, "42", TOKEN, "test", () -> true, client)) {
            session.prepare();
            assertEquals(NgaQrLoginResult.Kind.UNCONFIRMED, session.submit().kind);
            session.submit(); assertEquals(2, requests.size()); assertTrue(session.wasSubmitted());
        }
    }

    @Test public void duplicateClickDoesNotSendAnotherRequest() throws Exception {
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        List<Request> requests = new ArrayList<>();
        OkHttpClient client = NgaQrAuthorizationSession.newClientBuilder().addInterceptor(chain -> {
            Request request = chain.request(); requests.add(request);
            if (request.method().equals("GET")) return response(request, 200, FORM);
            request.body().writeTo(new Buffer()); entered.countDown();
            try { if (!release.await(5, TimeUnit.SECONDS)) throw new IOException("Test deadline"); }
            catch (InterruptedException e) { throw new IOException("Interrupted test"); }
            return response(request, 200, RESULT);
        }).build();
        try (NgaQrAuthorizationSession session = new NgaQrAuthorizationSession(TARGET, "42", TOKEN, "test", () -> true, client)) {
            session.prepare();
            AtomicReference<NgaQrLoginResult> result = new AtomicReference<>();
            Thread first = new Thread(() -> result.set(session.submit())); first.start();
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            assertEquals(NgaQrLoginResult.Kind.UNCONFIRMED, session.submit().kind);
            release.countDown(); first.join(5000);
            assertFalse(first.isAlive()); assertEquals(2, requests.size());
            assertEquals(NgaQrLoginResult.Kind.SERVER_MESSAGE, result.get().kind);
        } finally { release.countDown(); }
    }

    @Test public void cancelInFlightCancelsCallAndDiscardsLateResponse() throws Exception {
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        AtomicReference<okhttp3.Call> active = new AtomicReference<>();
        OkHttpClient client = NgaQrAuthorizationSession.newClientBuilder().addInterceptor(chain -> {
            if (chain.request().method().equals("GET")) return response(chain.request(), 200, FORM);
            active.set(chain.call()); entered.countDown();
            try { if (!release.await(5, TimeUnit.SECONDS)) throw new IOException("Test deadline"); }
            catch (InterruptedException e) { throw new IOException("Interrupted test"); }
            return response(chain.request(), 200, RESULT);
        }).build();
        NgaQrAuthorizationSession session = new NgaQrAuthorizationSession(TARGET, "42", TOKEN, "test", () -> true, client);
        try {
            session.prepare(); AtomicReference<NgaQrLoginResult> result = new AtomicReference<>();
            Thread first = new Thread(() -> result.set(session.submit())); first.start();
            assertTrue(entered.await(5, TimeUnit.SECONDS)); session.close();
            assertTrue(active.get().isCanceled()); release.countDown(); first.join(5000);
            assertFalse(first.isAlive()); assertEquals(NgaQrLoginResult.Kind.UNCONFIRMED, result.get().kind);
        } finally { release.countDown(); session.close(); }
    }

    @Test public void changingAccountImmediatelyBeforeBodyWritePreventsBody() throws Exception {
        AtomicBoolean current = new AtomicBoolean(true);
        AtomicReference<Buffer> written = new AtomicReference<>();
        OkHttpClient client = NgaQrAuthorizationSession.newClientBuilder().addInterceptor(chain -> {
            if (chain.request().method().equals("GET")) return response(chain.request(), 200, FORM);
            Buffer body = new Buffer(); written.set(body); current.set(false);
            chain.request().body().writeTo(body);
            return response(chain.request(), 200, RESULT);
        }).build();
        try (NgaQrAuthorizationSession session = new NgaQrAuthorizationSession(TARGET, "42", TOKEN, "test", current::get, client)) {
            session.prepare();
            assertEquals(NgaQrLoginResult.Kind.UNCONFIRMED, session.submit().kind);
            assertEquals(0, written.get().size());
        }
    }

    @Test public void gbkHtmlAndHiddenFieldsUseTheDeclaredEncoding() throws Exception {
        AtomicReference<String> encoded = new AtomicReference<>();
        String html = FORM.replace("a&amp;b=+", "中文");
        OkHttpClient client = NgaQrAuthorizationSession.newClientBuilder().addInterceptor(chain -> {
            if (chain.request().method().equals("GET")) return response(chain.request(), 200, "")
                    .newBuilder().body(ResponseBody.create(html.getBytes(java.nio.charset.Charset.forName("GBK")),
                            MediaType.get("text/html; charset=GBK"))).build();
            Buffer body = new Buffer(); chain.request().body().writeTo(body); encoded.set(body.readUtf8());
            return response(chain.request(), 200, RESULT);
        }).build();
        try (NgaQrAuthorizationSession session = new NgaQrAuthorizationSession(TARGET, "42", TOKEN, "test", () -> true, client)) {
            session.prepare(); session.submit();
            assertTrue(encoded.get(), encoded.get().contains("_csrf=%D6%D0%CE%C4"));
        }
    }

    @Test public void secretEchoAndUnrecognizedReplyCannotAppearAsServerMessage() throws Exception {
        for (String body : new String[]{"<html>login successful</html>", "{\"success\":true}",
                RESULT.replace("请检查电脑", TOKEN), RESULT.replace("请检查电脑", KEY)}) {
            OkHttpClient client = NgaQrAuthorizationSession.newClientBuilder().addInterceptor(chain ->
                    response(chain.request(), 200, chain.request().method().equals("GET") ? FORM : body)).build();
            try (NgaQrAuthorizationSession session = new NgaQrAuthorizationSession(TARGET, "42", TOKEN, "test", () -> true, client)) {
                session.prepare(); assertEquals(NgaQrLoginResult.Kind.UNCONFIRMED, session.submit().kind);
            }
        }
    }

    @Test public void rejectsRedirectErrorOversizeAndUnexpectedMediaBeforeConfirm() {
        for (int mode = 0; mode < 4; mode++) {
            final int test = mode;
            OkHttpClient client = NgaQrAuthorizationSession.newClientBuilder().addInterceptor(chain -> {
                Response response = response(chain.request(), test == 0 ? 302 : test == 1 ? 503 : 200,
                        test == 2 ? " ".repeat(262145) : FORM);
                if (test == 3) response = response.newBuilder().body(ResponseBody.create(FORM, MediaType.get("application/json"))).build();
                return response;
            }).build();
            try (NgaQrAuthorizationSession session = new NgaQrAuthorizationSession(TARGET, "42", TOKEN, "test", () -> true, client)) {
                assertThrows(IOException.class, session::prepare);
                assertFalse(session.wasSubmitted());
                assertEquals(NgaQrLoginResult.Kind.UNCONFIRMED, session.submit().kind);
            }
        }
    }
}

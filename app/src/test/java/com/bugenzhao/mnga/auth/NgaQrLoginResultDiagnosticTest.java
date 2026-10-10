package com.bugenzhao.mnga.auth;

import org.json.JSONObject;
import org.jsoup.Jsoup;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static com.bugenzhao.mnga.auth.NgaQrDiagnostic.*;
import static org.junit.Assert.*;

/** Every result remains unconfirmed until a recognized, safely displayable server message exists. */
public class NgaQrLoginResultDiagnosticTest {
    private static final String PREFIX = "window.script_muti_get_var_store=";
    private static final String KEY = "SyntheticQrKeyNeverLog0123";
    private static final String TOKEN = "SyntheticCookieNeverLog9876";

    @Test public void unconfirmedFactoriesHaveFixedDiagnosticsAndNoServerText() {
        expect(UNKNOWN, NgaQrLoginResult.unconfirmed());
        expect(UNKNOWN, NgaQrLoginResult.unconfirmed(null));
        for (NgaQrDiagnostic diagnostic : NgaQrDiagnostic.values())
            expect(diagnostic, NgaQrLoginResult.unconfirmed(diagnostic));
    }

    @Test public void unsupportedEnvelopeIsDistinctFromInvalidJsonOrValue() {
        for (String html : new String[]{"", "<html>success " + TOKEN + "</html>",
                "<!--" + script("{}") + "-->", "<pre>" + PREFIX + "{}</pre>",
                "<script src='https://example.test/" + TOKEN + "'>" + PREFIX + "{}</script>",
                script("{}") + "<script></script>", script("{}") + "<template></template>",
                script("{}") + "<iframe></iframe>", script("{}") + "<base href='/'>",
                "<script>window.other=" + data(TOKEN) + "</script>", script("[]"), script("null"),
                script("true"), script("{\"data\":[\"success\"]}" + ";alert('" + TOKEN + "')")})
            expect(RESULT_ENVELOPE, parse(html));
    }

    @Test public void malformedAmbiguousAndOvernestedJsonUseJsonCodeWithoutEchoingPayload() {
        for (String payload : new String[]{"{broken}", "{'data':['" + TOKEN + "']}",
                "{\"data\":[\"" + TOKEN + "\"],}", "{\"data\":[\"" + TOKEN + "\",]}",
                "{\"data\":[\"" + TOKEN + "\"],\"data\":[\"success\"]}",
                "{\"data\":{\"0\":\"" + TOKEN + "\",\"0\":\"success\"}}",
                "{\"data\":[\"success\"],\"extra\":" + "[".repeat(18) + "0" + "]".repeat(18) + "}",
                "{} {}", "{\"data\":[\"success\"],\"extra\":NaN}"})
            expect(RESULT_JSON, parse(script(payload)));
        expect(RESULT_JSON, NgaQrLoginResult.parse(null));
    }

    @Test public void oversizedPayloadIsDiagnosedBeforeJsonParsing() {
        expect(RESPONSE_SIZE, parse(script("{\"data\":[\"" + TOKEN + "\"],\"extra\":\"" + "x".repeat(65536) + "\"}")));
    }

    @Test public void malformedOrUnsafeMessageValuesNeverClaimLoginSuccess() {
        for (String payload : new String[]{"{}", "{\"success\":true}", "{\"data\":null}",
                "{\"data\":[]}", "{\"data\":[false,\"success\"]}", "{\"data\":{\"1\":\"success\"}}",
                "{\"error\":null,\"data\":[\"success\"]}", "{\"error\":[\"\"],\"data\":[\"success\"]}"})
            expect(RESULT_VALUE, parse(script(payload)));
        for (String message : new String[]{"", "  ", "x".repeat(1001), TOKEN + "\0end", TOKEN + "\u202eend"})
            expect(RESULT_VALUE, parse(script(data(message))));
    }

    @Test public void knownMessagesHaveNoDiagnosticAndAreNeverAConfirmedSuccessKind() {
        for (String member : new String[]{"data", "error"}) {
            NgaQrLoginResult result = parse(script("{\"" + member + "\":[\"登录成功\"]}"));
            assertEquals(member.equals("error") ? NgaQrLoginResult.Kind.SERVER_ERROR : NgaQrLoginResult.Kind.SERVER_MESSAGE, result.kind);
            assertEquals("登录成功", result.message);
            assertNull(result.diagnostic);
            assertFalse(result.toString().contains("登录成功"));
        }
    }

    @Test public void observedLoggedOutResponseRemainsAnOrdinaryServerError() throws IOException {
        try (InputStream input = getClass().getResourceAsStream("/qr/official-raw3-logged-out.html")) {
            assertNotNull(input);
            NgaQrLoginResult result = parse(new String(input.readAllBytes(), StandardCharsets.UTF_8));
            assertEquals(NgaQrLoginResult.Kind.SERVER_ERROR, result.kind);
            assertEquals("请求错误", result.message);
            assertNull(result.diagnostic);
        }
    }

    @Test public void credentialAndQrEchoesGetRedactionCodeForBothServerKinds() {
        for (String member : new String[]{"data", "error"}) {
            for (String message : new String[]{"Echo " + TOKEN, "Echo " + KEY, TOKEN + KEY}) {
                NgaQrLoginResult result = parse(script("{\"" + member + "\":[" + JSONObject.quote(message) + "]}"));
                expect(RESULT_REDACTED, result.hideSecrets(TOKEN, KEY));
                assertFalse(result.toString().contains(TOKEN));
                assertFalse(result.toString().contains(KEY));
            }
        }
        NgaQrLoginResult safe = parse(script(data("Please check your computer")));
        assertSame(safe, safe.hideSecrets(TOKEN, KEY));
        NgaQrLoginResult unknown = NgaQrLoginResult.unconfirmed(HTTP_ERROR);
        assertSame(unknown, unknown.hideSecrets(TOKEN, KEY));
    }

    private static String data(String message) { return "{\"data\":[" + JSONObject.quote(message) + "]}"; }
    private static String script(String payload) { return "<script>" + PREFIX + payload + "</script>"; }
    private static NgaQrLoginResult parse(String html) { return NgaQrLoginResult.parse(Jsoup.parse(html)); }
    private static void expect(NgaQrDiagnostic diagnostic, NgaQrLoginResult result) {
        assertEquals(NgaQrLoginResult.Kind.UNCONFIRMED, result.kind);
        assertEquals("", result.message);
        assertSame(diagnostic, result.diagnostic);
        assertFalse(result.toString().contains(TOKEN));
        assertFalse(result.toString().contains(KEY));
    }
}

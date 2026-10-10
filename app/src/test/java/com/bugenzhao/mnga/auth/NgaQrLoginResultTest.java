package com.bugenzhao.mnga.auth;

import org.json.JSONObject;
import org.jsoup.Jsoup;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

/** Only the logged-out error fixture is observed; every other response is synthetic. */
public class NgaQrLoginResultTest {
    private static final String PREFIX = "window.script_muti_get_var_store=";

    @Test public void parsesActualUnauthenticatedNumericKeyObjectAsServerError() throws IOException {
        try (InputStream input = getClass().getResourceAsStream("/qr/official-raw3-logged-out.html")) {
            assertNotNull(input);
            NgaQrLoginResult result = html(new String(input.readAllBytes(), StandardCharsets.UTF_8));
            assertEquals(NgaQrLoginResult.Kind.SERVER_ERROR, result.kind);
            assertEquals("请求错误", result.message);
        }
    }

    @Test public void syntheticNumericKeyedObjectAndArrayMessagesAreSupported() {
        for (String payload : new String[]{"{\"data\":{\"0\":\"Synthetic message\"}}",
                "{\"data\":[\"Synthetic message\"]}"}) {
            assertMessage(NgaQrLoginResult.Kind.SERVER_MESSAGE, "Synthetic message", result(payload));
        }
        for (String payload : new String[]{"{\"error\":{\"0\":\"Synthetic error\"}}",
                "{\"error\":[\"Synthetic error\"]}"}) {
            assertMessage(NgaQrLoginResult.Kind.SERVER_ERROR, "Synthetic error", result(payload));
        }
    }

    @Test public void syntheticServerTextIsNeverProofOfDesktopLoginSuccess() {
        for (String message : new String[]{"success", "登录成功", "电脑已登录", "true", "OK", "authorized"}) {
            assertMessage(NgaQrLoginResult.Kind.SERVER_MESSAGE, message, result(data(message)));
        }
        assertArrayEquals(new NgaQrLoginResult.Kind[]{NgaQrLoginResult.Kind.SERVER_MESSAGE,
                NgaQrLoginResult.Kind.SERVER_ERROR, NgaQrLoginResult.Kind.UNCONFIRMED}, NgaQrLoginResult.Kind.values());
    }

    @Test public void toleratesOnlyWhitespaceAndOneOptionalSemicolonAroundEnvelope() {
        String assignment = PREFIX + "  " + data("Synthetic message");
        for (String text : new String[]{assignment, assignment + ";", " \n\t" + assignment + " ; \n\t"})
            assertMessage(NgaQrLoginResult.Kind.SERVER_MESSAGE, "Synthetic message", script(text));
    }

    @Test public void trimsMessagesWithoutInterpretingTheirTextAsHtmlOrScript() {
        assertMessage(NgaQrLoginResult.Kind.SERVER_MESSAGE, "Synthetic message", result(data("  Synthetic message\n\t")));
        String text = "<b>Untrusted</b> &amp; alert('synthetic');";
        assertMessage(NgaQrLoginResult.Kind.SERVER_MESSAGE, text, result(data(text)));
        assertMessage(NgaQrLoginResult.Kind.SERVER_MESSAGE, "line one\nline two\ttab", result(data("line one\nline two\ttab")));
    }

    @Test public void errorAlwaysTakesPrecedenceOverDataInEitherPropertyOrder() {
        for (String payload : new String[]{
                "{\"error\":[\"Synthetic error\"],\"data\":[\"success\"]}",
                "{\"data\":[\"success\"],\"error\":{\"0\":\"Synthetic error\"}}"
        }) assertMessage(NgaQrLoginResult.Kind.SERVER_ERROR, "Synthetic error", result(payload));
    }

    @Test public void malformedErrorNeverFallsBackToAnApparentlySuccessfulDataMessage() {
        for (String error : new String[]{"null", "false", "true", "0", "\"failure\"", "{}", "[]",
                "[null]", "[false]", "[1]", "[{}]", "[[]]", "[\"\"]", "[\"   \"]",
                "{\"1\":\"error\"}", "{\"0\":null}"}) {
            assertUnconfirmed(result("{\"data\":[\"success\"],\"error\":" + error + "}"));
        }
    }

    @Test public void requiresIndexZeroToBeAStringAndDoesNotSearchLaterEntries() {
        for (String member : new String[]{"data", "error"}) {
            for (String container : new String[]{"null", "false", "true", "0", "1.5", "\"success\"",
                    "{}", "[]", "[null,\"success\"]", "[false,\"success\"]", "[1,\"success\"]",
                    "[{},\"success\"]", "[[],\"success\"]", "{\"1\":\"success\"}",
                    "{\"00\":\"success\"}", "{\"0\":1}", "{\"0\":true}", "{\"0\":{}}"}) {
                assertUnconfirmed(result("{\"" + member + "\":" + container + "}"));
            }
        }
    }

    @Test public void ignoresAdditionalMessagesAndMetadataWithoutInventingSuccess() {
        assertMessage(NgaQrLoginResult.Kind.SERVER_MESSAGE, "First synthetic message",
                result("{\"data\":[\"First synthetic message\",\"success\"],\"time\":1234}"));
        assertMessage(NgaQrLoginResult.Kind.SERVER_ERROR, "First synthetic error",
                result("{\"error\":{\"0\":\"First synthetic error\",\"1\":\"success\"},\"time\":1234}"));
    }

    @Test public void unknownAndWrongRootEnvelopesAreAlwaysUnconfirmed() {
        for (String payload : new String[]{"{}", "[]", "null", "true", "1", "\"success\"",
                "{\"success\":true}", "{\"message\":\"success\"}", "{\"result\":{\"data\":[\"success\"]}}",
                "{\"Data\":[\"success\"]}", "{\"ERROR\":[\"failure\"]}"}) assertUnconfirmed(result(payload));
    }

    @Test public void absentEmptyAndOrdinaryHtmlResponsesAreUnconfirmed() {
        for (String input : new String[]{"", " ", "success", "<html><body>登录成功</body></html>",
                "<div data-status='success'>success</div>", "<script></script>",
                "<!--" + PREFIX + data("success") + "-->", "<pre>" + PREFIX + data("success") + "</pre>"})
            assertUnconfirmed(html(input));
        assertUnconfirmed(NgaQrLoginResult.parse(null));
        assertUnconfirmed(NgaQrLoginResult.unconfirmed());
    }

    @Test public void requiresExactObservedAssignmentVariable() {
        for (String prefix : new String[]{"script_muti_get_var_store=", "window.script_multi_get_var_store=",
                "window.script_muti_get_var_store =", "window['script_muti_get_var_store']=",
                "var script_muti_get_var_store=", "window.data=", "parent.script_muti_get_var_store=",
                "/* comment */" + PREFIX, "// comment\n" + PREFIX, "var unrelated=1;" + PREFIX}) {
            assertUnconfirmed(script(prefix + data("success")));
        }
    }

    @Test public void rejectsMultipleExternalAndSpoofedScriptElements() {
        String validScript = "<script>" + PREFIX + data("success") + "</script>";
        assertUnconfirmed(html(validScript + "<script></script>"));
        assertUnconfirmed(html(validScript + validScript));
        assertUnconfirmed(html("<script src='https://evil.example/'>" + PREFIX + data("success") + "</script>"));
        assertUnconfirmed(html("<script src=''>" + PREFIX + data("success") + "</script>"));
        assertUnconfirmed(html("<!--" + validScript + "-->"));
        for (String element : new String[]{"<template></template>", "<iframe></iframe>", "<base href='/'>"})
            assertUnconfirmed(html(validScript + element));
        assertUnconfirmed(html("<template>" + validScript + "</template>"));
    }

    @Test public void rejectsTrailingJavascriptCommentsAndMultipleAssignments() {
        for (String suffix : new String[]{";alert('synthetic')", ";window.extra=true", ";;", "// comment",
                "/* comment */", ";" + PREFIX + data("success"), " {}", " []", ",{}", " garbage"}) {
            assertUnconfirmed(script(PREFIX + data("success") + suffix));
        }
    }

    @Test public void rejectsMalformedAndJavascriptLikeNonJson() {
        for (String payload : new String[]{"{", "}", "{\"data\":[\"success\"]", "{\"data\":[\"success\"}",
                "{data:[\"success\"]}", "{'data':['success']}", "{\"data\":[\"success\"],}",
                "{\"data\":[\"success\",]}", "{\"data\"=[\"success\"]}", "{\"data\":[success]}",
                "{\"data\":[\"success\"],/* comment */\"x\":1}", "{\"data\":[\"success\"],\"x\":NaN}",
                "{\"data\":[\"success\"],\"x\":Infinity}", "{\"data\":[\"success\"],\"x\":01}",
                "{\"data\":[\"success\"],\"x\":+1}", "{\"data\":[\"success\"],\"x\":undefined}",
                "{\"data\":[\"bad\\x41\"]}", "{\"data\":[\"bad\nnewline\"]}"}) {
            assertUnconfirmed(result(payload));
        }
    }

    @Test public void rejectsDuplicateMembersAtEveryDepth() {
        for (String payload : new String[]{
                "{\"data\":[\"success\"],\"data\":[\"failure\"]}",
                "{\"error\":null,\"error\":[\"failure\"],\"data\":[\"success\"]}",
                "{\"data\":{\"0\":\"success\",\"0\":\"failure\"}}",
                "{\"data\":[\"success\"],\"extra\":{\"same\":1,\"same\":2}}",
                "{\"data\":[\"success\"],\"d\\u0061ta\":[\"failure\"]}"
        }) assertUnconfirmed(result(payload));
    }

    @Test public void boundsJsonNestingAndPayloadSize() {
        assertUnconfirmed(result("{\"data\":[\"success\"],\"extra\":" + "[".repeat(18) + "0" + "]".repeat(18) + "}"));
        assertUnconfirmed(result("{\"data\":[\"success\"],\"extra\":\"" + "x".repeat(65536) + "\"}"));
        assertMessage(NgaQrLoginResult.Kind.SERVER_MESSAGE, "Synthetic message",
                result("{\"data\":[\"Synthetic message\"],\"extra\":[[{\"a\":1}]]}"));
    }

    @Test public void rejectsBlankAndOversizedMessages() {
        for (String message : new String[]{"", " ", "\n\t ", "x".repeat(1001)}) {
            assertUnconfirmed(result(data(message)));
            assertUnconfirmed(result("{\"error\":[" + JSONObject.quote(message) + "]}"));
        }
        assertMessage(NgaQrLoginResult.Kind.SERVER_MESSAGE, "x".repeat(1000), result(data("x".repeat(1000))));
    }

    @Test public void rejectsControlCharactersAndBidiOverridesInsideMessages() {
        for (char control : new char[]{0, 1, 8, 11, 12, 13, 27, 127, 0x85, 0x202d, 0x202e}) {
            assertUnconfirmed(result(data("before" + control + "after")));
        }
    }

    @Test public void redactsCredentialOrQrKeyEchoesInsteadOfDisplayingThem() {
        String token = "SyntheticCookieToken";
        String key = "SyntheticQrKey";
        for (String message : new String[]{"Server echoed " + token, "Server echoed " + key, token + key}) {
            assertUnconfirmed(result(data(message)).hideSecrets(token, key));
            assertUnconfirmed(result("{\"error\":[" + JSONObject.quote(message) + "]}").hideSecrets(token, key));
        }
        NgaQrLoginResult safe = result(data("Safe synthetic message"));
        assertSame(safe, safe.hideSecrets(token, key));
    }

    @Test public void diagnosticsNeverEchoServerMessageContents() {
        String privateValue = "SyntheticPotentialSecret";
        for (NgaQrLoginResult result : new NgaQrLoginResult[]{result(data(privateValue)),
                result("{\"error\":[" + JSONObject.quote(privateValue) + "]}"), NgaQrLoginResult.unconfirmed()}) {
            assertFalse(result.toString().contains(privateValue));
        }
    }

    private static String data(String message) {
        return "{\"data\":[" + JSONObject.quote(message) + "]}";
    }

    private static NgaQrLoginResult result(String payload) {
        return script(PREFIX + payload);
    }

    private static NgaQrLoginResult script(String content) {
        return html("<html><body><script>" + content + "</script></body></html>");
    }

    private static NgaQrLoginResult html(String content) {
        return NgaQrLoginResult.parse(Jsoup.parse(content));
    }

    private static void assertMessage(NgaQrLoginResult.Kind kind, String message, NgaQrLoginResult actual) {
        assertEquals(kind, actual.kind);
        assertEquals(message, actual.message);
    }

    private static void assertUnconfirmed(NgaQrLoginResult actual) {
        assertMessage(NgaQrLoginResult.Kind.UNCONFIRMED, "", actual);
    }
}

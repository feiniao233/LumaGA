package com.bugenzhao.mnga.auth;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static com.bugenzhao.mnga.auth.NgaQrDiagnostic.*;
import static org.junit.Assert.*;

/** Classifies rejections only; accepted authenticated forms remain synthetic. */
public class NgaQrLoginFormDiagnosticTest {
    private static final String KEY = "SyntheticQrSecretForDiagnostics0123";
    private static final String SECRET = "SyntheticHiddenSecretNeverLog_9876";
    private static final String UI = "https://bbs.nga.cn/nuke.php?__lib=login&__act=qrlogin_ui&qrkey=" + KEY;
    private static final String ACTION = "/nuke.php?__lib=login&__act=qrlogin_allow&raw=3";
    private static final String INPUT = "<input type='hidden' id='qrkey' name='qrkey' value=''>";
    private static final String SUBMIT = "<a id='loginsubmit' onclick='loginSubmit(this)'>Authorize</a>";
    private static final String NOTICE = "<div class='invertblock'>你没有在这台设备上登录</div>";
    private static final NgaQrLoginTarget TARGET = NgaQrLoginTarget.parse(UI);

    @Test public void observedLoggedOutFixtureHasSpecificSafeDiagnostic() throws IOException {
        try (InputStream input = getClass().getResourceAsStream("/qr/official-qrlogin-ui-logged-out.html")) {
            assertNotNull(input);
            expect(LOGIN_NOT_RECOGNIZED, new String(input.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    @Test public void exactVisibleOwnTextOnValidatedFormWithAbsentMarkersIsRecognized() {
        expect(LOGIN_NOT_RECOGNIZED, form(NOTICE));
        expect(LOGIN_NOT_RECOGNIZED, form(NOTICE.replace("class='invertblock'", "class='extra invertblock'")));
    }

    @Test public void missingMarkersNearMatchesAndNestedTextDoNotProveLoggedOut() {
        for (String content : new String[]{"", "你没有在这台设备上登录", "<p>你没有在这台设备上登录</p>",
                NOTICE.replace("登录", "登录。"), NOTICE.replace("你没有", "您没有"),
                NOTICE.replace("你没有", "提示：你没有"),
                "<div class='invertblock'><span>你没有在这台设备上登录</span></div>",
                "<div class='invertblock'>请先登录</div>"}) expect(KEY_MARKER, form(content));
        expect(KEY_MARKER, NOTICE + form(""));
        expect(KEY_MARKER, form(NOTICE + SUBMIT));
        expect(SUBMIT_MARKER, form(NOTICE + INPUT));
    }

    @Test public void hiddenNoticeOrHiddenAncestorNeverReceivesLoggedOutHint() {
        for (String attribute : new String[]{"hidden", "inert", "style='display: none'", "style='visibility: hidden'",
                "style=' DISPLAY : NONE '", "style='Visibility : Hidden'"}) {
            expect(KEY_MARKER, form(NOTICE.replace("class='invertblock'", "class='invertblock' " + attribute)));
            expect(KEY_MARKER, "<div " + attribute + ">" + form(NOTICE) + "</div>");
            expect(KEY_MARKER, form(NOTICE).replace("id='loginform'", "id='loginform' " + attribute));
        }
    }

    @Test public void wrongRouteWrongFormAndChallengeOrScriptCannotImpersonateTheObservedPage() {
        expect(FORM_ACTION, form(NOTICE).replace(ACTION, ACTION.replace("qrlogin_allow", "qrlogin_ui")));
        expect(FORM_ACTION, form(NOTICE).replace(ACTION, "https://evil.example/" + SECRET));
        expect(FORM_MISSING, form(NOTICE).replace("id='loginform'", "id='other'"));
        expect(FORM_METHOD, form(NOTICE).replace("method='post'", "method='get'"));
        expect(FORM_CONTEXT, "<template>" + form(NOTICE) + "</template>");
        expect(FORM_AMBIGUOUS, form(NOTICE) + "<form></form>");
        for (String content : new String[]{"<input name='captcha'>", "<!--" + NOTICE + "-->",
                "<script>var message='你没有在这台设备上登录';</script>",
                "<script class='invertblock'>你没有在这台设备上登录</script>",
                "<script>var markup=\"" + NOTICE + "\";</script>"}) expect(KEY_MARKER, form(content));
        expect(CHALLENGE_CONTROL, form(INPUT + "<input name='captcha'>" + SUBMIT));
    }

    @Test public void structuralAndSubmissionPolicyFailuresKeepSeparateCodes() {
        String good = form(INPUT + SUBMIT);
        expect(FORM_MISSING, "<div>" + SECRET + "</div>");
        expect(FORM_MISSING, good.replace("id='loginform'", "id='other'"));
        expect(FORM_AMBIGUOUS, good + "<form></form>");
        expect(FORM_AMBIGUOUS, good + "<div id='loginform'></div>");
        expect(FORM_AMBIGUOUS, good + "<div id='qrkey'></div>");
        expect(FORM_AMBIGUOUS, good + "<div id='loginsubmit'></div>");
        for (String markup : new String[]{"<base href='https://evil.example/'>", "<template></template>",
                "<noscript></noscript>", "<button form='loginform'>x</button>",
                "<button formaction='https://evil.example/'>x</button>", "<button formmethod='get'>x</button>",
                "<button formenctype='text/plain'>x</button>"}) expect(FORM_CONTEXT, good + markup);
        for (String method : new String[]{"get", "post ", ""})
            expect(FORM_METHOD, good.replace("method='post'", "method='" + method + "'"));
        expect(FORM_METHOD, good.replace("method='post'", ""));
        for (String charset : new String[]{"UTF-16", "unknown-charset", "UTF-8 GBK", ""})
            expect(FORM_ENCODING, good.replace("method='post'", "method='post' accept-charset='" + charset + "'"));
        expect(FORM_ENCODING, good.replace("method='post'", "method='post' enctype='multipart/form-data'"));
        expect(FORM_TARGET, good.replace("method='post'", "method='post' target='_blank'"));
        String frame = "<iframe id='loginframe' name='loginframe'></iframe>";
        expect(FORM_FRAME, good + frame + frame);
        expect(FORM_FRAME, good + frame.replace("id='loginframe'", "id='other'"));
        expect(FORM_FRAME, good + frame.replace("name='loginframe'", "name='other'"));
        expect(FORM_FRAME, good + frame.replace("name='loginframe'", "name='loginframe' src=''"));
        expect(FORM_FRAME, good + frame.replace("name='loginframe'", "name='loginframe' srcdoc=''"));
        for (String action : new String[]{"/nuke.php?raw=2", "javascript:" + SECRET,
                "https://evil.example/" + SECRET, "https://[" + SECRET, ""})
            expect(FORM_ACTION, good.replace(ACTION, action));
    }

    @Test public void markersAndSubmitControlFailuresKeepSeparateCodes() {
        expect(KEY_MARKER, form(SUBMIT));
        expect(SUBMIT_MARKER, form(INPUT));
        expect(KEY_INPUT, INPUT + form(SUBMIT));
        expect(KEY_INPUT, form("<div id='qrkey'></div>" + SUBMIT));
        expect(KEY_INPUT, form(INPUT.replace("name='qrkey'", "name='other'") + SUBMIT));
        expect(KEY_INPUT, form(INPUT.replace("type='hidden'", "type='text'") + SUBMIT));
        expect(SUBMIT_CONTROL, form(INPUT) + SUBMIT);
        expect(SUBMIT_CONTROL, form(INPUT + SUBMIT.replace("id='loginsubmit'", "id='loginsubmit' disabled")));
        expect(SUBMIT_CONTROL, form(INPUT + "<script id='loginsubmit'></script>"));
        expect(SUBMIT_CONTROL, form(INPUT + "<input id='loginsubmit' type='hidden'>"));
        expect(SUBMIT_VISIBILITY, form(INPUT + SUBMIT.replace("id='loginsubmit'", "id='loginsubmit' hidden")));
        expect(SUBMIT_VISIBILITY, form(INPUT + "<div inert>" + SUBMIT + "</div>"));
        expect(SUBMIT_VISIBILITY, form(INPUT + SUBMIT).replace("id='loginform'", "id='loginform' style='display:none'"));
        for (String handler : new String[]{"", "loginSubmit()", "loginSubmit(this);" + SECRET})
            expect(SUBMIT_HOOK, form(INPUT + SUBMIT.replace("loginSubmit(this)", handler)));
    }

    @Test public void inertEventsCannotBypassSubmissionChallengeOrHiddenFieldChecks() {
        String good = form(INPUT + SUBMIT).replace("method='post'", "method='post' onsubmit='return false'");
        expect(SUBMIT_HOOK, good.replace("loginSubmit(this)", SECRET));
        expect(FORM_ACTION, good.replace(ACTION, "https://evil.example/" + SECRET));
        expect(FORM_CONTEXT, good.replace("id='loginsubmit'", "id='loginsubmit' formaction='https://evil.example/'"));
        expect(KEY_MISMATCH, good.replace("value=''", "value='" + SECRET + "'"));
        for (String control : new String[]{"<input type='text' name='captcha'>", "<textarea></textarea>",
                "<select></select>", "<div contenteditable></div>"})
            expect(CHALLENGE_CONTROL, good.replace(SUBMIT, control + SUBMIT));
        expect(FIELD_STATE, good.replace("type='hidden'", "type='hidden' required onfocus='" + SECRET + "'"));
        expect(FIELD_NAME, good.replace(SUBMIT, hidden("bad-name", SECRET) + SUBMIT));
        expect(RESERVED_FIELD, good.replace(SUBMIT, hidden("access_token", SECRET) + SUBMIT));
        expect(DUPLICATE_FIELD, good.replace(SUBMIT, hidden("qrkey", "") + SUBMIT));
        expect(FIELD_LIMIT, good.replace(SUBMIT, hidden("csrf", SECRET + "x".repeat(4097)) + SUBMIT));
    }

    @Test public void challengeAndFieldPolicyFailuresKeepSeparateCodes() {
        for (String control : new String[]{"<select></select>", "<textarea></textarea>", "<fieldset disabled></fieldset>",
                "<div contenteditable></div>", "<object></object>", "<input type='text' name='captcha'>"})
            expect(CHALLENGE_CONTROL, form(INPUT + control + SUBMIT));
        for (String attribute : new String[]{"disabled", "required"})
            expect(FIELD_STATE, form(INPUT + hidden("csrf", SECRET).replace("type='hidden'", "type='hidden' " + attribute) + SUBMIT));
        expect(FIELD_NAME, form(INPUT + "<button name='confirm'>Authorize</button>" + SUBMIT));
        for (String name : new String[]{"", "9name", "csrf-token", "a".repeat(65)})
            expect(FIELD_NAME, form(INPUT + hidden(name, SECRET) + SUBMIT));
        for (String name : new String[]{"QRKEY", "__lib", "__ACT", "RAW", "Access_Token", "NGAPASSPORTCID", "cookie"})
            expect(RESERVED_FIELD, form(INPUT + hidden(name, SECRET) + SUBMIT));
        expect(DUPLICATE_FIELD, form(INPUT + hidden("csrf", SECRET) + hidden("csrf", SECRET) + SUBMIT));
        expect(KEY_MISMATCH, form(INPUT.replace("value=''", "value='" + SECRET + "'") + SUBMIT));
    }

    @Test public void everySizeLimitUsesTheSameFixedCodeAndDoesNotEchoTheValue() {
        expect(FIELD_LIMIT, form(INPUT + hidden("csrf", SECRET + "x".repeat(4097)) + SUBMIT));
        Document nul = Jsoup.parse(form(INPUT + hidden("csrf", SECRET) + SUBMIT), UI);
        nul.selectFirst("input[name=csrf]").attr("value", SECRET + "\0tail");
        expect(FIELD_LIMIT, nul);
        StringBuilder fields = new StringBuilder(INPUT);
        for (int i = 0; i < 32; i++) fields.append(hidden("f" + i, SECRET));
        expect(FIELD_LIMIT, form(fields + SUBMIT));
        fields = new StringBuilder(INPUT);
        for (int i = 0; i < 4; i++) fields.append(hidden("f" + i, "x".repeat(4096)));
        expect(FIELD_LIMIT, form(fields + SUBMIT));
    }

    @Test public void validSyntheticFormStillPreservesFieldsWithoutLeakingToString() {
        NgaQrLoginForm parsed = NgaQrLoginForm.parse(Jsoup.parse(form(INPUT + hidden("csrf", SECRET) + SUBMIT), UI), TARGET);
        assertEquals(KEY, parsed.fields.get("qrkey"));
        assertEquals(SECRET, parsed.fields.get("csrf"));
        assertEquals("NgaQrLoginForm([redacted])", parsed.toString());
        assertThrows(UnsupportedOperationException.class, () -> parsed.fields.put("csrf", "changed"));
    }

    private static String form(String content) {
        return "<form id='loginform' method='post' action='" + ACTION + "'>" + content + "</form>";
    }
    private static String hidden(String name, String value) {
        return "<input type='hidden' name='" + name + "' value='" + value + "'>";
    }
    private static void expect(NgaQrDiagnostic diagnostic, String html) {
        expect(diagnostic, Jsoup.parse(html, UI));
    }
    private static void expect(NgaQrDiagnostic diagnostic, Document page) {
        NgaQrDiagnostic.ParseFailure failure = assertThrows(NgaQrDiagnostic.ParseFailure.class,
                () -> NgaQrLoginForm.parse(page, TARGET));
        assertSame(diagnostic, failure.diagnostic);
        assertSame(diagnostic, NgaQrDiagnostic.from(failure));
        assertEquals("NGA QR diagnostic: " + diagnostic.code, failure.getMessage());
        assertFalse(failure.toString().contains(KEY));
        assertFalse(failure.toString().contains(SECRET));
        assertFalse(failure.toString().contains("你没有在这台设备上登录"));
        assertNull(failure.getCause());
        assertEquals(0, failure.getSuppressed().length);
    }
}

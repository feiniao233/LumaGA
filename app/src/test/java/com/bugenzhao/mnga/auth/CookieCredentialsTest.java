package com.bugenzhao.mnga.auth;

import org.junit.Test;
import static org.junit.Assert.*;

public class CookieCredentialsTest {
    @Test public void parsesHeaderWithoutDecodingToken() {
        CookieCredentials c = CookieCredentials.fromCookieHeader(
            "Cookie: other=discard; ngaPassportCid=synthetic%2Btoken==; ngaPassportUid=12345");
        assertEquals("12345", c.uid);
        assertEquals("synthetic%2Btoken==", c.cid);
        assertFalse(c.toString().contains(c.cid));
    }
    @Test public void parsesNewlinePairsAndFields() {
        assertEquals("test-token", CookieCredentials.fromCookieHeader(
            "ngaPassportUid=12345\r\nngaPassportCid=test-token").cid);
        assertEquals("12345", CookieCredentials.fromFields(" 12345 ", " test-token ").uid);
    }
    @Test public void rejectsInvalidAndAmbiguousInput() {
        String[] inputs = {"", "ngaPassportUid=12345", "ngaPassportCid=test-token",
            "ngaPassportUid=0; ngaPassportCid=test-token",
            "ngaPassportUid=-1; ngaPassportCid=test-token",
            "ngaPassportUid=１２３; ngaPassportCid=test-token",
            "ngaPassportUid=12345; ngaPassportCid=",
            "ngaPassportUid=12345; ngaPassportCid=test token",
            "ngaPassportUid=12345; ngaPassportCid=one; ngaPassportCid=two"};
        for (String input : inputs) assertThrows(IllegalArgumentException.class,
            () -> CookieCredentials.fromCookieHeader(input));
        for (String token : new String[]{"x\r\nInjected:yes", "x;other=value", "x\\y", "x\"y", "x,y"}) {
            assertThrows(IllegalArgumentException.class, () -> CookieCredentials.fromFields("12345", token));
        }
    }
    @Test public void boundsInput() {
        assertThrows(IllegalArgumentException.class,
            () -> CookieCredentials.fromCookieHeader("x".repeat(16385)));
        assertThrows(IllegalArgumentException.class,
            () -> CookieCredentials.fromFields("12345", "x".repeat(4097)));
    }
}

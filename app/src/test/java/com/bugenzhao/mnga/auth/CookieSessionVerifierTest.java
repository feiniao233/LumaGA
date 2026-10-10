package com.bugenzhao.mnga.auth;

import org.junit.Test;
import static org.junit.Assert.*;

public class CookieSessionVerifierTest {
    @Test public void requiresAuthenticatedVisitorMatchingUid() {
        assertTrue(CookieSessionVerifier.isAuthenticatedResponse("{\"data\":{\"__CU\":{\"uid\":12345}}}", "12345"));
        assertTrue(CookieSessionVerifier.isAuthenticatedResponse("{\"data\":{\"__CU\":{\"uid\":\"12345\"}}}", "12345"));
    }
    @Test public void rejectsGuestMismatchErrorsAndUnexpectedResponses() {
        String[] responses = {"", "<html>Sign in</html>", "{}", "{\"data\":{}}",
            "{\"data\":{\"__CU\":{\"uid\":0}}}",
            "{\"data\":{\"__CU\":{\"uid\":99999}}}",
            "{\"data\":{\"uid\":12345}}",
            "{\"error\":[\"not logged in\"],\"data\":{\"__CU\":{\"uid\":12345}}}",
            "{\"data\":{\"__MESSAGE\":\"error\",\"__CU\":{\"uid\":12345}}}"};
        for (String response : responses) assertFalse(CookieSessionVerifier.isAuthenticatedResponse(response, "12345"));
    }
}

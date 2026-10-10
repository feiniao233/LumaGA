package com.bugenzhao.mnga.auth;

import org.junit.Test;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.Set;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

import static org.junit.Assert.*;

/** Stable, local-only identifiers must never be derived from remote text or credentials. */
public class NgaQrDiagnosticTest {
    private static final String SECRET = "SyntheticTokenNeverDisplay_012345";
    private static final String[] CONTRACT = {
            "UNKNOWN QR-X00 UNKNOWN", "CREDENTIALS_INVALID QR-C01 CREDENTIALS",
            "CANCELED QR-C02 CANCELED", "ATTEMPT_USED QR-C03 CANCELED", "REQUEST_STATE QR-C04 CANCELED",
            "NETWORK_TIMEOUT QR-N01 NETWORK", "NETWORK_DNS QR-N02 NETWORK", "NETWORK_TLS QR-N03 NETWORK",
            "NETWORK_IO QR-N04 NETWORK", "HTTP_REDIRECT QR-H01 HTTP", "HTTP_ERROR QR-H02 HTTP",
            "DESTINATION QR-H03 HTTP", "RESPONSE_TYPE QR-R01 RESPONSE", "RESPONSE_SIZE QR-R02 RESPONSE",
            "RESPONSE_EMPTY QR-R03 RESPONSE", "RESPONSE_CHARSET QR-R04 RESPONSE", "RESPONSE_HTML QR-R05 RESPONSE",
            "RESULT_ENVELOPE QR-R06 RESPONSE", "RESULT_JSON QR-R07 RESPONSE", "RESULT_VALUE QR-R08 RESPONSE",
            "RESULT_REDACTED QR-R09 RESPONSE", "FORM_MISSING QR-F00 FORM", "FORM_AMBIGUOUS QR-F01 FORM",
            "FORM_CONTEXT QR-F02 FORM", "FORM_METHOD QR-F03 FORM", "FORM_ENCODING QR-F04 FORM",
            "FORM_TARGET QR-F05 FORM", "FORM_FRAME QR-F06 FORM", "FORM_ACTION QR-F07 FORM",
            "LOGIN_NOT_RECOGNIZED QR-F08 LOGGED_OUT", "KEY_MARKER QR-F09 FORM", "SUBMIT_MARKER QR-F10 FORM",
            "KEY_INPUT QR-F11 FORM", "SUBMIT_CONTROL QR-F12 FORM", "SUBMIT_VISIBILITY QR-F13 FORM",
            "SUBMIT_HOOK QR-F14 FORM", "FORM_EVENT QR-F15 FORM", "CHALLENGE_CONTROL QR-F16 FORM",
            "FIELD_STATE QR-F17 FORM", "FIELD_NAME QR-F18 FORM", "RESERVED_FIELD QR-F19 FORM",
            "DUPLICATE_FIELD QR-F20 FORM", "FIELD_LIMIT QR-F21 FORM", "KEY_MISMATCH QR-F22 FORM"
    };

    @Test public void everyIdentifierAndHintMatchesTheStableContract() {
        assertEquals(CONTRACT.length, NgaQrDiagnostic.values().length);
        Set<NgaQrDiagnostic> diagnostics = new HashSet<>();
        Set<String> codes = new HashSet<>();
        for (String row : CONTRACT) {
            String[] cells = row.split(" ");
            NgaQrDiagnostic diagnostic = NgaQrDiagnostic.valueOf(cells[0]);
            assertTrue(diagnostics.add(diagnostic));
            assertTrue(codes.add(diagnostic.code));
            assertTrue(diagnostic.code.matches("QR-[CNHRFX][0-9]{2}"));
            assertEquals(cells[1], diagnostic.code);
            assertEquals(cells[2], diagnostic.hint.name());
        }
    }

    @Test public void everyParseAndRequestFailureContainsOnlyItsFixedIdentifier() {
        for (NgaQrDiagnostic diagnostic : NgaQrDiagnostic.values()) {
            NgaQrDiagnostic.ParseFailure parse = diagnostic.parseFailure();
            NgaQrDiagnostic.RequestFailure request = diagnostic.requestFailure();
            assertSame(diagnostic, parse.diagnostic);
            assertSame(diagnostic, request.diagnostic);
            assertSame(diagnostic, NgaQrDiagnostic.from(parse));
            assertSame(diagnostic, NgaQrDiagnostic.from(request));
            assertSafe(parse, diagnostic);
            assertSafe(request, diagnostic);
        }
    }

    @Test public void mapsTransportTypesWithoutDependingOnPotentiallySecretMessages() {
        assertMapped(new SocketTimeoutException(SECRET), NgaQrDiagnostic.NETWORK_TIMEOUT);
        assertMapped(new InterruptedIOException(SECRET), NgaQrDiagnostic.NETWORK_TIMEOUT);
        assertMapped(new UnknownHostException(SECRET), NgaQrDiagnostic.NETWORK_DNS);
        assertMapped(new SSLException(SECRET), NgaQrDiagnostic.NETWORK_TLS);
        assertMapped(new SSLHandshakeException(SECRET), NgaQrDiagnostic.NETWORK_TLS);
        assertMapped(new IOException(SECRET), NgaQrDiagnostic.NETWORK_IO);
        assertMapped(new IllegalArgumentException(SECRET), NgaQrDiagnostic.UNKNOWN);
        assertMapped(new RuntimeException(SECRET), NgaQrDiagnostic.UNKNOWN);
        assertEquals(NgaQrDiagnostic.UNKNOWN, NgaQrDiagnostic.from(null));
    }

    @Test public void exceptionTextCannotImpersonateACodeOrAUsefulTransportSubtype() {
        for (NgaQrDiagnostic diagnostic : NgaQrDiagnostic.values()) {
            assertEquals(NgaQrDiagnostic.UNKNOWN,
                    NgaQrDiagnostic.from(new RuntimeException(diagnostic.code + " " + SECRET)));
        }
        assertEquals(NgaQrDiagnostic.NETWORK_IO,
                NgaQrDiagnostic.from(new IOException("timeout SSL UnknownHost " + SECRET)));
        assertEquals(NgaQrDiagnostic.UNKNOWN,
                NgaQrDiagnostic.from(new RuntimeException(new UnknownHostException(SECRET))));
    }

    private static void assertMapped(Throwable raw, NgaQrDiagnostic expected) {
        raw.addSuppressed(new IOException("Suppressed " + SECRET));
        assertSame(expected, NgaQrDiagnostic.from(raw));
        assertSafe(NgaQrDiagnostic.from(raw).requestFailure(), expected);
        assertSafe(NgaQrDiagnostic.from(raw).parseFailure(), expected);
    }

    private static void assertSafe(Throwable error, NgaQrDiagnostic expected) {
        assertEquals("NGA QR diagnostic: " + expected.code, error.getMessage());
        assertFalse(error.toString().contains(SECRET));
        assertFalse(error.getMessage().contains(SECRET));
        assertNull(error.getCause());
        assertEquals(0, error.getSuppressed().length);
    }
}

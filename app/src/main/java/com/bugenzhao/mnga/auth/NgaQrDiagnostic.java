package com.bugenzhao.mnga.auth;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.UnknownHostException;
import javax.net.ssl.SSLException;

/** Fixed, local-only diagnostics. Never interpolate server data or retain throwable causes. */
public enum NgaQrDiagnostic {
    UNKNOWN("QR-X00", Hint.UNKNOWN),
    CREDENTIALS_INVALID("QR-C01", Hint.CREDENTIALS),
    CANCELED("QR-C02", Hint.CANCELED),
    ATTEMPT_USED("QR-C03", Hint.CANCELED),
    REQUEST_STATE("QR-C04", Hint.CANCELED),
    NETWORK_TIMEOUT("QR-N01", Hint.NETWORK),
    NETWORK_DNS("QR-N02", Hint.NETWORK),
    NETWORK_TLS("QR-N03", Hint.NETWORK),
    NETWORK_IO("QR-N04", Hint.NETWORK),
    HTTP_REDIRECT("QR-H01", Hint.HTTP),
    HTTP_ERROR("QR-H02", Hint.HTTP),
    DESTINATION("QR-H03", Hint.HTTP),
    RESPONSE_TYPE("QR-R01", Hint.RESPONSE),
    RESPONSE_SIZE("QR-R02", Hint.RESPONSE),
    RESPONSE_EMPTY("QR-R03", Hint.RESPONSE),
    RESPONSE_CHARSET("QR-R04", Hint.RESPONSE),
    RESPONSE_HTML("QR-R05", Hint.RESPONSE),
    RESULT_ENVELOPE("QR-R06", Hint.RESPONSE),
    RESULT_JSON("QR-R07", Hint.RESPONSE),
    RESULT_VALUE("QR-R08", Hint.RESPONSE),
    RESULT_REDACTED("QR-R09", Hint.RESPONSE),
    FORM_MISSING("QR-F00", Hint.FORM),
    FORM_AMBIGUOUS("QR-F01", Hint.FORM),
    FORM_CONTEXT("QR-F02", Hint.FORM),
    FORM_METHOD("QR-F03", Hint.FORM),
    FORM_ENCODING("QR-F04", Hint.FORM),
    FORM_TARGET("QR-F05", Hint.FORM),
    FORM_FRAME("QR-F06", Hint.FORM),
    FORM_ACTION("QR-F07", Hint.FORM),
    LOGIN_NOT_RECOGNIZED("QR-F08", Hint.LOGGED_OUT),
    KEY_MARKER("QR-F09", Hint.FORM),
    SUBMIT_MARKER("QR-F10", Hint.FORM),
    KEY_INPUT("QR-F11", Hint.FORM),
    SUBMIT_CONTROL("QR-F12", Hint.FORM),
    SUBMIT_VISIBILITY("QR-F13", Hint.FORM),
    SUBMIT_HOOK("QR-F14", Hint.FORM),
    FORM_EVENT("QR-F15", Hint.FORM),
    CHALLENGE_CONTROL("QR-F16", Hint.FORM),
    FIELD_STATE("QR-F17", Hint.FORM),
    FIELD_NAME("QR-F18", Hint.FORM),
    RESERVED_FIELD("QR-F19", Hint.FORM),
    DUPLICATE_FIELD("QR-F20", Hint.FORM),
    FIELD_LIMIT("QR-F21", Hint.FORM),
    KEY_MISMATCH("QR-F22", Hint.FORM);

    public enum Hint { UNKNOWN, CREDENTIALS, CANCELED, NETWORK, HTTP, RESPONSE, FORM, LOGGED_OUT }
    public final String code;
    public final Hint hint;
    NgaQrDiagnostic(String code, Hint hint) { this.code = code; this.hint = hint; }

    public static NgaQrDiagnostic from(Throwable error) {
        if (error instanceof ParseFailure) return ((ParseFailure) error).diagnostic;
        if (error instanceof RequestFailure) return ((RequestFailure) error).diagnostic;
        if (error instanceof SSLException) return NETWORK_TLS;
        if (error instanceof UnknownHostException) return NETWORK_DNS;
        if (error instanceof InterruptedIOException) return NETWORK_TIMEOUT;
        if (error instanceof IOException) return NETWORK_IO;
        return UNKNOWN;
    }

    public ParseFailure parseFailure() { return new ParseFailure(this); }
    public RequestFailure requestFailure() { return new RequestFailure(this); }

    public static final class ParseFailure extends IllegalArgumentException {
        public final NgaQrDiagnostic diagnostic;
        private ParseFailure(NgaQrDiagnostic diagnostic) {
            super("NGA QR diagnostic: " + diagnostic.code, null);
            this.diagnostic = diagnostic;
        }
    }

    public static final class RequestFailure extends IOException {
        public final NgaQrDiagnostic diagnostic;
        private RequestFailure(NgaQrDiagnostic diagnostic) {
            super("NGA QR diagnostic: " + diagnostic.code, null);
            this.diagnostic = diagnostic;
        }
    }
}

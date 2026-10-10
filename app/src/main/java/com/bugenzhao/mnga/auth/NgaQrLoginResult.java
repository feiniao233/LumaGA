package com.bugenzhao.mnga.auth;

import static com.bugenzhao.mnga.auth.NgaQrDiagnostic.*;

import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import java.io.StringReader;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

/** A server message is not proof that the computer completed sign-in. */
public final class NgaQrLoginResult {
    public enum Kind { SERVER_MESSAGE, SERVER_ERROR, UNCONFIRMED }
    public final Kind kind;
    public final String message;

    public final NgaQrDiagnostic diagnostic;

    private NgaQrLoginResult(Kind kind, String message, NgaQrDiagnostic diagnostic) {
        this.kind = kind; this.message = message; this.diagnostic = diagnostic;
    }
    public static NgaQrLoginResult unconfirmed() { return unconfirmed(UNKNOWN); }
    public static NgaQrLoginResult unconfirmed(NgaQrDiagnostic diagnostic) {
        return new NgaQrLoginResult(Kind.UNCONFIRMED, "", diagnostic == null ? UNKNOWN : diagnostic);
    }

    public static NgaQrLoginResult parse(Document document) {
        try {
            // raw=3's observed envelope is a single assignment to this exact variable.
            // Do not execute JS or search arbitrary HTML for words such as "success".
            if (document.select("script").size() != 1 || !document.select("template, iframe, base").isEmpty()) return unconfirmed(RESULT_ENVELOPE);
            Element script = document.selectFirst("script");
            if (script == null || script.hasAttr("src")) return unconfirmed(RESULT_ENVELOPE);
            String text = script.data().trim();
            String prefix = "window.script_muti_get_var_store=";
            if (!text.startsWith(prefix)) return unconfirmed(RESULT_ENVELOPE);
            String payload = text.substring(prefix.length()).trim();
            if (payload.endsWith(";")) payload = payload.substring(0, payload.length() - 1).trim();
            if (!payload.startsWith("{") || !payload.endsWith("}")) return unconfirmed(RESULT_ENVELOPE);
            if (payload.length() > 65536) return unconfirmed(RESPONSE_SIZE);
            try (JsonReader reader = new JsonReader(new StringReader(payload))) {
                reader.setStrictness(Strictness.STRICT);
                validateJson(reader, 0);
                if (reader.peek() != JsonToken.END_DOCUMENT) return unconfirmed(RESULT_JSON);
            }
            JSONTokener tokener = new JSONTokener(payload);
            Object parsed = tokener.nextValue();
            if (!(parsed instanceof JSONObject) || tokener.nextClean() != 0) return unconfirmed(RESULT_JSON);
            JSONObject object = (JSONObject) parsed;
            // Never let a data message hide any error member, including malformed errors.
            boolean error = object.has("error");
            Object container = object.opt(error ? "error" : "data");
            Object first = container instanceof JSONObject ? ((JSONObject) container).opt("0")
                    : container instanceof JSONArray ? ((JSONArray) container).opt(0) : null;
            if (!(first instanceof String)) return unconfirmed(RESULT_VALUE);
            String message = ((String) first).trim();
            if (message.isEmpty() || message.length() > 1000) return unconfirmed(RESULT_VALUE);
            for (int i = 0; i < message.length(); i++) {
                char c = message.charAt(i);
                if ((Character.isISOControl(c) && c != '\n' && c != '\t') || c == '\u202e' || c == '\u202d') return unconfirmed(RESULT_VALUE);
            }
            return new NgaQrLoginResult(error ? Kind.SERVER_ERROR : Kind.SERVER_MESSAGE, message, null);
        } catch (Exception ignored) { return unconfirmed(RESULT_JSON); }
    }

    private static void validateJson(JsonReader reader, int depth) throws IOException {
        if (depth > 16) throw new IOException("Unsupported response nesting");
        switch (reader.peek()) {
            case BEGIN_OBJECT:
                reader.beginObject();
                Set<String> names = new HashSet<>();
                while (reader.hasNext()) {
                    if (!names.add(reader.nextName())) throw new IOException("Ambiguous response member");
                    validateJson(reader, depth + 1);
                }
                reader.endObject();
                break;
            case BEGIN_ARRAY:
                reader.beginArray();
                while (reader.hasNext()) validateJson(reader, depth + 1);
                reader.endArray();
                break;
            case STRING: case NUMBER: reader.nextString(); break;
            case BOOLEAN: reader.nextBoolean(); break;
            case NULL: reader.nextNull(); break;
            default: throw new IOException("Unsupported response value");
        }
    }

    NgaQrLoginResult hideSecrets(String token, String key) {
        // A server/proxy error must not echo the submitted credentials into the UI.
        if (message.contains(token) || message.contains(key)) return unconfirmed(RESULT_REDACTED);
        return this;
    }
    @Override public String toString() { return "NgaQrLoginResult(" + kind + ", [redacted])"; }
}

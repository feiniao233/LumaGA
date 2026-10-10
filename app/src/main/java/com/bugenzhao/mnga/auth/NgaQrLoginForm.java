package com.bugenzhao.mnga.auth;

import static com.bugenzhao.mnga.auth.NgaQrDiagnostic.*;

import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.net.URI;
import java.nio.charset.Charset;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** Reads HTML as data only. No script, resource, or form URL is ever executed. */
public final class NgaQrLoginForm {
    final Map<String, String> fields;
    final Charset charset;

    private NgaQrLoginForm(Map<String, String> fields, Charset charset) {
        this.fields = Collections.unmodifiableMap(new LinkedHashMap<>(fields));
        this.charset = charset;
    }

    public static NgaQrLoginForm parse(Document document, NgaQrLoginTarget target) {
        if (!document.select("base, template, noscript, [form], [formaction], [formmethod], [formenctype]").isEmpty()) throw FORM_CONTEXT.parseFailure();
        if (document.select("form").size() > 1 || document.select("[id=loginform]").size() > 1) throw FORM_AMBIGUOUS.parseFailure();
        Element form = document.selectFirst("form#loginform");
        if (form == null || document.select("form").size() != 1) throw FORM_MISSING.parseFailure();
        if (!"post".equalsIgnoreCase(form.attr("method"))) throw FORM_METHOD.parseFailure();
        if (form.hasAttr("enctype") && !"application/x-www-form-urlencoded".equalsIgnoreCase(form.attr("enctype"))) throw FORM_ENCODING.parseFailure();
        Charset charset;
        try { charset = form.hasAttr("accept-charset") ? Charset.forName(form.attr("accept-charset")) : document.charset(); }
        catch (Exception ignored) { throw FORM_ENCODING.parseFailure(); }
        if (!(charset.name().equals("UTF-8") || charset.name().equals("GBK") || charset.name().equals("GB18030"))) throw FORM_ENCODING.parseFailure();
        if (form.hasAttr("target") && !form.attr("target").equals("loginframe")) throw FORM_TARGET.parseFailure();
        for (Element frame : document.select("iframe")) {
            if (!frame.id().equals("loginframe") || !frame.attr("name").equals("loginframe")
                    || frame.hasAttr("src") || frame.hasAttr("srcdoc")) throw FORM_FRAME.parseFailure();
        }
        if (document.select("iframe").size() > 1) throw FORM_FRAME.parseFailure();
        String action = form.attr("action");
        // Only root-relative or fully qualified, same-origin official actions are valid.
        if (!(action.startsWith("/nuke.php?") || action.startsWith("https://"))) throw FORM_ACTION.parseFailure();
        String absolute;
        try { absolute = new URI(target.url).resolve(action).toString(); }
        catch (Exception ignored) { throw FORM_ACTION.parseFailure(); }
        if (!target.allowsRequest(absolute, "POST", false)) throw FORM_ACTION.parseFailure();
        int keyMarkers = document.select("[id=qrkey]").size();
        int submitMarkers = document.select("[id=loginsubmit]").size();
        if (keyMarkers > 1 || submitMarkers > 1) throw FORM_AMBIGUOUS.parseFailure();
        // This exact visible message was observed in the official logged-out form.
        // Missing markers or a different message alone never prove a login problem.
        if (keyMarkers == 0 && submitMarkers == 0) {
            for (Element notice : form.select(".invertblock")) {
                if (notice.ownText().equals("你没有在这台设备上登录") && visible(notice)) throw LOGIN_NOT_RECOGNIZED.parseFailure();
            }
        }
        if (keyMarkers != 1) throw KEY_MARKER.parseFailure();
        if (submitMarkers != 1) throw SUBMIT_MARKER.parseFailure();
        Element key = form.selectFirst("input#qrkey");
        Element submit = form.selectFirst("#loginsubmit");
        if (key == null || !"qrkey".equals(key.attr("name"))
                || !"hidden".equalsIgnoreCase(key.attr("type"))) throw KEY_INPUT.parseFailure();
        if (submit == null || submit.hasAttr("disabled")) throw SUBMIT_CONTROL.parseFailure();
        if (submit.hasAttr("hidden")) throw SUBMIT_VISIBILITY.parseFailure();
        if (!(submit.tagName().equals("a") || submit.tagName().equals("button")
                || submit.tagName().equals("input") || submit.tagName().equals("div"))) throw SUBMIT_CONTROL.parseFailure();
        if (submit.tagName().equals("input") && !(submit.attr("type").equalsIgnoreCase("submit")
                || submit.attr("type").equalsIgnoreCase("button"))) throw SUBMIT_CONTROL.parseFailure();
        if (!visible(submit)) throw SUBMIT_VISIBILITY.parseFailure();
        String click = submit.attr("onclick").trim();
        if (!(click.equals("loginSubmit(this)") || click.equals("loginSubmit(this);"))) throw SUBMIT_HOOK.parseFailure();
        // Other event attributes are inert HTML data: never execute or serialize them.
        // Only validated hidden name/value pairs below can enter the fixed native POST.
        // These are the only non-hidden control types whose values can be omitted safely.
        if (!form.select("select, textarea, fieldset[disabled], [contenteditable], object").isEmpty()) throw CHALLENGE_CONTROL.parseFailure();
        Map<String, String> fields = new LinkedHashMap<>();
        int total = 0;
        for (Element control : form.select("input, button")) {
            String type = control.attr("type").toLowerCase(Locale.ROOT);
            String name = control.attr("name");
            if (control.hasAttr("disabled") || control.hasAttr("required")) throw FIELD_STATE.parseFailure();
            if (type.equals("button") || type.equals("submit") || control.tagName().equals("button")) {
                if (!name.isEmpty()) throw FIELD_NAME.parseFailure();
                continue;
            }
            if (!type.equals("hidden")) throw CHALLENGE_CONTROL.parseFailure();
            if (!name.matches("[A-Za-z_][A-Za-z0-9_]{0,63}")) throw FIELD_NAME.parseFailure();
            String normalized = name.toLowerCase(Locale.ROOT);
            if ((normalized.equals("qrkey") && !name.equals("qrkey")) || normalized.equals("__lib") || normalized.equals("__act") || normalized.equals("raw") || normalized.startsWith("access_")
                    || normalized.startsWith("ngapassport") || normalized.equals("cookie")) throw RESERVED_FIELD.parseFailure();
            String value = control.attr("value");
            if (value.length() > 4096 || value.indexOf('\0') >= 0) throw FIELD_LIMIT.parseFailure();
            if (fields.put(name, value) != null) throw DUPLICATE_FIELD.parseFailure();
            total += name.length() + value.length();
            if (fields.size() > 32 || total > 16384) throw FIELD_LIMIT.parseFailure();
        }
        String keyValue = fields.get("qrkey");
        if (keyValue == null || (!keyValue.isEmpty() && !keyValue.equals(target.key()))) throw KEY_MISMATCH.parseFailure();
        // Official loginSubmit fills the hidden input from the scanned location.search.
        fields.put("qrkey", target.key());
        return new NgaQrLoginForm(fields, charset);
    }

    private static boolean visible(Element element) {
        for (Element ancestor = element; ancestor != null; ancestor = ancestor.parent()) {
            String style = ancestor.attr("style").replaceAll("\\s+", "").toLowerCase(Locale.ROOT);
            if (ancestor.hasAttr("hidden") || ancestor.hasAttr("inert") || style.contains("display:none")
                    || style.contains("visibility:hidden")) return false;
        }
        return true;
    }

    @Override public String toString() { return "NgaQrLoginForm([redacted])"; }
}

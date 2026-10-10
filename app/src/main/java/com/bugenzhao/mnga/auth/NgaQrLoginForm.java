package com.bugenzhao.mnga.auth;

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
        // Reject ambiguous or non-interactive forms, including forms hidden in templates.
        if (!document.select("base, template, noscript, [form], [formaction], [formmethod], [formenctype]").isEmpty()
                || document.select("form").size() != 1
                || document.select("[id=loginform]").size() != 1) throw invalid();
        Element form = document.selectFirst("form#loginform");
        if (form == null || !"post".equalsIgnoreCase(form.attr("method"))
                || (form.hasAttr("enctype") && !"application/x-www-form-urlencoded".equalsIgnoreCase(form.attr("enctype")))) throw invalid();
        Charset charset;
        try { charset = form.hasAttr("accept-charset") ? Charset.forName(form.attr("accept-charset")) : document.charset(); }
        catch (Exception ignored) { throw invalid(); }
        if (!(charset.name().equals("UTF-8") || charset.name().equals("GBK") || charset.name().equals("GB18030"))) throw invalid();
        if (form.hasAttr("target") && !form.attr("target").equals("loginframe")) throw invalid();
        for (Element frame : document.select("iframe")) {
            if (!frame.id().equals("loginframe") || !frame.attr("name").equals("loginframe")
                    || frame.hasAttr("src") || frame.hasAttr("srcdoc")) throw invalid();
        }
        if (document.select("iframe").size() > 1) throw invalid();
        String action = form.attr("action");
        // Only root-relative or fully qualified, same-origin official actions are valid.
        if (!(action.startsWith("/nuke.php?") || action.startsWith("https://"))) throw invalid();
        String absolute;
        try { absolute = new URI(target.url).resolve(action).toString(); }
        catch (Exception ignored) { throw invalid(); }
        if (!target.allowsRequest(absolute, "POST", false)) throw invalid();
        if (document.select("[id=qrkey]").size() != 1 || document.select("[id=loginsubmit]").size() != 1) throw invalid();
        Element key = form.selectFirst("input#qrkey");
        Element submit = form.selectFirst("#loginsubmit");
        if (key == null || submit == null || submit.hasAttr("disabled")
                || submit.hasAttr("hidden") || !"qrkey".equals(key.attr("name"))
                || !"hidden".equalsIgnoreCase(key.attr("type"))) throw invalid();
        if (!(submit.tagName().equals("a") || submit.tagName().equals("button")
                || submit.tagName().equals("input") || submit.tagName().equals("div"))) throw invalid();
        if (submit.tagName().equals("input") && !(submit.attr("type").equalsIgnoreCase("submit")
                || submit.attr("type").equalsIgnoreCase("button"))) throw invalid();
        for (Element ancestor = submit; ancestor != null; ancestor = ancestor.parent()) {
            String style = ancestor.attr("style").replaceAll("\\s+", "").toLowerCase(Locale.ROOT);
            if (ancestor.hasAttr("hidden") || ancestor.hasAttr("inert") || style.contains("display:none")
                    || style.contains("visibility:hidden")) throw invalid();
        }
        String click = submit.attr("onclick").trim();
        if (!(click.equals("loginSubmit(this)") || click.equals("loginSubmit(this);"))) throw invalid();
        for (Element element : form.getAllElements()) {
            for (org.jsoup.nodes.Attribute attribute : element.attributes()) {
                if (attribute.getKey().toLowerCase(Locale.ROOT).startsWith("on")
                        && !(element == submit && attribute.getKey().equalsIgnoreCase("onclick"))) throw invalid();
            }
        }
        // These are the only non-hidden control types whose values can be omitted safely.
        if (!form.select("select, textarea, fieldset[disabled], [contenteditable], object").isEmpty()) throw invalid();
        Map<String, String> fields = new LinkedHashMap<>();
        int total = 0;
        for (Element control : form.select("input, button")) {
            String type = control.attr("type").toLowerCase(Locale.ROOT);
            String name = control.attr("name");
            if (control.hasAttr("disabled") || control.hasAttr("required")) throw invalid();
            if (type.equals("button") || type.equals("submit") || control.tagName().equals("button")) {
                if (!name.isEmpty()) throw invalid();
                continue;
            }
            if (!type.equals("hidden") || !name.matches("[A-Za-z_][A-Za-z0-9_]{0,63}")) throw invalid();
            String normalized = name.toLowerCase(Locale.ROOT);
            if ((normalized.equals("qrkey") && !name.equals("qrkey")) || normalized.equals("__lib") || normalized.equals("__act") || normalized.equals("raw") || normalized.startsWith("access_")
                    || normalized.startsWith("ngapassport") || normalized.equals("cookie")) throw invalid();
            String value = control.attr("value");
            if (value.length() > 4096 || value.indexOf('\0') >= 0 || fields.put(name, value) != null) throw invalid();
            total += name.length() + value.length();
            if (fields.size() > 32 || total > 16384) throw invalid();
        }
        String keyValue = fields.get("qrkey");
        if (keyValue == null || (!keyValue.isEmpty() && !keyValue.equals(target.key()))) throw invalid();
        // Official loginSubmit fills the hidden input from the scanned location.search.
        fields.put("qrkey", target.key());
        return new NgaQrLoginForm(fields, charset);
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("NGA authorization form unavailable or unsupported");
    }

    @Override public String toString() { return "NgaQrLoginForm([redacted])"; }
}

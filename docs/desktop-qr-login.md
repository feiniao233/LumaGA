# Scan to sign in on a computer

## How to use

1. Sign in to LumaGA, including with the existing Cookie import option if needed.
2. On a computer you trust, open NGA at `https://bbs.nga.cn` or
   `https://ngabbs.com` and display its QR login code.
3. Open **Personal Center → Scan to sign in on computer**
   (**个人中心 → 扫码登录电脑**). Camera permission is requested only here.
4. Scan the code, check the displayed account, UID and official hostname, and
   choose **Check NGA authorization / 读取 NGA 授权信息**.
5. Once LumaGA has read and verified NGA's form, choose
   **Authorize computer sign-in / 确认授权电脑登录** if you trust that computer.
6. Read the message returned by NGA and check the computer's login state.

Scanning and checking the form do not approve a login. Never scan login QR
images sent by strangers: a genuine NGA code may belong to their computer.
Only the final native confirmation button sends an approval request, once.
Closing, backgrounding or changing accounts cancels outstanding work, but cannot
revoke an approval that already reached NGA. A timeout can happen after the
server accepts the request. Check the computer before refreshing its QR and
starting a new attempt; LumaGA never automatically retries an approval.

This feature uses native HTTP and a native confirmation screen. It does not
create a WebView or require `MULTI_PROFILE`, including on Huawei devices. The
existing WebView-based account sign-in flow is unchanged.

If a code expires, refresh it on the computer and scan again. If the form cannot
be verified, note the fixed diagnostic code and its explanation below; that
failure alone does not establish a problem with the account session. A login challenge,
changed site form, or authentication flow requiring extra server cookies is
currently unsupported and fails closed. If camera permission was permanently
denied, enable it in Android Settings.

## Local diagnostic codes (1.2.3)

A preflight failure now shows a brief explanation and a fixed code such as
`QR-F14`. Share only that code as text; no Cookie, QR contents, HTML, logs or
screenshots are needed. Nothing is automatically uploaded for diagnosis.
The code distinguishes a rejection stage; it does not establish the underlying
compatibility cause or mean the account session expired.

- `QR-Cxx`: credential format, canceled/stale attempt, or one-shot request state.
- `QR-Nxx`: timeout, DNS, TLS, or other I/O failure.
- `QR-Hxx`: redirect, non-200 status, or unexpected response destination.
- `QR-Rxx`: content type, body size/empty body, encoding/HTML, or unconfirmed
  result envelope/JSON/value/redaction.
- `QR-Fxx`: specific form, field, handler, action or challenge check. For example,
  `QR-F14` means the confirmation hook differs from the supported static form.
- `QR-F08` is reserved for the exact visible logged-out message observed in a
  correctly routed official form with neither authorization marker present.
  Missing controls alone do not trigger this diagnosis. It does not prove why
  the server did not recognize the session.
- `QR-X00`: the cause is still unknown.

Diagnostics use an enum and fixed localized strings only. Public exceptions are
recreated without raw messages, causes or suppressed exceptions; no arbitrary
HTML attribute names/values, endpoint URLs, credentials or scanned keys become
part of a code. This update does not relax authorization checks or guess a new
protocol. Explicitly invalid HTTP charset declarations are rejected instead of
guessing a fallback. Any failure after submission still remains unconfirmed.

The device-reported preflight incompatibility has not yet been reproduced with
an authenticated official page; 1.2.3 is a diagnostic update, not a confirmed fix.

## Security boundaries

- Only HTTPS `bbs.nga.cn` and `ngabbs.com`, exact `/nuke.php`, and exactly one
  each of `__lib=login`, `__act=qrlogin_ui`, and an ASCII-alphanumeric `qrkey`
  are accepted. Userinfo, explicit ports, fragments, encodings, duplicates,
  extra query arguments, legacy redirect domains and arbitrary QR URLs fail
  closed. Both request URLs are constructed from validated values.
- Each attempt uses its own OkHttp client with `CookieJar.NO_COOKIES`, no cache,
  redirects or authentication follow-ups. Only `access_uid` and `access_token`
  from the selected account snapshot are sent to the exact official origin.
  No CookieManager, WebView cookies, global cookie handler, or Rust auth state is
  read or changed. Server `Set-Cookie` headers are deliberately not retained.
- The GET must return bounded HTML from the original endpoint. jsoup parses it
  without fetching any resources or executing scripts. A single supported POST
  form is required, including the `qrkey` hidden input and visible
  `loginsubmit` marker with the known `loginSubmit(this)` hook. The public
  logged-out page has no such controls and cannot enable authorization.
- The action must resolve to the exact same-host `qrlogin_allow&raw=3` endpoint.
  Base URLs, external form-associated controls, method/action overrides,
  ambiguous forms, disabled fields, visible challenge controls, unknown event
  handlers and foreign frames are rejected. Hidden fields, including CSRF
  values, are preserved with bounded names/values and duplicate-name checks.
  Reserved routing/authentication fields are refused. The trusted scanned key
  fills an empty `qrkey`; a nonempty different key is refused.
- UTF-8, GBK and GB18030 form encodings are supported. Response bytes are bounded
  (256 KiB preflight, 64 KiB result) and decoded using HTTP/HTML charset data.
  Connect timeout is 10 seconds, read/write 15 seconds, total call 30 seconds.
- Generation, account snapshot and monotonic credential revision are checked
  around callbacks, before network transmission and before the POST body.
  Close, background, account change and disposal cancel the active call. Late
  responses are discarded, and disposed preflights cannot enable confirmation.
  Double clicks are blocked both by the UI and a per-session atomic submit gate.
- Every POST body is one-shot. Automatic connection retries are disabled and an
  additional per-call network gate refuses a second transmission, including
  status-driven retries. If a request has been consumed, it cannot be submitted
  again even after failure. Cancellation cannot guarantee revocation after send.
- `raw=3` results are read only from the observed single inline
  `window.script_muti_get_var_store=JSON` envelope. JSON must be strict, bounded,
  free of duplicate members and shallow enough to parse safely. The official
  page reads `error[0]` or `data[0]`; numeric-key objects and arrays are supported.
  Errors take precedence. Unknown bodies, empty/wrong-shaped results, extra
  scripts, malformed wrappers or network failures remain **unconfirmed**.
  There is deliberately no client-invented success indicator. A nonempty data
  message is shown as NGA's message, not proof that desktop sign-in finished.
- No JavaScript is evaluated. QR contents and credentials are not logged, saved
  in navigation state, or included in diagnostic string representations. No QR
  image is saved. The authorization dialog disables screenshots.

## Evidence and implementation provenance

The public official [`qrlogin_ui`](https://bbs.nga.cn/nuke.php?__lib=login&__act=qrlogin_ui)
was inspected without cookies or a QR key on 2026-10-10. It uses a form POST to
`/nuke.php?__lib=login&__act=qrlogin_allow&raw=3`, fills `qrkey` from the URL, and
reads `script_muti_get_var_store.error[0]` or `.data[0]` from a hidden iframe.
Both supported hosts returned HTTPS 200 without redirects. The exact
`NGA_Harmony/1.0.0` UA marker selects the app-cookie branch. LumaGA adds its own
identifier; the compatibility marker does not claim signed official-app status.

A read-only unauthenticated
[`iflogin&raw=3`](https://bbs.nga.cn/nuke.php?__lib=login&__act=iflogin&raw=3)
request verified the raw=3 HTML/JSON error wrapper and GBK content type. This is
not an observed `qrlogin_allow` response. No successful authorization payload
has been captured, and no success message is guessed. Captured public fixtures
and synthetic tests are clearly distinguished under `app/src/test/resources/qr`.

Protocol facts were also cross-checked against
[LNGA's QR feature](https://github.com/apap6628114/lnga_harmony/commit/b9b3bf883bebf2b6d6bd0322338ca414ed2e4265).
That project is GPL-2.0; no code, assets, translated functions or parser
implementation were copied. LumaGA implements its own native flow. Existing
LumaGA/MNGA redistribution restrictions still apply; see the repository README.
Camera decoding uses Apache-2.0 [ZXing Android Embedded](https://github.com/journeyapps/zxing-android-embedded),
HTML parsing uses MIT [jsoup](https://jsoup.org/), HTTP uses Apache-2.0
[OkHttp](https://square.github.io/okhttp/), and strict JSON validation uses
Apache-2.0 [Gson](https://github.com/google/gson).

## Verification and limits

All 148 JVM tests pass, including 34 diagnostic regressions added in 1.2.3.
They cover strict QR URLs, captured
logged-out form rejection, synthetic
supported forms/CSRF fields, hostile and ambiguous HTML, response envelopes,
strict JSON, unknown results, no-submit preflight, one-shot requests, duplicate
clicks, canceling in-flight requests, stale account state and body/status limits.
A direct fake network-chain test also verifies that a 503-style repeated
transmission and a stale account are blocked before another send.
Transport tests intercept all traffic in memory; they do not use NGA credentials
or send authorization requests. Debug and unsigned release builds are checked.
The full debug lint baseline has five pre-existing failures (`NonObservableLocale`,
two `RestrictedApi`, two `MissingTranslation`).

A physical device test is still required, especially Huawei:

- Camera permission allow/deny/permanent deny, camera unavailable, scanner
  background/resume, cancel/reopen, malformed QR and both official hosts.
- Authenticated official form compatibility, expired account/code, CSRF fields,
  and a deliberately confirmed login on a computer the owner trusts.
- Confirm selected account/UID; cancel before checking or confirmation; double
  tap either button; switch accounts away/back; sign out during a request.
- Offline/timeout, background/close while preparing or posting, checking desktop
  after an uncertain result, and large text/font scaling on the native screen.
- Ordinary account login and in-app browsing remain unaffected.

No real credentials were used and no approval POST was sent during development.
Authenticated form details and actual desktop sign-in have not been verified
end to end. Unsupported form changes fail closed rather than bypassing checks.

# NGA QR login parser fixtures

These are read-only, unauthenticated observations supplied with the QR-login
research on 2026-10-10. Both files are copied byte-for-byte from that research:

- `official-qrlogin-ui-logged-out.html`: `NGA_Harmony_1.0.0.html`, the official
  NGA QR-login UI fetched without an authenticated session. It contains the
  expected authorization form action, but says this device is not logged in and
  contains neither a QR-key control nor a confirmation control. The parser must
  reject it. The original research filename denotes the user-agent variant.
- `official-raw3-logged-out.html`: `iflogin-raw3-no-cookie.txt`, an official
  unauthenticated raw=3 response. Its actual observed result is the error
  `请求错误`, represented by a numeric-keyed object under `error`.

The saved files are UTF-8, although the original HTML declares GBK. Tests read
the saved bytes explicitly as UTF-8. Do not change the fixtures to make them
look authenticated or successful.

All accepted-form, data-message, alternate-error, and adversarial examples
created in the Java tests are synthetic contract tests. In particular, none is
evidence that an authenticated NGA session or desktop login succeeded, and none
was submitted to NGA. No real user ID, cookie, token, or QR secret is present.
The unit tests do not open a browser or make HTTP requests.

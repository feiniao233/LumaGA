# Scan to sign in on a computer

## How to use

1. Sign in to LumaGA, including with the existing Cookie import option if needed.
2. On a computer you trust, open NGA at `https://bbs.nga.cn` or
   `https://ngabbs.com` and display its QR login code.
3. In LumaGA, open **Personal Center → Scan to sign in on computer**
   (**个人中心 → 扫码登录电脑**). Camera permission is requested only here.
4. Scan the code. Check the account and official hostname, then choose
   **Continue to NGA confirmation**.
5. Read the official NGA authorization page and press its confirmation button.
   Read NGA's result message and check that the computer is signed in.

Scanning alone does not approve a login. Do not scan login QR images sent by
strangers: a genuine NGA code can still belong to somebody else's computer.
Closing or backgrounding the authorization page clears its temporary browser
credentials. It does not revoke a desktop login already approved on NGA.

If a code expires, refresh it on the computer and scan again. If NGA says the
phone is not signed in, refresh the LumaGA account session and retry. If camera
permission was denied permanently, enable it in Android Settings. An outdated
Android System WebView/Chrome may need updating: authorization requires WebView
multi-profile support and deliberately has no shared-cookie fallback.

## Security boundaries

- Only HTTPS `bbs.nga.cn` and `ngabbs.com`, exact `/nuke.php`, and exactly one
  each of `__lib=login`, `__act=qrlogin_ui`, and an ASCII-alphanumeric `qrkey`
  are accepted. Userinfo, explicit ports, fragments, encodings, duplicates,
  extra query arguments, legacy redirect domains and arbitrary QR URLs fail
  closed. A fresh canonical URL is constructed from validated fields.
- A new isolated AndroidX WebKit profile is used for each attempt. Existing
  sign-in and in-app browser cookies are never copied or cleared by this flow.
  The profile gets only host-only `access_uid` and `access_token` session cookies
  with `Secure`, `HttpOnly`, `SameSite=Strict`, and `Path=/nuke.php`.
- Cookies must finish installing before loading. Asynchronous callbacks and
  request checks verify the captured account and monotonic credential revision.
  Close, account changes, logout and app backgrounding invalidate the attempt.
  Late callbacks clean their own profile, never a new scan's profile.
- On exit the WebView is stopped/destroyed, then profile cookies are removed and
  flushed and profile storage cleared. Profile deletion is best effort because
  Android WebView may keep loaded profiles in memory; unused profiles are reaped
  on a later scan after a process restart. Forced process termination can prevent
  normal asynchronous cleanup; these profiles are never reused for browsing.
- Navigation/resource checks allow only that QR confirmation GET, its same-host
  hidden-frame `qrlogin_allow&raw=3` POST, and an empty `about:blank` subframe.
  Disallowed navigations and intercepted requests, external intents, downloads,
  new windows, file/content access, mixed content and permission requests are
  blocked. SSL errors are canceled. Android does not expose subsequent resource
  redirect hops to the request interceptor, and POST navigation is not passed
  to the navigation override. This flow therefore trusts NGA’s official
  endpoints/HTML; it is not a complete network sandbox. Host-only `HttpOnly`
  cookies keep the credentials scoped to the selected official host.
- The official page owns the confirmation form and result alert. There is no
  JS bridge, automatic click/submit, client-generated approval POST, desktop
  session polling, or guessed success indicator. QR contents and credentials
  are not logged or saved in navigation state. The authorization dialog disables
  screenshots; no QR image is saved by the scanner.

## Protocol evidence and implementation provenance

Behavior was researched using the publicly accessible official
[`qrlogin_ui`](https://bbs.nga.cn/nuke.php?__lib=login&__act=qrlogin_ui) page
without cookies or a QR key on 2026-10-10. Its inline form targets
`/nuke.php?__lib=login&__act=qrlogin_allow&raw=3` by POST in `loginframe` and
shows results using a JavaScript alert. Both allowed hosts returned HTTPS 200
without redirects in that check. An uncredentialed static GET also confirmed
that `NGA_Harmony/1.0.0` selects the official app-cookie branch; generic Android
NGA markers did not. LumaGA keeps this compatibility marker and adds its own
identifier. The marker does not claim to be a genuine signed official app.

The independently implemented Android flow was informed by protocol behavior
in [LNGA's QR feature](https://github.com/apap6628114/lnga_harmony/commit/b9b3bf883bebf2b6d6bd0322338ca414ed2e4265).
That repository's license is GPL-2.0; no source, assets or translated functions
were copied. Existing LumaGA/MNGA redistribution restrictions still apply; see
the repository README. Camera decoding uses the Apache-2.0 licensed
[ZXing Android Embedded](https://github.com/journeyapps/zxing-android-embedded).

## Verification

Automated checks for this change: all 51 JVM tests pass (31 added for QR),
debug and unsigned release APK builds pass, and release vital lint passes.
Full debug lint remains blocked by the same five pre-existing issues
(`NonObservableLocale`, two `RestrictedApi`, two `MissingTranslation`); there
are no lint findings in the new QR source files.

JVM tests cover parser spoofing, canonicalization, request boundaries, stale
callbacks, cancellation/reopening, token refresh, logout and account switches.
These tests do not replace a camera/device end-to-end test.

Before release, verify on a physical Android device:

- Permission allow/deny/permanently deny; cancel before a result; reopen quickly;
  camera unavailable; leave the app during scanning and resume.
- Non-NGA QR, lookalike hostname, stale code, and both supported NGA hostnames.
- Review the selected account; cancel review; scan again; only pressing NGA's
  official button should authorize the matching desktop.
- Close/background during cookie setup and page loading; then rescan. Switch
  accounts, including away and back, and sign out while a flow is open.
- Expired account/QR, offline/network failure, page timeout, blocked navigation,
  SSL failure and back/close after an official result.
- Existing web login and in-app browsing remain unaffected by profile cleanup.
- System WebView without `MULTI_PROFILE` reports the update requirement.

No real account credentials were used, no authorization POST was submitted,
and no actual desktop login was granted during implementation. Authenticated
page contents and `HttpOnly`/path-restricted cookie compatibility still require
this device-level verification with the owner's explicit confirmation.

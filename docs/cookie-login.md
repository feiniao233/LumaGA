# Cookie login

Open **Sign in to NGA → Import Cookie**. Paste your own Cookie request header
(with or without `Cookie:`), or choose **UID / CID** and enter
`ngaPassportUid` and `ngaPassportCid` separately. Newline-separated `name=value`
pairs also work. Only the two passport values are used; extra browser cookies
are discarded. Values are not URL-decoded. Conflicting duplicate passport
values, missing values, invalid UIDs and unsafe cookie characters are rejected.

This imports the same two passport credentials used by the reference
`Import-NgaSession.ps1` approach. It does not run PowerShell, import a browser
profile, embed a personal UID, or copy an expiry date. CID is a login secret:
do not paste it into issues, logs, screenshots or shared documents.

## Verification and storage

Before changing accounts, an isolated HTTPS POST is made directly to
`https://bbs.nga.cn/thread.php?fid=7&__output=11` with the candidate passport
cookies and `access_uid` / `access_token` form fields. Redirects are refused,
response size and timeouts are bounded, and the app’s configurable backend/proxy is not
used for this probe (Android system networking settings still apply). The response must contain a positive `data.__CU.uid`
matching the candidate UID. HTTP 200, a public profile, or an arbitrary `data`
object alone does not count as a successful login. This request only reads a
public forum listing; it does not post, send messages, or check in.

The [NGA API thread documentation](https://github.com/wolfcon/NGA-API-Documents/wiki/%E4%B8%BB%E9%A2%98)
and [common-field documentation](https://github.com/wolfcon/NGA-API-Documents/wiki/%E5%85%AC%E5%85%B1%E4%BF%A1%E6%81%AF%E8%AF%B4%E6%98%8E)
describe `__CU` as the current authenticated visitor; guests lack this field.
If NGA changes or blocks this interface, import fails closed and leaves the
existing account unchanged. Use ordinary web login or retry later.

Successful verification uses the existing `AuthStorage.setCurrentAuth`
path, including normal account switching and sign-out. The app's existing
account storage uses SharedPreferences and is not encrypted; this feature
adds no extra credential file or preference. Imported credentials are never
inserted into the WebView cookie store. Inputs are held only in the dialog's
in-memory state, excluded from saved instance state, masked and protected
against screenshots. Cancel/Back invalidates pending results. Closing the
login sheet also clears its temporary WebView cookies. Signing out removes
the account using the existing account-removal behavior (another saved account
may become active).

## Verification checklist

- JVM tests: parser/header handling, duplicates, size/character limits, token
  preservation, authenticated response matching, guest/error/malformed responses,
  one-use completion, cancel/late completion, failure/retry and supersession.
- With Android tooling: `./gradlew testDebugUnitTest lintDebug assembleDebug`.
- On a device: test both input modes, malformed/expired cookies, offline/TLS
  errors, repeated submit, cancel/Back while verifying, reopen after cancel,
  successful import, existing-account preservation on failure, account switching
  and sign-out. Ensure normal web login still works after closing import.
- A real authenticated success must be tested locally with the account owner's
  own credentials; never include them in test fixtures or CI.

The original README attribution and redistribution restrictions still apply.

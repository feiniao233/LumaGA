package com.bugenzhao.mnga.ui.screens.login

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Bitmap
import android.net.http.SslError
import android.webkit.JsResult
import android.webkit.PermissionRequest
import android.webkit.SslErrorHandler
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.webkit.Profile
import androidx.webkit.ProfileStore
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import com.bugenzhao.mnga.BuildConfig
import com.bugenzhao.mnga.auth.CookieCredentials
import com.bugenzhao.mnga.auth.NgaQrLoginTarget
import java.io.ByteArrayInputStream
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/** One isolated browser profile. Never reads or changes the app's default cookie jar. */
// MULTI_PROFILE is checked before construction and again in init; it stays
// supported for this WebView provider lifetime, including asynchronous cleanup.
@SuppressLint("SetJavaScriptEnabled", "RequiresFeature")
internal class QrAuthorizationWebSession(
    context: Context,
    private val target: NgaQrLoginTarget,
    private val isCurrent: () -> Boolean,
    private val onReady: () -> Unit,
    private val onFailure: () -> Unit,
    private val onAlert: (String, JsResult) -> Unit,
) {
    companion object {
        private const val PROFILE_PREFIX = "nga-qr-"
        // Only our own profiles are eligible for cleanup, never default/login profiles.
        private val activeProfiles = mutableSetOf<String>()

        fun supported(): Boolean = WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROFILE)
    }

    private val closed = AtomicBoolean(false)
    private val profileName = PROFILE_PREFIX + UUID.randomUUID()
    private val profile: Profile
    val view: WebView

    init {
        check(supported())
        val store = ProfileStore.getInstance()
        // Reap profiles left by process death before loading any of them into memory.
        store.allProfileNames.filter { it.startsWith(PROFILE_PREFIX) && it !in activeProfiles }
            .forEach { name -> runCatching { store.deleteProfile(name) } }
        activeProfiles.add(profileName)
        view = WebView(context)
        // Must precede settings, clients and every other operation on the new WebView.
        WebViewCompat.setProfile(view, profileName)
        profile = WebViewCompat.getProfile(view)
        profile.cookieManager.setAcceptCookie(true)
        profile.cookieManager.setAcceptThirdPartyCookies(view, false)
        view.settings.apply {
            javaScriptEnabled = true // Official confirmation form and its result alert only.
            useWideViewPort = true
            loadWithOverviewMode = true
            domStorageEnabled = false
            allowFileAccess = false
            allowContentAccess = false
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            cacheMode = WebSettings.LOAD_NO_CACHE
            javaScriptCanOpenWindowsAutomatically = false
            setSupportMultipleWindows(true) // New windows are rejected by default client.
            setGeolocationEnabled(false)
            // Compatibility token recognized by NGA's official app-cookie login branch.
            userAgentString = "$userAgentString NGA_Harmony/1.0.0 LumaGA/${BuildConfig.VERSION_NAME}"
        }
        view.setDownloadListener { _, _, _, _, _ -> fail() }
        view.webChromeClient = object : WebChromeClient() {
            override fun onPermissionRequest(request: PermissionRequest) { request.deny() }
            override fun onJsAlert(webView: WebView?, url: String?, message: String?, result: JsResult): Boolean {
                if (!live()) { result.cancel(); return true }
                // The form result is shown verbatim; never infer success from an alert.
                onAlert(message.orEmpty().take(4000), result)
                return true
            }
        }
        view.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest): Boolean {
                val allowed = live() && target.allowsRequest(
                    request.url.toString(), request.method, request.isForMainFrame,
                )
                if (!allowed && request.isForMainFrame) fail()
                return !allowed
            }

            override fun shouldInterceptRequest(view: WebView?, request: WebResourceRequest): WebResourceResponse? {
                // Called off the UI thread. Both the gate and auth StateFlow reads are thread safe.
                if (!live() || !target.allowsRequest(request.url.toString(), request.method, request.isForMainFrame)) {
                    return WebResourceResponse("text/plain", "UTF-8", 403, "Blocked", emptyMap(), ByteArrayInputStream(byteArrayOf()))
                }
                return null
            }

            override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
                if (!live() || url == null || !target.allowsRequest(url, "GET", true)) fail()
            }

            override fun onPageFinished(view: WebView?, url: String?) {
                if (live() && url == target.url) onReady()
            }

            override fun onReceivedError(view: WebView?, request: WebResourceRequest, error: WebResourceError?) {
                if (request.isForMainFrame || target.allowsRequest(request.url.toString(), request.method, false)) fail()
            }

            override fun onReceivedHttpError(view: WebView?, request: WebResourceRequest, errorResponse: WebResourceResponse?) {
                if (request.isForMainFrame || target.allowsRequest(request.url.toString(), request.method, false)) fail()
            }

            override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler, error: SslError?) {
                handler.cancel()
                fail()
            }
        }
    }

    private fun live(): Boolean = !closed.get() && isCurrent()

    fun load(uid: String, token: String) {
        val credentials = runCatching { CookieCredentials.fromFields(uid, token) }.getOrElse { fail(); return }
        if (!live()) { close(); return }
        val cookies = profile.cookieManager
        // Host-only, narrowly scoped session cookies. No credentials in URLs, JS or logs.
        val suffix = "; Path=/nuke.php; Secure; HttpOnly; SameSite=Strict"
        cookies.setCookie(target.url, "access_uid=${credentials.uid}$suffix") { first ->
            if (!live()) { clearProfile(); return@setCookie }
            if (!first) { fail(); return@setCookie }
            cookies.setCookie(target.url, "access_token=${credentials.cid}$suffix") { second ->
                if (!live()) clearProfile()
                else if (!second) fail()
                else view.loadUrl(target.url)
            }
        }
    }

    private fun fail() {
        view.post {
            if (closed.get()) return@post
            close()
            onFailure()
        }
    }

    fun close() {
        if (!closed.compareAndSet(false, true)) return
        view.stopLoading()
        view.webChromeClient = WebChromeClient()
        // Keep the guarded client installed until destroy; closed blocks late requests.
        (view.parent as? android.view.ViewGroup)?.removeView(view)
        view.clearHistory()
        view.destroy()
        clearProfile()
    }

    private fun clearProfile() {
        // Late setCookie callbacks also clear their OWN profile. They cannot touch a newer scan.
        runCatching {
            profile.cookieManager.removeAllCookies {
                runCatching { profile.cookieManager.flush() }
                runCatching { profile.webStorage.deleteAllData() }
                activeProfiles.remove(profileName)
                // Loaded profiles cannot always be deleted until process restart. Cookies are
                // already gone; the next scan reaps unloaded profiles without opening them.
                runCatching { ProfileStore.getInstance().deleteProfile(profileName) }
            }
        }
    }
}

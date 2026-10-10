package com.bugenzhao.mnga.ui.screens.login

import android.Manifest
import android.content.pm.PackageManager
import android.webkit.JsResult
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.bugenzhao.mnga.App
import com.bugenzhao.mnga.R
import com.bugenzhao.mnga.auth.NgaQrLoginTarget
import com.bugenzhao.mnga.auth.QrAuthorizationAttempt
import com.google.zxing.BarcodeFormat
import com.journeyapps.barcodescanner.BarcodeCallback
import com.journeyapps.barcodescanner.CameraPreview
import com.journeyapps.barcodescanner.BarcodeResult
import com.journeyapps.barcodescanner.DecoratedBarcodeView
import com.journeyapps.barcodescanner.DefaultDecoderFactory

/** Signed-in phone scans a desktop QR. Only a user's click on NGA can grant authorization. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DesktopQrLoginSheet(onDismiss: () -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val original = remember { App.authStorage.authInfo.value }
    val originalRevision = remember { App.authStorage.sessionRevision }
    val current by App.authStorage.authInfo.collectAsState()
    val gate = remember { QrAuthorizationAttempt() }
    val generation = remember { runCatching { gate.begin(original.uid, original.token) }.getOrDefault(-1L) }
    fun isCurrent(): Boolean = originalRevision == App.authStorage.sessionRevision &&
        gate.isActive(generation, App.authStorage.authInfo.value.uid, App.authStorage.authInfo.value.token)

    var target by remember { mutableStateOf<NgaQrLoginTarget?>(null) }
    var reviewed by remember { mutableStateOf(false) }
    var session by remember { mutableStateOf<QrAuthorizationWebSession?>(null) }
    var error by remember { mutableStateOf<Int?>(null) }
    var loading by remember { mutableStateOf(true) }
    var alert by remember { mutableStateOf<Pair<String, JsResult>?>(null) }
    val supported = remember { runCatching { QrAuthorizationWebSession.supported() }.getOrDefault(false) }

    fun close() {
        gate.cancel()
        alert?.second?.cancel()
        alert = null
        session?.close()
        onDismiss()
    }

    LaunchedEffect(current.uid, current.token) {
        if (!isCurrent()) {
            gate.cancel()
            alert?.second?.cancel()
            alert = null
            session?.close()
            error = R.string.qr_account_changed
        }
    }
    LaunchedEffect(session) {
        if (session != null) {
            kotlinx.coroutines.delay(30_000)
            if (loading) { session?.close(); error = R.string.qr_page_failed }
        }
    }
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            // Do not leave a credential-bearing authorization page live in the background.
            if (event == Lifecycle.Event.ON_STOP && session != null) {
                gate.cancel()
                alert?.second?.cancel()
                alert = null
                session?.close()
                error = R.string.qr_interrupted
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            gate.cancel()
            alert?.second?.cancel()
            session?.close()
        }
    }

    Dialog(onDismissRequest = { close() }, properties = DialogProperties(
        usePlatformDefaultWidth = false,
        securePolicy = SecureFlagPolicy.SecureOn,
    )) {
        Surface(Modifier.fillMaxSize()) {
            Column(Modifier.fillMaxSize()) {
                TopAppBar(
                    title = { Text(stringResource(R.string.qr_desktop_login)) },
                    navigationIcon = {
                        IconButton(onClick = { close() }) {
                            Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.qr_close))
                        }
                    },
                )
                when {
                    error != null || !supported -> {
                        Text(stringResource(error ?: R.string.qr_webview_update), Modifier.padding(24.dp))
                        TextButton(onClick = { close() }, modifier = Modifier.padding(horizontal = 16.dp)) {
                            Text(stringResource(R.string.qr_close))
                        }
                    }
                    target == null -> QrCameraScanner(onScanned = { contents ->
                        if (isCurrent()) target = runCatching { NgaQrLoginTarget.parse(contents) }.getOrNull()
                        target != null
                    })
                    !reviewed -> {
                        Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                            Text(stringResource(R.string.qr_review_account, original.cachedName.ifEmpty { original.uid }), style = MaterialTheme.typography.titleMedium)
                            Text(stringResource(R.string.qr_review_site, target!!.host))
                            Text(stringResource(R.string.qr_review_notice))
                            Button(onClick = {
                                if (isCurrent()) reviewed = true else error = R.string.qr_account_changed
                            }) { Text(stringResource(R.string.qr_open_official_page)) }
                            TextButton(onClick = { target = null }) { Text(stringResource(R.string.qr_scan_again)) }
                        }
                    }
                    else -> {
                        Text(stringResource(R.string.qr_official_page, target!!.host), Modifier.padding(horizontal = 16.dp, vertical = 8.dp), style = MaterialTheme.typography.labelMedium)
                        Text(stringResource(R.string.qr_result_notice), Modifier.padding(horizontal = 16.dp, vertical = 4.dp), style = MaterialTheme.typography.bodySmall)
                        Box(Modifier.weight(1f).fillMaxWidth()) {
                            AndroidView(
                                modifier = Modifier.fillMaxSize(),
                                factory = { ctx ->
                                    try { QrAuthorizationWebSession(ctx, target!!, ::isCurrent,
                                        onReady = { loading = false },
                                        onFailure = { alert?.second?.cancel(); alert = null; error = R.string.qr_page_failed },
                                        onAlert = { message, result -> alert?.second?.cancel(); alert = message to result },
                                    ).also { new ->
                                        session = new
                                        new.load(original.uid, original.token)
                                    }.view } catch (_: Exception) {
                                        error = R.string.qr_page_failed
                                        android.view.View(ctx)
                                    }
                                },
                            )
                            if (loading) CircularProgressIndicator(Modifier.align(Alignment.Center))
                        }
                    }
                }
            }
        }
    }
    alert?.let { (message, result) ->
        AlertDialog(
            onDismissRequest = { result.cancel(); alert = null },
            title = { Text(stringResource(R.string.qr_official_result)) },
            text = { Text(message) },
            confirmButton = { TextButton(onClick = { result.confirm(); alert = null }) { Text(stringResource(R.string.qr_ok)) } },
        )
    }
}

@Composable
private fun QrCameraScanner(onScanned: (String) -> Boolean) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var permitted by remember { mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) }
    var view by remember { mutableStateOf<DecoratedBarcodeView?>(null) }
    var invalid by remember { mutableStateOf(false) }
    var cameraFailed by remember { mutableStateOf(false) }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { permitted = it }
    val callback = remember {
        object : BarcodeCallback {
            override fun barcodeResult(result: BarcodeResult) {
                view?.pause()
                if (!onScanned(result.text)) invalid = true
            }
        }
    }
    fun resume() {
        if (permitted && !invalid && !cameraFailed && lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) {
            view?.decodeSingle(callback)
            view?.resume()
        }
    }
    DisposableEffect(lifecycleOwner, view, permitted, invalid, cameraFailed) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) resume()
            else if (event == Lifecycle.Event.ON_PAUSE) view?.pause()
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        resume()
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer); view?.pause() }
    }
    // This composable exists only after the user deliberately opens the scanner.
    LaunchedEffect(Unit) { if (!permitted) permission.launch(Manifest.permission.CAMERA) }
    Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(stringResource(R.string.qr_scan_instruction), Modifier.padding(horizontal = 24.dp, vertical = 12.dp))
        when {
            !permitted -> {
                Text(stringResource(R.string.qr_camera_permission), Modifier.padding(horizontal = 24.dp))
                TextButton(onClick = { permission.launch(Manifest.permission.CAMERA) }, modifier = Modifier.padding(horizontal = 16.dp)) {
                    Text(stringResource(R.string.qr_allow_camera))
                }
            }
            cameraFailed -> Text(stringResource(R.string.qr_camera_failed), Modifier.padding(24.dp))
            invalid -> {
                Text(stringResource(R.string.qr_invalid), Modifier.padding(horizontal = 24.dp))
                TextButton(onClick = { invalid = false }, modifier = Modifier.padding(horizontal = 16.dp)) {
                    Text(stringResource(R.string.qr_scan_again))
                }
            }
            else -> AndroidView(
                modifier = Modifier.weight(1f).fillMaxWidth(),
                factory = { ctx -> DecoratedBarcodeView(ctx).apply {
                    barcodeView.decoderFactory = DefaultDecoderFactory(listOf(BarcodeFormat.QR_CODE))
                    barcodeView.addStateListener(object : CameraPreview.StateListener {
                        override fun previewSized() {}
                        override fun previewStarted() {}
                        override fun previewStopped() {}
                        override fun cameraClosed() {}
                        override fun cameraError(error: Exception) { cameraFailed = true }
                    })
                    setStatusText("")
                    view = this
                } },
            )
        }
    }
}

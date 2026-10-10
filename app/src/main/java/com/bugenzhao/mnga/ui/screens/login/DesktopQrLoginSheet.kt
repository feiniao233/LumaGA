package com.bugenzhao.mnga.ui.screens.login

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
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
import androidx.compose.runtime.rememberCoroutineScope
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
import com.bugenzhao.mnga.BuildConfig
import com.bugenzhao.mnga.auth.NgaQrAuthorizationSession
import com.bugenzhao.mnga.auth.NgaQrLoginResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.bugenzhao.mnga.R
import com.bugenzhao.mnga.auth.NgaQrLoginTarget
import com.bugenzhao.mnga.auth.QrAuthorizationAttempt
import com.google.zxing.BarcodeFormat
import com.journeyapps.barcodescanner.BarcodeCallback
import com.journeyapps.barcodescanner.CameraPreview
import com.journeyapps.barcodescanner.BarcodeResult
import com.journeyapps.barcodescanner.DecoratedBarcodeView
import com.journeyapps.barcodescanner.DefaultDecoderFactory

/** Native approval only. Scanning and preparing the form never authorize the computer. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DesktopQrLoginSheet(onDismiss: () -> Unit) {
    val lifecycleOwner = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()
    val original = remember { App.authStorage.authInfo.value }
    val originalRevision = remember { App.authStorage.sessionRevision }
    val current by App.authStorage.authInfo.collectAsState()
    val gate = remember { QrAuthorizationAttempt() }
    val generation = remember { runCatching { gate.begin(original.uid, original.token) }.getOrDefault(-1L) }
    fun isCurrent(): Boolean = originalRevision == App.authStorage.sessionRevision &&
        gate.isActive(generation, App.authStorage.authInfo.value.uid, App.authStorage.authInfo.value.token)

    var target by remember { mutableStateOf<NgaQrLoginTarget?>(null) }
    var session by remember { mutableStateOf<NgaQrAuthorizationSession?>(null) }
    var ready by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<Int?>(null) }
    var result by remember { mutableStateOf<NgaQrLoginResult?>(null) }

    fun close() {
        gate.cancel()
        session?.close()
        onDismiss()
    }

    LaunchedEffect(current.uid, current.token) {
        if (!isCurrent()) {
            gate.cancel()
            session?.close()
            error = if (session?.wasSubmitted() == true) R.string.qr_result_unconfirmed else R.string.qr_account_changed
        }
    }
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP && session != null) {
                gate.cancel()
                session?.close()
                error = if (session?.wasSubmitted() == true) R.string.qr_result_unconfirmed else R.string.qr_interrupted
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            gate.cancel()
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
                    error != null -> {
                        Text(stringResource(error!!), Modifier.padding(24.dp))
                        TextButton(onClick = { close() }, modifier = Modifier.padding(horizontal = 16.dp)) {
                            Text(stringResource(R.string.qr_close))
                        }
                    }
                    result != null -> {
                        Column(Modifier.verticalScroll(rememberScrollState()).padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                            when (result!!.kind) {
                                NgaQrLoginResult.Kind.UNCONFIRMED -> Text(stringResource(R.string.qr_result_unconfirmed))
                                else -> {
                                    Text(stringResource(if (result!!.kind == NgaQrLoginResult.Kind.SERVER_ERROR) R.string.qr_server_error else R.string.qr_official_result), style = MaterialTheme.typography.titleMedium)
                                    Text(result!!.message)
                                    Text(stringResource(R.string.qr_result_notice))
                                }
                            }
                            TextButton(onClick = { close() }) { Text(stringResource(R.string.qr_close)) }
                        }
                    }
                    target == null -> QrCameraScanner(onScanned = { contents ->
                        if (isCurrent()) target = runCatching { NgaQrLoginTarget.parse(contents) }.getOrNull()
                        target != null
                    })
                    else -> {
                        Column(Modifier.verticalScroll(rememberScrollState()).padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                            Text(stringResource(R.string.qr_review_account, original.cachedName.ifEmpty { original.uid }), style = MaterialTheme.typography.titleMedium)
                            Text(stringResource(R.string.qr_review_uid, original.uid))
                            Text(stringResource(R.string.qr_review_site, target!!.host))
                            Text(stringResource(if (ready) R.string.qr_confirm_notice else R.string.qr_review_notice))
                            if (busy) {
                                CircularProgressIndicator()
                                Text(stringResource(if (session?.wasSubmitted() == true) R.string.qr_submitting else R.string.qr_preparing))
                            } else if (ready) {
                                Button(onClick = {
                                    if (busy) return@Button
                                    val active = session ?: return@Button
                                    if (!isCurrent()) { error = R.string.qr_account_changed; return@Button }
                                    busy = true
                                    scope.launch {
                                        try {
                                            val response = withContext(Dispatchers.IO) { active.submit() }
                                            if (session === active) {
                                                busy = false
                                                if (isCurrent()) result = response else error = R.string.qr_result_unconfirmed
                                            }
                                        } finally { active.close() }
                                    }
                                }) { Text(stringResource(R.string.qr_confirm_login)) }
                            } else {
                                Button(onClick = {
                                    if (busy) return@Button
                                    if (!isCurrent()) { error = R.string.qr_account_changed; return@Button }
                                    val active = runCatching { NgaQrAuthorizationSession(target!!, original.uid, original.token, BuildConfig.VERSION_NAME, ::isCurrent) }
                                        .getOrElse { error = R.string.qr_page_failed; return@Button }
                                    session = active
                                    busy = true
                                    scope.launch {
                                        var keepOpen = false
                                        try {
                                            val prepared = withContext(Dispatchers.IO) { runCatching { active.prepare() }.isSuccess }
                                            if (session === active) {
                                                busy = false
                                                if (!isCurrent()) error = R.string.qr_account_changed
                                                else if (prepared) { ready = true; keepOpen = true }
                                                else error = R.string.qr_page_failed
                                            }
                                        } finally { if (!keepOpen) active.close() }
                                    }
                                }) { Text(stringResource(R.string.qr_prepare_login)) }
                            }
                            if (!busy) TextButton(onClick = {
                                session?.close()
                                session = null
                                ready = false
                                target = null
                            }) { Text(stringResource(R.string.qr_scan_again)) }
                        }
                    }
                }
            }
        }
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

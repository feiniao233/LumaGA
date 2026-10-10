package com.bugenzhao.mnga.ui.screens.login

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import com.bugenzhao.mnga.R
import com.bugenzhao.mnga.auth.CookieCredentials
import com.bugenzhao.mnga.auth.CookieImportAttempt
import com.bugenzhao.mnga.auth.CookieSessionVerifier
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun CookieImportDialog(
    onDismiss: () -> Unit,
    onVerified: (CookieCredentials) -> Unit,
) {
    // Deliberately not rememberSaveable: credentials must not go into saved instance state.
    var cookie by remember { mutableStateOf("") }
    var uid by remember { mutableStateOf("") }
    var cid by remember { mutableStateOf("") }
    var separateFields by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<Int?>(null) }
    var job by remember { mutableStateOf<Job?>(null) }
    val attempt = remember { CookieImportAttempt() }
    val scope = rememberCoroutineScope()

    fun clear() { cookie = ""; uid = ""; cid = "" }
    fun cancel() {
        attempt.cancel()
        job?.cancel()
        clear()
        onDismiss()
    }

    DisposableEffect(Unit) {
        onDispose {
            attempt.cancel()
            job?.cancel()
        }
    }

    AlertDialog(
        onDismissRequest = { cancel() },
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
        title = { Text(stringResource(R.string.import_cookie)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(stringResource(R.string.import_cookie_help))
                Row {
                    TextButton(enabled = !busy && separateFields, onClick = {
                        separateFields = false; error = null; clear()
                    }) { Text(stringResource(R.string.cookie_header)) }
                    TextButton(enabled = !busy && !separateFields, onClick = {
                        separateFields = true; error = null; clear()
                    }) { Text("UID / CID") }
                }
                if (separateFields) {
                    OutlinedTextField(
                        value = uid, onValueChange = { if (it.length <= 20) { uid = it; error = null } },
                        label = { Text("ngaPassportUid") }, singleLine = true, enabled = !busy,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = cid, onValueChange = { if (it.length <= 4096) { cid = it; error = null } },
                        label = { Text("ngaPassportCid") }, singleLine = true, enabled = !busy,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        modifier = Modifier.fillMaxWidth(),
                    )
                } else {
                    OutlinedTextField(
                        value = cookie, onValueChange = { if (it.length <= 16384) { cookie = it; error = null } },
                        label = { Text(stringResource(R.string.cookie_header)) },
                        minLines = 3, maxLines = 6, enabled = !busy,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                error?.let { Text(stringResource(it), color = androidx.compose.material3.MaterialTheme.colorScheme.error) }
                if (busy) {
                    CircularProgressIndicator()
                    Text(stringResource(R.string.verifying_cookie))
                }
            }
        },
        confirmButton = {
            TextButton(enabled = !busy, onClick = {
                if (busy) return@TextButton
                val credentials = try {
                    if (separateFields) CookieCredentials.fromFields(uid, cid)
                    else CookieCredentials.fromCookieHeader(cookie)
                } catch (_: IllegalArgumentException) {
                    error = R.string.invalid_cookie_input
                    return@TextButton
                }
                busy = true
                error = null
                val id = attempt.begin()
                job = scope.launch {
                    try {
                        val verified = withContext(Dispatchers.IO) { CookieSessionVerifier.verify(credentials) }
                        ensureActive()
                        if (attempt.finish(id, verified)) {
                            clear()
                            onVerified(credentials)
                        } else {
                            error = R.string.cookie_verification_failed
                        }
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Exception) {
                        attempt.finish(id, false)
                        error = R.string.cookie_network_error
                    } finally {
                        busy = false
                    }
                }
            }) { Text(stringResource(R.string.import_and_sign_in)) }
        },
        dismissButton = {
            TextButton(onClick = { cancel() }) { Text(stringResource(R.string.cancel)) }
        },
    )
}

package com.azluk.patcher.viewmodel

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.azluk.patcher.BuildConfig
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.File
import java.io.FileInputStream

// ── Installer state ───────────────────────────────────────────────────────────

data class InstallerState(
    val isInstalling:   Boolean      = false,
    val installResult:  Boolean?     = null,   // null=idle true=ok false=fail
    val errorMessage:   String?      = null,
    val errorCode:      String?      = null,
    val currentApkPath: String?      = null,
    val aiDiagnosis:    AiDiagnosis  = AiDiagnosis()
)

/**
 * InstallerViewModel — owns the PackageInstaller session lifecycle.
 *
 * Root cause of the broken installer in previous versions:
 *   1. PendingIntent.FLAG_MUTABLE without FLAG_UPDATE_CURRENT → new PI slot
 *      per call, old session's IntentSender goes stale after first install.
 *   2. Broadcast sent without setPackage() → Android 8+ drops implicit
 *      broadcasts from background; the receiver never fires.
 *   3. session.close() called before commit() → session cancelled.
 *
 * All three are fixed here. The AI diagnosis runs silently on failure — no
 * "AI" label exposed anywhere in the UI; it just appears as a helpful hint.
 */
class InstallerViewModel : ViewModel() {

    private val _state = MutableStateFlow(InstallerState())
    val state: StateFlow<InstallerState> = _state.asStateFlow()

    // ── Install ───────────────────────────────────────────────────────────────

    fun install(ctx: Context, file: File) {
        if (!file.exists()) {
            _state.update { it.copy(
                installResult = false,
                errorMessage  = "File not found: ${file.name}",
                errorCode     = "FILE_NOT_FOUND"
            )}
            return
        }
        _state.update { it.copy(isInstalling = true, installResult = null,
            errorMessage = null, currentApkPath = file.absolutePath, aiDiagnosis = AiDiagnosis()) }

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val pi       = ctx.packageManager.packageInstaller
                val params   = PackageInstaller.SessionParams(
                    PackageInstaller.SessionParams.MODE_FULL_INSTALL)
                val sessionId = pi.createSession(params)
                val session   = pi.openSession(sessionId)

                // Write APK data into session
                FileInputStream(file).use { fis ->
                    session.openWrite("base.apk", 0, file.length()).use { os ->
                        fis.copyTo(os, 65536)
                        session.fsync(os)
                    }
                }

                // FIX 1: setPackage() — explicit package prevents implicit broadcast drop
                val receiverIntent = Intent("com.azluk.patcher.INSTALL_RESULT").apply {
                    setPackage(ctx.packageName)
                }
                // FIX 2: FLAG_UPDATE_CURRENT — reuses same PI slot on retry
                val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
                else PendingIntent.FLAG_UPDATE_CURRENT

                val pending = PendingIntent.getBroadcast(ctx, sessionId, receiverIntent, flags)

                // FIX 3: commit() before close()
                session.commit(pending.intentSender)
                session.close()

            } catch (e: Exception) {
                _state.update { it.copy(
                    isInstalling  = false,
                    installResult = false,
                    errorMessage  = e.message ?: "Unknown install error",
                    errorCode     = "SESSION_EXCEPTION"
                )}
                silentDiagnose(e.message ?: "", file.absolutePath)
            }
        }
    }

    // ── Uninstall then install ────────────────────────────────────────────────

    fun uninstallThenInstall(ctx: Context, packageName: String, apk: File) {
        _state.update { it.copy(isInstalling = true, installResult = null,
            errorMessage = null, currentApkPath = apk.absolutePath, aiDiagnosis = AiDiagnosis()) }

        viewModelScope.launch {
            try {
                // Kick Android's uninstall dialog
                val uninstallIntent = Intent(Intent.ACTION_DELETE,
                    Uri.parse("package:$packageName")).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                ctx.startActivity(uninstallIntent)
                // Wait for uninstall (user-driven) — poll package manager
                var removed = false
                repeat(60) {
                    delay(1000)
                    val gone = try {
                        ctx.packageManager.getPackageInfo(packageName, 0); false
                    } catch (_: Exception) { true }
                    if (gone) { removed = true; return@repeat }
                }
                if (removed) {
                    delay(500)
                    install(ctx, apk)
                } else {
                    _state.update { it.copy(isInstalling = false, installResult = false,
                        errorMessage = "Uninstall timed out or was cancelled") }
                }
            } catch (e: Exception) {
                _state.update { it.copy(isInstalling = false, installResult = false,
                    errorMessage = e.message) }
            }
        }
    }

    // ── Called by broadcast receiver ──────────────────────────────────────────

    fun onInstallResult(status: Int, message: String?) {
        when (status) {
            PackageInstaller.STATUS_SUCCESS -> {
                _state.update { it.copy(isInstalling = false, installResult = true,
                    errorMessage = null, errorCode = null) }
            }
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                // The Activity handles the confirmation intent — we stay in installing state
            }
            else -> {
                val code = installStatusName(status)
                val msg  = message ?: "Install failed (code $status)"
                _state.update { it.copy(isInstalling = false, installResult = false,
                    errorMessage = msg, errorCode = code) }
                // Trigger silent AI diagnosis
                silentDiagnose("$code: $msg", _state.value.currentApkPath ?: "")
            }
        }
    }

    // ── Silent AI diagnosis — no UI label, just a helpful suggestion ──────────
    // Runs on IO, updates aiDiagnosis.suggestion. The UI shows it as plain text.

    private fun silentDiagnose(error: String, apkPath: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.update { it.copy(aiDiagnosis = AiDiagnosis(loading = true)) }
            try {
                val apkInfo = runCatching {
                    val f = File(apkPath)
                    "APK: ${f.name}, ${f.length()/1024}KB"
                }.getOrDefault("")

                val prompt = """
Android APK install failed. Give a 2-sentence diagnosis and one specific fix.
Error: $error
$apkInfo
No preamble. Be direct.
""".trimIndent()

                val body = org.json.JSONObject().apply {
                    put("model", BuildConfig.TOKENROUTER_MODEL)
                    put("max_tokens", 200)
                    put("messages", org.json.JSONArray().apply {
                        put(org.json.JSONObject().apply {
                            put("role", "system")
                            put("content", "Android APK signing expert. Be concise.")
                        })
                        put(org.json.JSONObject().apply {
                            put("role", "user"); put("content", prompt)
                        })
                    })
                }

                val url  = java.net.URL("${BuildConfig.TOKENROUTER_BASE_URL}/chat/completions")
                val conn = url.openConnection() as java.net.HttpURLConnection
                conn.apply {
                    requestMethod = "POST"
                    setRequestProperty("Content-Type",  "application/json")
                    setRequestProperty("Authorization", "Bearer ${BuildConfig.TOKENROUTER_API_KEY}")
                    doOutput      = true
                    connectTimeout = 8000
                    readTimeout    = 15000
                }
                conn.outputStream.use { it.write(body.toString().toByteArray()) }
                val resp = conn.inputStream.bufferedReader().readText()
                val text = org.json.JSONObject(resp)
                    .getJSONArray("choices").getJSONObject(0)
                    .getJSONObject("message").getString("content").trim()

                _state.update { it.copy(aiDiagnosis = AiDiagnosis(loading = false, suggestion = text)) }
            } catch (e: Exception) {
                // Silent failure — don't bother user if AI is unavailable
                _state.update { it.copy(aiDiagnosis = AiDiagnosis(loading = false)) }
            }
        }
    }

    fun reset() {
        _state.update { InstallerState() }
    }

    private fun installStatusName(status: Int) = when (status) {
        PackageInstaller.STATUS_FAILURE_ABORTED   -> "ABORTED"
        PackageInstaller.STATUS_FAILURE_BLOCKED   -> "BLOCKED"
        PackageInstaller.STATUS_FAILURE_CONFLICT  -> "CONFLICT"
        PackageInstaller.STATUS_FAILURE_INCOMPATIBLE -> "INCOMPATIBLE"
        PackageInstaller.STATUS_FAILURE_INVALID   -> "INVALID"
        PackageInstaller.STATUS_FAILURE_STORAGE   -> "NO_STORAGE"
        else -> "FAILURE_$status"
    }
}

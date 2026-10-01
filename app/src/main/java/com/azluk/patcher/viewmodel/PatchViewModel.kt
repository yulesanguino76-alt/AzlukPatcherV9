package com.azluk.patcher.viewmodel

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageInstaller
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import androidx.core.app.NotificationCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.azluk.patcher.ai.AzlukAI
import com.azluk.patcher.core.*
import com.azluk.patcher.engine.ApkEngine
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.File
import java.io.IOException

data class AiDiagnosis(
    val loading:    Boolean = false,
    val suggestion: String  = "",
    val error:      String  = ""
)

data class PatchUiState(
    val selectedPatches: Set<PatchType>   = emptySet(),
    val patchState:      PatchState       = PatchState.Idle,
    val installState:    InstallState     = InstallState.Idle,
    val scanResults:     List<ScanResult> = emptyList(),
    val isScanning:      Boolean          = false,
    val aiDiagnosis:     AiDiagnosis      = AiDiagnosis(),
    val lastOutputPath:  String           = "",
    val scannedPkg:      String?          = null,
    val scannedFile:     File?            = null,
    val scannedFileName: String?          = null,
    val scanError:       String?          = null
)

class PatchViewModel(app: Application) : AndroidViewModel(app) {

    private val _state = MutableStateFlow(PatchUiState())
    val state: StateFlow<PatchUiState> = _state.asStateFlow()
    private val engine = ApkEngine(app)

    private val notifMgr = app.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    private val CHANNEL  = "azluk_patch"
    private val NOTIF_ID = 0xA9

    init { createChannel() }

    // ── Scan (installed apps) ─────────────────────────────────────────────────

    fun ensureScanned(pkg: String) {
        if (_state.value.scannedPkg != pkg &&
            _state.value.scannedFile == null &&
            !_state.value.isScanning
        ) {
            scan(pkg)
        }
    }

    fun scan(pkg: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.update {
                it.copy(
                    isScanning      = true,
                    scanResults     = emptyList(),
                    scanError       = null,
                    scannedPkg      = null,
                    scannedFile     = null,
                    scannedFileName = null
                )
            }

            runCatching { engine.scan(pkg) }.fold(
                onSuccess = { list ->
                    val detected = list.mapNotNull {
                        runCatching { PatchType.valueOf(it.patchType) }.getOrNull()
                    }.toSet()

                    _state.update {
                        it.copy(
                            isScanning      = false,
                            scannedPkg      = pkg,
                            scanResults     = list,
                            selectedPatches = detected
                        )
                    }
                },
                onFailure = { e ->
                    _state.update {
                        it.copy(
                            isScanning      = false,
                            scannedPkg      = pkg,
                            scanError       = e.message ?: "Scan failed",
                            scanResults     = emptyList(),
                            selectedPatches = emptySet()
                        )
                    }
                }
            )
        }
    }

    // ── Scan + patch (imported files: APK / XAPK / APKM / APKS) ───────────────

    /**
     * Copies the SAF-selected Uri into app-owned cache (no ongoing
     * URI-permission issues) and scans it. Routes internally to the APK
     * or container scanner by extension.
     */
    fun importAndScan(uri: Uri) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.update {
                it.copy(
                    isScanning      = true,
                    scanResults     = emptyList(),
                    scanError       = null,
                    scannedPkg      = null,
                    scannedFile     = null,
                    scannedFileName = null
                )
            }

            runCatching {
                val app = getApplication<Application>()
                val resolver = app.contentResolver

                val displayName = runCatching {
                    resolver.query(
                        uri,
                        arrayOf(OpenableColumns.DISPLAY_NAME),
                        null, null, null
                    )?.use { cursor ->
                        if (cursor.moveToFirst()) cursor.getString(0) else null
                    }
                }.getOrNull() ?: "import_${System.currentTimeMillis()}"

                val safeName = displayName.replace(
                    Regex("[^A-Za-z0-9._\\- ]"), "_"
                )

                val dir = File(app.cacheDir, "imports").apply { mkdirs() }
                val dest = File(dir, safeName)

                resolver.openInputStream(uri)?.use { input ->
                    dest.outputStream().use { output ->
                        input.copyTo(output, 256 * 1024)
                    }
                } ?: throw IOException("Cannot open selected file")

                dest
            }.fold(
                onSuccess = { dest ->
                    runCatching { engine.scanExternal(dest) }.fold(
                        onSuccess = { list ->
                            val detected = list.mapNotNull {
                                runCatching { PatchType.valueOf(it.patchType) }.getOrNull()
                            }.toSet()

                            _state.update {
                                it.copy(
                                    isScanning      = false,
                                    scannedFile     = dest,
                                    scannedFileName = dest.name,
                                    scanResults     = list,
                                    selectedPatches = detected
                                )
                            }
                        },
                        onFailure = { e ->
                            _state.update {
                                it.copy(
                                    isScanning = false,
                                    scanError  = e.message ?: "Scan failed"
                                )
                            }
                        }
                    )
                },
                onFailure = { e ->
                    _state.update {
                        it.copy(
                            isScanning = false,
                            scanError  = e.message ?: "Import failed"
                        )
                    }
                }
            )
        }
    }

    /**
     * Single entry point for the Patch button: patches the imported file
     * if one is loaded, otherwise the installed package.
     */
    fun patchActiveSource(pkg: String) {
        val file = _state.value.scannedFile
        if (file != null) {
            patchFile(file)
        } else {
            patch(pkg)
        }
    }

    fun togglePatch(type: PatchType) {
        _state.update { s ->
            val set = s.selectedPatches.toMutableSet()
            if (type in set) set.remove(type) else set.add(type)
            s.copy(selectedPatches = set)
        }
    }

    fun selectAll(types: Set<PatchType>) {
        _state.update { s ->
            val set = s.selectedPatches.toMutableSet()
            types.forEach { set.add(it) }
            s.copy(selectedPatches = set)
        }
    }

    // ── Patch ─────────────────────────────────────────────────────────────────

    fun patch(pkg: String) {
        val patches = _state.value.selectedPatches.toList()
        if (patches.isEmpty()) return
        doLaunchPatch { progress -> engine.patch(pkg, patches, progress) }
    }

    fun patchFile(file: File) {
        val patches = _state.value.selectedPatches.toList()
        if (patches.isEmpty()) return
        doLaunchPatch { progress -> engine.patchExternal(file, patches, progress) }
    }

    private fun doLaunchPatch(block: (ApkEngine.Progress) -> File) {
        if (_state.value.patchState is PatchState.Running) return

        val log   = mutableListOf<String>()
        var dirty = false

        viewModelScope.launch {
            _state.update { it.copy(patchState = PatchState.Running(emptyList())) }
            showNotif("Patching in background…")

            val ticker = launch(Dispatchers.Main) {
                while (isActive) {
                    delay(200)
                    if (dirty) {
                        _state.update { it.copy(patchState = PatchState.Running(log.toList())) }
                        dirty = false
                    }
                }
            }

            val result = withContext(Dispatchers.IO) {
                android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND)
                runCatching {
                    block(ApkEngine.Progress { msg ->
                        synchronized(log) { log.add(msg); dirty = true }
                    })
                }
            }

            ticker.cancel()
            _state.update { it.copy(patchState = PatchState.Running(log.toList())) }
            delay(50)

            result.fold(
                onSuccess = { out ->
                    showNotif("Patch complete: ${out.name}")
                    _state.update {
                        it.copy(
                            patchState     = PatchState.Success(out.absolutePath, log.toList()),
                            lastOutputPath = out.absolutePath
                        )
                    }
                },
                onFailure = { e ->
                    synchronized(log) { log.add("[ERROR] ${e.message}") }
                    showNotif("Patch failed")
                    _state.update {
                        it.copy(patchState = PatchState.Failure(e.message ?: "Unknown error", log.toList()))
                    }
                }
            )
        }
    }

    private fun showNotif(text: String) {
        val notif = NotificationCompat.Builder(getApplication(), CHANNEL)
            .setContentTitle("AzlukPatcher")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_popup_sync)
            .setOngoing(text.contains("background"))
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
        runCatching { notifMgr.notify(NOTIF_ID, notif) }
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(CHANNEL, "Patching", NotificationManager.IMPORTANCE_LOW)
            ch.description = "AzlukPatcher background patching"
            notifMgr.createNotificationChannel(ch)
        }
    }

    // ── Install result + AzlukAI ───────────────────────────────────────────────

    fun onInstallResult(status: Int, message: String?) {
        val msg = message ?: ""

        val ist = when {
            /*
             * Finsky rejects installing a lone base.apk as an update of a
             * package that was installed with split APKs. The build is
             * valid — the container (.apks) must be installed instead.
             */
            msg.contains("missing splits", ignoreCase = true) ->
                InstallState.Failure(
                    "MISSING_SPLITS",
                    "The original app is installed with split APKs.",
                    "Install the .apks container from Patched Files — it includes " +
                            "base + all splits. Uninstall the original app first: " +
                            "the signature changed.",
                    true
                )

            /*
             * Package verifier rejected the APK after it parsed cleanly —
             * usually the unknown signing certificate. Uninstall-first
             * resolves the signature conflict; Play Protect is the fallback.
             */
            msg.contains("VERIFICATION_FAILURE", ignoreCase = true) ->
                InstallState.Failure(
                    "INSTALL_FAILED_VERIFICATION_FAILURE",
                    "System package verifier rejected the APK.",
                    "The build is structurally valid — the verifier blocked it. " +
                            "Uninstall the original app first (different signature), " +
                            "then install the patched file. If it persists, disable " +
                            "Play Protect scanning and retry.",
                    true
                )

            status == PackageInstaller.STATUS_SUCCESS ->
                InstallState.Success

            status == PackageInstaller.STATUS_FAILURE_INVALID ->
                InstallState.Failure("INSTALL_FAILURE_INVALID",
                    "Invalid APK — signature or structure is corrupt.",
                    "The signing block may be malformed.", true)

            status == PackageInstaller.STATUS_FAILURE_CONFLICT ->
                InstallState.Failure("INSTALL_FAILURE_CONFLICT",
                    "Version conflict — uninstall the original first.",
                    msg.ifEmpty { "A different version is already installed." }, false)

            status == PackageInstaller.STATUS_FAILURE_BLOCKED ->
                InstallState.Failure("INSTALL_FAILURE_BLOCKED",
                    "Installation blocked.",
                    "Enable 'Install unknown apps' for AzlukPatcher in Settings.", false)

            status == PackageInstaller.STATUS_FAILURE_STORAGE ->
                InstallState.Failure("INSTALL_FAILURE_STORAGE",
                    "Not enough storage space.", "Free up space and try again.", false)

            else ->
                InstallState.Failure("INSTALL_FAILURE_$status",
                    msg.ifEmpty { "Unknown installer error (code $status)" },
                    "Unexpected installer error.", true)
        }
        _state.update { it.copy(installState = ist) }
        if (ist is InstallState.Failure) diagnoseWithAi(ist, _state.value.lastOutputPath)
    }

    fun diagnoseWithAi(failure: InstallState.Failure, apkPath: String) {
        _state.update { it.copy(aiDiagnosis = AiDiagnosis(loading = true)) }
        viewModelScope.launch {
            val f = File(apkPath)
            val result = AzlukAI.diagnose(
                errorCode    = failure.code,
                errorMessage = failure.message,
                apkName      = f.name,
                apkSizeKb    = if (f.exists()) f.length() / 1024 else 0
            )
            _state.update {
                it.copy(aiDiagnosis = AiDiagnosis(
                    loading    = false,
                    suggestion = if (result.success) result.suggestion else "",
                    error      = if (!result.success) result.error else ""
                ))
            }
        }
    }

    fun dismissAi()  { _state.update { it.copy(aiDiagnosis = AiDiagnosis()) } }
    fun resetPatch() {
        _state.update {
            it.copy(patchState = PatchState.Idle, installState = InstallState.Idle, aiDiagnosis = AiDiagnosis())
        }
    }
}

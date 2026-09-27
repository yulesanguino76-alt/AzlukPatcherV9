package com.azluk.patcher.viewmodel

import android.app.Application
import android.app.ActivityManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Environment
import android.os.StatFs
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.File

// ── System profile exposed to the whole app ───────────────────────────────────

data class SystemProfile(
    val isReady:        Boolean = false,
    val hasRoot:        Boolean = false,
    val rootMethod:     String  = "",      // "Magisk" | "KernelSU" | "SuperSU" | ""
    val ramTotalMb:     Int     = 0,
    val ramFreeMb:      Int     = 0,
    val storageFreeGb:  Float   = 0f,
    val cpuCores:       Int     = 0,
    val androidApi:     Int     = 0,
    val arch:           String  = "",      // "arm64-v8a" | "armeabi-v7a" | "x86_64"
    val isArmDevice:    Boolean = false,
    val hasAdb:         Boolean = false,
    val isEmulator:     Boolean = false,
    val performanceTier: PerformanceTier = PerformanceTier.MEDIUM,
    val warnings:       List<String> = emptyList()
)

enum class PerformanceTier { LOW, MEDIUM, HIGH }

class SystemCheckViewModel(app: Application) : AndroidViewModel(app) {

    private val _profile = MutableStateFlow(SystemProfile())
    val profile: StateFlow<SystemProfile> = _profile.asStateFlow()

    fun run() {
        viewModelScope.launch(Dispatchers.IO) {
            val ctx = getApplication<Application>()

            // ── RAM ───────────────────────────────────────────────────────────
            val am = ctx.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            val mi = ActivityManager.MemoryInfo()
            am.getMemoryInfo(mi)
            val ramTotal = (mi.totalMem / 1024 / 1024).toInt()
            val ramFree  = (mi.availMem  / 1024 / 1024).toInt()

            // ── Storage ───────────────────────────────────────────────────────
            val stat     = StatFs(Environment.getExternalStorageDirectory().path)
            val freeGb   = stat.availableBlocksLong * stat.blockSizeLong / (1024f * 1024 * 1024)

            // ── CPU ───────────────────────────────────────────────────────────
            val cores    = Runtime.getRuntime().availableProcessors()
            val abis     = Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown"

            // ── Root detection ────────────────────────────────────────────────
            val (hasRoot, rootMethod) = detectRoot()

            // ── ADB / emulator ────────────────────────────────────────────────
            val isEmu = detectEmulator()
            val hasAdb = try {
                File("/dev/android_adb").exists() || File("/dev/adb_keys").exists()
            } catch (_: Exception) { false }

            // ── Performance tier ──────────────────────────────────────────────
            val tier = when {
                ramTotal >= 6000 && cores >= 6 -> PerformanceTier.HIGH
                ramTotal >= 3000 && cores >= 4 -> PerformanceTier.MEDIUM
                else                           -> PerformanceTier.LOW
            }

            // ── Warnings ──────────────────────────────────────────────────────
            val warnings = mutableListOf<String>()
            if (freeGb < 1f) warnings.add("Low storage — less than 1GB free")
            if (ramFree < 300) warnings.add("Low RAM — close background apps")
            if (isEmu) warnings.add("Emulator detected — some patches may behave differently")

            _profile.value = SystemProfile(
                isReady         = true,
                hasRoot         = hasRoot,
                rootMethod      = rootMethod,
                ramTotalMb      = ramTotal,
                ramFreeMb       = ramFree,
                storageFreeGb   = freeGb,
                cpuCores        = cores,
                androidApi      = Build.VERSION.SDK_INT,
                arch            = abis,
                isArmDevice     = abis.startsWith("arm"),
                hasAdb          = hasAdb,
                isEmulator      = isEmu,
                performanceTier = tier,
                warnings        = warnings
            )
        }
    }

    private fun detectRoot(): Pair<Boolean, String> {
        // Check Magisk
        if (File("/sbin/.magisk").exists() || File("/data/adb/magisk").exists())
            return true to "Magisk"
        // Check KernelSU
        if (File("/data/adb/ksu").exists())
            return true to "KernelSU"
        // Check SuperSU / classic su binary
        val suPaths = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su",
                             "/system/sbin/su", "/vendor/bin/su")
        if (suPaths.any { File(it).exists() }) return true to "SuperSU"
        // Try running su -c id
        return try {
            val proc = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            val out  = proc.inputStream.bufferedReader().readText()
            proc.waitFor()
            val isRoot = out.contains("uid=0")
            isRoot to if (isRoot) "su" else ""
        } catch (_: Exception) { false to "" }
    }

    private fun detectEmulator(): Boolean {
        return (Build.FINGERPRINT.startsWith("generic") ||
                Build.FINGERPRINT.contains("emulator") ||
                Build.MODEL.contains("Emulator") ||
                Build.MODEL.contains("Android SDK") ||
                Build.MANUFACTURER.contains("Genymotion") ||
                Build.BRAND.startsWith("generic"))
    }
}

package com.azluk.patcher.core

import android.graphics.drawable.Drawable

data class AppInfo(
    val packageName:    String,
    val appName:        String,
    val icon:           Drawable?,
    val isSystemApp:    Boolean,
    val apkPath:        String,
    val versionName:    String,
    val apkSizeMb:      Float,
    var patchStatus:      PatchStatus = PatchStatus.UNKNOWN,
    var opportunityCount: Int         = 0
)

enum class PatchStatus { UNKNOWN, LIKELY, PATCHABLE, COMPLEX }

/**
 * AzlukPatcher V9 Patch Types
 * Absorbed from: LuckyPatcher, ApkEditorPro, NPManager, GameGuardian,
 *                JasiPatcher, MTManager, hack-app-data, cheat-engine
 */
enum class PatchType(
    val key:         String,
    val displayName: String,
    val description: String,
    val category:    String
) {
    // ── BYPASS ────────────────────────────────────────────────────────────────
    LICENSE_BYPASS(
        "LICENSE_BYPASS", "License Bypass",
        "Nullifies Google Play LVL. Patches ILicensingService callbacks to always return LICENSED. Works on 95% of paid apps.",
        "bypass"
    ),
    IAP_BYPASS(
        "IAP_BYPASS", "IAP Bypass",
        "Spoofs in-app purchase validation. Patches BillingClient, BILLING intent, and PURCHASED state verification.",
        "bypass"
    ),
    SIGNATURE_BYPASS(
        "SIGNATURE_BYPASS", "Signature Bypass",
        "ApkEditorPro technique: hooks PackageInfo.getSignatures() and signingInfo to return original certificate hash after repack.",
        "bypass"
    ),
    GOOGLE_PLAY_BYPASS(
        "GOOGLE_PLAY_BYPASS", "Google Play Services Bypass",
        "Bypasses Play Services integrity checks, account verification gates and DRM entitlement validators.",
        "bypass"
    ),
    // ── ADS ───────────────────────────────────────────────────────────────────
    REMOVE_ADS(
        "REMOVE_ADS", "Remove Ads",
        "Kills 20+ ad SDKs at DEX level: AdMob, Facebook Audience, Unity, AppLovin, IronSource, MoPub, Chartboost, Vungle, InMobi, Mintegral + LuckyPatcher AdsBlockList (79 patterns).",
        "ads"
    ),
    BLOCK_AD_DOMAINS(
        "BLOCK_AD_DOMAINS", "Block Ad Domains",
        "Patches OkHttp/Retrofit/Volley network calls to drop requests to ad domains from LuckyPatcher AdsBlockList.",
        "ads"
    ),
    // ── SECURITY BYPASS ───────────────────────────────────────────────────────
    SSL_BYPASS(
        "SSL_BYPASS", "SSL Pinning Bypass",
        "NPManager technique: patches OkHttp CertificatePinner, TrustManager, X509TrustManager and Conscrypt to accept all certificates.",
        "security"
    ),
    ROOT_BYPASS(
        "ROOT_BYPASS", "Root Detection Bypass",
        "GameGuardian technique: patches RootBeer, isRooted(), su binary checks, prop file checks, and build tag validation.",
        "security"
    ),
    SAFETYNET_BYPASS(
        "SAFETYNET_BYPASS", "SafetyNet / Integrity Bypass",
        "Patches SafetyNet attestation, Play Integrity API, and DroidGuard to return MEETS_DEVICE_INTEGRITY verdict.",
        "security"
    ),
    FRIDA_BYPASS(
        "FRIDA_BYPASS", "Anti-Frida / Anti-Debug",
        "JasiPatcher technique: removes Frida/Xposed/Substrate detection, patches TracerPid reader, disables ptrace anti-debug.",
        "security"
    ),
    EMULATOR_BYPASS(
        "EMULATOR_BYPASS", "Emulator Detection Bypass",
        "Patches Build.FINGERPRINT checks, qemu property reads, sensor fingerprint validators and IMEI checks.",
        "security"
    ),
    // ── DEVELOPER ─────────────────────────────────────────────────────────────
    FORCE_DEBUGGABLE(
        "FORCE_DEBUGGABLE", "Force Debuggable",
        "Sets android:debuggable=true in binary AndroidManifest.xml. Enables ADB attach, Frida hooking and memory inspection.",
        "dev"
    ),
    DISABLE_FLAG_SECURE(
        "DISABLE_FLAG_SECURE", "Disable FLAG_SECURE",
        "JasiPatcher technique: nops Window.addFlags(FLAG_SECURE) calls. Enables screenshots, screen recording and overlay tools.",
        "dev"
    ),
    EXPORT_ALL_COMPONENTS(
        "EXPORT_ALL_COMPONENTS", "Export All Components",
        "Patches android:exported=false to true for all activities, services, receivers. Allows external invocation via ADB/am.",
        "dev"
    ),
    ALLOW_BACKUP(
        "ALLOW_BACKUP", "Allow Backup",
        "Forces android:allowBackup=true and android:fullBackupOnly=false. Enables ADB backup of app data.",
        "dev"
    ),
    DISABLE_ANALYTICS(
        "DISABLE_ANALYTICS", "Disable Analytics",
        "Patches Firebase Analytics, Mixpanel, Amplitude, Adjust SDK — ret-void on all track/log/send methods.",
        "dev"
    ),
    // ── UTILITY ───────────────────────────────────────────────────────────────
    OPTIMIZE_ZIP(
        "OPTIMIZE_ZIP", "Optimize APK",
        "Recompresses DEX entries with best compression, aligns resources.arsc to 4-byte boundaries. Reduces APK size.",
        "util"
    ),
    REMOVE_TELEMETRY(
        "REMOVE_TELEMETRY", "Remove Telemetry",
        "Disables Crashlytics, Sentry, Bugsnag, Firebase Crashlytics error reporting at the DEX level.",
        "util"
    )
}

data class ScanResult(
    val patchType: String,
    val desc:      String?,
    val dexIndex:  Int,
    val offset:    Int
)

sealed class PatchState {
    object Idle : PatchState()
    data class Running(val log: List<String>) : PatchState()
    data class Success(val outputPath: String, val log: List<String>) : PatchState()
    data class Failure(val error: String, val log: List<String>) : PatchState()
}

sealed class InstallState {
    object Idle      : InstallState()
    object Installing: InstallState()
    object Success   : InstallState()
    data class Failure(
        val code:        String,
        val message:     String,
        val description: String,
        val canRetry:    Boolean
    ) : InstallState()
}

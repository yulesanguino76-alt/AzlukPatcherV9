package com.azluk.patcher.core

import android.graphics.drawable.Drawable

data class AppInfo(
    val packageName:      String,
    val appName:          String,
    val icon:             Drawable?,
    val isSystemApp:      Boolean,
    val apkPath:          String,
    val versionName:      String,
    val apkSizeMb:        Float,
    var patchStatus:      PatchStatus = PatchStatus.UNKNOWN,
    var opportunityCount: Int         = 0
)

enum class PatchStatus { UNKNOWN, LIKELY, PATCHABLE, COMPLEX }

/**
 * AzlukPatcher V10 — Patch Types
 * Note: SAFETYNET_BYPASS / FRIDA_BYPASS / EMULATOR_BYPASS / DISABLE_FLAG_SECURE
 * now have structural recipes in SuperDexPatcher (V10 addition).
 * BLOCK_AD_DOMAINS reads AdsBlockList.txt via AdDomainBlocker.
 */
enum class PatchType(
    val key:         String,
    val displayName: String,
    val description: String,
    val category:    String
) {
    LICENSE_BYPASS(
        "LICENSE_BYPASS", "License Bypass",
        "Nullifies Google Play LVL. Patches ILicensingService callbacks to always return LICENSED.",
        "bypass"
    ),
    IAP_BYPASS(
        "IAP_BYPASS", "IAP Bypass",
        "Spoofs in-app purchase validation. Patches BillingClient, BILLING intent, and PURCHASED state.",
        "bypass"
    ),
    SIGNATURE_BYPASS(
        "SIGNATURE_BYPASS", "Signature Bypass",
        "Hooks PackageInfo.getSignatures() and signingInfo to return original certificate hash.",
        "bypass"
    ),
    GOOGLE_PLAY_BYPASS(
        "GOOGLE_PLAY_BYPASS", "Google Play Services Bypass",
        "Bypasses Play Services integrity checks, account verification gates and DRM validators.",
        "bypass"
    ),
    REMOVE_ADS(
        "REMOVE_ADS", "Remove Ads",
        "Kills 20+ ad SDKs at DEX level: AdMob, Facebook, Unity, AppLovin, IronSource, MoPub and more.",
        "ads"
    ),
    BLOCK_AD_DOMAINS(
        "BLOCK_AD_DOMAINS", "Block Ad Domains",
        "Patches OkHttp/Retrofit host resolution to drop requests to 79 known ad/tracking domains.",
        "ads"
    ),
    SSL_BYPASS(
        "SSL_BYPASS", "SSL Pinning Bypass",
        "Patches OkHttp CertificatePinner, TrustManager, X509TrustManager to accept all certificates.",
        "security"
    ),
    ROOT_BYPASS(
        "ROOT_BYPASS", "Root Detection Bypass",
        "Patches RootBeer, isRooted(), su binary checks, prop file checks, build tag validation.",
        "security"
    ),
    SAFETYNET_BYPASS(
        "SAFETYNET_BYPASS", "SafetyNet / Integrity Bypass",
        "Stubs SafetyNet attest(), Play Integrity API getIntegrityToken(), DroidGuard callbacks.",
        "security"
    ),
    FRIDA_BYPASS(
        "FRIDA_BYPASS", "Anti-Frida / Anti-Debug",
        "Removes Frida/Xposed detection, patches TracerPid reader, disables ptrace anti-debug.",
        "security"
    ),
    EMULATOR_BYPASS(
        "EMULATOR_BYPASS", "Emulator Detection Bypass",
        "Patches Build.FINGERPRINT checks, qemu property reads, sensor validators, IMEI checks.",
        "security"
    ),
    FORCE_DEBUGGABLE(
        "FORCE_DEBUGGABLE", "Force Debuggable",
        "Sets android:debuggable=true in binary AndroidManifest.xml.",
        "dev"
    ),
    DISABLE_FLAG_SECURE(
        "DISABLE_FLAG_SECURE", "Disable FLAG_SECURE",
        "Nops Window.addFlags(FLAG_SECURE) calls. Enables screenshots and screen recording.",
        "dev"
    ),
    EXPORT_ALL_COMPONENTS(
        "EXPORT_ALL_COMPONENTS", "Export All Components",
        "Patches android:exported=false to true for all activities, services, receivers.",
        "dev"
    ),
    ALLOW_BACKUP(
        "ALLOW_BACKUP", "Allow Backup",
        "Forces android:allowBackup=true and android:fullBackupOnly=false.",
        "dev"
    ),
    DISABLE_ANALYTICS(
        "DISABLE_ANALYTICS", "Disable Analytics",
        "Patches Firebase Analytics, Mixpanel — ret-void on all track/log/send methods.",
        "dev"
    ),
    OPTIMIZE_ZIP(
        "OPTIMIZE_ZIP", "Optimize APK",
        "Recompresses DEX entries, aligns resources.arsc to 4-byte boundaries.",
        "util"
    ),
    REMOVE_TELEMETRY(
        "REMOVE_TELEMETRY", "Remove Telemetry",
        "Disables Crashlytics, Sentry, Bugsnag, Firebase Crashlytics at the DEX level.",
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
    object Idle       : InstallState()
    object Installing : InstallState()
    object Success    : InstallState()
    data class Failure(
        val code:        String,
        val message:     String,
        val description: String,
        val canRetry:    Boolean
    ) : InstallState()
}

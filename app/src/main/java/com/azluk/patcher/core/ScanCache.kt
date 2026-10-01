package com.azluk.patcher.core

import android.content.Context
import android.content.SharedPreferences

/**
 * Per-package scan cache, keyed with the APK's lastUpdateTime so a
 * badge can never survive an app update: an updated APK automatically
 * re-scans on the next background pass.
 */
class ScanCache(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("scan_cache_v9", Context.MODE_PRIVATE)

    fun has(pkg: String): Boolean =
        prefs.contains("s_$pkg") && prefs.contains("c_$pkg")

    /**
     * True only when the cached fingerprint matches the installed APK's
     * lastUpdateTime — stale entries count as a miss.
     */
    fun hasFresh(pkg: String, apkFingerprint: Long): Boolean =
        has(pkg) && prefs.getLong("v_$pkg", -1L) == apkFingerprint

    fun getStatus(pkg: String): PatchStatus =
        prefs.getString("s_$pkg", null)?.let {
            runCatching { PatchStatus.valueOf(it) }
                .getOrDefault(PatchStatus.UNKNOWN)
        } ?: PatchStatus.UNKNOWN

    fun getCount(pkg: String): Int =
        prefs.getInt("c_$pkg", 0)

    fun save(pkg: String, status: PatchStatus, count: Int) {
        save(pkg, status, count, -1L)
    }

    fun save(pkg: String, status: PatchStatus, count: Int, apkFingerprint: Long) {
        prefs.edit()
            .putString("s_$pkg", status.name)
            .putInt("c_$pkg", count)
            .putLong("v_$pkg", apkFingerprint)
            .apply()
    }

    fun clear() = prefs.edit().clear().apply()
}

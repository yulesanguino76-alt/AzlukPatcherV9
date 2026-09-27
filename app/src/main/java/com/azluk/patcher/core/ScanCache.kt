package com.azluk.patcher.core

import android.content.Context

class ScanCache(ctx: Context) {
    private val prefs = ctx.getSharedPreferences("scan_cache_v7", Context.MODE_PRIVATE)

    fun has(pkg: String): Boolean = prefs.contains("s_$pkg")

    fun getStatus(pkg: String): PatchStatus =
        prefs.getString("s_$pkg", null)?.let {
            runCatching { PatchStatus.valueOf(it) }.getOrDefault(PatchStatus.UNKNOWN)
        } ?: PatchStatus.UNKNOWN

    fun getCount(pkg: String): Int = prefs.getInt("c_$pkg", 0)

    fun save(pkg: String, status: PatchStatus, count: Int) {
        prefs.edit()
            .putString("s_$pkg", status.name)
            .putInt("c_$pkg", count)
            .apply()
    }

    fun clear() = prefs.edit().clear().apply()
}

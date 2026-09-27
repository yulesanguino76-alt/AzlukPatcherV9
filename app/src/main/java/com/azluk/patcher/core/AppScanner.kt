package com.azluk.patcher.core

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.AdaptiveIconDrawable
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.os.Build
import java.io.File

class AppScanner(private val ctx: Context) {

    fun getAll(): List<AppInfo> {
        val pm = ctx.packageManager
        return pm.getInstalledPackages(0).mapNotNull { pi ->
            if (pi.packageName == ctx.packageName) return@mapNotNull null
            try {
                val ai = pi.applicationInfo
                AppInfo(
                    packageName  = pi.packageName,
                    appName      = pm.getApplicationLabel(ai).toString(),
                    icon         = safeIcon(pm, ai),
                    isSystemApp  = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                    apkPath      = ai.sourceDir,
                    versionName  = pi.versionName ?: "?",
                    apkSizeMb    = File(ai.sourceDir).length() / (1024f * 1024f)
                )
            } catch (_: Exception) { null }
        }.sortedWith(
            compareBy<AppInfo> { it.isSystemApp }.thenBy { it.appName.lowercase() }
        )
    }

    /**
     * Convert any Drawable (including AdaptiveIconDrawable on API 26+)
     * to a BitmapDrawable so Compose canvas can render it safely.
     * AdaptiveIconDrawable crashes when drawn directly via nativeCanvas.
     */
    private fun safeIcon(pm: PackageManager, ai: ApplicationInfo): Drawable? {
        return try {
            val raw = pm.getApplicationIcon(ai)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
                raw is AdaptiveIconDrawable) {
                toBitmap(raw)
            } else {
                raw
            }
        } catch (_: Exception) { null }
    }

    private fun toBitmap(d: Drawable): BitmapDrawable {
        val size = 192
        val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bmp)
        d.setBounds(0, 0, size, size)
        d.draw(canvas)
        return BitmapDrawable(ctx.resources, bmp)
    }
}

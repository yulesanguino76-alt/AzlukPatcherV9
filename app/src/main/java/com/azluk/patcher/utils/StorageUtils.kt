package com.azluk.patcher.utils

import android.os.Environment
import java.io.File

object StorageUtils {

    /**
     * Extensions the patcher emits. MUST include every container type
     * patchContainer()/patchInstalledWithSplits() can produce, or the
     * output never shows up in Patched Files.
     */
    private val PATCHED_EXTENSIONS =
        setOf("apk", "apks", "xapk", "apkm")

    fun getPatchedDir(): File {
        val dir = File(
            Environment.getExternalStorageDirectory(),
            "AzlukPatcher/Patched"
        )
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    fun getTempDir(): File {
        val dir = File(
            Environment.getExternalStorageDirectory(),
            "AzlukPatcher/Temp"
        )
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    /**
     * Deletes leftover scan/staging artifacts from the engine's cache
     * dir (azluk-scan-*, azul-v9-*, azul-container-*, imports/).
     */
    fun clearEngineArtifacts(cacheDir: File): Int {
        var deleted = 0
        cacheDir.listFiles()?.forEach { f ->
            if (f.name.startsWith("azluk-") ||
                f.name == "imports"
            ) {
                if (f.deleteRecursively()) deleted++
            }
        }
        return deleted
    }

    fun getPatchedFiles(): List<File> =
        getPatchedDir().listFiles()
            ?.filter { it.extension.lowercase() in PATCHED_EXTENSIONS }
            ?.sortedByDescending { it.lastModified() }
            ?: emptyList()
}

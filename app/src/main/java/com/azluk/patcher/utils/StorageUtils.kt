package com.azluk.patcher.utils

import android.os.Environment
import java.io.File

object StorageUtils {
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

    fun getPatchedFiles(): List<File> =
        getPatchedDir().listFiles()
            ?.filter { it.extension in listOf("apk", "xapk") }
            ?.sortedByDescending { it.lastModified() }
            ?: emptyList()
}

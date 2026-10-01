package com.azluk.patcher.engine

import android.content.Context
import android.os.Handler
import android.os.Looper
import com.azluk.patcher.core.PatchStatus
import com.azluk.patcher.core.PatchType
import com.azluk.patcher.core.ScanResult
import com.azluk.patcher.engine.sign.ApkSignerV2
import com.azluk.patcher.utils.StorageUtils
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.FilterOutputStream
import java.io.IOException
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.HashSet
import java.util.LinkedHashMap
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

/**
 * AzlukPatcher V9 - APK Engine
 *
 * Transactional pipeline:
 *
 *   INPUT -> ZIP validation -> staging
 *     -> DEX / manifest transformation
 *     -> repack + alignment (exact byte counter)
 *     -> signing -> verification -> atomic publication
 *
 * Alignment is computed from an exact byte counter flushed after every
 * entry: an offset that is off by one byte makes Android 12+ reject the
 * APK with a package parse error at install time.
 */
class ApkEngine(
    private val ctx: Context
) {

    companion object {
        private const val TAG = "AzlukEngineV9"

        private const val BUFFER_SIZE = 256 * 1024

        private const val MAX_ENTRY_SIZE =
            512L * 1024L * 1024L

        private const val MAX_MANIFEST_SIZE =
            8 * 1024 * 1024

        private const val MAX_CONTAINER_DEPTH = 1

        private val DEX_MAGIC = byteArrayOf(
            0x64,
            0x65,
            0x78,
            0x0a
        )
    }

    /**
     * Counts exactly how many bytes the ZipOutputStream has pushed into
     * the archive. After closeEntry() + flush(), count is the file offset
     * where the NEXT local file header will start — the number the
     * alignment math needs.
     */
    private class CountingOutputStream(
        out: OutputStream
    ) : FilterOutputStream(out) {

        var count: Long = 0
            private set

        override fun write(b: Int) {
            out.write(b)
            count++
        }

        override fun write(b: ByteArray?, off: Int, len: Int) {
            out.write(b, off, len)
            count += len
        }
    }

    fun interface Progress {
        fun on(message: String)
    }

    private val mainHandler =
        Handler(Looper.getMainLooper())

    private val signer by lazy {
        ApkSignerV2(ctx)
    }

    private fun emit(
        progress: Progress,
        message: String
    ) {
        mainHandler.post {
            progress.on(message)
        }
    }

    // -------------------------------------------------------------------------
    // Public APK API
    // -------------------------------------------------------------------------

    fun quickStatus(
        pkg: String
    ): PatchStatus {
        return try {
            val apk = File(
                ctx.packageManager
                    .getApplicationInfo(pkg, 0)
                    .sourceDir
            )

            val result = scanFile(apk)

            when {
                result.isEmpty() ->
                    PatchStatus.UNKNOWN

                result.size >= 3 ->
                    PatchStatus.PATCHABLE

                else ->
                    PatchStatus.LIKELY
            }
        } catch (_: Throwable) {
            PatchStatus.UNKNOWN
        }
    }

    fun quickCount(
        pkg: String
    ): Int {
        return try {
            val apk = File(
                ctx.packageManager
                    .getApplicationInfo(pkg, 0)
                    .sourceDir
            )

            scanFile(apk).size
        } catch (_: Throwable) {
            0
        }
    }

    fun scan(
        pkg: String
    ): List<ScanResult> {
        val apk = File(
            ctx.packageManager
                .getApplicationInfo(pkg, 0)
                .sourceDir
        )

        return scanFile(apk)
    }

    fun patch(
        pkg: String,
        patches: List<PatchType>,
        progress: Progress
    ): File {
        val input = File(
            ctx.packageManager
                .getApplicationInfo(pkg, 0)
                .sourceDir
        )

        val output = File(
            StorageUtils.getPatchedDir(),
            "${pkg}_azluk.apk"
        )

        patchToDisk(
            input,
            output,
            patches,
            progress
        )

        return output
    }

    fun patchExternal(
        input: File,
        patches: List<PatchType>,
        progress: Progress
    ): File {
        require(input.exists()) {
            "Input file does not exist: ${input.absolutePath}"
        }

        val extension =
            input.extension.lowercase()

        return when (extension) {
            "xapk",
            "apkm",
            "apks" -> {
                val output = File(
                    StorageUtils.getPatchedDir(),
                    "${input.nameWithoutExtension}_azluk.$extension"
                )

                patchContainer(
                    input,
                    output,
                    patches,
                    progress
                )

                output
            }

            "apk" -> {
                val output = File(
                    StorageUtils.getPatchedDir(),
                    "${input.nameWithoutExtension}_azluk.apk"
                )

                patchToDisk(
                    input,
                    output,
                    patches,
                    progress
                )

                output
            }

            else -> {
                throw IllegalArgumentException(
                    "Unsupported input type: .$extension"
                )
            }
        }
    }

    // -------------------------------------------------------------------------
    // External scanning (APK / XAPK / APKM / APKS)
    // -------------------------------------------------------------------------

    fun scanExternal(
        input: File
    ): List<ScanResult> {
        require(input.exists()) {
            "Input file does not exist: ${input.absolutePath}"
        }

        return when (input.extension.lowercase()) {
            "apk" -> scanFile(input)

            "xapk",
            "apkm",
            "apks" -> scanContainer(input)

            else -> throw IllegalArgumentException(
                "Unsupported input type: .${input.extension}"
            )
        }
    }

    /**
     * Scans a split-APK container without extracting it. Keys are unioned
     * across splits — a patch found in ANY split is offered once for the
     * whole container.
     */
    fun scanContainer(
        input: File
    ): List<ScanResult> {
        val union =
            LinkedHashMap<String, ScanResult>()

        var apkCount = 0

        ZipInputStream(
            BufferedInputStream(
                FileInputStream(input),
                BUFFER_SIZE
            )
        ).use { zip ->

            while (true) {
                val entry =
                    zip.nextEntry ?: break

                if (!entry.isDirectory &&
                    entry.name.endsWith(".apk", true)
                ) {
                    apkCount++

                    val tmp = File(
                        ctx.cacheDir,
                        "azluk-scan-${System.nanoTime()}.apk"
                    )

                    try {
                        copyZipEntryToFile(
                            zip,
                            tmp
                        )

                        for (r in scanFile(tmp)) {
                            union.putIfAbsent(
                                r.patchType,
                                r
                            )
                        }
                    } finally {
                        tmp.delete()
                    }
                } else {
                    drain(zip)
                }

                zip.closeEntry()
            }
        }

                if (apkCount == 0) {
            throw IOException(
                "Container contains no APK files"
            )
        }

        return union.values.toList() + ScanResult(
            "OPTIMIZE_ZIP",
            "Repack-level optimization, always available",
            -1,
            0
        )
    }

    // -------------------------------------------------------------------------
    // APK patching
    // -------------------------------------------------------------------------

    private fun patchToDisk(
        input: File,
        output: File,
        patches: List<PatchType>,
        progress: Progress
    ) {
        require(input.length() > 0L) {
            "Input APK is empty"
        }

        output.parentFile?.mkdirs()

        val workRoot = File(
            ctx.cacheDir,
            "azluk-v9-${System.nanoTime()}"
        )

        val staged = File(workRoot, "entries")
        val unsigned = File(workRoot, "unsigned.apk")
        val signed = File(workRoot, "signed.apk")

        workRoot.mkdirs()
        staged.mkdirs()

        try {
            emit(progress, "Phase 1/6 — validating APK")

            val entries = stageApk(input, staged, progress)

            emit(progress, "Phase 2/6 — transforming entries")
            transformEntries(entries, patches, progress)

            emit(progress, "Phase 3/6 — repacking and aligning")
            repack(entries, unsigned)

            emit(progress, "Phase 4/6 — signing")
            signer.signApk(unsigned, signed)

            emit(progress, "Phase 5/6 — verifying signature")

            val verification = signer.verify(signed)

            if (!verification.verified) {
                throw SecurityException("Self-verification failed")
            }

            if (!verification.v2 && !verification.v3) {
                throw SecurityException(
                    "No valid V2/V3 signature after signing"
                )
            }

            emit(
                progress,
                "Signature OK — V1=${verification.v1}, " +
                        "V2=${verification.v2}, V3=${verification.v3}"
            )

            emit(progress, "Phase 6/6 — publishing atomically")
            atomicPublish(signed, output)

            emit(
                progress,
                "[SUCCESS] ${output.name} (${formatSize(output.length())})"
            )
        } finally {
            workRoot.deleteRecursively()
        }
    }

    // -------------------------------------------------------------------------
    // ZIP staging
    // -------------------------------------------------------------------------

    private data class StagedEntry(
        val name: String,
        val file: File,
        val directory: Boolean,
        val originalMethod: Int
    )

    private fun stageApk(
        input: File,
        staging: File,
        progress: Progress
    ): List<StagedEntry> {
        val result = ArrayList<StagedEntry>()
        val names = HashSet<String>()

        ZipInputStream(
            BufferedInputStream(
                FileInputStream(input),
                BUFFER_SIZE
            )
        ).use { zip ->

            while (true) {
                val entry = zip.nextEntry ?: break

                validateEntryName(entry.name)

                if (!names.add(entry.name)) {
                    throw IOException(
                        "Duplicate ZIP entry: ${entry.name}"
                    )
                }

                if (isSignatureEntry(entry.name)) {
                    drain(zip)
                    zip.closeEntry()
                    continue
                }

                if (entry.isDirectory) {
                    result.add(
                        StagedEntry(
                            entry.name,
                            File(staging, safeFileName(entry.name)),
                            true,
                            entry.method
                        )
                    )

                    zip.closeEntry()
                    continue
                }

                val target =
                    File(staging, safeFileName(entry.name))

                target.parentFile?.mkdirs()

                copyZipEntryToFile(zip, target)

                result.add(
                    StagedEntry(
                        entry.name,
                        target,
                        false,
                        entry.method
                    )
                )

                emit(progress, "  staged ${entry.name}")

                zip.closeEntry()
            }
        }

        if (result.none { it.name == "AndroidManifest.xml" }) {
            throw IOException("APK has no AndroidManifest.xml")
        }

        if (result.none { it.name.endsWith(".dex", true) }) {
            throw IOException("APK contains no DEX files")
        }

        return result
    }

    private fun copyZipEntryToFile(
        input: ZipInputStream,
        output: File
    ) {
        var total = 0L

        FileOutputStream(output).use { out ->
            val buffer = ByteArray(BUFFER_SIZE)

            while (true) {
                val read = input.read(buffer)

                if (read == -1) {
                    break
                }

                total += read

                if (total > MAX_ENTRY_SIZE) {
                    throw IOException(
                        "ZIP entry exceeds maximum allowed size: " +
                                output.name
                    )
                }

                out.write(buffer, 0, read)
            }
        }
    }

    // -------------------------------------------------------------------------
    // Transformations
    // -------------------------------------------------------------------------

    private fun transformEntries(
        entries: List<StagedEntry>,
        patches: List<PatchType>,
        progress: Progress
    ) {
        val keys = patches.map { it.key }.toHashSet()

        val manifestKeys = setOf(
            "FORCE_DEBUGGABLE",
            "EXPORT_ALL_COMPONENTS",
            "ALLOW_BACKUP"
        )

        val manifest = entries.firstOrNull {
            it.name == "AndroidManifest.xml"
        }

        if (manifest != null && keys.any { it in manifestKeys }) {
            emit(progress, "  patching AndroidManifest.xml")

            val bytes = manifest.file.readBytes()

            manifest.file.writeBytes(
                SuperDexPatcher.patchManifest(bytes, keys)
            )
        }

        val dexEntries = entries.filter {
            !it.directory && it.name.endsWith(".dex", true)
        }

        if (dexEntries.isEmpty()) {
            return
        }

        val executor = Executors.newFixedThreadPool(
            minOf(
                4,
                maxOf(1, Runtime.getRuntime().availableProcessors())
            )
        )

        try {
            val futures = dexEntries.map { entry ->
                executor.submit(Callable {
                    emit(progress, "  patching ${entry.name}")

                    val original = entry.file.readBytes()

                    require(isDex(original)) {
                        "${entry.name} has invalid DEX magic"
                    }

                    val transformed = SuperDexPatcher.patch(
                        original,
                        keys
                    ) { message ->
                        emit(progress, "${entry.name}: $message")
                    }

                    if (!original.contentEquals(transformed)) {
                        entry.file.writeBytes(transformed)
                        emit(progress, "  ${entry.name}: changed")
                    } else {
                        emit(progress, "  ${entry.name}: no changes")
                    }
                })
            }

            futures.forEach { it.get() }
        } finally {
            executor.shutdown()

            if (!executor.awaitTermination(10, TimeUnit.MINUTES)) {
                executor.shutdownNow()

                if (!executor.awaitTermination(30, TimeUnit.SECONDS)) {
                    throw IOException("DEX executor did not terminate")
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // ZIP repacking — EXACT alignment
    // -------------------------------------------------------------------------

    private fun repack(
        entries: List<StagedEntry>,
        output: File
    ) {
        output.parentFile?.mkdirs()

        /*
         * ZipOutputStream -> CountingOutputStream -> disk.
         *
         * After every closeEntry() the counting stream holds EXACTLY the
         * number of bytes written so far, so counting.count is the file
         * offset where the next local file header will start. Alignment
         * extras computed from it are byte-perfect — the old
         * approximateOffset (uncompressed size for DEFLATED entries)
         * produced misaligned resources.arsc, and Android 12+ rejects
         * such APKs with a package parse error.
         */
        val counting = CountingOutputStream(
            FileOutputStream(output)
        )

        ZipOutputStream(counting).use { zip ->
            zip.setComment("Patched by AzlukPatcher V9")

            for (entry in entries) {
                if (entry.directory) {
                    zip.putNextEntry(
                        ZipEntry(ensureDirectoryName(entry.name))
                    )
                    zip.closeEntry()
                    continue
                }

                val dataIsStored = shouldStore(entry.name)
                val entryNameBytes =
                    entry.name.toByteArray(StandardCharsets.UTF_8)

                val zipEntry = ZipEntry(entry.name)

                if (dataIsStored) {
                    val size = entry.file.length()
                    val crc = crc32(entry.file)

                    zipEntry.method = ZipEntry.STORED
                    zipEntry.size = size
                    zipEntry.compressedSize = size
                    zipEntry.crc = crc

                    zipEntry.extra = createAlignmentExtra(
                        counting.count,
                        entryNameBytes.size,
                        alignmentFor(entry.name)
                    )
                } else {
                    zipEntry.method = ZipEntry.DEFLATED
                }

                zip.putNextEntry(zipEntry)

                entry.file.inputStream()
                    .buffered(BUFFER_SIZE)
                    .use { input ->
                        input.copyTo(zip, BUFFER_SIZE)
                    }

                zip.closeEntry()
                zip.flush()
            }
        }
    }

    private fun createAlignmentExtra(
        currentOffset: Long,
        nameLength: Int,
        alignment: Int
    ): ByteArray? {
        if (alignment <= 1) {
            return null
        }

        /*
         * Local file header = 30 bytes fixed + name.
         */
        val base = currentOffset + 30L + nameLength

        var extraLength =
            ((alignment - (base % alignment)) % alignment).toInt()

        if (extraLength == 0) {
            return null
        }

        /*
         * Extra fields need at least 4 bytes: header-id u16 + size u16.
         */
        if (extraLength < 4) {
            extraLength += alignment
        }

        if (extraLength > 65535) {
            throw IOException(
                "ZIP alignment extra field is too large"
            )
        }

        val dataLength = extraLength - 4
        val extra = ByteArray(extraLength)

        extra[0] = 0x99.toByte()
        extra[1] = 0x99.toByte()
        extra[2] = (dataLength and 0xff).toByte()
        extra[3] = ((dataLength ushr 8) and 0xff).toByte()

        return extra
    }

    private fun shouldStore(name: String): Boolean {
        return name.equals("resources.arsc", ignoreCase = true) ||
                name.endsWith(".so", ignoreCase = true)
    }

    private fun alignmentFor(name: String): Int {
        return if (name.endsWith(".so", ignoreCase = true)) {
            16 * 1024
        } else {
            4
        }
    }

    // -------------------------------------------------------------------------
    // XAPK/APKM/APKS patching
    // -------------------------------------------------------------------------

    private fun patchContainer(
        input: File,
        output: File,
        patches: List<PatchType>,
        progress: Progress
    ): File {
        val root = File(
            ctx.cacheDir,
            "azluk-container-${System.nanoTime()}"
        )

        val extracted = File(root, "extracted")
        val patchedDir = File(root, "patched")

        root.mkdirs()
        extracted.mkdirs()
        patchedDir.mkdirs()

        try {
            emit(progress, "Container: ${input.name}")

            val files = extractContainer(input, extracted)

            val apkFiles = files.filter {
                it.extension.equals("apk", true)
            }

            if (apkFiles.isEmpty()) {
                throw IOException("Container contains no APK files")
            }

            for (apk in apkFiles) {
                val relativePath = apk.relativeTo(extracted)
                val destination = File(patchedDir, relativePath.path)

                destination.parentFile?.mkdirs()

                emit(progress, "Patching container APK: ${apk.name}")

                patchToDisk(apk, destination, patches, progress)
            }

            val unchanged = files.filter {
                !it.extension.equals("apk", true)
            }

            for (file in unchanged) {
                val relativePath = file.relativeTo(extracted)
                val destination = File(patchedDir, relativePath.path)

                destination.parentFile?.mkdirs()

                Files.copy(
                    file.toPath(),
                    destination.toPath(),
                    StandardCopyOption.REPLACE_EXISTING
                )
            }

            repackContainer(patchedDir, output)

            return output
        } finally {
            root.deleteRecursively()
        }
    }

    private fun extractContainer(
        input: File,
        root: File
    ): List<File> {
        val result = ArrayList<File>()

        ZipInputStream(
            BufferedInputStream(
                FileInputStream(input),
                BUFFER_SIZE
            )
        ).use { zip ->

            while (true) {
                val entry = zip.nextEntry ?: break

                validateEntryName(entry.name)

                val destination = File(root, entry.name)

                if (entry.isDirectory) {
                    destination.mkdirs()
                } else {
                    destination.parentFile?.mkdirs()

                    copyZipEntryToFile(zip, destination)

                    result.add(destination)
                }

                zip.closeEntry()
            }
        }

        return result
    }

    private fun repackContainer(
        root: File,
        output: File
    ) {
        output.parentFile?.mkdirs()

        ZipOutputStream(
            BufferedOutputStream(
                FileOutputStream(output),
                BUFFER_SIZE
            )
        ).use { zip ->
            zip.setComment("Patched by AzlukPatcher V9")

            val files = root.walkTopDown()
                .filter { it.isFile }
                .toList()

            for (file in files) {
                val name = file.relativeTo(root)
                    .path
                    .replace(File.separatorChar, '/')

                val entry = ZipEntry(name)
                entry.method = ZipEntry.DEFLATED

                zip.putNextEntry(entry)

                file.inputStream()
                    .buffered(BUFFER_SIZE)
                    .use { input ->
                        input.copyTo(zip, BUFFER_SIZE)
                    }

                zip.closeEntry()
            }
        }
    }

    // -------------------------------------------------------------------------
    // Scanner
    // -------------------------------------------------------------------------

    fun scanFile(
        apk: File
    ): List<ScanResult> {
        val result = ArrayList<ScanResult>()

        var dexIndex = 0

        ZipInputStream(
            BufferedInputStream(
                FileInputStream(apk),
                BUFFER_SIZE
            )
        ).use { zip ->

            while (true) {
                val entry = zip.nextEntry ?: break

                when {
                    entry.name.endsWith(".dex", true) -> {
                        val matches =
                            SuperDexPatcher.quickScan(zip)

                        for (match in matches) {
                            result.add(
                                ScanResult(
                                    match[0],
                                    match.getOrNull(1),
                                    dexIndex,
                                    0
                                )
                            )
                        }

                        dexIndex++
                    }

                    entry.name.equals(
                        "AndroidManifest.xml",
                        true
                    ) -> {
                        val bytes = readEntryBounded(
                            zip,
                            MAX_MANIFEST_SIZE
                        )

                        for (key in SuperDexPatcher.scanManifestKeys(bytes)) {
                            result.add(
                                ScanResult(
                                    key,
                                    "Manifest attribute patchable",
                                    -1,
                                    0
                                )
                            )
                        }
                    }

                    else -> drain(zip)
                }

                zip.closeEntry()
            }
        }

        result.add(
            ScanResult(
                "OPTIMIZE_ZIP",
                "Repack-level optimization, always available",
                -1,
                0
            )
        )

        return result
            .distinctBy { "${it.patchType}:${it.desc}" }
    }

    private fun readEntryBounded(
        input: ZipInputStream,
        max: Int
    ): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(BUFFER_SIZE)

        var total = 0

        while (true) {
            val read = input.read(buffer)

            if (read == -1) {
                break
            }

            total += read

            if (total > max) {
                throw IOException(
                    "Manifest exceeds maximum scan size"
                )
            }

            out.write(buffer, 0, read)
        }

        return out.toByteArray()
    }

    // -------------------------------------------------------------------------
    // ZIP safety
    // -------------------------------------------------------------------------

    private fun validateEntryName(name: String) {
        require(name.isNotBlank()) {
            "ZIP contains an empty entry name"
        }

        require(!name.startsWith("/")) {
            "Absolute ZIP path is forbidden: $name"
        }

        require(!name.contains("\\")) {
            "Backslash path is forbidden: $name"
        }

        val parts = name.split('/')

        require(parts.none { it == ".." }) {
            "Path traversal detected: $name"
        }
    }

    private fun safeFileName(name: String): String {
        return name
            .replace('/', '_')
            .replace(':', '_')
    }

    private fun ensureDirectoryName(name: String): String {
        return if (name.endsWith('/')) name else "$name/"
    }

    private fun isSignatureEntry(name: String): Boolean {
        if (!name.startsWith("META-INF/", true)) {
            return false
        }

        return name.endsWith(".SF", true) ||
                name.endsWith(".RSA", true) ||
                name.endsWith(".DSA", true) ||
                name.endsWith(".EC", true) ||
                name.endsWith(".MF", true)
    }

    private fun drain(input: ZipInputStream) {
        val buffer = ByteArray(BUFFER_SIZE)

        while (input.read(buffer) != -1) {
            // intentionally drained
        }
    }

    // -------------------------------------------------------------------------
    // Verification/helpers
    // -------------------------------------------------------------------------

    private fun atomicPublish(
        source: File,
        destination: File
    ) {
        destination.parentFile?.mkdirs()

        try {
            Files.move(
                source.toPath(),
                destination.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING
            )
        } catch (_: Exception) {
            Files.move(
                source.toPath(),
                destination.toPath(),
                StandardCopyOption.REPLACE_EXISTING
            )
        }
    }

    private fun isDex(data: ByteArray): Boolean {
        return data.size >= 8 &&
                data[0] == DEX_MAGIC[0] &&
                data[1] == DEX_MAGIC[1] &&
                data[2] == DEX_MAGIC[2] &&
                data[3] == DEX_MAGIC[3]
    }

    private fun crc32(file: File): Long {
        val crc = CRC32()

        file.inputStream()
            .buffered(BUFFER_SIZE)
            .use { input ->
                val buffer = ByteArray(BUFFER_SIZE)

                while (true) {
                    val read = input.read(buffer)

                    if (read == -1) {
                        break
                    }

                    crc.update(buffer, 0, read)
                }
            }

        return crc.value
    }

    private fun formatSize(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"

            bytes < 1024L * 1024L ->
                "%.1f KB".format(bytes / 1024.0)

            bytes < 1024L * 1024L * 1024L ->
                "%.1f MB".format(bytes / (1024.0 * 1024.0))

            else ->
                "%.2f GB".format(bytes / (1024.0 * 1024.0 * 1024.0))
        }
    }
}


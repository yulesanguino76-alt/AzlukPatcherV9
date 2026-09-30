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
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

/**
 * AzlukPatcher V9 - APK Engine
 *
 * Transactional, streaming pipeline:
 *
 *   INPUT
 *     |
 *     v
 *   analyze (ZipFile central directory, no decompression)
 *     - entry names validated (traversal / absolute / backslash)
 *     - duplicate names -> hard failure
 *     - signature entries dropped from the plan
 *     - per-entry size cap checked before any work
 *     - AndroidManifest.xml + >= 1 DEX required
 *     |
 *     v
 *   transform (second pass, only requested entries hit disk)
 *     - manifest staged only if a manifest key applies
 *     - DEX staged only if a DEX key applies (bounded staging)
 *     - unchanged artifacts are removed and the original is streamed
 *     |
 *     v
 *   repack + align (third pass, entries stream input -> output)
 *     - exact byte counter flushed after every closeEntry
 *     - STORED: resources.arsc @ 4, native libs @ 4096/16384
 *     - unknown-size STORED entries spool to disk before header write
 *     - plan/lockstep order check, mismatch -> explicit IOException
 *     |
 *     v
 *   signing (apksig V1/V2/V3, device-local Keystore key)
 *     |
 *     v
 *   signature verification (self-check before publication)
 *     |
 *     v
 *   atomic publication
 *
 * The destination is never modified before the whole pipeline succeeds.
 * No execution path can produce a silently broken APK: every transform
 * that cannot be proven valid throws instead of returning the original.
 */
class ApkEngine(
    private val ctx: Context
) {

    companion object {
        private const val TAG = "AzlukEngineV9"

        private const val BUFFER_SIZE = 256 * 1024

        /** Hard cap for any single materialized entry. */
        private const val MAX_ENTRY_SIZE =
            512L * 1024L * 1024L

        /** Hard cap for everything staged on disk in one run. */
        private const val MAX_STAGED_TOTAL =
            1024L * 1024L * 1024L

        private const val MAX_CONTAINER_DEPTH = 1

        private val DEX_MAGIC = byteArrayOf(
            0x64, 0x65, 0x78, 0x0a
        )

        /** Patch keys that are satisfied by binary XML surgery alone. */
        private val MANIFEST_KEYS = setOf(
            "FORCE_DEBUGGABLE",
            "EXPORT_ALL_COMPONENTS",
            "ALLOW_BACKUP"
        )
    }

    fun interface Progress {
        fun on(message: String)
    }

    private val mainHandler =
        Handler(Looper.getMainLooper())

    private val signer by lazy {
        ApkSignerV2(ctx)
    }

    /**
     * Serialized progress: every emit funnels through the main looper,
     * so worker threads can log without interleaving partial lines.
     */
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
    // Pipeline
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

        val staging = File(workRoot, "staged")
        val unsigned = File(workRoot, "unsigned.apk")
        val signed = File(workRoot, "signed.apk")

        workRoot.mkdirs()
        staging.mkdirs()

        try {
            emit(progress, "Phase 1/6 — analyzing APK structure")

            val plan = analyze(input, progress)

            emit(progress, "Phase 2/6 — transforming entries")

            val replacements = transform(
                input,
                patches,
                staging,
                progress
            )

            emit(progress, "Phase 3/6 — repacking and aligning")

            repack(
                input,
                plan,
                replacements,
                unsigned,
                staging,
                progress
            )

            emit(progress, "Phase 4/6 — signing")

            signer.signApk(unsigned, signed)

            emit(progress, "Phase 5/6 — verifying signature")

            val verification = signer.verify(signed)

            if (!verification.verified) {
                throw SecurityException(
                    "Self-verification failed — output withheld"
                )
            }

            if (!verification.v2 && !verification.v3) {
                throw SecurityException(
                    "No valid V2/V3 signature after signing"
                )
            }

            emit(
                progress,
                "Signature OK — V1=${verification.v1}, " +
                        "V2=${verification.v2}, " +
                        "V3=${verification.v3}"
            )

            emit(progress, "Phase 6/6 — publishing atomically")

            atomicPublish(signed, output)

            emit(
                progress,
                "[SUCCESS] ${output.name} " +
                        "(${formatSize(output.length())})"
            )
        } finally {
            /*
             * Temp files die here on success and on failure alike.
             * Publication already happened (or never will).
             */
            workRoot.deleteRecursively()
        }
    }

    // -------------------------------------------------------------------------
    // Pass 1: analyze (central directory, zero decompression)
    // -------------------------------------------------------------------------

    private data class PlanEntry(
        val name: String,
        val directory: Boolean
    )

    private fun analyze(
        input: File,
        progress: Progress
    ): List<PlanEntry> {
        val plan = ArrayList<PlanEntry>()
        val names = HashSet<String>()
        var hasManifest = false
        var dexCount = 0

        ZipFile(input).use { zipFile ->
            val entries = zipFile.entries()

            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()

                validateEntryName(entry.name)

                if (!names.add(entry.name)) {
                    throw IOException(
                        "Duplicate ZIP entry: ${entry.name}"
                    )
                }

                /*
                 * Old signatures are dropped from the plan; the repack
                 * pass skips them with the same predicate.
                 */
                if (isSignatureEntry(entry.name)) {
                    continue
                }

                if (entry.isDirectory) {
                    plan.add(
                        PlanEntry(entry.name, true)
                    )
                    continue
                }

                if (entry.size > MAX_ENTRY_SIZE) {
                    throw IOException(
                        "ZIP entry exceeds maximum allowed size: " +
                                "${entry.name} (${entry.size} bytes)"
                    )
                }

                if (entry.name == "AndroidManifest.xml") {
                    hasManifest = true
                }

                if (entry.name.endsWith(".dex", true)) {
                    dexCount++
                }

                plan.add(
                    PlanEntry(entry.name, false)
                )
            }
        }

        if (!hasManifest) {
            throw IOException("APK has no AndroidManifest.xml")
        }

        if (dexCount == 0) {
            throw IOException("APK contains no DEX files")
        }

        emit(
            progress,
            "  ${plan.size} entries, $dexCount DEX, manifest OK"
        )

        return plan
    }

    // -------------------------------------------------------------------------
    // Pass 2: transform (stage only what the recipes can touch)
    // -------------------------------------------------------------------------

    private fun transform(
        input: File,
        patches: List<PatchType>,
        staging: File,
        progress: Progress
    ): Map<String, File> {
        val keys =
            patches.map { it.key }.toHashSet()

        if (keys.isEmpty()) {
            return emptyMap()
        }

        val needManifest =
            keys.any { it in MANIFEST_KEYS }

        val needDex =
            keys.any { it !in MANIFEST_KEYS }

        if (!needManifest && !needDex) {
            return emptyMap()
        }

        /*
         * Concurrent because the DEX pool removes unchanged entries
         * from it while the manifest path runs on this thread.
         */
        val replacements = ConcurrentHashMap<String, File>()
        var stagedBytes = 0L

        ZipInputStream(
            BufferedInputStream(
                FileInputStream(input),
                BUFFER_SIZE
            )
        ).use { zip ->

            while (true) {
                val entry = zip.nextEntry ?: break

                if (isSignatureEntry(entry.name)) {
                    drain(zip)
                    zip.closeEntry()
                    continue
                }

                val stageManifest =
                    needManifest &&
                            !entry.isDirectory &&
                            entry.name == "AndroidManifest.xml"

                val stageDex =
                    needDex &&
                            !entry.isDirectory &&
                            entry.name.endsWith(".dex", true)

                if (!stageManifest && !stageDex) {
                    drain(zip)
                    zip.closeEntry()
                    continue
                }

                if (stagedBytes >= MAX_STAGED_TOTAL) {
                    throw IOException(
                        "Staging budget exhausted: " +
                                "$stagedBytes bytes materialized"
                    )
                }

                val target = File(
                    staging,
                    safeFileName(entry.name)
                )

                target.parentFile?.mkdirs()

                stagedBytes += copyZipEntryToFile(zip, target)

                if (stagedBytes > MAX_STAGED_TOTAL) {
                    throw IOException(
                        "Staging budget exceeded by ${entry.name}"
                    )
                }

                replacements[entry.name] = target

                emit(progress, "  staged ${entry.name}")

                zip.closeEntry()
            }
        }

        // ---- binary XML -----------------------------------------------------

        val manifestFile =
            replacements["AndroidManifest.xml"]

        if (manifestFile != null) {
            emit(progress, "  patching AndroidManifest.xml")

            val original = manifestFile.readBytes()
            val transformed = SuperDexPatcher.patchManifest(
                original,
                keys
            )

            if (original.contentEquals(transformed)) {
                /*
                 * Untouched manifest: drop the staged copy so the
                 * repack pass streams the original bytes instead.
                 */
                manifestFile.delete()
                replacements.remove("AndroidManifest.xml")

                emit(progress, "  AndroidManifest.xml: no changes")
            } else {
                manifestFile.writeBytes(transformed)

                emit(progress, "  AndroidManifest.xml: changed")
            }
        }

        // ---- DEX ------------------------------------------------------------

        val dexReplacements = replacements.filterKeys {
            it.endsWith(".dex", true)
        }

        if (dexReplacements.isEmpty()) {
            return replacements
        }

        val executor = Executors.newFixedThreadPool(
            minOf(
                4,
                maxOf(
                    1,
                    Runtime.getRuntime().availableProcessors()
                )
            )
        )

        try {
            val futures = dexReplacements.map { (name, file) ->

                executor.submit(
                    Callable {

                        emit(progress, "  patching $name")

                        val original = file.readBytes()

                        if (!isDex(original)) {
                            throw IOException(
                                "$name has invalid DEX magic"
                            )
                        }

                        val transformed =
                            SuperDexPatcher.patch(
                                original,
                                keys
                            ) { message ->
                                emit(
                                    progress,
                                    "$name: $message"
                                )
                            }

                        if (original.contentEquals(transformed)) {
                            file.delete()
                            replacements.remove(name)

                            emit(
                                progress,
                                "  $name: no changes"
                            )
                        } else {
                            file.writeBytes(transformed)

                            emit(
                                progress,
                                "  $name: changed"
                            )
                        }
                    }
                )
            }

            /*
             * A failed patch surfaces here as ExecutionException —
             * loud, before a single byte reaches the output zip.
             */
            futures.forEach { it.get() }
        } finally {
            executor.shutdown()

            if (!executor.awaitTermination(
                    10,
                    TimeUnit.MINUTES
                )
            ) {
                executor.shutdownNow()

                if (!executor.awaitTermination(
                        30,
                        TimeUnit.SECONDS
                    )
                ) {
                    throw IOException(
                        "DEX executor did not terminate"
                    )
                }
            }
        }

        return replacements
    }

    // -------------------------------------------------------------------------
    // Pass 3: repack + align (stream, exact offsets)
    // -------------------------------------------------------------------------

    /**
     * Byte counter sitting between the ZipOutputStream's buffer and the
     * file. After closeEntry() + flush() it holds the exact offset of the
     * next local file header — the only value alignment math may trust.
     */
    private class CountingOutputStream(
        inner: OutputStream
    ) : FilterOutputStream(inner) {

        var count: Long = 0L
            private set

        override fun write(b: Int) {
            out.write(b)
            count++
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            out.write(b, off, len)
            count += len
        }
    }

    private fun repack(
        input: File,
        plan: List<PlanEntry>,
        replacements: Map<String, File>,
        output: File,
        staging: File,
        progress: Progress
    ) {
        output.parentFile?.mkdirs()

        val counting = CountingOutputStream(
            FileOutputStream(output)
        )

        val buffered = BufferedOutputStream(
            counting,
            BUFFER_SIZE
        )

        var index = 0
        var processed = 0

        ZipOutputStream(buffered).use { out ->

            ZipInputStream(
                BufferedInputStream(
                    FileInputStream(input),
                    BUFFER_SIZE
                )
            ).use { zip ->

                while (true) {
                    val entry = zip.nextEntry ?: break

                    if (isSignatureEntry(entry.name)) {
                        drain(zip)
                        zip.closeEntry()
                        continue
                    }

                    val planned = plan.getOrNull(index)
                        ?: throw IOException(
                            "ZIP has more entries than the plan: " +
                                    entry.name
                        )

                    if (planned.name != entry.name) {
                        throw IOException(
                            "ZIP entry order changed — expected " +
                                    "${planned.name}, got ${entry.name}"
                        )
                    }

                    index++

                    // ---- directories ---------------------------------------

                    if (planned.directory || entry.isDirectory) {
                        out.putNextEntry(
                            ZipEntry(
                                ensureDirectoryName(entry.name)
                            )
                        )
                        out.closeEntry()
                        buffered.flush()
                        continue
                    }

                    val replacement =
                        replacements[entry.name]

                    val nameBytes = entry.name.toByteArray(
                        StandardCharsets.UTF_8
                    )

                    // ---- STORED + alignment --------------------------------

                    if (shouldStore(entry.name)) {
                        val alignment =
                            alignmentFor(entry.name)

                        val extra = createAlignmentExtra(
                            counting.count,
                            nameBytes.size,
                            alignment
                        )

                        when {
                            replacement != null -> {
                                val size = replacement.length()
                                val crc = crc32(replacement)

                                out.putNextEntry(
                                    storedEntry(
                                        entry.name,
                                        size,
                                        crc,
                                        extra
                                    )
                                )

                                replacement
                                    .inputStream()
                                    .buffered(BUFFER_SIZE)
                                    .use { src ->
                                        src.copyTo(
                                            out,
                                            BUFFER_SIZE
                                        )
                                    }
                            }

                            entry.method == ZipEntry.STORED &&
                                    entry.size >= 0L &&
                                    entry.crc >= 0L -> {
                                /*
                                 * Sizes live in the local header —
                                 * stream straight through, no copy.
                                 */
                                out.putNextEntry(
                                    storedEntry(
                                        entry.name,
                                        entry.size,
                                        entry.crc,
                                        extra
                                    )
                                )

                                zip.copyTo(out, BUFFER_SIZE)
                            }

                            else -> {
                                /*
                                 * Data-descriptor STORED entry: size and
                                 * CRC are unknown until the last byte.
                                 * Spool, compute, then write the header —
                                 * guessing here is how zips get corrupt.
                                 */
                                val spool = File(
                                    staging,
                                    "spool_${safeFileName(entry.name)}"
                                )

                                spool.parentFile?.mkdirs()

                                copyZipEntryToFile(zip, spool)

                                val size = spool.length()
                                val crc = crc32(spool)

                                out.putNextEntry(
                                    storedEntry(
                                        entry.name,
                                        size,
                                        crc,
                                        extra
                                    )
                                )

                                spool
                                    .inputStream()
                                    .buffered(BUFFER_SIZE)
                                    .use { src ->
                                        src.copyTo(
                                            out,
                                            BUFFER_SIZE
                                        )
                                    }

                                spool.delete()
                            }
                        }

                        out.closeEntry()
                        buffered.flush()

                    } else {
                        // ---- DEFLATED --------------------------------------

                        val zipEntry = ZipEntry(entry.name)
                        zipEntry.method = ZipEntry.DEFLATED

                        out.putNextEntry(zipEntry)

                        if (replacement != null) {
                            replacement
                                .inputStream()
                                .buffered(BUFFER_SIZE)
                                .use { src ->
                                    src.copyTo(out, BUFFER_SIZE)
                                }
                        } else {
                            /*
                             * The hot path: bytes bounce from the input
                             * inflater straight into the output deflater,
                             * never touching the heap as a whole.
                             */
                            zip.copyTo(out, BUFFER_SIZE)
                        }

                        out.closeEntry()
                        buffered.flush()
                    }

                    processed++

                    if (processed % 25 == 0) {
                        emit(
                            progress,
                            "  repacked $processed/${plan.size}"
                        )
                    }
                }
            }

            if (index != plan.size) {
                throw IOException(
                    "ZIP entry count changed during repack — " +
                            "planned ${plan.size}, saw $index"
                )
            }
        }

        emit(
            progress,
            "  repacked $processed entries, " +
                    "alignments from exact offsets"
        )
    }

    private fun storedEntry(
        name: String,
        size: Long,
        crc: Long,
        extra: ByteArray?
    ): ZipEntry {
        val entry = ZipEntry(name)

        entry.method = ZipEntry.STORED
        entry.size = size
        entry.compressedSize = size
        entry.crc = crc
        entry.extra = extra

        return entry
    }

    /**
     * Local header is 30 bytes; data begins at
     * offset + 30 + nameLen + extraLen. Pad the extra field so that
     * value lands on the alignment boundary.
     */
    private fun createAlignmentExtra(
        currentOffset: Long,
        nameLength: Int,
        alignment: Int
    ): ByteArray? {
        if (alignment <= 1) {
            return null
        }

        val base =
            currentOffset +
                    30L +
                    nameLength

        var extraLength =
            ((alignment -
                    (base % alignment)) %
                    alignment).toInt()

        if (extraLength == 0) {
            // Already aligned — an empty extra would only shift it.
            return null
        }

        /*
         * Extra fields need at least four bytes:
         *   header-id u16
         *   data-size u16
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

        // Private padding field id.
        extra[0] = 0x99.toByte()
        extra[1] = 0x99.toByte()
        extra[2] = (dataLength and 0xff).toByte()
        extra[3] = ((dataLength ushr 8) and 0xff).toByte()

        return extra
    }

    private fun shouldStore(name: String): Boolean {
        return name.equals(
            "resources.arsc",
            ignoreCase = true
        ) || name.endsWith(
            ".so",
            ignoreCase = true
        )
    }

    private fun alignmentFor(name: String): Int {
        return if (name.endsWith(".so", ignoreCase = true)) {
            /*
             * 16 KiB covers 16K-page devices (Android 15+) and is a
             * valid multiple for every 4K-page device shipping today.
             * resources.arsc stays at 4 bytes for targetSdk 30+.
             */
            16 * 1024
        } else {
            4
        }
    }

    // -------------------------------------------------------------------------
    // Entry extraction
    // -------------------------------------------------------------------------

    private fun copyZipEntryToFile(
        input: ZipInputStream,
        output: File
    ): Long {
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

        return total
    }

    // -------------------------------------------------------------------------
    // XAPK/APKM/APKS containers
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
        val patched = File(root, "patched")

        root.mkdirs()
        extracted.mkdirs()
        patched.mkdirs()

        try {
            emit(progress, "Container: ${input.name}")

            val files = extractContainer(input, extracted)

            val apkFiles = files.filter {
                it.extension.equals("apk", true)
            }

            if (apkFiles.isEmpty()) {
                throw IOException(
                    "Container contains no APK files"
                )
            }

            /*
             * Every split APK is signed with the same Keystore key —
             * a set with mixed certificates refuses to install.
             */
            for (apk in apkFiles) {
                val destination = File(
                    patched,
                    apk.relativeTo(extracted)
                )

                destination.parentFile?.mkdirs()

                emit(
                    progress,
                    "Patching container APK: ${apk.name}"
                )

                patchToDisk(
                    apk,
                    destination,
                    patches,
                    progress
                )
            }

            val unchanged = files.filter {
                !it.extension.equals("apk", true)
            }

            for (file in unchanged) {
                val destination = File(
                    patched,
                    file.relativeTo(extracted)
                )

                destination.parentFile?.mkdirs()

                Files.copy(
                    file.toPath(),
                    destination.toPath(),
                    StandardCopyOption.REPLACE_EXISTING
                )
            }

            repackContainer(patched, output)

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
                        "Duplicate ZIP entry in container: " +
                                entry.name
                    )
                }

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

                if (entry.name.endsWith(".dex", true)) {

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
                } else {
                    drain(zip)
                }

                zip.closeEntry()
            }
        }

        return result
            .distinctBy {
                "${it.patchType}:${it.desc}"
            }
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
        return if (name.endsWith('/')) {
            name
        } else {
            "$name/"
        }
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
            bytes < 1024 ->
                "$bytes B"

            bytes < 1024L * 1024L ->
                "%.1f KB".format(bytes / 1024.0)

            bytes < 1024L * 1024L * 1024L ->
                "%.1f MB".format(bytes / (1024.0 * 1024.0))

            else ->
                "%.2f GB".format(
                    bytes / (1024.0 * 1024.0 * 1024.0)
                )
        }
    }
}

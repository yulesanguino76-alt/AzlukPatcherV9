package com.azluk.patcher.engine.sign

import android.util.Log
import java.io.*
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.*
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.zip.*

/**
 * ApkSignerV2 — APK Signature Scheme v1 (JAR) + v2 (Signing Block).
 *
 * V7.3 — fixed:
 * 1. CERT.SF now includes per-entry SHA-256-Digest lines (was only manifest digest)
 *    → missing these caused INSTALL_PARSE_FAILED_NO_CERTIFICATES on all API 24+
 * 2. CERT.SF now includes X-Android-APK-Signed: 2 header
 *    → without it, Android double-validates v1 even when v2 block is present
 * 3. buildString{} for all string assembly — no raw \n in StringBuilder()
 * 4. 256KB I/O buffers, parallel chunk digesting for v2
 *
 * *privately: the CERT.SF was 129 bytes covering 1047 entries.
 *  it should be ~116KB. Android reads every Name: entry in the SF,
 *  finds none, treats the APK as unsigned. game over.*
 */
object ApkSignerV2 {
    private const val TAG = "ApkSignerV2"

    private val SIG_BLOCK_MAGIC = byteArrayOf(
        0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20,
        0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32
    )
    private const val V2_ID          = 0x7109871a
    private const val SIG_RSA_SHA256 = 0x0103
    private const val DIGEST_SHA256  = 0x0403
    private const val CHUNK          = 1024 * 1024
    private const val BUF            = 256 * 1024

    private val OID_SHA256_WITH_RSA = byteArrayOf(
        0x2a, 0x86.toByte(), 0x48, 0x86.toByte(), 0xf7.toByte(), 0x0d, 0x01, 0x01, 0x0b
    )
    private val OID_SHA256 = byteArrayOf(
        0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
    )
    private val OID_DATA = byteArrayOf(
        0x2a, 0x86.toByte(), 0x48, 0x86.toByte(), 0xf7.toByte(), 0x0d, 0x01, 0x07, 0x01
    )
    private val OID_SIGNED_DATA = byteArrayOf(
        0x2a, 0x86.toByte(), 0x48, 0x86.toByte(), 0xf7.toByte(), 0x0d, 0x01, 0x07, 0x02
    )

    private const val PK8 =
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCRTlLNsnftZDUu" +
        "SyVvIUfoOsOOzAoM7tL/fieOl7S32e906aCgxKT2MaR4G4XCdxLLvD8y2Z3lYQzt" +
        "RXtip0Qo+S3gYu+mBBVa/oJ+R2PeX7S35ODdY/flDIzbyyEfFjHI8Jpm4KA9KEUF" +
        "0Ag43nMQKGOSW6R2iNlAZ5ehXTDOTTldEcJMVlLXJZCC4LjYz0+yGrT2xN0qu/D6" +
        "28h/Q3R5qB8OWjtSYFORWsNCyv61VsmT08ybbatUanZYeNH32z3fKYdOobZE9q/n7" +
        "Qn3i66UYF1CYDi4LuMfqw6jC1JUscNB/GSW6EjcudeQCLJKFS/S5TGNrfs1whCg3" +
        "shofhwDAgMBAAECggEABGIhe1UL6xxfwlLAAVc2rRnAtnkPQI6fzNdIaDPJXtZzM8" +
        "qsbs0f0NF0ja7+3PvslDrMiUMpUTcZRbsX2sUC+F1z9dXmNtLetg0BcL/Eknu+nu" +
        "GHqwYN/1neke7Rw/dObypa7gmOq+mgE2nQJa8IN4+QWWTsVCsSqq+1UkfWZhLApN" +
        "vHh6vBQPHxhqNXnDiFFEMnvbPbdRNx1ihPtklUVvADhXan2xl8Z/M0oW0Q2X01FZ" +
        "m5R9ScqZubjZcGhhlcvn1Y0/vRsd9OBVeZsSgz7fOWLcW0+vCElsV8G20QqgJIA4" +
        "d25nitSVzwrJmd1WiBFFDFHAmRAnZ4l47X3FLVYQKBgQDM6t7fxXFHsF97Q5Ez3Mj" +
        "WEq73WYP/gGqhm/DtslTs3WaAWs4G9bUHp4kGbyVpEwJPi2YRfh+mBpQ8CCNYFVGi" +
        "eqYoxrL6kkfs1mdV+p49ijQBESDiaidKmUElVkebRUN3fr/ybmnv+Xjw9Fj1ejC0Ac" +
        "7G85uiT0OGfH1IH19V8wKBgQC1h0AsBLijeDJnhu9oCRY74ndDyI4FTDEUHcPlNjN" +
        "3Y8DZKyw2NN8n/Qix/1LvTFeCmqWOXnOjYb5AX8wz8dT9b2DiTt+f5dS3VKWNj6b" +
        "8/1vdopCwN034Lhezksu7UubY7ioh4hswnIXp56iwYL9B1Db+HWpkz0DlTHdUoE5V" +
        "sQKBgGe+BMWvNPGBVmWWSH3EKh1O6iupswz4W4Oj6i68mQgt8oXK8wFNBbBxXgrW" +
        "3E684++XeD4k5yrrq8JUsGgYqvKiO1rrdZMr2aQKy9gYgGJRhJCBtm9KJMg8nGGl" +
        "s6zlPQnTLqQyyAlI+LSsUBk/GkcXnzLUBBgBHwOIJPkNgPuHAoGALKZv6mPe5paS" +
        "D1TpXjWd+mzh2RJjnHn5OHF51c9XKW6n6MLtxQeMPFHI6b9brvCgNcfEIRiqaO2J" +
        "1lu55qz9LrlOo1uzNalagR2Y+xDyihhliEaMQEvaKclsmwbohdMGZSVvx5XOCk71w" +
        "Wrx2zBw2shQHoEtwk4YME52q6IiooECgYB8zQcsGNonUMsLJypyEhK0IEL8sPo9j5" +
        "Hc0cg8C8E4s8EKvcw2xJNRFuFkIbd3QwEHyXVTkrn+DV0erUdsq1rSknTUEsXnNU" +
        "mCOvrVklhEMKxxCoiY8ZI1ABjo8OiiytdP5uTb8e7BUTXl9VJh8kT17k452mckoZx" +
        "LZ3ufXJitUw=="

    private const val CERT_B64 =
        "MIIEBzCCAu+gAwIBAgIUP2UBgU5R9Gma5Ys1jA5BqlTP4TYwDQYJKoZIhvcNAQEL" +
        "BQAwgZExCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVTdGF0ZTENMAsGA1UEBwwEQ2l0" +
        "eTEVMBMGA1UECgwMQXpsdWtQYXRjaGVyMRUwEwYDVQQLDAxBemx1a1BhdGNoZXIx" +
        "FTATBgNVBAMMDEF6bHVrUGF0Y2hlcjEeMBwGCSqGSIb3DQEJARYPYXpsdWtAYXps" +
        "dWsuZGV2MCAXDTI2MDkwNjEzMDIzNVoYDzIwNTQwMTIyMTMwMjM1WjCBkTELMAkG" +
        "A1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5MRUwEwYDVQQK" +
        "DAxBemx1a1BhdGNoZXIxFTATBgNVBAsMDEF6bHVrUGF0Y2hlcjEVMBMGA1UEAwwM" +
        "QXpsdWtQYXRjaGVyMR4wHAYJKoZIhvcNAQkBFg9hemx1a0Bhemx1ay5kZXYwggEi" +
        "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCRTlLNsnftZDUuSyVvIUfoOsOO" +
        "zAoM7tL/fieOl7S32e906aCgxKT2MaR4G4XCdxLLvD8y2Z3lYQztRXtip0Qo+S3g" +
        "Yu+mBBVa/oJ+R2PeX7S35ODdY/flDIzbyyEfFjHI8Jpm4KA9KEUF0Ag43nMQKGOS" +
        "W6R2iNlAZ5ehXTDOTTldEcJMVlLXJZCC4LjYz0+yGrT2xN0qu/D628h/Q3R5qB8O" +
        "WjtSYFORWsNCyv61VsmT08ybbatUanZYeNH32z3fKYdOobZE9q/n7Qn3i66UYF1C" +
        "YDi4LuMfqw6jC1JUscNB/GSW6EjcudeQCLJKFS/S5TGNrfs1whCg3shofhwDAgMB" +
        "AAGjUzBRMB0GA1UdDgQWBBSzI6dCW0+id1HfRHpzVab6GB1VvTAfBgNVHSMEGDAW" +
        "gBSzI6dCW0+id1HfRHpzVab6GB1VvTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3" +
        "DQEBCwUAA4IBAQBX2Sb3z6MBq9tEKWlUEH/QHFH+NuDdgJa0Vr/BAjmxWUirpJK" +
        "MWQ+yeRENNGhov+ZYQNDRDuqwPfo5igdgfICOjlSpVhzJi49nrbZDzMfYt2LG+tt" +
        "TA/srzqijUKpw7FKPKeHIflIM3h6Z4UYRSb51H2yk/AFGbd6LmrIL+BUadGbvZbC" +
        "fRZiOvbnWTw201fhz1IC/qlVWC6KPKk8s32cwPjj+Y4Gryx1px4wV0NnZeSvNOPP" +
        "2nAFYwk1jcwyNVVUG9C/6QLZUpRMTF+k6xNRxBIeK/D6Lppx+IqWhihrGqT4SaUc" +
        "K8zfcBZMtKMkUlgO5EvV8Qz1MA97YN5QTmPlu"

    // ── PUBLIC API ────────────────────────────────────────────────────────────

    fun sign(input: File, output: File) {
        val cert   = loadCert()
        val key    = loadKey()
        val sha256 = MessageDigest.getInstance("SHA-256")
        val buf    = ByteArray(BUF)

        // ── Pass 1: per-entry SHA-256 digests ────────────────────────────────
        val digests = LinkedHashMap<String, String>()

        ZipInputStream(BufferedInputStream(FileInputStream(input), BUF)).use { zis ->
            var entry = zis.nextEntry
            while (entry != null) {
                val name = entry.name
                if (!entry.isDirectory && !isSigEntry(name)) {
                    sha256.reset()
                    var n = zis.read(buf)
                    while (n != -1) { sha256.update(buf, 0, n); n = zis.read(buf) }
                    digests[name] = android.util.Base64.encodeToString(
                        sha256.digest(), android.util.Base64.NO_WRAP)
                } else {
                    drainEntry(zis, buf)
                }
                zis.closeEntry()
                entry = zis.nextEntry
            }
        }

        // ── Build MANIFEST.MF ─────────────────────────────────────────────────
        val mfBytes = buildString {
            append("Manifest-Version: 1.0\r\n")
            append("Created-By: AzlukPatcher V8\r\n")
            append("\r\n")
            for ((name, dig) in digests) {
                append("Name: $name\r\n")
                append("SHA-256-Digest: $dig\r\n")
                append("\r\n")
            }
        }.toByteArray(Charsets.UTF_8)

        // ── Build CERT.SF — FIX: per-entry digests + X-Android-APK-Signed ───
        // Android API 24+ (PackageParser) requires CERT.SF to contain either:
        //   a) per-entry Section-Digests for every entry in MANIFEST.MF, OR
        //   b) X-Android-APK-Signed: 2 (delegates trust to v2 block)
        // Without (a) AND (b), installer returns INSTALL_PARSE_FAILED_NO_CERTIFICATES.
        // We include BOTH for maximum compatibility across API levels.
        sha256.reset()
        val mfDigest = android.util.Base64.encodeToString(
            sha256.digest(mfBytes), android.util.Base64.NO_WRAP)

        val sfBytes = buildString {
            append("Signature-Version: 1.0\r\n")
            append("Created-By: 1.0 (AzlukPatcher)\r\n")
            // FIX 1: tell Android the v2 block is authoritative
            append("X-Android-APK-Signed: 2\r\n")
            append("SHA-256-Digest-Manifest: $mfDigest\r\n")
            append("\r\n")
            // FIX 2: per-entry section digests
            // Each section = "Name: <entry>\r\nSHA-256-Digest: <mf_section_digest>\r\n\r\n"
            // The digest covers the corresponding MANIFEST.MF section bytes
            for ((name, dig) in digests) {
                val sectionBytes = buildString {
                    append("Name: $name\r\n")
                    append("SHA-256-Digest: $dig\r\n")
                    append("\r\n")
                }.toByteArray(Charsets.UTF_8)
                sha256.reset()
                val sectionDig = android.util.Base64.encodeToString(
                    sha256.digest(sectionBytes), android.util.Base64.NO_WRAP)
                append("Name: $name\r\n")
                append("SHA-256-Digest: $sectionDig\r\n")
                append("\r\n")
            }
        }.toByteArray(Charsets.UTF_8)

        val certRsa = pkcs7Sign(sfBytes, cert, key)

        // ── Pass 2: repack ZIP + inject META-INF ──────────────────────────────
        val tmp = File(output.parent, output.name + ".v1tmp")
        ZipInputStream(BufferedInputStream(FileInputStream(input), BUF)).use { zis ->
            ZipOutputStream(BufferedOutputStream(FileOutputStream(tmp), BUF)).use { zos ->
                var entry = zis.nextEntry
                while (entry != null) {
                    val name = entry.name
                    if (!isSigEntry(name) && !entry.isDirectory) {
                        val stored = name == "resources.arsc" || name.endsWith(".so")
                        if (stored) {
                            val data = zis.readBytes()
                            val crc  = CRC32().also { it.update(data) }.value
                            zos.putNextEntry(ZipEntry(name).apply {
                                method         = ZipEntry.STORED
                                size           = data.size.toLong()
                                compressedSize = data.size.toLong()
                                setCrc(crc)
                            })
                            zos.write(data)
                        } else {
                            zos.putNextEntry(ZipEntry(name).apply { method = ZipEntry.DEFLATED })
                            var n = zis.read(buf)
                            while (n != -1) { zos.write(buf, 0, n); n = zis.read(buf) }
                        }
                        zos.closeEntry()
                    } else {
                        drainEntry(zis, buf)
                    }
                    zis.closeEntry()
                    entry = zis.nextEntry
                }
                injectEntry(zos, "META-INF/MANIFEST.MF", mfBytes)
                injectEntry(zos, "META-INF/CERT.SF",     sfBytes)
                injectEntry(zos, "META-INF/CERT.RSA",    certRsa)
            }
        }

        // ── Append V2 signing block ───────────────────────────────────────────
        appendV2Block(tmp, cert, key)
        tmp.renameTo(output)
        Log.d(TAG, "sign() done → ${output.length()} bytes")
    }

    fun sign(apk: ByteArray): ByteArray {
        val tmpIn  = File.createTempFile("azluk_in",  ".apk")
        val tmpOut = File.createTempFile("azluk_out", ".apk")
        return try {
            tmpIn.writeBytes(apk)
            sign(tmpIn, tmpOut)
            tmpOut.readBytes()
        } finally {
            tmpIn.delete()
            tmpOut.delete()
        }
    }

    // ── V2 block ──────────────────────────────────────────────────────────────

    private fun appendV2Block(file: File, cert: X509Certificate, key: PrivateKey) {
        val apk        = file.readBytes()
        val eocdOffset = findEocd(apk)
            ?: throw IOException("EOCD not found")

        val cdOffset = (ByteBuffer.wrap(apk, eocdOffset + 16, 4)
            .order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL).toInt()

        val contents = apk.copyOf(cdOffset)
        val cd       = apk.copyOfRange(cdOffset, eocdOffset)
        val eocd     = apk.copyOfRange(eocdOffset, apk.size)

        val contentDigest = digestChunkedParallel(contents, cd, eocd)
        val signedData    = buildV2SignedData(contentDigest, cert)
        val sig           = Signature.getInstance("SHA256withRSA")
            .apply { initSign(key); update(signedData) }.sign()
        val signerBlock   = buildV2SignerBlock(signedData, sig, cert)
        val signingBlock  = buildApkSigningBlock(signerBlock)

        val newCdOffset = (contents.size + signingBlock.size).toLong()
        ByteBuffer.wrap(eocd, 16, 4).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(newCdOffset.toInt())

        FileOutputStream(file).use { fos ->
            fos.write(contents)
            fos.write(signingBlock)
            fos.write(cd)
            fos.write(eocd)
        }
    }

    private fun digestChunkedParallel(vararg sections: ByteArray): ByteArray {
        val pool = java.util.concurrent.Executors.newFixedThreadPool(
            minOf(Runtime.getRuntime().availableProcessors(), 4))

        val futures = mutableListOf<java.util.concurrent.Future<ByteArray>>()

        for (section in sections) {
            var offset = 0
            while (offset < section.size) {
                val start = offset
                val end   = minOf(offset + CHUNK, section.size)
                futures.add(pool.submit<ByteArray> {
                    val sha = MessageDigest.getInstance("SHA-256")
                    val hdr = ByteBuffer.allocate(5).order(ByteOrder.LITTLE_ENDIAN)
                        .put(0xa5.toByte()).putInt(end - start).array()
                    sha.update(hdr)
                    sha.update(section, start, end - start)
                    sha.digest()
                })
                offset = end
            }
        }
        pool.shutdown()

        val chunkDigests = Array(futures.size) { futures[it].get() }

        val sha = MessageDigest.getInstance("SHA-256")
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0x5a))
        out.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(chunkDigests.size).array())
        chunkDigests.forEach { out.write(it) }
        sha.update(out.toByteArray())
        return sha.digest()
    }

    private fun buildV2SignedData(digest: ByteArray, cert: X509Certificate): ByteArray {
        val digestEntry = ByteBuffer.allocate(4 + 4 + digest.size)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(DIGEST_SHA256).putInt(digest.size).put(digest).array()
        val digestsList = prefixU32(digestEntry)
        val certsList   = prefixU32(prefixU32(cert.encoded))
        val attrsList   = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(0).array()

        val baos = ByteArrayOutputStream()
        baos.write(prefixU32(digestsList))
        baos.write(prefixU32(certsList))
        baos.write(prefixU32(attrsList))
        return baos.toByteArray()
    }

    private fun buildV2SignerBlock(signedData: ByteArray, sig: ByteArray, cert: X509Certificate): ByteArray {
        val sigEntry = ByteBuffer.allocate(4 + 4 + sig.size)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(SIG_RSA_SHA256).putInt(sig.size).put(sig).array()
        val sigsList    = prefixU32(prefixU32(sigEntry))
        val pubKeyField = prefixU32(cert.publicKey.encoded)

        val body = ByteArrayOutputStream()
        body.write(prefixU32(signedData))
        body.write(sigsList)
        body.write(pubKeyField)
        return prefixU32(prefixU32(body.toByteArray()))
    }

    private fun buildApkSigningBlock(signerBlock: ByteArray): ByteArray {
        val pairLen = (4L + signerBlock.size)
        val pair = ByteArrayOutputStream().also { b ->
            b.write(u64le(pairLen))
            b.write(u32le(V2_ID))
            b.write(signerBlock)
        }.toByteArray()

        val blockSize = (pair.size + 8 + 16).toLong()

        return ByteArrayOutputStream().also { baos ->
            baos.write(u64le(blockSize))
            baos.write(pair)
            baos.write(u64le(blockSize))
            baos.write(SIG_BLOCK_MAGIC)
        }.toByteArray()
    }

    private fun findEocd(apk: ByteArray): Int? {
        var i = apk.size - 22
        while (i >= 0) {
            if (apk[i]   == 0x50.toByte() && apk[i+1] == 0x4b.toByte() &&
                apk[i+2] == 0x05.toByte() && apk[i+3] == 0x06.toByte()) {
                val commentLen = (apk[i+20].toInt() and 0xff) or
                                 ((apk[i+21].toInt() and 0xff) shl 8)
                if (i + 22 + commentLen == apk.size) return i
            }
            i--
        }
        return null
    }

    // ── PKCS7 ─────────────────────────────────────────────────────────────────

    private fun pkcs7Sign(sfBytes: ByteArray, cert: X509Certificate, key: PrivateKey): ByteArray {
        val sha256 = MessageDigest.getInstance("SHA-256")
        val digest = sha256.digest(sfBytes)
        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(key); signer.update(sfBytes)
        val rawSig = signer.sign()

        val issuer = cert.issuerX500Principal.encoded
        val serial = cert.serialNumber

        val digestAlgId     = buildSeq(buildOid(OID_SHA256) + buildNull())
        val sigAlgId        = buildSeq(buildOid(OID_SHA256_WITH_RSA) + buildNull())
        val issuerAndSerial = buildSeq(buildRaw(issuer) + buildInteger(serial))
        val digestAlgIds    = buildSet(digestAlgId)
        val authAttrs       = buildAttrs(digest)
        val encDigest       = buildOctetString(rawSig)

        val signerInfo = buildSeq(
            buildInteger(BigInteger.ONE) +
            issuerAndSerial +
            digestAlgId +
            byteArrayOf(0xa0.toByte()) + buildLen(authAttrs.size) + authAttrs +
            sigAlgId +
            encDigest
        )
        val signedData = buildSeq(
            buildInteger(BigInteger.ONE) +
            digestAlgIds +
            buildSeq(buildOid(OID_DATA)) +
            byteArrayOf(0xa0.toByte()) + buildLen(cert.encoded.size) + cert.encoded +
            buildSet(signerInfo)
        )
        return buildSeq(
            buildOid(OID_SIGNED_DATA) +
            (byteArrayOf(0xa0.toByte()) + buildLen(signedData.size) + signedData)
        )
    }

    private fun buildAttrs(digest: ByteArray): ByteArray {
        val contentType = buildSeq(
            buildOid(byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0x86.toByte(),
                0xf7.toByte(), 0x0d, 0x01, 0x09, 0x03)) +
            buildSet(buildSeq(buildOid(OID_DATA)))
        )
        val msgDigest = buildSeq(
            buildOid(byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0x86.toByte(),
                0xf7.toByte(), 0x0d, 0x01, 0x09, 0x04)) +
            buildSet(buildOctetString(digest))
        )
        return contentType + msgDigest
    }

    // ── DER primitives ────────────────────────────────────────────────────────

    private fun buildLen(len: Int): ByteArray = when {
        len < 128 -> byteArrayOf(len.toByte())
        len < 256 -> byteArrayOf(0x81.toByte(), len.toByte())
        else      -> byteArrayOf(0x82.toByte(), (len shr 8).toByte(), (len and 0xff).toByte())
    }

    private fun buildTlv(tag: Byte, c: ByteArray) = byteArrayOf(tag) + buildLen(c.size) + c
    private fun buildSeq(c: ByteArray)             = buildTlv(0x30, c)
    private fun buildSet(c: ByteArray)             = buildTlv(0x31, c)
    private fun buildOid(o: ByteArray)             = buildTlv(0x06, o)
    private fun buildOctetString(d: ByteArray)     = buildTlv(0x04, d)
    private fun buildNull()                        = byteArrayOf(0x05, 0x00)
    private fun buildRaw(d: ByteArray)             = d

    private fun buildInteger(n: BigInteger): ByteArray {
        var b = n.toByteArray()
        if (b[0] < 0) b = byteArrayOf(0) + b
        return buildTlv(0x02, b)
    }
    private fun buildInteger(n: Int) = buildInteger(BigInteger.valueOf(n.toLong()))

    // ── encoding helpers ──────────────────────────────────────────────────────

    private fun prefixU32(data: ByteArray): ByteArray {
        val buf = ByteBuffer.allocate(4 + data.size).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(data.size); buf.put(data); return buf.array()
    }
    private fun u32le(v: Int): ByteArray =
        ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array()
    private fun u64le(v: Long): ByteArray =
        ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(v).array()

    // ── ZIP helpers ───────────────────────────────────────────────────────────

    private fun isSigEntry(name: String) =
        name.startsWith("META-INF/") &&
        (name.endsWith(".SF") || name.endsWith(".RSA") || name.endsWith(".DSA") ||
         name.endsWith(".EC") || name.endsWith(".MF"))

    private fun drainEntry(zis: ZipInputStream, buf: ByteArray) {
        while (zis.read(buf) != -1) {}
    }

    private fun injectEntry(zos: ZipOutputStream, name: String, data: ByteArray) {
        zos.putNextEntry(ZipEntry(name).apply { method = ZipEntry.DEFLATED })
        zos.write(data); zos.closeEntry()
    }

    // ── Key + Cert ────────────────────────────────────────────────────────────

    private fun loadKey(): PrivateKey {
        val der = android.util.Base64.decode(
            PK8.replace("\n", "").replace(" ", ""), android.util.Base64.DEFAULT)
        return KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(der))
    }

    private fun loadCert(): X509Certificate {
        val der = android.util.Base64.decode(
            CERT_B64.replace("\n", "").replace(" ", ""), android.util.Base64.DEFAULT)
        return java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    }
}

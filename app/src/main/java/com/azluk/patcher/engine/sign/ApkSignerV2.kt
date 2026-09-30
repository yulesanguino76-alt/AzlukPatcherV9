package com.azluk.patcher.engine.sign

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.android.apksig.ApkSigner
import com.android.apksig.ApkVerifier
import java.io.File
import java.io.IOException
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal

/**
 * AzlukPatcher V9 - Production signing facade.
 *
 * Responsibilities:
 *  - create/load an installation-local RSA key from Android Keystore
 *    (no private key material is ever embedded in source or assets)
 *  - expose the certificate fingerprint for the UI
 *  - sign APKs through Google's apksig library: V1 + V2 + V3
 *  - verify the result BEFORE it can replace the published APK
 *  - publish atomically: the destination holds either the old APK or
 *    the new verified APK, never a half-written file
 *
 * Key-change warning (UI must surface this):
 *  The signing key is generated per installation. If this app is
 *  reinstalled or its data is cleared, a NEW key is generated. Any
 *  app previously patched and installed with the old key will REFUSE
 *  to update from a APK signed with the new key (INSTALL_FAILED_UPDATE_INCOMPATIBLE).
 *  The user must uninstall the old installation first. There is no
 *  way to export or back up an Android Keystore key by design.
 */
class ApkSignerV2(
    private val context: Context
) {

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "azlukpatcher.v9.signing"

        private const val RSA_BITS = 2048

        /**
         * Minimum SDK the signed APK must satisfy. Drives which signature
         * schemes apksig requires and verifies. V2 is enforced from 24+;
         * we target 26+.
         */
        private const val DEFAULT_MIN_SDK = 26

        private const val SUBJECT =
            "CN=AzlukPatcher V9, OU=AzlukPatcher"

        private const val VALIDITY_YEARS = 30

        private val ZIP_MAGIC = byteArrayOf(0x50, 0x4B)

        /**
         * Compatibility entry point for code that used:
         *
         * ApkSignerV2.sign(context, input, output)
         */
        @JvmStatic
        fun sign(
            context: Context,
            input: File,
            output: File
        ) {
            ApkSignerV2(context).signApk(input, output)
        }
    }

    // -------------------------------------------------------------------------
    // Key management (Android Keystore — non-exportable by design)
    // -------------------------------------------------------------------------

    /**
     * Ensures that the installation-local signing key exists.
     *
     * The key is bound to this installation: PURPOSE_SIGN | PURPOSE_VERIFY,
     * PKCS#1 padding, SHA-256/SHA-512 digests. apksig selects a compatible
     * algorithm per scheme (V1: PKCS#1 over CERT.SF, V2/V3: PKCS#1 over
     * the digest blocks).
     */
    @Synchronized
    private fun ensureKey() {
        val keyStore = KeyStore.getInstance(KEYSTORE)
        keyStore.load(null)

        if (keyStore.containsAlias(KEY_ALIAS)) {
            return
        }

        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            KEYSTORE
        )

        val now = System.currentTimeMillis()

        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or
                    KeyProperties.PURPOSE_VERIFY
        )
            .setKeySize(RSA_BITS)
            .setDigests(
                KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA512
            )
            .setSignaturePaddings(
                KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
            )
            .setCertificateSubject(
                X500Principal(SUBJECT)
            )
            .setCertificateSerialNumber(
                BigInteger.ONE
            )
            .setCertificateNotBefore(Date(now))
            .setCertificateNotAfter(
                Date(
                    now +
                            VALIDITY_YEARS.toLong() *
                            365L *
                            24L *
                            60L *
                            60L *
                            1000L
                )
            )
            .build()

        generator.initialize(spec)
        generator.generateKeyPair()
    }

    private fun keyStore(): KeyStore {
        ensureKey()

        return KeyStore.getInstance(KEYSTORE).also {
            it.load(null)
        }
    }

    private fun privateKey(): PrivateKey {
        val key = keyStore().getKey(KEY_ALIAS, null)

        require(key is PrivateKey) {
            "Android Keystore did not return a private key"
        }

        return key
    }

    private fun certificate(): X509Certificate {
        val cert = keyStore().getCertificate(KEY_ALIAS)

        require(cert is X509Certificate) {
            "Android Keystore did not return an X.509 certificate"
        }

        return cert
    }

    /**
     * SHA-256 fingerprint of our signing certificate, shown in the UI.
     */
    fun certificateFingerprintSha256(): String {
        return sha256(certificate())
    }

    fun certificateInfo(): SigningCertificateInfo {
        val cert = certificate()

        return SigningCertificateInfo(
            subject = cert.subjectX500Principal.name,
            serial = cert.serialNumber.toString(16),
            fingerprintSha256 = certificateFingerprintSha256(),
            notBefore = cert.notBefore,
            notAfter = cert.notAfter
        )
    }

    // -------------------------------------------------------------------------
    // Signing
    // -------------------------------------------------------------------------

    /**
     * Signs an APK using V1/V2/V3.
     *
     * Contract:
     *  - the input must be a fully repacked and aligned, unsigned ZIP
     *  - the destination is NEVER touched until the output has been
     *    signed and verified; on any failure the old APK survives
     *  - the private key never leaves Android Keystore
     */
    fun signApk(
        input: File,
        output: File
    ) {
        require(input.exists()) {
            "Input APK does not exist: ${input.absolutePath}"
        }

        require(input.isFile) {
            "Input APK is not a regular file"
        }

        require(input.length() >= 8L) {
            "Input APK is empty or truncated"
        }

        requireZip(input)

        output.parentFile?.mkdirs()

        val temporaryOutput = File(
            output.parentFile,
            output.name + ".signing"
        )

        try {
            temporaryOutput.delete()

            val signerConfig =
                ApkSigner.SignerConfig.Builder(
                    "azluk-v9",
                    privateKey(),
                    listOf(certificate())
                ).build()

            val signer = ApkSigner.Builder(
                listOf(signerConfig)
            )
                .setInputApk(input)
                .setOutputApk(temporaryOutput)
                /*
                 * V1 stays enabled: harmless at minSdk 26 and covers
                 * installers that still consult the JAR signature.
                 */
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .setV4SigningEnabled(false)
                .setMinSdkVersion(DEFAULT_MIN_SDK)
                .build()

            signer.sign()

            require(
                temporaryOutput.exists() &&
                        temporaryOutput.length() > 0L
            ) {
                "apksig produced no APK"
            }

            /*
             * Verify before publication: scheme validity AND proof that
             * the bytes were signed with THIS installation's key.
             */
            verifyOrThrow(temporaryOutput)

            atomicMove(
                temporaryOutput,
                output
            )
        } catch (t: Throwable) {
            throw IOException(
                "APK signing failed: ${t.message}",
                t
            )
        } finally {
            /*
             * The temp must never outlive this call — success or failure.
             * After a successful atomicMove the file no longer exists and
             * delete() is a no-op.
             */
            temporaryOutput.delete()
        }
    }

    /**
     * Compatibility overload used by simple callers.
     */
    fun sign(
        input: File,
        output: File
    ) {
        signApk(input, output)
    }

    /**
     * Signs a byte array through temporary files.
     *
     * Intended for tests and small APKs.
     */
    fun sign(
        apk: ByteArray
    ): ByteArray {
        require(apk.isNotEmpty()) {
            "APK byte array is empty"
        }

        val input = File.createTempFile(
            "azluk-v9-input-",
            ".apk",
            context.cacheDir
        )

        val output = File.createTempFile(
            "azluk-v9-output-",
            ".apk",
            context.cacheDir
        )

        return try {
            input.writeBytes(apk)

            signApk(
                input,
                output
            )

            output.readBytes()
        } finally {
            input.delete()
            output.delete()
        }
    }

    // -------------------------------------------------------------------------
    // Verification
    // -------------------------------------------------------------------------

    /**
     * Verifies V1/V2/V3 using apksig's verifier.
     */
    fun verify(
        apk: File
    ): VerificationResult {
        require(apk.exists()) {
            "APK does not exist"
        }

        val result = ApkVerifier.Builder(apk)
            .setMinCheckedPlatformVersion(DEFAULT_MIN_SDK)
            .build()
            .verify()

        val signerCertificates: List<X509Certificate> =
            result.signerCertificates

        val fingerprints =
            signerCertificates.map { cert ->
                sha256(cert)
            }

        return VerificationResult(
            verified = result.isVerified,
            v1 = result.isVerifiedUsingV1Scheme,
            v2 = result.isVerifiedUsingV2Scheme,
            v3 = result.isVerifiedUsingV3Scheme,
            certificateFingerprints = fingerprints
        )
    }

    private fun verifyOrThrow(
        apk: File
    ) {
        val verification = verify(apk)

        if (!verification.verified) {
            throw SecurityException(
                "apksig verification failed"
            )
        }

        if (!verification.v2 && !verification.v3) {
            throw SecurityException(
                "APK has no valid V2/V3 signature"
            )
        }

        /*
         * The APK must carry THIS installation's certificate. A valid
         * signature from any other key is a hard failure — it would
         * break updates on devices where a previous build was installed.
         */
        val expected = certificateFingerprintSha256()

        if (verification.certificateFingerprints.none { it == expected }) {
            throw SecurityException(
                "Signed APK does not carry this installation's " +
                        "certificate (expected $expected)"
            )
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private fun requireZip(
        file: File
    ) {
        file.inputStream().use { input ->
            val magic = ByteArray(2)

            var read = 0

            while (read < 2) {
                val n = input.read(magic, read, 2 - read)

                if (n < 0) {
                    break
                }

                read += n
            }

            if (read < 2 || magic[0] != ZIP_MAGIC[0] || magic[1] != ZIP_MAGIC[1]) {
                throw IOException(
                    "Input is not a ZIP archive: ${file.name}"
                )
            }
        }
    }

    private fun sha256(
        certificate: X509Certificate
    ): String {
        return MessageDigest
            .getInstance("SHA-256")
            .digest(certificate.encoded)
            .joinToString(":") {
                "%02X".format(it.toInt() and 0xff)
            }
    }

    private fun atomicMove(
        source: File,
        destination: File
    ) {
        val sourcePath = source.toPath()
        val destinationPath = destination.toPath()

        try {
            java.nio.file.Files.move(
                sourcePath,
                destinationPath,
                java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING
            )
        } catch (_: Exception) {
            /*
             * Same filesystem required for atomicity; if ATOMIC_MOVE is
             * unsupported the fallback keeps correctness (old file only
             * replaced after full verification) even if not atomicity.
             */
            java.nio.file.Files.move(
                sourcePath,
                destinationPath,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING
            )
        }
    }

    data class SigningCertificateInfo(
        val subject: String,
        val serial: String,
        val fingerprintSha256: String,
        val notBefore: Date,
        val notAfter: Date
    )

    data class VerificationResult(
        val verified: Boolean,
        val v1: Boolean,
        val v2: Boolean,
        val v3: Boolean,
        val certificateFingerprints: List<String>
    )
}

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
 * AzlukPatcher V9
 *
 * Production signing facade.
 *
 * Responsibilities:
 *  - create/load an installation-local RSA key from Android Keystore
 *  - expose the certificate fingerprint
 *  - sign APKs through Google's apksig library
 *  - enable V1/V2/V3 signing
 *  - verify the resulting APK before it is published
 *
 * No private key is embedded in source or assets.
 */
class ApkSignerV2(
    private val context: Context
) {

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "azlukpatcher.v9.signing"

        private const val RSA_BITS = 2048

        private const val DEFAULT_MIN_SDK = 26

        private const val SUBJECT =
            "CN=AzlukPatcher V9, OU=AzlukPatcher"

        private const val VALIDITY_YEARS = 30

        /**
         * Compatibility entry point for code that used:
         *
         * ApkSignerV2.sign(input, output)
         *
         * New engine code should construct the signer with Context.
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

    /**
     * Ensures that the installation-local signing key exists.
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

        val notBefore = Date(now)

        val notAfter = Date(
            now +
                    VALIDITY_YEARS.toLong() *
                    365L *
                    24L *
                    60L *
                    60L *
                    1000L
        )

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
            .setCertificateNotBefore(notBefore)
            .setCertificateNotAfter(notAfter)
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
        val store = keyStore()

        val key = store.getKey(
            KEY_ALIAS,
            null
        )

        require(key is PrivateKey) {
            "Android Keystore did not return a private key"
        }

        return key
    }

    private fun certificate(): X509Certificate {
        val store = keyStore()

        val cert = store.getCertificate(
            KEY_ALIAS
        )

        require(cert is X509Certificate) {
            "Android Keystore did not return an X.509 certificate"
        }

        return cert
    }

    /**
     * SHA-256 certificate fingerprint shown by the UI.
     */
    fun certificateFingerprintSha256(): String {
        val digest = MessageDigest.getInstance("SHA-256")

        return digest
            .digest(certificate().encoded)
            .joinToString(":") {
                "%02X".format(it.toInt() and 0xff)
            }
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

    /**
     * Signs an APK using V1/V2/V3.
     *
     * The APK must already be completely repacked/aligned.
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

        require(input.length() > 0L) {
            "Input APK is empty"
        }

        output.parentFile?.mkdirs()

        val temporaryOutput = File(
            output.parentFile,
            output.name + ".signing"
        )

        if (temporaryOutput.exists()) {
            temporaryOutput.delete()
        }

        if (output.exists()) {
            output.delete()
        }

        val signerConfig =
            ApkSigner.SignerConfig.Builder(
                "azluk-v9",
                privateKey(),
                listOf(certificate())
            ).build()

        try {
            val signer = ApkSigner.Builder(
                listOf(signerConfig)
            )
                .setInputApk(input)
                .setOutputApk(temporaryOutput)
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

            verifyOrThrow(temporaryOutput)

            atomicMove(
                temporaryOutput,
                output
            )
        } catch (t: Throwable) {
            temporaryOutput.delete()

            throw IOException(
                "APK signing failed: ${t.message}",
                t
            )
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

    /**
     * Verifies V1/V2/V3 using apksig's verifier.
     *
     * This is deliberately called after signing and before publication.
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

        val signerCertificates =
            result.signers.flatMap { signer ->
                signer.certs
            }

        val fingerprints =
            signerCertificates.map {
                sha256(it)
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

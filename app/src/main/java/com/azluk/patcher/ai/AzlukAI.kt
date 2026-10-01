package com.azluk.patcher.ai

import com.azluk.patcher.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

object AzlukAI {

    data class Result(
        val success: Boolean,
        val suggestion: String = "",
        val error: String = ""
    )

    private const val SYSTEM_PROMPT =
        "You are the built-in diagnostic expert of AzlukPatcher, an Android " +
        "APK patcher. Its pipeline: ZIP staging (config splits legitimately " +
        "have no classes.dex) -> structural DEX recipes (exact class+method " +
        "match, try/catch methods are stubbed head-only preserving " +
        "instruction boundaries) -> repack with exact byte-counter " +
        "alignment -> apksig V1/V2/V3 signing -> self-verify -> atomic " +
        "publish. Split apps are emitted as .apks containers. Diagnose " +
        "against THIS pipeline. Reply: 2-sentence diagnosis, then 'Fix:' " +
        "and ONE concrete action. No preamble."

    private fun hasKey() = BuildConfig.TOKENROUTER_API_KEY.isNotBlank()

    /**
     * Offline expert system: always available, no network, no key.
     * Matched FIRST, so the app diagnoses even without configuration.
     */
    private fun localDiagnosis(error: String, context: String): String? {
        val e = error.lowercase()

        return when {
            "verification_failure" in e ->
                "The system package verifier rejected the APK. " +
                "This is normal for patched apps. Fix: uninstall the " +
                "original app first (different signature), then install; " +
                "if it persists, disable Play Protect scanning. ($context)"
            "missing splits" in e ->
                "The original app is installed with split APKs. " +
                "Fix: install the .apks container from Patched Files — " +
                "it includes base + all splits — after uninstalling the " +
                "original. ($context)"
            "signature" in e && "conflict" in e ||
                    "install_failed_update_incompatible" in e ->
                "Signature mismatch with the installed version. " +
                "Fix: uninstall the original app, then install the " +
                "patched output. ($context)"
            "invalid" in e || "parse" in e ->
                "The installer could not parse the package. " +
                "Fix: re-patch and watch the log for DEX/signing errors; " +
                "if the log shows a signing failure, retry — Keystore " +
                "can transiently fail. ($context)"
            "insufficient" in e && "storage" in e ->
                "Not enough storage. Fix: free space and retry. ($context)"
            "blocked" in e ->
                "Install blocked by the system. Fix: enable 'Install " +
                "unknown apps' for AzlukPatcher in Settings. ($context)"
            "no dex" in e || "dex magic" in e ->
                "A staged entry lacked valid DEX. Config splits have no " +
                "classes.dex — that is logged and safe. If this error " +
                "came from the BASE apk, the input may be corrupted. ($context)"
            "signing" in e || "keystore" in e ->
                "Signing failed. Fix: retry; if persistent, clear the " +
                "app's signing key from system settings or reinstall " +
                "AzlukPatcher. ($context)"
            "timeout" in e || "timed out" in e ->
                "A phase timed out — the file is large or the device is " +
                "under load. Fix: close background apps and retry. ($context)"
            else -> null
        }
    }

    private fun post(prompt: String, maxTokens: Int): Result {
        val body = JSONObject().apply {
            put("model", BuildConfig.TOKENROUTER_MODEL)
            put("max_tokens", maxTokens)
            put("messages", JSONArray().apply {
                put(JSONObject().apply {
                    put("role", "system"); put("content", SYSTEM_PROMPT)
                })
                put(JSONObject().apply {
                    put("role", "user"); put("content", prompt)
                })
            })
        }

        val conn = (URL("${BuildConfig.TOKENROUTER_BASE_URL}/chat/completions")
                .openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty(
                "Authorization", "Bearer ${BuildConfig.TOKENROUTER_API_KEY}"
            )
            doOutput = true
            connectTimeout = 10000
            readTimeout = 20000
        }

        conn.outputStream.use {
            it.write(body.toString().toByteArray())
        }

        val code = conn.responseCode

        if (code !in 200..299) {
            return Result(false, error = "HTTP $code")
        }

        val text = JSONObject(conn.inputStream.bufferedReader().readText())
                .getJSONArray("choices").getJSONObject(0)
                .getJSONObject("message").getString("content").trim()

        return Result(true, suggestion = text)
    }

    private fun remote(
        prompt: String,
        maxTokens: Int
    ): Result = try {
        if (!hasKey()) {
            Result(false, error = "not_configured")
        } else {
            post(prompt, maxTokens)
        }
    } catch (e: Exception) {
        Result(false, error = e.message ?: "unknown_error")
    }

    suspend fun diagnose(
        errorCode: String,
        errorMessage: String,
        apkName: String,
        apkSizeKb: Long
    ): Result = withContext(Dispatchers.IO) {
        val context = "$apkName (${apkSizeKb} KB)"

        localDiagnosis("$errorCode $errorMessage", context)?.let {
            return@withContext Result(true, suggestion = it)
        }

        remote(
            """
            Android APK install failed.
            Error code: $errorCode
            Error message: $errorMessage
            APK: $apkName ($apkSizeKb KB)
            """.trimIndent(),
            250
        )
    }

    suspend fun analyzePatchLog(
        error: String,
        logLines: List<String>
    ): Result = withContext(Dispatchers.IO) {
        localDiagnosis(error, "patch pipeline")?.let {
            return@withContext Result(true, suggestion = it)
        }

        val tail = logLines.takeLast(40).joinToString("\n")

        remote(
            """
            AzlukPatcher patch run FAILED.
            Exception: $error
            Patch log (last ${logLines.size.coerceAtMost(40)} lines):
            $tail
            Identify the failing pipeline stage and the concrete fix.
            """.trimIndent(),
            300
        )
    }

    suspend fun suggestPatches(
        appName: String,
        detectedKeys: List<String>
    ): Result = withContext(Dispatchers.IO) {
        if (detectedKeys.isEmpty()) {
            return@withContext Result(false)
        }

        remote(
            "App: $appName\nDetected patches: " +
                    "${detectedKeys.joinToString(", ")}\n" +
                    "Recommend priority in one sentence.",
            120
        )
    }
}
